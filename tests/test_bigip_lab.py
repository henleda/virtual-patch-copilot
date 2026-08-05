"""L2 — the BIG-IP lab: the AS3 client, the tenant guard, and create/rm.

Offline throughout: `FakeBigIP` stands in for the appliance and the one client-level test drives
`httpx.MockTransport`, the same technique `test_xc.py` uses for the XC client. No network, no
appliance, no credentials.

The behaviour this file exists to pin is the guard — a command that removes infrastructure is only
safe to hand someone if the thing it cannot touch is genuinely untouchable.
"""
from __future__ import annotations

import json

import httpx
import pytest

from vpcopilot import audit, bigip_lab
from vpcopilot.bigip import AS3_PATH, BigIP, BigIPError


class FakeBigIP:
    """Just enough appliance: a tenant store, and a record of every call for ordering assertions."""

    def __init__(self, tenants=None, as3_version="3.56.0"):
        self._tenants = list(tenants or [])
        self.as3_version = as3_version
        self.deployed: list[dict] = []
        self.deleted: list[str] = []
        self.dry_runs: list[dict] = []

    def info(self):
        return {"version": self.as3_version}

    def tenants(self):
        return sorted(self._tenants)

    def deploy(self, declaration, *, dry_run=False):
        if dry_run:
            self.dry_runs.append(declaration)
            return {"results": [{"code": 200, "message": "success", "dryRun": True}]}
        self.deployed.append(declaration)
        body = declaration.get("declaration", {})
        for k, v in body.items():
            if isinstance(v, dict) and v.get("class") == "Tenant" and k not in self._tenants:
                self._tenants.append(k)
        return {"results": [{"code": 200, "message": "success"}]}

    def delete_tenant(self, tenant):
        self.deleted.append(tenant)
        self._tenants = [t for t in self._tenants if t != tenant]
        return {"results": [{"code": 200, "message": "success"}]}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(bigip_lab.PROTECTED_ENV, raising=False)
    for k in ("BIGIP_URL", "BIGIP_USER", "BIGIP_PASSWORD"):
        monkeypatch.delenv(k, raising=False)


# ---------------------------------------------------------------- the guard


def test_common_is_refused_and_the_refusal_cannot_be_overridden():
    """/Common holds the appliance's own configuration. Every other guard in this project lets an
    override through because the operator may know something the tool does not; there is nothing to
    know here, so this one is absolute — including on a dry run, because previewing the deletion of
    the appliance's config is previewing an outage."""
    for allow, dry in ((False, False), (True, False), (False, True), (True, True)):
        with pytest.raises(RuntimeError, match="appliance's own configuration"):
            bigip_lab.guard_tenant("Common", allow_protected=allow, dry_run=dry)


def test_common_is_protected_even_with_the_env_var_cleared(monkeypatch):
    monkeypatch.setenv(bigip_lab.PROTECTED_ENV, "")
    assert "Common" in bigip_lab.protected_tenants()


@pytest.mark.parametrize("name", [
    "common", "COMMON", "CoMmOn",        # BIG-IP resolves these to the SAME object as `Common`
])
def test_the_common_refusal_is_case_insensitive(name):
    """A set-membership test on the exact string would wave the lower-case spelling through to the
    very tenant the guard exists to protect."""
    with pytest.raises(RuntimeError, match="appliance's own configuration"):
        bigip_lab.guard_tenant(name, allow_protected=True, dry_run=False)


@pytest.mark.parametrize("name", [
    "Common ", " Common",                # whitespace: not literally "Common", may resolve to it
    "../Common", "lab/../Common",        # a `/` would address a different path segment on DELETE
    "vpcopilot%2Flab", "a b", "", "  ",
    "9lab",                              # AS3 names do not start with a digit
])
def test_a_tenant_name_that_is_not_a_plain_identifier_is_refused(name):
    """The /Common refusal is only worth as much as the parsing in front of it — and the sharp case
    is `/`, which would sit in `DELETE …/declare/<tenant>` and walk out of its own path segment."""
    with pytest.raises(RuntimeError):
        bigip_lab.guard_tenant(name, allow_protected=False, dry_run=False)


def test_a_protected_name_is_matched_case_insensitively_too(monkeypatch):
    monkeypatch.setenv(bigip_lab.PROTECTED_ENV, "Prod_Tenant")
    with pytest.raises(RuntimeError, match="refusing to mutate protected"):
        bigip_lab.guard_tenant("prod_tenant", allow_protected=False, dry_run=False)


def test_a_named_protected_tenant_is_refused_but_overridable(monkeypatch):
    monkeypatch.setenv(bigip_lab.PROTECTED_ENV, "prod_tenant,staging")
    with pytest.raises(RuntimeError, match="refusing to mutate protected"):
        bigip_lab.guard_tenant("prod_tenant", allow_protected=False, dry_run=False)
    bigip_lab.guard_tenant("prod_tenant", allow_protected=True, dry_run=False)   # override works
    bigip_lab.guard_tenant("prod_tenant", allow_protected=False, dry_run=True)   # a preview is fine
    bigip_lab.guard_tenant("some_other", allow_protected=False, dry_run=False)   # unlisted is fine


def test_the_guard_runs_before_the_appliance_is_ever_contacted(monkeypatch):
    """A refusal must not depend on being able to reach the appliance — the K2 precedent, where a
    gate that constructed its client first came back as "credentials not set" instead of "refused"."""
    monkeypatch.setenv(bigip_lab.PROTECTED_ENV, "prod_tenant")

    def boom(*a, **k):
        raise AssertionError("guard must refuse before any client is constructed")
    monkeypatch.setattr(bigip_lab, "BigIP", boom)
    for fn in (lambda: bigip_lab.create("Common", "h:1", "1.2.3.4"),
               lambda: bigip_lab.remove("Common"),
               lambda: bigip_lab.create("prod_tenant", "h:1", "1.2.3.4"),
               lambda: bigip_lab.remove("prod_tenant")):
        with pytest.raises(RuntimeError):
            fn()


def test_both_surfaces_reach_the_same_guard(monkeypatch, tmp_path):
    """One module function, two surfaces. The console must not be able to do what the CLI refuses."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    monkeypatch.setattr(A, "OUT", tmp_path)
    r = TestClient(A.app).post("/api/bigip-lab", json={"action": "rm", "tenant": "Common",
                                                       "dry_run": False})
    assert r.status_code == 409                       # a refusal is an answer, not a fault
    assert "appliance's own configuration" in r.json()["detail"]


# ---------------------------------------------------------------- create / rm


def test_create_deploys_a_clean_slate_tenant_with_no_waf_attached(tmp_path):
    """Clean-slate in `lab._clean_slate`'s sense. Shipping a WAF policy here would mean the band-aid
    was already on before anyone applied it — the "looks applied and is not" confusion G2's canary
    exists to prevent, arriving one layer earlier."""
    fake = FakeBigIP()
    res = bigip_lab.create("vpcopilot_lab", "10.30.10.22:8080", "10.30.10.190",
                           out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert res["code"] == 200 and res["existed"] is False
    decl = fake.deployed[0]["declaration"]
    app = decl["vpcopilot_lab"]["lab"]
    assert app["serviceMain"]["virtualAddresses"] == ["10.30.10.190"]
    assert app["lab_pool"]["members"][0]["serverAddresses"] == ["10.30.10.22"]
    assert app["lab_pool"]["members"][0]["servicePort"] == 8080
    blob = json.dumps(fake.deployed[0])
    for waf_key in ("WAF_Policy", "policyWAF", "securityLogProfiles"):
        assert waf_key not in blob


def test_an_origin_with_no_port_defaults_rather_than_crashing(tmp_path):
    fake = FakeBigIP()
    bigip_lab.create("t", "10.30.10.22", "10.30.10.190", out_dir=str(tmp_path),
                     client=fake, log=lambda m: None)
    assert fake.deployed[0]["declaration"]["t"]["lab"]["lab_pool"]["members"][0]["servicePort"] == 8080


def test_create_is_idempotent_and_converges_rather_than_refusing(tmp_path):
    """`lab.py`'s shape: idempotent by existence. Re-running with a changed origin should MOVE the
    pool member — "idempotent" is not "do nothing if the name is taken"."""
    fake = FakeBigIP()
    bigip_lab.create("t", "10.0.0.1:8080", "10.30.10.190", out_dir=str(tmp_path),
                     client=fake, log=lambda m: None)
    res = bigip_lab.create("t", "10.0.0.9:9090", "10.30.10.190", out_dir=str(tmp_path),
                           client=fake, log=lambda m: None)
    assert res["existed"] is True and len(fake.deployed) == 2
    member = fake.deployed[1]["declaration"]["t"]["lab"]["lab_pool"]["members"][0]
    assert member["serverAddresses"] == ["10.0.0.9"] and member["servicePort"] == 9090


def test_remove_is_the_explicit_inverse_lab_py_never_had(tmp_path):
    fake = FakeBigIP(tenants=["vpcopilot_lab"])
    res = bigip_lab.remove("vpcopilot_lab", out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert res["removed"] is True and fake.deleted == ["vpcopilot_lab"]
    assert fake.tenants() == []


def test_removing_an_absent_tenant_reports_it_rather_than_claiming_success(tmp_path):
    """"There was nothing to remove" and "we removed it" are different facts, and only one of them
    means the appliance changed."""
    fake = FakeBigIP(tenants=["other"])
    res = bigip_lab.remove("vpcopilot_lab", out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert res["removed"] is False and res["reason"] == "not present"
    assert fake.deleted == []
    assert audit.load(str(tmp_path)) == []            # nothing changed, so nothing is recorded


def test_remove_deletes_by_tenant_scope_not_by_reposting_the_declaration(tmp_path):
    """Scoped by URL on purpose: `updateMode: complete` on a whole-declaration POST would delete
    every OTHER tenant as a side effect of removing this one."""
    fake = FakeBigIP(tenants=["vpcopilot_lab", "someone_elses_app"])
    bigip_lab.remove("vpcopilot_lab", out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert fake.deployed == []                        # no declaration was posted
    assert fake.tenants() == ["someone_elses_app"]    # the other tenant survives


# ---------------------------------------------------------------- dry run + audit


def test_a_dry_run_asks_as3_what_it_would_change_and_writes_nothing(tmp_path):
    fake = FakeBigIP()
    res = bigip_lab.create("t", "10.0.0.1:8080", "10.30.10.190", dry_run=True,
                           out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert res["dry_run"] is True and res["audited"] is False
    assert fake.deployed == [] and len(fake.dry_runs) == 1
    assert audit.load(str(tmp_path)) == []            # a dry run changed nothing (docs/AUDIT.md)


def test_a_dry_run_removal_removes_nothing(tmp_path):
    fake = FakeBigIP(tenants=["t"])
    res = bigip_lab.remove("t", dry_run=True, out_dir=str(tmp_path), client=fake, log=lambda m: None)
    assert res["removed"] is False and fake.deleted == [] and fake.tenants() == ["t"]
    assert audit.load(str(tmp_path)) == []


@pytest.mark.parametrize("action,expected", [("create", "bigip_lab_create"), ("rm", "bigip_lab_remove")])
def test_every_mutation_writes_an_audit_record(tmp_path, action, expected):
    """The gap `lab-create` has: docs/AUDIT.md says out loud that it mutates a tenant and writes
    nothing, so the trail cannot show it. This one is recorded like any other mutating action."""
    fake = FakeBigIP(tenants=["t"] if action == "rm" else [])
    if action == "create":
        bigip_lab.create("t", "10.0.0.1:8080", "10.30.10.190", out_dir=str(tmp_path),
                         client=fake, log=lambda m: None)
    else:
        bigip_lab.remove("t", out_dir=str(tmp_path), client=fake, log=lambda m: None)
    entries = audit.load(str(tmp_path))
    assert [e["action"] for e in entries] == [expected]
    e = entries[0]
    assert e["tenant"] == "t"
    # Identity is stamped centrally, exactly as for every other action — not by this call site.
    for k in ("ts", "run_id", "actor", "host", "tool_version"):
        assert e.get(k)


# ---------------------------------------------------------------- status


@pytest.mark.parametrize("action,outcome", [("bigip_lab_create", "created"),
                                            ("bigip_lab_remove", "removed")])
def test_the_new_actions_are_registered_in_the_exporter(tmp_path, action, outcome):
    """CONTRIBUTING.md requires a new action to be registered in `export.CATEGORY`/`_outcome`, or
    the evidence bundle shows `other` / `recorded` — a real appliance mutation reading as a no-op."""
    from vpcopilot.export import build_audit_events
    audit.record(str(tmp_path), action, tenant="t", code=200, message="success")
    row = build_audit_events(str(tmp_path))[0]
    assert row["category"] == "lab"        # not "other"
    assert row["outcome"] == outcome       # not "recorded"


def test_status_says_not_configured_rather_than_erroring():
    """An unset lab must not surface a connection error — "nobody set this up" and "it is broken"
    are different answers."""
    st = bigip_lab.status()
    assert st["configured"] is False and st["tenants"] == []


def test_status_separates_unreachable_from_as3_missing(monkeypatch):
    """The PAYG images ship WITHOUT AS3, so an appliance that answers perfectly can still be unable
    to take a declaration. That needs a different fix from one that cannot be reached, so it must
    not render the same."""
    monkeypatch.setenv("BIGIP_URL", "https://10.0.0.1:8443")

    class Dead:
        def info(self):
            raise BigIPError("ConnectTimeout")
    st = bigip_lab.status(client=Dead())
    assert st["reachable"] is False and "ConnectTimeout" in st["reason"]

    st = bigip_lab.status(client=FakeBigIP(tenants=["vpcopilot_lab"]))
    assert st["reachable"] is True and st["as3"] == "3.56.0" and st["tenants"] == ["vpcopilot_lab"]
    assert "Common" in st["protected"]


# ---------------------------------------------------------------- the client


def test_the_client_never_lets_the_password_reach_an_error_string():
    """`xc._redact`'s precedent: a token must not leak into a log, an error or a traceback.

    The response body MUST contain the password, or this test proves nothing. It used to mock
    `text="boom"` — a body that never contained the secret — so `BigIP._redact` could be deleted
    outright and the assertion still held. Vacuous, in the one test named for a credential leak.

    The realistic shape it now mocks: AS3 rejects a declaration and echoes the submitted document
    back in the error. Declarations legitimately carry credentials (remote logging targets, pool
    member auth), so the password coming back in `r.text` is the normal failure, not a contrived
    one."""
    echoed = ('{"code":422,"message":"declaration is invalid",'
              '"declaration":{"remoteLogging":{"user":"admin","pass":"s3cr3t-pw"}}}')

    c = BigIP(base_url="https://bigip.test", user="admin", password="s3cr3t-pw")
    c._c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(422, text=echoed)),
                        auth=("admin", "s3cr3t-pw"))
    with pytest.raises(BigIPError) as e:
        c.get_declaration()
    assert "s3cr3t-pw" not in str(e.value), "the appliance echoed the password and we passed it on"
    assert "REDACTED" in str(e.value), "it must be visibly redacted, not silently truncated away"
    assert "declaration is invalid" in str(e.value), \
        "redaction must not eat the diagnostic — an unreadable error is its own failure"


def test_the_password_is_redacted_out_of_a_transport_error_too():
    """The other branch of `_req`. httpx puts the request URL in some transport errors, and a
    connection string can carry credentials — so both raise paths need the same treatment."""
    def boom(request):
        raise httpx.ConnectError("failed connecting to https://admin:s3cr3t-pw@bigip.test")

    c = BigIP(base_url="https://bigip.test", user="admin", password="s3cr3t-pw")
    c._c = httpx.Client(transport=httpx.MockTransport(boom))
    with pytest.raises(BigIPError) as e:
        c.get_declaration()
    assert "s3cr3t-pw" not in str(e.value)


def test_an_appliance_with_no_tenants_answers_204_and_is_not_an_error():
    """AS3 answers 204 with an empty body when nothing is deployed. Letting `.json()` raise on that
    would make "nothing deployed yet" indistinguishable from a broken appliance."""
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(204)))
    assert c.get_declaration() == {}
    assert c.tenants() == []


def test_tenants_ignores_as3s_own_bookkeeping_keys():
    """A declaration carries `class`, `schemaVersion`, `id`, `updateMode`, `controls` … beside the
    tenants. A tenant is identified by `class == Tenant`, not by "a key I do not recognise"."""
    body = {"class": "ADC", "schemaVersion": "3.0.0", "id": "x", "updateMode": "selective",
            "controls": {"archiveTimestamp": "…"},
            "vpcopilot_lab": {"class": "Tenant"}, "other_app": {"class": "Tenant"}}
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"declaration": body})))
    assert c.tenants() == ["other_app", "vpcopilot_lab"]


def test_a_dry_run_sets_as3s_own_action_rather_than_being_simulated_here():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"results": [{"code": 200}]})
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(handler))
    c.deploy({"class": "AS3", "declaration": {}}, dry_run=True)
    assert seen["action"] == "dry-run"


def test_a_schema_rejection_raises_rather_than_reading_as_success():
    """Measured against the real appliance: AS3 answers an invalid declaration with `HTTP 422` and a
    TOP-LEVEL `{code, errors, message}` and **no `results` array at all** — so a caller reading
    `results[0]` gets `None` and renders "AS3: None None" as though it had worked. Reproduced live
    with a bad virtualAddress before this guard existed."""
    body = {"code": 422, "message": "declaration is invalid",
            "errors": ["/t/app/serviceMain/virtualAddresses/0: should match format \"f5ip\""],
            "declarationId": "badtest"}
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(422, json=body)))
    with pytest.raises(BigIPError) as e:
        c.deploy({"class": "AS3"})
    assert "422" in str(e.value) and "f5ip" in str(e.value)


def test_a_per_tenant_failure_inside_an_http_200_raises():
    """The other half, and the one a status-code check cannot see: AS3 answers **HTTP 200** with the
    bad code inside `results[].code`. Without this the lab reports success and deployed nothing."""
    body = {"results": [{"code": 422, "message": "declaration failed", "tenant": "t"}]}
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=body)))
    with pytest.raises(BigIPError, match="per tenant"):
        c.deploy({"class": "AS3"})


def test_a_failed_deploy_is_never_audited_as_a_successful_lab(tmp_path):
    """The consequence that makes the two tests above matter: an audit record claiming a lab was
    created when the appliance rejected it is a confident wrong answer in the trail."""
    class Failing(FakeBigIP):
        def deploy(self, declaration, *, dry_run=False):
            raise BigIPError("AS3 rejected the declaration (422): declaration is invalid")

    with pytest.raises(BigIPError):
        bigip_lab.create("t", "10.0.0.1:8080", "10.30.10.190", out_dir=str(tmp_path),
                         client=Failing(), log=lambda m: None)
    assert audit.load(str(tmp_path)) == []


def test_the_client_refuses_a_delete_whose_tenant_name_carries_a_separator():
    """Percent-encoding alone is NOT enough, and writing this test is what proved it: `httpx`
    normalizes `%2F` back to `/` when building the URL, so `quote('a/b')` still produced the path
    `…/declare/a/b` — a name that walks out of its own path segment and addresses a different
    endpoint. Refusing the name is the guarantee; the encoding is defence in depth behind it. The
    check is repeated here rather than left to `bigip_lab` because this is the one call that
    interpolates a caller-supplied string into a URL."""
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"results": [{"code": 200}]})))
    for bad in ("a/b", "../Common", "a b", "", "9lab"):
        with pytest.raises(BigIPError, match="refusing to DELETE"):
            c.delete_tenant(bad)


def test_delete_is_scoped_to_one_tenant_in_the_url():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["method"] = request.method
        return httpx.Response(200, json={"results": [{"code": 200}]})
    c = BigIP(base_url="https://bigip.test", user="admin", password="pw")
    c._c = httpx.Client(transport=httpx.MockTransport(handler))
    c.delete_tenant("vpcopilot_lab")
    assert seen["method"] == "DELETE" and seen["path"] == f"{AS3_PATH}/vpcopilot_lab"


# ---------------------------------------------------------------- surfaces


def test_the_cli_command_exists_and_is_kebab_case():
    from vpcopilot import cli
    assert "bigip-lab" in {c.name for c in cli.app.registered_commands}


@pytest.mark.parametrize("env,tenant", [({}, "Common"),
                                        ({"VPCOPILOT_PROTECTED_BIGIP_TENANTS": "held"}, "held")])
def test_a_refused_guard_exits_non_zero_rather_than_tracebacking(monkeypatch, env, tenant, tmp_path):
    """Found by running it live, and it is the one way a refusal is worse than no guard: the guard
    fired correctly, printed a Python traceback, and exited **0** — so a script or a CI gate reading
    the exit code would have been told the removal succeeded."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("BIGIP_URL", "https://127.0.0.1:1")   # never contacted: the guard runs first
    monkeypatch.setenv("BIGIP_PASSWORD", "pw")
    res = CliRunner().invoke(cli.app, ["bigip-lab", "rm", "--tenant", tenant, "--out", str(tmp_path)])
    assert res.exit_code == 3                      # 3 = policy refusal, distinct from 1
    assert "refused" in res.output and "Traceback" not in res.output
    # Not just "refused": assert on the RAISED type, because Rich truncates the rendered panel to
    # the terminal width and a substring check on the box body is width-dependent. The type is what
    # the surfaces actually branch on, and it is what distinguishes a policy decision from a
    # connection error — the distinction whose absence let the misclassification below ship.
    with pytest.raises(bigip_lab.LabRefused):
        bigip_lab.remove(tenant, out_dir=str(tmp_path), client=FakeBigIP(), log=lambda m: None)


def test_an_unreachable_appliance_is_not_reported_as_a_policy_refusal(monkeypatch, tmp_path):
    """Found by adversarial review. A dropped tunnel is the likeliest failure of a command whose
    management path is an SSM port-forward, and it rendered under the same red `refused:` heading
    with the same exit code as the unoverridable `/Common` guard. A CI gate must respond oppositely
    to the two: a refusal means fix the request, a transport failure means retry."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    monkeypatch.setenv("BIGIP_URL", "https://127.0.0.1:1")     # nothing listening
    monkeypatch.setenv("BIGIP_PASSWORD", "pw")
    res = CliRunner().invoke(cli.app, ["bigip-lab", "rm", "--tenant", "some_lab", "--out", str(tmp_path)])
    assert res.exit_code == 1                      # 1 = the appliance/path, not a decision
    # `res.output` is width-truncated by Rich, so assert on the exit code (the thing a CI gate
    # reads) plus the raised type, which is what the surfaces branch on.
    assert "appliance error" in res.output
    with pytest.raises(BigIPError):                # NOT LabRefused — nobody declined anything
        bigip_lab.remove("some_lab", out_dir=str(tmp_path), log=lambda m: None)


def test_the_console_separates_a_refusal_from_an_unreachable_appliance(monkeypatch, tmp_path):
    """The same distinction on the other surface: 409 says "we declined", 502 says "we could not
    reach it". A caller that cannot tell them apart retries the wrong one."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setenv("BIGIP_URL", "https://127.0.0.1:1")
    monkeypatch.setenv("BIGIP_PASSWORD", "pw")
    c = TestClient(A.app)
    assert c.post("/api/bigip-lab", json={"action": "rm", "tenant": "Common",
                                          "dry_run": False}).status_code == 409
    assert c.post("/api/bigip-lab", json={"action": "rm", "tenant": "some_lab",
                                          "dry_run": False}).status_code == 502


@pytest.mark.parametrize("origin", ["10.0.0.1:http", "10.0.0.1:0", "10.0.0.1:99999", ":8080", ""])
def test_a_malformed_origin_is_refused_rather_than_crashing(origin, tmp_path):
    """`int()` raises ValueError, which is NOT a RuntimeError, so it escaped both surfaces' handlers
    entirely: the CLI printed a traceback exposing `_split_origin`'s body and the console answered a
    bare 500, where every other bad input on that endpoint gets a message."""
    with pytest.raises(bigip_lab.LabRefused, match="invalid origin"):
        bigip_lab.create("t", origin, "10.30.10.190", out_dir=str(tmp_path),
                         client=FakeBigIP(), log=lambda m: None)


def test_status_answers_rather_than_raising_when_only_the_password_is_missing(monkeypatch):
    """The routine half-configured state — the Setup page manages the three BIGIP_* keys as separate
    fields and only sends the ones that were filled in. `status()`'s whole job is to answer, and it
    was raising `BigIPError` out of a CLI readout and 500ing the endpoint the page polls."""
    monkeypatch.setenv("BIGIP_URL", "https://127.0.0.1:18443")
    monkeypatch.delenv("BIGIP_PASSWORD", raising=False)
    st = bigip_lab.status()                        # must not raise
    assert st["configured"] is True and st["reachable"] is False
    assert "BIGIP_PASSWORD" in st["reason"]


@pytest.mark.parametrize("status,expect", [
    (404, "AS3 is not installed"),                 # every PAYG image ships in this state
    (401, "check BIGIP_USER"),
    (403, "check BIGIP_USER"),
])
def test_status_tells_apart_failures_that_need_different_fixes(monkeypatch, status, expect):
    """A 404 on the AS3 path is an appliance that answers perfectly and simply has no AS3 — this
    very lab hit it. Reporting that as "unreachable" sends an operator hunting a network problem
    when the fix is a package install."""
    monkeypatch.setenv("BIGIP_URL", "https://10.0.0.1:8443")

    class Answering:
        def info(self):
            raise BigIPError(f"GET /info -> {status}", status=status)
    st = bigip_lab.status(client=Answering())
    assert st["reachable"] is True                 # the box answered — that IS reachable
    assert expect in st["reason"]
    if status == 404:
        assert st["as3_installed"] is False


def test_every_status_branch_returns_the_same_keys(monkeypatch):
    """A degraded branch that silently omitted `protected` rendered as a blank list on the CLI,
    which reads as "nothing is protected" rather than "we could not get that far"."""
    monkeypatch.setenv("BIGIP_URL", "https://10.0.0.1:8443")

    class Half:
        def info(self):
            return {"version": "3.56.0"}

        def tenants(self):
            raise BigIPError("GET /declare -> 503: operation in progress", status=503)

    monkeypatch.delenv("BIGIP_URL", raising=False)
    unset = bigip_lab.status()
    monkeypatch.setenv("BIGIP_URL", "https://10.0.0.1:8443")
    degraded = bigip_lab.status(client=Half())
    healthy = bigip_lab.status(client=FakeBigIP(tenants=["t"]))
    assert set(unset) == set(degraded) == set(healthy)
    assert degraded["protected"] == healthy["protected"] != []
    # …and an unknown tenant list carries the reason that says so, rather than reading as "none".
    assert degraded["tenants"] == [] and degraded["reason"]


def test_the_console_endpoint_and_the_cli_call_the_same_module_function(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    monkeypatch.setattr(A, "OUT", tmp_path)
    assert TestClient(A.app).get("/api/bigip-lab").json() == bigip_lab.status()


def test_the_bigip_keys_are_on_the_setup_page_and_the_password_is_secret():
    from vpcopilot.console import app
    for k in ("BIGIP_URL", "BIGIP_USER", "BIGIP_PASSWORD"):
        assert k in app.MANAGED_KEYS
    assert "BIGIP_PASSWORD" in app.SECRET_KEYS
    assert "BIGIP_URL" not in app.SECRET_KEYS       # the page must be able to show what is configured


def test_the_setup_page_actually_calls_the_endpoint():
    """A surface nothing calls is not a surface (the I1 precedent)."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1]
            / "src/vpcopilot/console/static/index.html").read_text()
    assert "/api/bigip-lab" in html and "bigipStatus" in html and "loadBigip(" in html


def test_the_lab_module_never_imports_xc():
    """The BIG-IP lab and the XC tenant are separate estates; a stray import is how they get
    entangled (K1's `mcp.py` never imports `xc` is the precedent, pinned the same way)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/bigip_lab.py").read_text()
    assert "from .xc import" not in src and "XC()" not in src
