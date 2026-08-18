"""I1 — patch expiry and the reconcile loop.

The whole point of this module is what it does when nobody is watching, so most of these tests are
about restraint: what it refuses to do, what it holds, and what it declines to conclude. Offline
throughout — no XC, no GitHub, no HTTP.

`now` is injected everywhere (the same constructor-injection the apply spine uses for `sleep`)
because nothing in this suite fakes wall-clock and freezegun is not a dependency. Without it the
not-yet-expired branch would be untestable."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from vpcopilot import ledger, reconcile

T0 = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
EXPLOIT = {"method": "POST", "path": "/users/v1/register"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv(reconcile.TARGETS_ENV, "lab=http://origin.test")
    monkeypatch.delenv(reconcile.WEBHOOK_ENV, raising=False)
    monkeypatch.delenv("VPCOPILOT_PROBE_TOKEN", raising=False)
    monkeypatch.delenv("VPCOPILOT_PROBE_USER", raising=False)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


def _at(hours):
    return lambda: T0 + timedelta(hours=hours)


def _seed(tmp_path, *, applied_h=-1, ttl=168, state="remediated", cure="https://github.com/a/b/pull/1",
          fid="f1", lb="lab", control="service_policy", **extra):
    applied = T0 + timedelta(hours=applied_h)
    e = {"finding_id": fid, "state": state, "title": "SQLi in login", "severity": "critical",
         "vuln_class": "sqli",
         "mitigation": {"control": control, "policy_name": "deny-x", "lb": lb},
         "ttl": {"applied_at": applied.isoformat(), "ttl_hours": ttl,
                 "expires_at": (applied + timedelta(hours=ttl)).isoformat()},
         **extra}
    if cure:
        e["cure"] = {"pr_url": cure, "pr_number": 1}
    ledger.save(str(tmp_path), {fid: e})
    return e


def _probes(tmp_path, fid="f1"):
    (tmp_path / "probes.json").write_text(json.dumps(
        [{"finding_id": fid, "exploit": EXPLOIT, "legit": {"method": "GET", "path": "/"}}]))


def _no_github(monkeypatch, state="open"):
    monkeypatch.setattr(reconcile, "_cure_state", lambda e, cache, *, log: state)


def _fake_probe(monkeypatch, result):
    monkeypatch.setattr(reconcile, "_probe", lambda e, o, origin, *, log: result)


def _healthy(monkeypatch, ok=True, reason="unreachable"):
    monkeypatch.setattr(reconcile, "origin_health",
                        lambda url, *, log=print: {"ok": ok, "status": 200 if ok else None,
                                                   "reason": "" if ok else reason})


def _actions(tmp_path):
    from vpcopilot import audit
    return [a["action"] for a in audit.load(str(tmp_path))]


def _run(tmp_path, **kw):
    kw.setdefault("log", lambda m: None)
    return reconcile.reconcile(str(tmp_path), **kw)


# ---- TTL, stamped where every apply path already passes ----
def test_every_apply_gets_a_ttl_without_touching_any_apply_call_site(tmp_path):
    """`mark_mitigated` is the one chokepoint all eight apply paths already call, so 'give every
    applied control a TTL at apply time' needs no edit at any of them."""
    e = ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    assert e["ttl"]["ttl_hours"] == ledger.DEFAULT_TTL_HOURS
    assert e["ttl"]["applied_at"] and e["ttl"]["expires_at"] > e["ttl"]["applied_at"]


def test_the_ttl_default_is_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_DEFAULT_TTL_HOURS", "24")
    e = ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    assert e["ttl"]["ttl_hours"] == 24


def test_a_nonsense_ttl_env_falls_back_rather_than_crashing_an_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_DEFAULT_TTL_HOURS", "soon")
    e = ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    assert e["ttl"]["ttl_hours"] == ledger.DEFAULT_TTL_HOURS


def test_ttl_lives_beside_mitigation_not_inside_it(tmp_path):
    """report.py renders `mitigation` as `html.escape(str(dict))` — a key nested in there would
    rewrite the committed demo report fixture."""
    e = ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    assert set(e["mitigation"]) == {"control", "policy_name", "lb"}


def test_an_entry_with_no_ttl_never_expires(tmp_path):
    """Pre-I1 entries and every hand-built test fixture have no `ttl`. Reading that as 'overdue'
    would escalate the entire back catalogue on the first pass."""
    exp = reconcile.expiry({"finding_id": "f1"}, T0)
    assert exp["expired"] is False and exp["remaining_hours"] is None


def test_a_malformed_timestamp_reads_as_unknown_not_expired(tmp_path):
    exp = reconcile.expiry({"ttl": {"applied_at": "yesterday", "expires_at": "soon"}}, T0)
    assert exp["expired"] is False and exp["age_hours"] is None


# ---- the allowlist ----
def test_targets_parses_lb_and_origin_pairs(monkeypatch):
    monkeypatch.setenv(reconcile.TARGETS_ENV, "crapi-lab=http://10.0.0.5:8888, vampi-lab=http://10.0.0.5:5000")
    assert reconcile.targets() == {"crapi-lab": "http://10.0.0.5:8888",
                                   "vampi-lab": "http://10.0.0.5:5000"}


def test_a_bare_lb_is_allowed_and_means_escalate_but_never_probe(monkeypatch):
    """One real lab origin sits behind a BIG-IP that answers direct requests with 403. Declaring
    the LB without an origin is how you say 'watch this, but you can never probe it'."""
    monkeypatch.setenv(reconcile.TARGETS_ENV, "vpcopilot-lab")
    assert reconcile.targets() == {"vpcopilot-lab": ""}


def test_no_allowlist_refuses_to_run_at_all(tmp_path, monkeypatch):
    monkeypatch.delenv(reconcile.TARGETS_ENV, raising=False)
    _seed(tmp_path)
    with pytest.raises(RuntimeError, match="allowlist"):
        _run(tmp_path)


def test_an_lb_outside_the_allowlist_is_skipped_untouched(tmp_path, monkeypatch):
    _seed(tmp_path, lb="somebody-elses-lb", applied_h=-999)
    _no_github(monkeypatch)
    r = _run(tmp_path, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_not_allowlisted"
    assert r["escalations"] == 0


def test_a_protected_lb_is_refused_even_when_allowlisted(tmp_path, monkeypatch):
    monkeypatch.setenv(reconcile.TARGETS_ENV, "nimbus-www=http://origin.test")
    _seed(tmp_path, lb="nimbus-www", applied_h=-999)
    _no_github(monkeypatch)
    assert _run(tmp_path, now=_at(0))["actions"][0]["outcome"] == "skipped_protected"


def test_a_missing_ledger_refuses_rather_than_minting_an_empty_run_dir(tmp_path):
    """A cron line with no working directory would otherwise create a fresh out dir and report
    zero patches forever."""
    with pytest.raises(RuntimeError, match="nothing to reconcile"):
        _run(tmp_path / "nowhere")


# ---- branch 3: escalation ----
def test_an_expired_patch_with_no_merged_cure_escalates(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-200, ttl=168)
    _no_github(monkeypatch, "open")
    r = _run(tmp_path, now=_at(0))
    assert r["escalations"] == 1 and r["actions"][0]["outcome"] == "escalated"
    assert "escalation" in _actions(tmp_path)


def test_an_escalation_leaves_the_control_in_place(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    _run(tmp_path, now=_at(0))
    from vpcopilot import audit
    ev = [a for a in audit.load(str(tmp_path)) if a["action"] == "escalation"][0]
    assert ev["kept"] is True
    assert ledger.load(str(tmp_path))["f1"]["state"] == "remediated"   # not retired


def test_an_escalation_carries_its_own_justification(tmp_path, monkeypatch):
    """`build_audit_events` joins title/vuln_class/severity from findings.json and ledger.json —
    both of which the next scan overwrites. A record that relies on the join loses the reason it
    exists the moment someone re-scans."""
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    _run(tmp_path, now=_at(0))
    from vpcopilot import audit
    ev = [a for a in audit.load(str(tmp_path)) if a["action"] == "escalation"][0]
    assert ev["title"] == "SQLi in login" and ev["severity"] == "critical"
    assert ev["vuln_class"] == "sqli" and ev["lb"] == "lab"
    assert ev["expires_at"] and ev["ttl_hours"] == 168


def test_a_patch_inside_its_ttl_is_left_alone(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-1, ttl=168)
    _no_github(monkeypatch, "open")
    r = _run(tmp_path, now=_at(0))
    assert r["actions"][0]["outcome"] == "ok" and r["escalations"] == 0
    assert _actions(tmp_path) == []          # a pass that changes nothing writes nothing


def test_escalation_does_not_repeat_every_night(tmp_path, monkeypatch):
    """A nightly cron would otherwise append another escalation forever and drown the trail."""
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    _run(tmp_path, now=_at(0))
    r2 = _run(tmp_path, now=_at(24))
    assert r2["escalations"] == 0 and r2["actions"][0]["outcome"] == "ok"
    assert _actions(tmp_path).count("escalation") == 1


def test_escalation_repeats_after_the_renotify_interval(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    _run(tmp_path, now=_at(0))
    r2 = _run(tmp_path, now=_at(200))        # past the 168h default re-notify
    assert r2["escalations"] == 1
    assert ledger.load(str(tmp_path))["f1"]["reconcile"]["escalation_count"] == 2


def test_a_merged_cure_never_escalates_however_old(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-9999)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    assert _run(tmp_path, now=_at(0))["escalations"] == 0


def test_an_unreadable_pr_holds_rather_than_escalating(tmp_path, monkeypatch):
    """A rate-limited or expired GitHub token must never read as 'no cure exists'."""
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "unknown")
    r = _run(tmp_path, now=_at(0))
    assert r["actions"][0]["outcome"] == "escalated"     # overdue is still overdue
    from vpcopilot import audit
    assert [a for a in audit.load(str(tmp_path)) if a["action"] == "escalation"][0]["cure_state"] == "unknown"


# ---- branch 2: the cure merged but did not work ----
def test_a_merged_cure_whose_exploit_still_reproduces_is_held_and_reported(tmp_path, monkeypatch):
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["fix_ineffective"] == 1 and r["retired"] == 0
    assert "fix_ineffective" in _actions(tmp_path)
    assert ledger.load(str(tmp_path))["f1"]["state"] == "remediated"   # band-aid stays


# ---- branch 1: retire, and the report-only gate ----
def test_a_proven_fix_is_reported_but_not_detached_without_apply(tmp_path, monkeypatch):
    """Report-only is the default: authoring the crontab is the human gate, exercised once."""
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    r = _run(tmp_path, now=_at(0))
    assert r["actions"][0]["outcome"] == "would_retire" and r["retired"] == 0
    assert ledger.load(str(tmp_path))["f1"]["state"] == "remediated"
    assert _actions(tmp_path) == []


def test_apply_retires_a_proven_fix(tmp_path, monkeypatch, fake_xc):
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr("vpcopilot.retire.XC", lambda *a, **k: fake_xc)
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["retired"] == 1
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"
    assert fake_xc.put_lb_calls                                  # actually detached
    assert "reconcile_retire" in _actions(tmp_path)
    assert "retire" in _actions(tmp_path)      # the existing action too, so old consumers still work


def test_apply_retires_a_bigip_bandaid_on_the_appliance_not_via_xc(tmp_path, monkeypatch):
    """A reconciled BIG-IP AWAF band-aid (control `bigip_awaf`) detaches on the appliance via
    retire_bigip — tenant/app recovered from the ledger's mitigation.lb — NOT through the XC PUT.
    A bring-your-own-BIG-IP user has no XC at all, so the XC-only presence checks must be skipped."""
    monkeypatch.setenv(reconcile.TARGETS_ENV, "vpcopilot_lab/lab=http://origin.test")
    _seed(tmp_path, control="bigip_awaf", lb="vpcopilot_lab/lab")
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True})
    # a BIG-IP-only user has no XC — constructing it raises, and reconcile must tolerate that
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no XC")))
    seen = {}

    def fake_retire(finding_id, *, tenant, app, out_dir, allow_protected, log):
        seen.update(finding_id=finding_id, tenant=tenant, app=app)
        ledger.mark_retired(out_dir, finding_id)               # the real retire_bigip does this
        return {"retired": True, "finding_id": finding_id, "tenant": tenant, "app": app}

    monkeypatch.setattr("vpcopilot.bigip_apply.retire_bigip", fake_retire)
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda *a, **k: pytest.fail("routed a BIG-IP band-aid to the XC detach"))
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["retired"] == 1
    assert seen == {"finding_id": "f1", "tenant": "vpcopilot_lab", "app": "lab"}  # recovered from the ledger lb
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"
    assert "reconcile_retire" in _actions(tmp_path)


def test_apply_retires_a_nginx_bandaid_on_the_box_not_via_xc(tmp_path, monkeypatch):
    """A reconciled NGINX App Protect band-aid (control `nginx_app_protect`) detaches on the box via
    retire_nginx — server/location recovered from the ledger's mitigation.lb — NOT through the XC PUT,
    for the same reason as BIG-IP: a bring-your-own-NGINX user has no XC at all."""
    monkeypatch.setenv(reconcile.TARGETS_ENV, "vpcopilot.lab/=http://origin.test")
    _seed(tmp_path, control="nginx_app_protect", lb="vpcopilot.lab/")
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True})
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no XC")))
    seen = {}

    def fake_retire(finding_id, *, server, location, out_dir, allow_protected, log):
        seen.update(finding_id=finding_id, server=server, location=location)
        ledger.mark_retired(out_dir, finding_id)               # the real retire_nginx does this
        return {"retired": True, "finding_id": finding_id, "server": server, "location": location}

    monkeypatch.setattr("vpcopilot.nginx_apply.retire_nginx", fake_retire)
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda *a, **k: pytest.fail("routed a NGINX band-aid to the XC detach"))
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["retired"] == 1
    assert seen == {"finding_id": "f1", "server": "vpcopilot.lab", "location": "/"}  # recovered from the lb
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"
    assert "reconcile_retire" in _actions(tmp_path)


def test_a_data_guard_leak_probe_reconciles_without_a_legit_leg(tmp_path, monkeypatch):
    """A response-masking (`waf_data_guard`) finding's probe has a `leak` request and NO `exploit` or
    `legit` leg. TWO gates must let it through and BOTH are exercised for real here — that is the point
    of patching `probe_from_spec` rather than `_probe` wholesale (an earlier version of this test
    patched `_probe`, which skipped `_probe`'s own fireable-precondition and hid a bug where a
    leak-only spec short-circuited to `{}` and held at `skipped_no_probe`, never reaching the leak
    exemption). With both fixed, a proven origin fix must auto-retire."""
    monkeypatch.setenv(reconcile.TARGETS_ENV, "vpcopilot_lab/lab=http://origin.test")
    _seed(tmp_path, control="bigip_awaf", lb="vpcopilot_lab/lab")
    (tmp_path / "probes.json").write_text(json.dumps(
        [{"finding_id": "f1", "leak": {"method": "GET", "path": "/api/profile"},
          "leak_secrets": ["4111111111111111"]}]))
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    seen = {}

    def fake_pfs(target_url, probe, log=None, auth=None):
        seen["spec"] = probe        # the REAL _probe let a leak-only spec through to probe_from_spec
        # origin fixed: leak observed (200), no secret present -> masked/blocked True, legit_ok True
        return {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True,
                "leak": True, "leak_observed": True}

    monkeypatch.setattr("vpcopilot.probe.probe_from_spec", fake_pfs)   # NOT reconcile._probe
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no XC")))
    monkeypatch.setattr("vpcopilot.bigip_apply.retire_bigip",
                        lambda finding_id, **k: {"retired": True, "finding_id": finding_id})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert seen.get("spec", {}).get("leak"), "_probe must reach probe_from_spec with the leak spec"
    assert r["retired"] == 1                    # not held at skipped_no_probe / skipped_no_legit_baseline
    outcomes = [a for a in r["actions"] if a["finding_id"] == "f1"]
    assert outcomes and outcomes[0]["outcome"] == "retired"


def test_a_control_already_gone_is_marked_retired_without_a_put(tmp_path, monkeypatch, fake_xc):
    """Someone retired it by hand. Detach would still PUT `no_service_policies` and claim a
    removal that did not happen."""
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    fake_xc.lb["spec"] = {}                                      # nothing attached
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["retired"] == 1 and fake_xc.put_lb_calls == []
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"


# ---- refusing to guess ----
def test_a_merged_cure_with_no_origin_holds_the_bandaid(tmp_path, monkeypatch):
    """Without an origin the exploit can only be fired at the LB, where the band-aid blocks it —
    which proves the band-aid works, not that the code was fixed."""
    monkeypatch.setenv(reconcile.TARGETS_ENV, "lab")
    _seed(tmp_path)
    _no_github(monkeypatch, "merged")
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_no_origin" and r["retired"] == 0


def test_an_unreachable_origin_holds_the_bandaid(tmp_path, monkeypatch):
    """The dangerous failure: a connection error reads as 'the exploit did not succeed', which
    reads as 'fixed', which detaches a control protecting a still-vulnerable app."""
    _seed(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch, ok=False)
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_origin_unhealthy" and r["retired"] == 0


def test_a_finding_with_no_probe_holds_the_bandaid(tmp_path, monkeypatch):
    """No fallback to the Nimbus-specific probes: firing crAPI's SQLi probe at VAmPI would produce
    a confident, wrong answer about an unrelated app."""
    _seed(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    r = _run(tmp_path, apply=True, now=_at(0))     # no probes.json at all
    assert r["actions"][0]["outcome"] == "skipped_no_probe" and r["retired"] == 0


def test_a_failing_legit_request_invalidates_the_exploit_result(tmp_path, monkeypatch):
    """If the legit request cannot reach the app, the origin is wrong or broken and a 'not
    exploitable' reading means nothing."""
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 404, "exploit_blocked": True, "legit_ok": False})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_origin_unhealthy" and r["retired"] == 0


def test_a_403_origin_is_not_healthy(monkeypatch):
    """Measured live: one lab origin is fronted by a BIG-IP that answers `403 Direct origin access
    denied`. That is a wall, not a health check passing."""
    import httpx

    class R:
        status_code = 403
    monkeypatch.setattr(httpx, "Client", lambda **k: type(
        "C", (), {"__enter__": lambda s: type("X", (), {"get": lambda s2, u: R()})(),
                  "__exit__": lambda *a: False})())
    assert reconcile.origin_health("http://x")["ok"] is False


def test_a_probe_that_raises_does_not_end_the_pass(tmp_path, monkeypatch):
    e1 = _seed(tmp_path, fid="f1")
    e2 = _seed(tmp_path, fid="f2")
    ledger.save(str(tmp_path), {"f1": e1, "f2": e2})   # _seed replaces the file; keep both
    (tmp_path / "probes.json").write_text(json.dumps(
        [{"finding_id": f, "exploit": EXPLOIT, "legit": {"method": "GET", "path": "/"}}
         for f in ("f1", "f2")]))
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)

    def boom(*a, **k):
        raise ConnectionError("dns")
    monkeypatch.setattr("vpcopilot.probe.probe_from_spec", boom)
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["checked"] == 2 and r["retired"] == 0
    assert all(a["outcome"].startswith("skipped") for a in r["actions"])


# ---- the destructive-replay cooldown ----
def test_the_probe_is_throttled_per_finding(tmp_path, monkeypatch):
    """These exploits genuinely move money and escalate roles, and they feed the same
    malicious-user telemetry the tenant reports on."""
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    fired = []
    monkeypatch.setattr(reconcile, "_probe", lambda e, o, origin, *, log: fired.append(1) or
                        {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    _run(tmp_path, now=_at(0))
    _run(tmp_path, now=_at(2))       # well inside the 24h default
    assert len(fired) == 1


def test_the_cooldown_never_delays_an_escalation(tmp_path, monkeypatch):
    """The TTL and PR checks are free reads and run every pass; only the destructive part is
    throttled."""
    _seed(tmp_path, applied_h=-200, cure=None)
    _no_github(monkeypatch, "none")
    ledger.record_reconcile(str(tmp_path), "f1", last_probe_at=T0.isoformat())
    assert _run(tmp_path, now=_at(1))["escalations"] == 1


def test_force_probe_overrides_the_cooldown(tmp_path, monkeypatch):
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    fired = []
    monkeypatch.setattr(reconcile, "_probe", lambda e, o, origin, *, log: fired.append(1) or
                        {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    _run(tmp_path, now=_at(0))
    _run(tmp_path, now=_at(1), force_probe=True, finding_id="f1")
    assert len(fired) == 2


def test_reconcile_builds_its_own_auth_to_avoid_a_nightly_login_storm(monkeypatch):
    """`apply._probe_auth_from_env` always sets login_path, so a token-only setup fires a spurious
    empty-credential POST /api/login before every probe — nightly, per finding, straight into the
    Malicious-User detection this tool demonstrates."""
    monkeypatch.setenv("VPCOPILOT_PROBE_TOKEN", "t0k")
    auth = reconcile._reconcile_auth()
    assert auth == {"token": "t0k"} and "login_path" not in auth


# ---- cron safety ----
def test_a_second_pass_exits_cleanly_instead_of_piling_up(tmp_path, monkeypatch):
    _seed(tmp_path)
    _no_github(monkeypatch, "open")
    with reconcile.PassLock(str(tmp_path)):
        r = _run(tmp_path, now=_at(0))
    assert r["lock"] == "busy" and r["checked"] == 0


def test_a_stale_lock_is_broken_so_one_crash_does_not_disable_reconcile_forever(tmp_path):
    (tmp_path / "reconcile.lock").write_text(json.dumps(
        {"pid": 1, "ts": (T0 - timedelta(hours=4)).isoformat()}))
    with reconcile.PassLock(str(tmp_path), now=_at(0)) as lk:
        assert lk.acquired


def test_a_fresh_lock_is_respected(tmp_path):
    (tmp_path / "reconcile.lock").write_text(json.dumps({"pid": 1, "ts": T0.isoformat()}))
    with reconcile.PassLock(str(tmp_path), now=_at(0)) as lk:
        assert not lk.acquired


def test_the_lock_is_released_even_when_the_pass_raises(tmp_path):
    with pytest.raises(ValueError), reconcile.PassLock(str(tmp_path), now=_at(0)):
        raise ValueError("boom")
    assert not (tmp_path / "reconcile.lock").exists()


def test_a_pass_is_idempotent(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-1)
    _no_github(monkeypatch, "open")
    a, b = _run(tmp_path, now=_at(0)), _run(tmp_path, now=_at(0))
    assert [x["outcome"] for x in a["actions"]] == [x["outcome"] for x in b["actions"]]
    assert _actions(tmp_path) == []


def test_findings_with_no_live_bandaid_are_not_walked(tmp_path, monkeypatch):
    ledger.save(str(tmp_path), {"f1": {"finding_id": "f1", "state": "found"},
                                "f2": {"finding_id": "f2", "state": "retired",
                                       "mitigation": {"control": "waf", "lb": "lab"}}})
    _no_github(monkeypatch, "open")
    assert _run(tmp_path, now=_at(0))["checked"] == 0


# ---- the webhook ----
def test_an_escalation_posts_to_the_webhook_when_one_is_configured(tmp_path, monkeypatch):
    monkeypatch.setenv(reconcile.WEBHOOK_ENV, "http://hook.test/x")
    sent = {}

    class C:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, json):
            sent.update(url=url, body=json)
            return type("R", (), {"status_code": 200})()
    import httpx
    monkeypatch.setattr(httpx, "Client", lambda **k: C())
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    _run(tmp_path, now=_at(0))
    assert sent["url"] == "http://hook.test/x"
    assert sent["body"]["finding_id"] == "f1" and sent["body"]["event"] == "vpcopilot.escalation"
    assert sent["body"]["severity"] == "critical"


def test_a_dead_webhook_never_changes_the_outcome(tmp_path, monkeypatch):
    """The audit record is the durable notification; the webhook is the convenient one."""
    monkeypatch.setenv(reconcile.WEBHOOK_ENV, "http://hook.test/x")
    import httpx

    def boom(**k):
        raise ConnectionError("refused")
    monkeypatch.setattr(httpx, "Client", boom)
    _seed(tmp_path, applied_h=-200)
    _no_github(monkeypatch, "open")
    r = _run(tmp_path, now=_at(0))
    assert r["escalations"] == 1 and "escalation" in _actions(tmp_path)
    from vpcopilot import audit
    assert [a for a in audit.load(str(tmp_path)) if a["action"] == "escalation"][0]["notified"] == "failed"


def test_no_webhook_configured_is_silent(tmp_path):
    assert reconcile.notify({"x": 1}, log=lambda m: None) == "skipped"


# ---- patches-list ----
def test_patches_list_shows_age_ttl_and_cure_state(tmp_path):
    _seed(tmp_path, applied_h=-48, ttl=168)
    rows = reconcile.list_patches(str(tmp_path), now=_at(0))
    assert len(rows) == 1
    r = rows[0]
    assert r["age_hours"] == 48 and round(r["remaining_hours"]) == 120
    assert r["expired"] is False and r["control"] == "service_policy" and r["lb"] == "lab"


def test_patches_list_marks_the_expired_ones(tmp_path):
    _seed(tmp_path, applied_h=-200, ttl=168)
    assert reconcile.list_patches(str(tmp_path), now=_at(0))[0]["expired"] is True


def test_patches_list_omits_retired_and_unmitigated_findings(tmp_path):
    ledger.save(str(tmp_path), {
        "a": {"finding_id": "a", "state": "found"},
        "b": {"finding_id": "b", "state": "retired", "mitigation": {"control": "waf", "lb": "lab"}},
        "c": {"finding_id": "c", "state": "mitigated", "mitigation": {"control": "waf", "lb": "lab"}}})
    assert [r["finding_id"] for r in reconcile.list_patches(str(tmp_path), now=_at(0))] == ["c"]


def test_patches_list_tolerates_a_pre_i1_entry(tmp_path):
    """One committed fixture omits `policy_name` from `mitigation` entirely; none of them have a
    TTL. Every reader has to use .get(), never subscript."""
    ledger.save(str(tmp_path), {"f1": {"finding_id": "f1", "state": "mitigated",
                                       "mitigation": {"control": "waf", "lb": "lab"}}})
    r = reconcile.list_patches(str(tmp_path), now=_at(0))[0]
    assert r["ttl_hours"] is None and r["expired"] is False and r["policy"] is None


def test_patches_list_fires_nothing(tmp_path, monkeypatch):
    """It has to stay cheap enough to render on every page load."""
    _seed(tmp_path)
    monkeypatch.setattr("vpcopilot.retire.pr_is_merged",
                        lambda u: pytest.fail("patches-list must not call GitHub"))
    reconcile.list_patches(str(tmp_path), now=_at(0))


# ---- no regressions ----
def test_a_rescan_no_longer_orphans_a_live_bandaid(tmp_path):
    """The old pruning deleted any entry absent from the new triage — including one whose control
    was still attached, stranding it where reconcile could never find it."""
    _seed(tmp_path, fid="old-finding", state="mitigated")
    ledger.init_from_scan(str(tmp_path), [{"id": "new-1"}],
                          [{"finding_id": "new-1", "bandaids": []}], [])
    entries = ledger.load(str(tmp_path))
    assert set(entries) == {"old-finding", "new-1"}
    assert entries["old-finding"]["mitigation"]["lb"] == "lab"


def test_a_rescan_still_drops_a_finding_with_no_live_bandaid(tmp_path):
    """P0-3: the ledger must still never mix targets (VAmPI + crAPI)."""
    ledger.save(str(tmp_path), {"stale": {"finding_id": "stale", "state": "found"},
                                "also-stale": {"finding_id": "also-stale", "state": "retired",
                                               "mitigation": {"control": "waf", "lb": "lab"}}})
    ledger.init_from_scan(str(tmp_path), [{"id": "new-1"}],
                          [{"finding_id": "new-1", "bandaids": []}], [])
    assert set(ledger.load(str(tmp_path))) == {"new-1"}


def test_the_ledger_state_machine_is_untouched(tmp_path):
    """`fix_ineffective` and `escalated` are data, not lifecycle positions — a finding past its TTL
    is still `mitigated`. Four other modules order these states by index."""
    assert ledger.STATES == ("found", "mitigated", "remediated", "retired")


def test_reconcile_records_are_data_not_a_state_change(tmp_path, monkeypatch):
    _seed(tmp_path, applied_h=-200, state="mitigated", cure=None)
    _no_github(monkeypatch, "none")
    _run(tmp_path, now=_at(0))
    e = ledger.load(str(tmp_path))["f1"]
    assert e["state"] == "mitigated"
    assert e["reconcile"]["outcome"] == "escalated"


def test_a_probe_that_cannot_authenticate_is_not_reported_as_a_missing_probe(tmp_path, monkeypatch):
    """`probe_from_spec` returns auth_failed with every field None rather than a misleading
    "not blocked". One is a credential to fix, the other is a finding that can never be
    auto-retired — at 3am the difference is the whole message."""
    _seed(tmp_path)
    _probes(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": None, "exploit_blocked": None,
                              "legit_ok": None, "auth_failed": True})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_auth_failed" and r["retired"] == 0


# ---- the adversarial-review findings, each pinned ----
def _legit_probe(tmp_path, fid="f1"):
    (tmp_path / "probes.json").write_text(json.dumps(
        [{"finding_id": fid, "exploit": EXPLOIT, "legit": {"method": "GET", "path": "/"}}]))


def test_an_edge_block_at_origin_never_retires(tmp_path, monkeypatch):
    """THE dangerous case. If the probe reaches a load balancer instead of the origin — a redirect
    to the public host, a mistyped origin — the band-aid under test blocks the exploit and gets to
    vouch for its own removal."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True,
                              "blocked_by_edge": True})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_not_at_origin" and r["retired"] == 0


def test_the_apps_own_block_still_retires(tmp_path, monkeypatch, fake_xc):
    """The mirror of the above — if edge-detection were too eager nothing could ever retire."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 400, "exploit_blocked": True, "legit_ok": True,
                              "blocked_by_edge": False})
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr("vpcopilot.retire.XC", lambda *a, **k: fake_xc)
    assert _run(tmp_path, apply=True, now=_at(0))["retired"] == 1


def test_an_origin_that_is_the_lbs_own_domain_is_detectable():
    from vpcopilot.reconcile import origin_is_an_lb
    lb = {"spec": {"domains": ["crapi.example.com"]}}
    assert origin_is_an_lb("https://crapi.example.com", lb) is True
    assert origin_is_an_lb("http://10.0.0.5:8888", lb) is False


def test_a_shared_lb_wide_control_is_not_detached(tmp_path, monkeypatch):
    """Six of seven controls are LB-wide. Retiring finding A's WAF removes finding B's too, and
    B's ledger entry would still claim `mitigated`."""
    a = _seed(tmp_path, fid="f1", control="waf")
    b = _seed(tmp_path, fid="f2", control="waf", state="mitigated", cure=None)
    ledger.save(str(tmp_path), {"f1": a, "f2": b})
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 400, "exploit_blocked": True, "legit_ok": True,
                              "blocked_by_edge": False})
    r = _run(tmp_path, apply=True, finding_id="f1", now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_shared_control" and r["retired"] == 0
    assert r["actions"][0]["shared_with"] == ["f2"]


def test_data_guard_blocks_retiring_the_waf_it_depends_on(tmp_path, monkeypatch):
    """Data Guard's masking rules live on the LB's attached app_firewall — detach the WAF and the
    masking dies with it. This exact pair ships in the demo dataset."""
    a = _seed(tmp_path, fid="f-waf", control="waf")
    b = _seed(tmp_path, fid="f-dg", control="waf_data_guard", state="mitigated", cure=None)
    ledger.save(str(tmp_path), {"f-waf": a, "f-dg": b})
    _legit_probe(tmp_path, "f-waf")
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 400, "exploit_blocked": True, "legit_ok": True,
                              "blocked_by_edge": False})
    r = _run(tmp_path, apply=True, finding_id="f-waf", now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_shared_control"
    assert "needs waf" in r["actions"][0]["reason"]


def test_a_different_policy_on_the_lb_is_not_detached(tmp_path, monkeypatch, fake_xc):
    """Every apply replaces `active_service_policies` wholesale (I2's displacement finding), so a
    later finding's policy is probably what is attached. Detaching would remove theirs."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 400, "exploit_blocked": True, "legit_ok": True,
                              "blocked_by_edge": False})
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "somebody-elses-policy"}]}}
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_not_our_policy"
    assert fake_xc.put_lb_calls == []


def test_a_transient_ok_never_erases_a_standing_verdict(tmp_path, monkeypatch):
    """After a fix_ineffective, the next pass hits the probe cooldown and would record `ok` —
    turning a known-broken fix green on the dashboard and in cron."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    _run(tmp_path, now=_at(0))
    assert ledger.load(str(tmp_path))["f1"]["reconcile"]["outcome"] == "fix_ineffective"
    _run(tmp_path, now=_at(2))          # inside the cooldown -> "ok"
    rec = ledger.load(str(tmp_path))["f1"]["reconcile"]
    assert rec["outcome"] == "fix_ineffective" and "cooling down" in rec["transient"]


def test_a_probe_that_never_fired_does_not_arm_the_cooldown(tmp_path, monkeypatch):
    """Stamping last_probe_at on a pass with no probes.json would silence the real probe for 24h."""
    _seed(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _run(tmp_path, now=_at(0))
    assert "last_probe_at" not in (ledger.load(str(tmp_path))["f1"].get("reconcile") or {})


def test_a_probe_with_no_legit_leg_cannot_justify_a_retire(tmp_path, monkeypatch):
    """probe_from_spec defaults legit_ok to True with no legit request, so the origin-sanity gate
    would pass vacuously against a target nothing confirmed we can reach."""
    _seed(tmp_path)
    (tmp_path / "probes.json").write_text(json.dumps([{"finding_id": "f1", "exploit": EXPLOIT}]))
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 400, "exploit_blocked": True, "legit_ok": True})
    r = _run(tmp_path, apply=True, now=_at(0))
    assert r["actions"][0]["outcome"] == "skipped_no_legit_baseline" and r["retired"] == 0


def test_one_findings_exception_does_not_end_the_pass(tmp_path, monkeypatch):
    a = _seed(tmp_path, fid="f1", applied_h=-200, cure=None)
    b = _seed(tmp_path, fid="f2", applied_h=-200, cure=None)
    ledger.save(str(tmp_path), {"f1": a, "f2": b})
    _no_github(monkeypatch, "none")
    real = reconcile._escalate
    monkeypatch.setattr(reconcile, "_escalate", lambda fid, *a, **k: (_ for _ in ()).throw(
        RuntimeError("XC exploded")) if fid == "f1" else real(fid, *a, **k))
    r = _run(tmp_path, now=_at(0))
    assert r["checked"] == 2
    assert r["actions"][0]["outcome"] == "skipped_error"
    assert r["escalations"] == 1                      # f2 still got its escalation


def test_force_probe_without_a_finding_is_refused_in_the_module(tmp_path):
    """Guarding this only in the CLI left the console able to mass-replay every exploit at once."""
    _seed(tmp_path)
    with pytest.raises(RuntimeError, match="force_probe requires a finding_id"):
        _run(tmp_path, force_probe=True, now=_at(0))


def test_a_cron_pass_can_identify_itself(tmp_path, monkeypatch):
    """AUDIT.md documents trigger=cron, but cron invokes the CLI — without this the value appeared
    in the docs and in no record ever written."""
    monkeypatch.setenv("VPCOPILOT_RECONCILE_TRIGGER", "cron")
    _seed(tmp_path, applied_h=-200, cure=None)
    _no_github(monkeypatch, "none")
    _run(tmp_path, now=_at(0))
    from vpcopilot import audit
    assert [a for a in audit.load(str(tmp_path)) if a["action"] == "escalation"][0]["trigger"] == "cron"


def test_reconcile_records_do_not_pollute_the_report_impact_table(tmp_path, monkeypatch):
    """report._impact_rows renders any entry carrying `before_after` and marks it `fail` unless
    `passed` is set — a successful auto-retire would have shown up as a failure."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    _run(tmp_path, apply=True, now=_at(0))
    from vpcopilot import audit
    from vpcopilot.report import _impact_rows
    entries = audit.load(str(tmp_path))
    assert all("before_after" not in a for a in entries)
    assert _impact_rows(entries) == ""


def test_a_reconcile_record_carries_its_own_finding_metadata_into_the_export(tmp_path, monkeypatch):
    """findings.json and ledger.json are rewritten by the next scan; the export must prefer the
    value the record preserved for exactly that reason."""
    _seed(tmp_path, applied_h=-200, cure=None)
    _no_github(monkeypatch, "none")
    _run(tmp_path, now=_at(0))
    ledger.save(str(tmp_path), {})              # a re-scan wipes the join source
    from vpcopilot.export import build_audit_events
    ev = [e for e in build_audit_events(str(tmp_path)) if e["action"] == "escalation"][0]
    assert ev["title"] == "SQLi in login" and ev["severity"] == "critical"
    assert ev["outcome"] == "escalated"


def test_an_auth_failure_does_not_arm_the_destructive_replay_cooldown(tmp_path, monkeypatch):
    """Observed live: a wrong login path put a finding into a day-long "cooling down" with no probe
    behind it. The cooldown throttles destructive replays — an auth failure never fired one."""
    _seed(tmp_path)
    _legit_probe(tmp_path)
    _no_github(monkeypatch, "merged")
    _healthy(monkeypatch)
    _fake_probe(monkeypatch, {"exploit_status": None, "exploit_blocked": None, "legit_ok": None,
                              "auth_failed": True})
    _run(tmp_path, apply=True, now=_at(0))
    assert "last_probe_at" not in (ledger.load(str(tmp_path))["f1"].get("reconcile") or {})
