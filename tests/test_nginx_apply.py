"""nginx_apply spine — offline, with a fake Nginx client.

The live SSH transport + real NAP enforcement are proven separately on a real box (the Phase-1 spike,
docs/design/nginx-app-protect-apply.md §12). Here we pin the spine LOGIC that must hold regardless of
the box: honest decline, the dry-run self-test, keep/rollback, the enforcement settle-poll, the
ledger + audit records, and the surgical `vpcopilot-`only detach.
"""
from __future__ import annotations

import json

import pytest

from vpcopilot import audit, ledger, nginx_apply
from vpcopilot.nginx import NginxError


class FakeNginx:
    """A box's filesystem + reload counter, with the Nginx methods apply_nginx calls."""

    def __init__(self):
        self.files: dict[str, str] = {}
        self.reloads = 0
        self.tests = 0
        self.policy_dir = "/etc/app_protect/conf"
        self.include_dir = "/etc/nginx/conf.d"

    def put_file(self, path, content):
        self.files[path] = content

    def remove_file(self, path):
        self.files.pop(path, None)

    def test_config(self):
        self.tests += 1
        return "ok"

    def reload(self):
        self.reloads += 1

    def get_config(self):
        return "\n".join(self.files)


def _seed(tmp_path, control="service_policy"):
    (tmp_path / "policies.json").write_text(json.dumps([
        {"finding_id": "f1", "control": control, "policy_name": "deny-x"}]))
    (tmp_path / "probes.json").write_text(json.dumps([
        {"finding_id": "f1",
         "exploit": {"method": "POST", "path": "/api/transfer", "json_body": {"amount_cents": -50}},
         "legit": {"method": "POST", "path": "/api/transfer", "json_body": {"amount_cents": 50}}}]))


def _seq(*results):
    """A fake `_run_validation` that returns `results` in order, repeating the last — so a test can
    script `before`, then each `after` poll (open… open… blocked)."""
    calls = {"n": 0}

    def fake(url, finding_id, out_dir, fallback, log, **kw):
        calls["n"] += 1
        return results[min(calls["n"], len(results)) - 1]
    return fake, calls


BLOCKED = {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True}
OPEN = {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True}


def test_declines_a_control_with_no_nap_form(tmp_path):
    """rate_limit has no declarative-WAF object — apply must return an honest decline with a reason and
    touch the box for nothing (no file, no reload)."""
    _seed(tmp_path, control="rate_limit")
    nx = FakeNginx()
    r = nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x",
                                out_dir=str(tmp_path), client=nx)
    assert r["applied"] is False and r["emitted"] is False and r["reason"]
    assert nx.files == {} and nx.reloads == 0


def test_dry_run_self_tests_then_detaches_without_reloading(tmp_path):
    _seed(tmp_path)
    nx = FakeNginx()
    r = nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x",
                                out_dir=str(tmp_path), dry_run=True, client=nx)
    assert r["dry_run"] is True and r["applied"] is False
    assert nx.tests >= 1                 # nginx -t ran
    assert nx.reloads == 0               # nothing was reloaded
    assert nx.files == {}                # staged files were rolled back


def test_keep_and_passed_marks_the_ledger_and_writes_the_audit_dict(tmp_path, monkeypatch):
    _seed(tmp_path)
    fake, _ = _seq(OPEN, BLOCKED)
    monkeypatch.setattr(nginx_apply, "_run_validation", fake)
    nx = FakeNginx()
    r = nginx_apply.apply_nginx("f1", server="vpcopilot.lab", location="/", url="http://x",
                                out_dir=str(tmp_path), keep=True, client=nx)
    assert r["applied"] and r["passed"] and r["kept"] and not r["rolled_back"]
    # kept => the band-aid stays on the box
    assert any("vpcopilot-f1" in p for p in nx.files)
    # ledger recorded under the NEW control string, lb carries server+location
    entry = ledger.load(str(tmp_path))["f1"]
    assert entry["state"] == "mitigated"
    assert entry["mitigation"]["control"] == "nginx_app_protect"
    assert entry["mitigation"]["lb"] == "vpcopilot.lab/"
    # audit before_after is the {"before":…,"after":…} DICT the report reads (never a list)
    rec = next(a for a in audit.load(str(tmp_path)) if a["action"] == "apply_nginx_app_protect")
    assert set(rec["before_after"]) == {"before", "after"}
    assert rec["before_after"]["after"]["exploit_blocked"] is True


def test_not_passed_rolls_back_and_marks_nothing(tmp_path, monkeypatch):
    """A policy that never blocks (exploit still succeeds after the settle window) is rolled back and
    is NOT recorded as mitigated — the iron rule, fail closed."""
    _seed(tmp_path)
    fake, _ = _seq(OPEN, OPEN)
    monkeypatch.setattr(nginx_apply, "_run_validation", fake)
    nx = FakeNginx()
    r = nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x", out_dir=str(tmp_path),
                                keep=True, settle_timeout=0.0, client=nx)
    assert r["applied"] and r["passed"] is False and r["rolled_back"] is True
    assert nx.files == {}                                   # detached
    assert "f1" not in ledger.load(str(tmp_path))           # never recorded as mitigated


def test_settle_poll_waits_for_enforcement_to_load(tmp_path, monkeypatch):
    """§10.4: NAP loads a policy into the enforcer asynchronously after reload. A validation that is
    open on the first poll and blocked on the next must resolve to passed — not a false rollback."""
    _seed(tmp_path)
    fake, calls = _seq(OPEN, OPEN, BLOCKED)   # before open; after-poll open, then blocked
    monkeypatch.setattr(nginx_apply, "_run_validation", fake)
    nx = FakeNginx()
    # first _run_validation is the `before` (open); the `after` poll then sees open->blocked
    r = nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x", out_dir=str(tmp_path),
                                keep=True, settle_timeout=5.0, settle_interval=0.0, client=nx)
    assert r["passed"] is True
    assert calls["n"] >= 3               # before + at least two after-polls (open, then blocked)


def test_retire_detaches_surgically_and_marks_retired(tmp_path):
    _seed(tmp_path)
    nx = FakeNginx()
    # a user's own policy on the same server must survive a retire
    nx.files["/etc/nginx/conf.d/user-own.conf"] = "app_protect_policy_file /theirs.json;"
    nx.files["/etc/app_protect/conf/vpcopilot-f1.json"] = "{}"
    nx.files["/etc/nginx/conf.d/vpcopilot-active/vpcopilot-f1.conf"] = "app_protect_enable on;"
    r = nginx_apply.retire_nginx("f1", server="vpcopilot.lab", location="/", out_dir=str(tmp_path),
                                 client=nx)
    assert r["retired"] is True and nx.reloads == 1
    assert "/etc/nginx/conf.d/user-own.conf" in nx.files          # untouched
    assert not any("vpcopilot-f1" in p for p in nx.files)         # ours gone
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"
    assert any(a["action"] == "retire_nginx_app_protect" for a in audit.load(str(tmp_path)))


def test_a_config_the_box_rejects_raises_not_a_fake_dry_run(tmp_path):
    """`nginx -t` rejecting the staged policy is a box error surfaced as one (→ raises), never a
    benign 'would deploy' dry-run — the looks-applied-and-is-not false positive. Staged files roll back."""
    _seed(tmp_path)

    class Rejecting(FakeNginx):
        def test_config(self):
            raise NginxError("nginx -t failed: duplicate default server")

    nx = Rejecting()
    with pytest.raises(NginxError):
        nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x",
                                out_dir=str(tmp_path), client=nx)
    assert nx.files == {} and nx.reloads == 0                # staged files rolled back, nothing reloaded


@pytest.mark.parametrize("bad", ["x/../../../etc/nginx/nginx", "a/b", "-rf", "x`whoami`", "a;rm -rf /"])
def test_a_traversal_or_injecting_finding_id_is_refused_before_any_path_is_built(tmp_path, bad):
    """A finding id lands in on-box file paths, so a value with '/', '..' or a leading '-' must be
    refused at the apply/retire boundary — the console takes finding_id from the HTTP body, so this is
    a remote-write / remote-delete guard, not just a local nicety. Nothing touches the box."""
    _seed(tmp_path)
    nx = FakeNginx()
    with pytest.raises(NginxError, match="refusing finding id"):
        nginx_apply.apply_nginx(bad, server="s", location="/", url="http://x", out_dir=str(tmp_path), client=nx)
    with pytest.raises(NginxError, match="refusing finding id"):
        nginx_apply.retire_nginx(bad, server="s", location="/", out_dir=str(tmp_path), client=nx)
    assert nx.files == {} and nx.reloads == 0


def test_an_exception_after_the_real_apply_detaches_and_reraises(tmp_path, monkeypatch):
    """If anything raises once the band-aid is on the box (a step-3 nginx -t the operator's config now
    rejects, a transient error mid-validation), it must be detached + reloaded before the error
    propagates — never left enforcing but un-ledgered, where retire/reconcile could never find it."""
    _seed(tmp_path)
    fake, _ = _seq(OPEN)
    monkeypatch.setattr(nginx_apply, "_run_validation", fake)

    class BlowUpAfterApply(FakeNginx):
        def __init__(self):
            super().__init__()
            self._reloads = 0

        def reload(self):
            self._reloads += 1
            self.reloads += 1
            if self._reloads == 2:            # 1st reload = the clean-slate before; 2nd = the real apply
                raise NginxError("enforcer daemon crashed on reload")

    nx = BlowUpAfterApply()
    with pytest.raises(NginxError):
        nginx_apply.apply_nginx("f1", server="s", location="/", url="http://x", out_dir=str(tmp_path), client=nx)
    assert nx.files == {}                     # the band-aid was detached, not left enforcing
    assert "f1" not in ledger.load(str(tmp_path))


def test_await_enforcement_short_circuits_on_an_unvalidatable_probe(tmp_path, monkeypatch):
    """auth_failed / no_probe won't change by re-polling — the settle loop must break immediately
    rather than re-hammer a failing login for the whole window."""
    calls = {"n": 0}

    def fake(url, fid, out, fb, log, **kw):
        calls["n"] += 1
        return {"exploit_status": 401, "exploit_blocked": False, "legit_ok": False, "auth_failed": True}
    monkeypatch.setattr(nginx_apply, "_run_validation", fake)
    r = nginx_apply._await_enforcement("http://x", "f1", str(tmp_path), lambda *a: None,
                                       timeout=30.0, interval=0.0)
    assert r.get("auth_failed") is True and calls["n"] == 1     # one shot, no re-poll


def test_lb_encoding_roundtrips_server_and_location():
    assert nginx_apply._lb("vpcopilot.lab", "/") == "vpcopilot.lab/"
    assert nginx_apply._unlb("vpcopilot.lab/") == ("vpcopilot.lab", "/")
    assert nginx_apply._unlb(nginx_apply._lb("s", "/api")) == ("s", "/api")
