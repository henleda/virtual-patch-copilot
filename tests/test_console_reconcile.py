"""I1 console surface: `GET /api/patches` is a cheap pure read, `POST /api/reconcile` runs a pass
through the shared background-job contract, and report-only stays the default across the wire."""
import json
import time
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from vpcopilot import ledger
from vpcopilot.console import app as A

NOW = datetime.now(timezone.utc)


def _client():
    return TestClient(A.app)


def _seed(out, *, applied_h=-48, ttl=168, state="mitigated"):
    applied = NOW + timedelta(hours=applied_h)
    ledger.save(str(out), {"f1": {
        "finding_id": "f1", "state": state, "title": "SQLi in login", "severity": "critical",
        "mitigation": {"control": "service_policy", "policy_name": "deny-x", "lb": "lab"},
        "ttl": {"applied_at": applied.isoformat(), "ttl_hours": ttl,
                "expires_at": (applied + timedelta(hours=ttl)).isoformat()}}})


def _await_job(c, job, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        s = c.get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("job never finished")


def test_patches_reports_age_and_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    _seed(tmp_path)
    body = _client().get("/api/patches").json()
    assert body["out"] == str(tmp_path)
    p = body["patches"][0]
    assert p["finding_id"] == "f1" and p["expired"] is False
    assert 47 < p["age_hours"] < 49


def test_patches_marks_an_overdue_bandaid(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    _seed(tmp_path, applied_h=-400)
    assert _client().get("/api/patches").json()["patches"][0]["expired"] is True


def test_patches_is_empty_before_any_run(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path / "never")
    r = _client().get("/api/patches")
    assert r.status_code == 200 and r.json()["patches"] == []


def test_patches_calls_nothing_expensive(tmp_path, monkeypatch):
    """It renders on every Retire render, so it must not touch XC, GitHub, or fire a probe."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    _seed(tmp_path)
    def forbidden(*a, **k):
        raise AssertionError("/api/patches must not call XC or GitHub")
    monkeypatch.setattr("vpcopilot.xc.XC", forbidden)
    monkeypatch.setattr("vpcopilot.retire.pr_is_merged", forbidden)
    assert _client().get("/api/patches").status_code == 200


def test_reconcile_runs_a_pass_and_streams_its_log(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setenv("VPCOPILOT_RECONCILE_TARGETS", "lab=http://origin.test")
    monkeypatch.setattr("vpcopilot.reconcile._cure_state", lambda e, cache, *, log: "open")
    _seed(tmp_path, applied_h=-400)
    c = _client()
    job = c.post("/api/reconcile", json={}).json()["job"]
    s = _await_job(c, job)
    assert s["state"] == "done"
    assert s["result"]["escalations"] == 1 and s["result"]["checked"] == 1
    assert s["log_total"] > 0 and any("ESCALATED" in ln for ln in s["log"])


def test_report_only_is_the_default_across_the_wire(tmp_path, monkeypatch):
    """The console must not be able to detach a control just by omitting a field."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setenv("VPCOPILOT_RECONCILE_TARGETS", "lab=http://origin.test")
    seen = {}
    monkeypatch.setattr("vpcopilot.reconcile.reconcile",
                        lambda out, **kw: seen.update(kw) or {"lock": "acquired", "checked": 0,
                                                              "actions": [], "retired": 0,
                                                              "escalations": 0,
                                                              "fix_ineffective": 0})
    _seed(tmp_path)
    c = _client()
    _await_job(c, c.post("/api/reconcile", json={}).json()["job"])
    assert seen["apply"] is False and seen["trigger"] == "console"


def test_apply_reaches_the_pass_when_asked(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    seen = {}
    monkeypatch.setattr("vpcopilot.reconcile.reconcile",
                        lambda out, **kw: seen.update(kw) or {"lock": "acquired", "checked": 0,
                                                              "actions": [], "retired": 0,
                                                              "escalations": 0,
                                                              "fix_ineffective": 0})
    _seed(tmp_path)
    c = _client()
    _await_job(c, c.post("/api/reconcile", json={"apply": True}).json()["job"])
    assert seen["apply"] is True


def test_the_worker_uses_the_out_dir_captured_at_request_time(tmp_path, monkeypatch):
    """POST /api/scan reassigns the OUT global with no lock; a worker reading it would follow a
    scan started mid-pass into another directory."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    seen = {}
    monkeypatch.setattr("vpcopilot.reconcile.reconcile",
                        lambda out, **kw: seen.update(out=out) or {"lock": "acquired", "checked": 0,
                                                                   "actions": [], "retired": 0,
                                                                   "escalations": 0,
                                                                   "fix_ineffective": 0})
    _seed(tmp_path)
    c = _client()
    job = c.post("/api/reconcile", json={}).json()["job"]
    monkeypatch.setattr(A, "OUT", tmp_path / "somewhere-else")   # a scan repoints it mid-flight
    _await_job(c, job)
    assert seen["out"] == str(tmp_path)


def test_a_configuration_error_surfaces_as_a_job_error_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.delenv("VPCOPILOT_RECONCILE_TARGETS", raising=False)
    _seed(tmp_path)
    c = _client()
    s = _await_job(c, c.post("/api/reconcile", json={}).json()["job"])
    assert s["state"] == "error" and "allowlist" in s["error"]


def test_a_running_job_is_never_evicted(tmp_path, monkeypatch):
    """Reconcile is the longest job in the app; trimming it mid-pass would 404 the poll and lose
    the transcript of a run that is still mutating the tenant."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    A._jobs.clear()
    A._jobs["long-running"] = {"state": "running", "log": [], "result": None, "error": None,
                               "control": "reconcile", "finding_id": None}
    for i in range(30):
        A._jobs[f"done-{i}"] = {"state": "done", "log": [], "result": {}, "error": None,
                                "control": "x", "finding_id": None}
    _seed(tmp_path)
    monkeypatch.setattr("vpcopilot.console.app._run_action", lambda *a: None)
    _client().post("/api/action", json={"control": "service_policy", "lb": "lab"})
    assert "long-running" in A._jobs
    A._jobs.clear()


def test_the_retire_step_calls_the_new_endpoints():
    """A surface nothing calls is not a surface — the console is one static file, so the wiring is
    only real if index.html references it."""
    html = (A.STATIC / "index.html").read_text() if hasattr(A, "STATIC") else \
        (__import__("pathlib").Path(A.__file__).parent / "static" / "index.html").read_text()
    assert "/api/patches" in html and "/api/reconcile" in html
    assert "loadPatches" in html and "runReconcile" in html


def test_the_reconcile_request_model_defaults_are_safe():
    r = A.ReconcileReq()
    assert r.apply is False and r.force_probe is False and r.allow_protected_lb is False
    assert json.loads(r.model_dump_json())["apply"] is False


def test_the_console_cannot_mass_replay_every_exploit(tmp_path, monkeypatch):
    """The --force-probe guard used to live only in the CLI, so a console request with
    force_probe and no finding_id replayed every destructive exploit at once."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setenv("VPCOPILOT_RECONCILE_TARGETS", "lab=http://origin.test")
    _seed(tmp_path)
    c = _client()
    s = _await_job(c, c.post("/api/reconcile", json={"force_probe": True}).json()["job"])
    assert s["state"] == "error" and "finding_id" in s["error"]


def test_a_pass_refreshes_the_audit_trail_and_hero_too():
    """A retire changes what is live and writes audit records; refreshing only the ledger leaves
    an operator looking at a page that says nothing happened."""
    from pathlib import Path
    html = (Path(A.__file__).parent / "static" / "index.html").read_text()
    block = html[html.index("async function runReconcile"):]
    block = block[:block.index("\n}")]
    for fn in ("loadLedger()", "loadAudit()", "loadHero()"):
        assert fn in block, fn
