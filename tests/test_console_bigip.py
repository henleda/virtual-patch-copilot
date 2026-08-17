"""The console's BIG-IP apply endpoint: POST /api/apply-bigip starts a job that runs apply_bigip on a
worker thread and is polled through the shared GET /api/action, exactly like the XC apply actions.
apply_bigip itself is faked here — its own loop is covered in test_bigip_apply.py."""
from __future__ import annotations

import time

from fastapi.testclient import TestClient


def test_apply_bigip_endpoint_runs_a_job_and_reports_the_result(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))

    seen = {}

    def fake_apply(finding_id, *, tenant, app, url, dry_run, keep, allow_protected, out_dir, log):
        seen.update(finding_id=finding_id, tenant=tenant, app=app, url=url, keep=keep, out_dir=out_dir)
        log("attaching band-aid…")
        log("exploit blocked ✓")
        return {"applied": True, "passed": True, "kept": keep, "rolled_back": not keep,
                "policy_name": "deny-neg-pay", "finding_id": finding_id, "tenant": tenant}

    monkeypatch.setattr("vpcopilot.bigip_apply.apply_bigip", fake_apply)

    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/apply-bigip",
               json={"finding_id": "f1", "tenant": "my_app", "app": "lab", "url": "http://x", "keep": True})
    assert r.status_code == 200
    job = r.json()["job"]

    for _ in range(100):                                    # the worker runs on another thread
        s = c.get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
        time.sleep(0.02)

    assert s["state"] == "done"
    assert s["result"]["kept"] is True and s["result"]["policy_name"] == "deny-neg-pay"
    assert any("blocked" in line for line in s["log"])       # the worker's log streamed through
    # the request-thread values (not a stale global) reached apply_bigip
    assert seen["finding_id"] == "f1" and seen["tenant"] == "my_app" and seen["keep"] is True
    assert seen["out_dir"] == str(tmp_path)


def test_apply_bigip_endpoint_surfaces_an_error_as_job_state(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))

    def boom(*a, **k):
        raise RuntimeError("tenant 'my_app' not found on the appliance")

    monkeypatch.setattr("vpcopilot.bigip_apply.apply_bigip", boom)
    c = TestClient(A.app, raise_server_exceptions=False)
    job = c.post("/api/apply-bigip", json={"finding_id": "f1", "url": "http://x"}).json()["job"]
    for _ in range(100):
        s = c.get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
        time.sleep(0.02)
    assert s["state"] == "error" and "not found" in s["error"]     # an appliance error is the job's error, not a 500
