"""The console's NGINX apply endpoint + retire routing — mirrors test_console_bigip.py. apply_nginx /
retire_nginx are faked here; their own loops are covered in test_nginx_apply.py."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient


def test_apply_nginx_endpoint_runs_a_job_and_reports_the_result(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    seen = {}

    def fake_apply(finding_id, *, server, location, url, dry_run, keep, allow_protected, out_dir, log):
        seen.update(finding_id=finding_id, server=server, location=location, keep=keep, out_dir=out_dir)
        log("attaching band-aid…")
        log("exploit blocked ✓")
        return {"applied": True, "passed": True, "kept": keep, "rolled_back": not keep,
                "policy_name": "deny-neg-transfer", "finding_id": finding_id, "server": server}

    monkeypatch.setattr("vpcopilot.nginx_apply.apply_nginx", fake_apply)
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/apply-nginx",
               json={"finding_id": "f1", "server": "vpcopilot.lab", "location": "/",
                     "url": "http://x", "keep": True})
    assert r.status_code == 200
    job = r.json()["job"]
    for _ in range(100):
        s = c.get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
        time.sleep(0.02)
    assert s["state"] == "done"
    assert s["result"]["kept"] is True and s["result"]["policy_name"] == "deny-neg-transfer"
    assert any("blocked" in line for line in s["log"])          # the worker's log streamed through
    assert seen["finding_id"] == "f1" and seen["server"] == "vpcopilot.lab" and seen["keep"] is True
    assert seen["out_dir"] == str(tmp_path)


def test_console_retire_routes_a_nginx_bandaid_to_the_box(tmp_path, monkeypatch):
    from vpcopilot import ledger
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    ledger.mark_mitigated(str(tmp_path), "f1", control="nginx_app_protect", policy_name="deny-x",
                          lb="vpcopilot.lab/")
    seen = {}

    def fake_retire(finding_id, *, server, location, out_dir, allow_protected, log):
        seen.update(finding_id=finding_id, server=server, location=location)
        return {"retired": True, "finding_id": finding_id, "server": server, "location": location}

    monkeypatch.setattr("vpcopilot.nginx_apply.retire_nginx", fake_retire)
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda *a, **k: pytest.fail("routed a NGINX band-aid to the XC detach"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/retire", json={"finding_id": "f1"})
    assert r.json().get("retired") is True
    assert seen == {"finding_id": "f1", "server": "vpcopilot.lab", "location": "/"}  # recovered from the lb
