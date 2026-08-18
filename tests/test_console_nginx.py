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


def test_nginx_lab_status_endpoint_is_configured_false_without_a_host(monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    monkeypatch.delenv("NGINX_SSH_HOST", raising=False)
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.get("/api/nginx-lab")
    assert r.status_code == 200
    assert r.json()["configured"] is False and "NGINX_SSH_HOST" in r.json()["reason"]


def test_emit_endpoint_feeds_the_nginx_panel_supported_and_declined(tmp_path, monkeypatch):
    """The 'Apply on your own NGINX' panel populates its dropdown from POST /api/emit
    (target=nginx-app-protect) — every shipped form selectable, every decline carrying a reason."""
    import json

    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    (tmp_path / "policies.json").write_text(json.dumps([
        {"finding_id": "f-dg", "control": "waf_data_guard", "policy_name": "mask-pii"},
        {"finding_id": "f-rl", "control": "rate_limit", "policy_name": "rl"}]))
    (tmp_path / "probes.json").write_text("[]")
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/emit", json={"target": "nginx-app-protect"})
    assert r.status_code == 200
    by = {x["finding_id"]: x for x in r.json()["results"]}
    assert by["f-dg"]["supported"] is True and by["f-dg"]["control"] == "waf_data_guard"  # a form → selectable
    assert by["f-rl"]["supported"] is False and by["f-rl"]["reason"]                      # declined, with a why


def test_the_mitigate_page_wires_the_nginx_panel():
    """The static page must call the NGINX endpoints — a panel that renders but posts nothing is worse
    than no panel (the agent-native parity Task A held for BIG-IP, mirrored here)."""
    from pathlib import Path

    html = (Path(__file__).resolve().parents[1] / "src/vpcopilot/console/static/index.html").read_text()
    assert 'id="nginxApply"' in html and 'runNginxApply()' in html
    assert '/api/apply-nginx' in html and '"nginx-app-protect"' in html and '/api/nginx-lab' in html
    assert "loadNginxApply();" in html          # actually invoked on the ④ Mitigate render
