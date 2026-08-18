"""The console's BIG-IP apply endpoint: POST /api/apply-bigip starts a job that runs apply_bigip on a
worker thread and is polled through the shared GET /api/action, exactly like the XC apply actions.
apply_bigip itself is faked here — its own loop is covered in test_bigip_apply.py."""
from __future__ import annotations

import json
import time

import pytest
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


def test_console_retire_routes_a_bigip_bandaid_to_the_appliance(tmp_path, monkeypatch):
    from vpcopilot import ledger
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    # a BIG-IP mitigation records tenant/app in the ledger's mitigation.lb
    ledger.mark_mitigated(str(tmp_path), "f1", control="bigip_awaf", policy_name="deny-x", lb="my_app/lab")

    seen = {}

    def fake_retire(finding_id, *, tenant, app, out_dir, allow_protected, log):
        seen.update(finding_id=finding_id, tenant=tenant, app=app)
        return {"retired": True, "finding_id": finding_id, "tenant": tenant}

    monkeypatch.setattr("vpcopilot.bigip_apply.retire_bigip", fake_retire)
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda *a, **k: pytest.fail("routed a BIG-IP band-aid to the XC detach"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/retire", json={"finding_id": "f1"})
    assert r.status_code == 200 and r.json()["retired"] is True
    assert seen == {"finding_id": "f1", "tenant": "my_app", "app": "lab"}   # both recovered from the ledger


def test_console_retire_still_uses_xc_for_a_non_bigip_bandaid(tmp_path, monkeypatch):
    from vpcopilot import ledger
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    ledger.mark_mitigated(str(tmp_path), "f2", control="service_policy", policy_name="deny-y", lb="some-lb")
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda out, fid, **k: {"retired": True, "finding_id": fid, "via": "xc"})
    monkeypatch.setattr("vpcopilot.bigip_apply.retire_bigip",
                        lambda *a, **k: pytest.fail("routed an XC band-aid to the appliance"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/retire", json={"finding_id": "f2"})
    assert r.json().get("via") == "xc"


def test_emit_endpoint_feeds_the_bigip_panel_supported_and_declined(tmp_path, monkeypatch):
    """The 'Apply on your own BIG-IP' panel now populates its dropdown from POST /api/emit
    (target=bigip-awaf) rather than a hardcoded service_policy filter, so every shipped form is
    selectable and every decline carries a reason. This pins that contract — the endpoint the
    panel's loadBigipApply() consumes."""
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path)
    (tmp_path / "policies.json").write_text(json.dumps([
        {"finding_id": "f-dg", "control": "waf_data_guard", "policy_name": "mask-pii"},
        {"finding_id": "f-rl", "control": "rate_limit", "policy_name": "rl"}]))
    (tmp_path / "probes.json").write_text("[]")
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/emit", json={"target": "bigip-awaf"})
    assert r.status_code == 200
    by = {x["finding_id"]: x for x in r.json()["results"]}
    assert by["f-dg"]["supported"] is True and by["f-dg"]["control"] == "waf_data_guard"   # a form → selectable
    assert by["f-rl"]["supported"] is False and by["f-rl"]["reason"]                       # declined, with a why
