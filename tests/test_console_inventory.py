"""The console's Retire tab reads the global inventory, not the active session's ledger — so a live
band-aid applied in another session (the mixing the user hit) shows up correctly labeled, and retiring
it routes to the appliance it actually lives on, in the session it was applied from."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from vpcopilot import inventory


def _seed_inventory(finding_id, *, control, lb, session):
    inventory.record_mitigated(finding_id, control=control, policy_name="p", lb=lb,
                               ttl={"applied_at": "2026-08-13T06:00:00+00:00", "ttl_hours": 168,
                                    "expires_at": "2026-08-20T06:00:00+00:00"},
                               session=session, meta={"title": "T", "severity": "critical"})


def test_patches_endpoint_shows_a_bandaid_from_another_session(tmp_path, monkeypatch):
    """/api/patches (the Retire tab's 'live band-aids' list) is cross-session: a patch whose session is
    NOT the console's active OUT must still appear, with its target + applied date, so a 5-day-old
    mitigation from a prior scan is visible instead of silently mixed into — or missing from — the view."""
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path / "session-now")     # active session, empty
    _seed_inventory("neg-pay-001", control="service_policy", lb="nimbus-www",
                    session=str(tmp_path / "old-session"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.get("/api/patches")
    assert r.status_code == 200
    rows = {p["finding_id"]: p for p in r.json()["patches"]}
    assert "neg-pay-001" in rows                                 # cross-session band-aid is listed
    assert rows["neg-pay-001"]["lb"] == "nimbus-www" and rows["neg-pay-001"]["applied_at"]


def test_retire_routes_a_cross_session_nginx_bandaid_to_its_own_session(tmp_path, monkeypatch):
    """A band-aid applied in session A but retired from the console while session B is active must
    detach on the NGINX box (its control), using A's dir for the audit trail — the routing reads the
    inventory, not OUT's ledger (which does not contain this finding at all)."""
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "OUT", tmp_path / "session-b")       # a DIFFERENT active session
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    applied_session = str(tmp_path / "session-a")
    _seed_inventory("f-nginx", control="nginx_app_protect", lb="vpcopilot.lab/", session=applied_session)
    seen = {}

    def fake_retire_nginx(finding_id, *, server, location, out_dir, allow_protected, log):
        seen.update(finding_id=finding_id, server=server, location=location, out_dir=out_dir)
        return {"retired": True, "finding_id": finding_id}

    monkeypatch.setattr("vpcopilot.nginx_apply.retire_nginx", fake_retire_nginx)
    monkeypatch.setattr("vpcopilot.retire.retire_finding",
                        lambda *a, **k: pytest.fail("cross-session NGINX band-aid was routed to the XC detach"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/retire", json={"finding_id": "f-nginx"})
    assert r.json().get("retired") is True
    assert seen["finding_id"] == "f-nginx" and seen["server"] == "vpcopilot.lab"
    assert seen["out_dir"] == applied_session                   # audited in the session it was applied from


def test_retire_tab_has_the_two_labeled_sections():
    """The static page must split the tab: a cross-session 'live band-aids' list (with the retire
    control) and a read-only 'this session' progress track — the fix for the mixed-session view."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src/vpcopilot/console/static/index.html").read_text()
    assert "Live band-aids on your infrastructure" in html and "This session's findings" in html
    # retire lives in the patches (inventory) render, and that render carries the applied-date label
    assert "loadPatches()" in html and "applied ${applied}" in html


def test_startup_migration_seeds_inventory_from_session_dirs(tmp_path, monkeypatch):
    """Importing the console runs a one-time migration so a band-aid applied before the split is not
    invisible. Driven here directly against a temp tree to keep it hermetic."""
    from vpcopilot import ledger
    from vpcopilot.console import app as A
    sess = tmp_path / "out-old"
    ledger.save(str(sess), {"legacy": {"finding_id": "legacy", "state": "mitigated", "title": "t",
                                       "mitigation": {"control": "waf", "policy_name": "p", "lb": "lab"}}})
    monkeypatch.chdir(tmp_path)
    added = A._seed_inventory_from_sessions()
    assert added == 1 and "legacy" in inventory.live()
