"""Regression tests for the three P0 safety/correctness bugs the audits found."""
import json

import pytest


def test_resolve_token_callable_with_no_arg(monkeypatch):
    """P0-1: retire.pr_is_merged calls _resolve_token() with no arg — it must not TypeError."""
    from vpcopilot.pr import _resolve_token
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    assert _resolve_token() == "ghp_test"


def test_refine_refuses_protected_policy(monkeypatch, tmp_path):
    """P0-2: the refine path must honor PROTECTED_POLICIES (it bypassed the guard before)."""
    from vpcopilot import refiner
    art = tmp_path / "service_policy.nimbus-bizlogic-policy.json"
    art.write_text(json.dumps({"metadata": {"name": "nimbus-bizlogic-policy"}, "spec": {}}))

    class FakeXC:
        ns = "test-ns"

    monkeypatch.setattr(refiner, "XC", FakeXC)
    monkeypatch.setattr(refiner, "_protected_lbs", lambda: set())
    with pytest.raises(RuntimeError, match="protected"):
        refiner.refine_apply_service_policy(str(art), "lab", "http://x", out_dir=str(tmp_path),
                                            log=lambda m: None)


def test_ledger_scopes_to_current_scan(tmp_path):
    """P0-3: init_from_scan must drop entries from a prior/different app (no cross-target mixing)."""
    from vpcopilot import ledger
    out = str(tmp_path)
    ledger.init_from_scan(
        out,
        [{"id": "vampi-1", "file": "a.py", "vuln_class": "sqli", "severity": "high", "title": "A"}],
        [{"finding_id": "vampi-1", "bandaids": [], "no_bandaid": True}], [])
    assert "vampi-1" in ledger.load(out)
    # re-scan a DIFFERENT app — the VAmPI finding must not linger
    ledger.init_from_scan(
        out,
        [{"id": "crapi-1", "file": "b.py", "vuln_class": "broken_object_authz", "severity": "high", "title": "B"}],
        [{"finding_id": "crapi-1", "bandaids": [], "no_bandaid": True}], [])
    entries = ledger.load(out)
    assert "crapi-1" in entries and "vampi-1" not in entries
