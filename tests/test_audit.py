"""Audit log append/load."""
from vpcopilot import audit


def test_audit_append_and_load(tmp_path):
    out = str(tmp_path)
    audit.record(out, "apply_service_policy", lb="nimbus-www", passed=True, rolled_back=False)
    audit.record(out, "open_pr", finding="neg-pay-001", url="http://pr/1", number=1)
    entries = audit.load(out)
    assert len(entries) == 2
    assert entries[0]["action"] == "apply_service_policy" and entries[0]["lb"] == "nimbus-www"
    assert "ts" in entries[0]
    assert entries[1]["action"] == "open_pr" and entries[1]["number"] == 1


def test_audit_empty(tmp_path):
    assert audit.load(str(tmp_path)) == []
