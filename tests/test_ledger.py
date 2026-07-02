"""Ledger lifecycle tests — pure functions, no API/model needed."""
import json

from vpcopilot import ledger


def test_ledger_lifecycle(tmp_path):
    out = str(tmp_path)
    findings = [
        {"id": "neg-pay-001", "file": "pay/route.js", "vuln_class": "business_logic",
         "severity": "high", "title": "negative amount"},
        {"id": "pw-002", "file": "login/route.js", "vuln_class": "sensitive_data",
         "severity": "critical", "title": "plaintext pw"},
    ]
    decisions = [
        {"finding_id": "neg-pay-001", "bandaids": [{"control": "service_policy"}], "no_bandaid": False},
        {"finding_id": "pw-002", "bandaids": [], "no_bandaid": True},
    ]
    remediations = [{"finding_id": "neg-pay-001"}, {"finding_id": "pw-002"}]

    ent = ledger.init_from_scan(out, findings, decisions, remediations)
    assert ent["neg-pay-001"]["state"] == "found"
    assert ent["neg-pay-001"]["has_cure"] is True
    assert ent["pw-002"]["no_bandaid"] is True

    ledger.mark_mitigated(out, "neg-pay-001", control="service_policy", policy_name="deny-neg", lb="lb1")
    assert ledger.load(out)["neg-pay-001"]["state"] == "mitigated"

    ledger.mark_remediated(out, "neg-pay-001", pr_url="http://pr/1", pr_number=1)
    e = ledger.load(out)["neg-pay-001"]
    assert e["state"] == "remediated" and e["cure"]["pr_number"] == 1

    # state only moves forward (a later mitigate must not regress remediated)
    ledger.mark_mitigated(out, "neg-pay-001", control="service_policy", policy_name="deny-neg", lb="lb1")
    assert ledger.load(out)["neg-pay-001"]["state"] == "remediated"


def test_find_finding_for_policy(tmp_path):
    (tmp_path / "policies.json").write_text(json.dumps(
        [{"finding_id": "neg-pay-001", "control": "service_policy", "policy_name": "deny-neg"}]))
    assert ledger.find_finding_for_policy(str(tmp_path), "deny-neg") == "neg-pay-001"
    assert ledger.find_finding_for_policy(str(tmp_path), "missing") is None
