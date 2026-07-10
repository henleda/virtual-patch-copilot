"""C1: the hero/impact numbers are computed, not asserted — pin them against a seeded out/."""
import json

from vpcopilot import audit, impact, ledger


def _seed(out):
    (out / "summary.json").write_text(json.dumps({"candidates": 5, "verified": 3, "code_fix_prs": ["a", "b", "c"]}))
    ledger.save(str(out), {
        "a": {"finding_id": "a", "state": "mitigated", "severity": "high", "title": "t",
              "mitigation": {"control": "service_policy", "lb": "lab"}},
        "b": {"finding_id": "b", "state": "remediated", "severity": "critical", "title": "t",
              "mitigation": {"control": "waf", "lb": "lab"}},
        "c": {"finding_id": "c", "state": "found", "severity": "low", "title": "t", "mitigation": None},
    })
    audit.record(str(out), "apply_timing", control="service_policy", passed=True, elapsed_s=30.0)
    audit.record(str(out), "apply_timing", control="waf", passed=True, elapsed_s=50.0)
    audit.record(str(out), "apply_timing", control="bot_defense", passed=False, elapsed_s=999.0)  # ignored (failed)


def test_impact_numbers(tmp_path, monkeypatch):
    monkeypatch.setenv("CHANGE_CONTROL_DAYS", "20")
    _seed(tmp_path)
    im = impact.impact(str(tmp_path))
    assert im["vulns"] == 3
    assert im["mitigated"] == 2          # mitigated + remediated
    assert im["remediated"] == 1
    assert im["code_prs"] == 3
    assert im["change_control_days"] == 20
    assert im["mttm_seconds"] == 40.0    # mean of the two PASSED timings (30, 50); failed one excluded
    assert im["controls_live"] == {"service_policy": 1, "waf": 1}
    assert im["speedup"] == round(20 * 86400 / 40.0)


def test_change_control_days_default_and_bad(monkeypatch):
    monkeypatch.delenv("CHANGE_CONTROL_DAYS", raising=False)
    assert impact.change_control_days() == 25
    monkeypatch.setenv("CHANGE_CONTROL_DAYS", "notanint")
    assert impact.change_control_days() == 25


def test_impact_empty_out(tmp_path):
    im = impact.impact(str(tmp_path))
    assert im["vulns"] == 0 and im["mttm_seconds"] is None and im["speedup"] is None
