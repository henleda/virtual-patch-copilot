import json
import re
from pathlib import Path

from vpcopilot import report


def _seed(out: Path):
    (out / "summary.json").write_text(json.dumps({
        "candidates": 2, "verified": 2, "policies": ["waf/waf-block-sqli", "service_policy/deny-x"],
        "no_bandaid": ["b-002"], "code_fix_prs": ["a-001", "b-002"], "out_dir": str(out)}))
    (out / "findings.json").write_text(json.dumps([
        {"id": "a-001", "title": "SQLi login", "vuln_class": "sqli", "severity": "critical",
         "file": "api/login.js", "line": 10, "description": "d", "exploit_sketch": "e",
         "code_snippet": "q = 'SELECT * ' + x  // <script>alert(1)</script>"},
        {"id": "b-002", "title": "Info leak", "vuln_class": "sensitive_data", "severity": "low",
         "file": "api/me.js", "line": 0, "description": "d2", "exploit_sketch": "", "code_snippet": ""},
    ]))
    (out / "triage.json").write_text(json.dumps([
        {"finding_id": "a-001", "bandaids": [{"control": "waf", "coverage": "full", "recommended": True,
         "rationale": "r"}], "no_bandaid": False, "residual_risk": "none", "code_cure_required": True},
        {"finding_id": "b-002", "bandaids": [], "no_bandaid": True, "residual_risk": "",
         "code_cure_required": True},
    ]))
    (out / "remediations.json").write_text(json.dumps([
        {"finding_id": "a-001", "summary": "s", "file": "api/login.js", "diff": "",
         "patched_content": "", "pr_title": "Fix SQLi in login", "pr_body": "b"}]))


def test_report_renders_and_is_selfcontained(tmp_path):
    _seed(tmp_path)
    html = report.build_report(str(tmp_path))
    assert "SQLi login" in html and "a-001" in html
    assert "no band-aid" in html          # b-002 shown as code-cure-only
    assert "code fix drafted" in html     # a-001 has a remediation
    # no external resource-loading tags => truly shareable
    assert not re.findall(r'<(?:script[^>]*\ssrc|link[^>]*\shref|img[^>]*\ssrc)', html, re.I)


def test_report_escapes_model_content(tmp_path):
    _seed(tmp_path)
    html = report.build_report(str(tmp_path))
    # the code_snippet's <script> must be escaped, never emitted as a live tag
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_write_report_handles_empty(tmp_path):
    (tmp_path / "summary.json").write_text("{}")
    (tmp_path / "findings.json").write_text("[]")
    p = report.write_report(str(tmp_path))
    assert Path(p).exists() and "<html" in Path(p).read_text()


def test_normalize_unifies_probe_keys():
    from vpcopilot import probe
    assert probe.normalize({"neg_status": 200, "neg_blocked": False, "legit_ok": True}) == \
        {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True}
    assert probe.normalize({"sqli_status": 403, "sqli_blocked": True, "legit_ok": True})["exploit_blocked"] is True
    assert probe.normalize(None)["exploit_status"] is None


def test_report_impact_panel(tmp_path):
    _seed(tmp_path)
    (tmp_path / "audit.log").write_text(json.dumps({
        "ts": "2026-07-05T00:00:00Z", "action": "apply_waf", "app_firewall": "vpcopilot-lab-waf",
        "passed": True, "rolled_back": True,
        "before_after": {"before": {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True},
                         "after": {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True}}}) + "\n")
    html = report.build_report(str(tmp_path))
    assert "Band-aid impact" in html
    assert "200 allowed" in html and "200 blocked" in html
    assert "PASS" in html


def test_report_metrics_panel(tmp_path):
    _seed(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({
        "timing_s": {"discover": 3.1, "verify": 2.4, "synthesize": 5.0, "total": 10.5},
        "verify": {"candidates": 10, "verified": 8, "refuted": 1, "dropped_low_confidence": 1,
                   "confirm_rate": 0.8, "avg_confidence": 0.83, "min_confidence": 0.5},
        "synthesize": {"policies": 6, "dupe_bandaids_collapsed": 2, "code_fix_prs": 8}}))
    html = report.build_report(str(tmp_path))
    assert "Pipeline metrics" in html
    assert "10.5s" in html and "80%" in html                 # total time + confirm-rate
    assert "10 candidates → 8 verified" in html


def test_report_impact_panel_behavioral(tmp_path):
    _seed(tmp_path)
    (tmp_path / "audit.log").write_text(json.dumps({
        "ts": "2026-07-05T00:00:00Z", "action": "apply_rate_limit", "rate": "10/MINUTE",
        "passed": True, "rolled_back": True,
        "behavioral": {"sent": 30, "limited": 20, "passed": 10, "codes": {"200": 10, "429": 20}}}) + "\n")
    html = report.build_report(str(tmp_path))
    assert "Band-aid impact" in html
    assert "rate_limit" in html and "20/30 rate-limited (429)" in html
