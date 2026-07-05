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
