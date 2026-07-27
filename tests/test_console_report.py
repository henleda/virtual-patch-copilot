"""GET /api/report — the shareable HTML report the Review step links to. It is rebuilt from the
console's current out dir on every request (so it is always the latest run), served inline for the
new-tab view, and as a stamped attachment when `download=1`."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


def _seed(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps({"candidates": 1, "verified": 1, "policies": [],
                                                  "no_bandaid": [], "code_fix_prs": []}))
    (out / "findings.json").write_text(json.dumps([
        {"id": "a-001", "title": "SQLi login", "vuln_class": "sqli", "severity": "critical",
         "file": "api/login.js", "line": 10, "description": "d", "exploit_sketch": "e",
         "code_snippet": ""}]))
    (out / "triage.json").write_text(json.dumps([
        {"finding_id": "a-001", "bandaids": [], "no_bandaid": True, "residual_risk": "",
         "code_cure_required": True}]))
    (out / "remediations.json").write_text(json.dumps([]))


def test_report_is_served_inline_for_the_new_tab_view(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    r = _client().get("/api/report")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "attachment" not in r.headers.get("content-disposition", "")
    assert "SQLi login" in r.text


def test_report_is_rebuilt_from_the_current_out_dir(tmp_path, monkeypatch):
    """Review advertises 'the latest run' — so a changed findings.json must show up without a
    restart, and repointing OUT must serve the other run."""
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    assert "SQLi login" in _client().get("/api/report").text
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "a-001", "title": "Broken object auth", "vuln_class": "bola", "severity": "high",
         "file": "api/order.js", "line": 3, "description": "d", "exploit_sketch": "",
         "code_snippet": ""}]))
    body = _client().get("/api/report").text
    assert "Broken object auth" in body and "SQLi login" not in body


def test_report_download_sends_a_stamped_attachment(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    cd = _client().get("/api/report?download=1").headers["content-disposition"]
    assert cd.startswith("attachment")
    assert "vpcopilot-report-" in cd and cd.rstrip('"').endswith(".html")


def test_report_download_filename_carries_the_run_dir(tmp_path, monkeypatch):
    """Several downloaded reports have to be distinguishable in one folder."""
    run = tmp_path / "out-claude-vampi"
    _seed(run)
    monkeypatch.setattr(A, "OUT", run)
    assert "out-claude-vampi" in _client().get("/api/report?download=1").headers["content-disposition"]


def test_report_on_an_empty_run_dir_still_renders(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path / "never-scanned")
    r = _client().get("/api/report")
    assert r.status_code == 200 and "<html" in r.text.lower()
