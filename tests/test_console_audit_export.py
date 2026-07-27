"""F3 — the Retire step's audit surface: /api/audit-events renders the trail on screen, and
/api/audit-export downloads the evidence bundle for this run or for every run on disk."""
import io
import json
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from vpcopilot import audit
from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


def _seed(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps([
        {"id": "f-1", "title": "SQL injection in login", "vuln_class": "sqli",
         "severity": "critical", "file": "api/login.js"}]))
    audit.record(str(out), "apply_service_policy", finding_id="f-1", lb="lab", namespace="ns",
                 policy="deny-login-sqli", passed=True, kept=True)


def test_audit_events_are_shown_before_they_can_be_exported(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    body = _client().get("/api/audit-events").json()
    assert body["out"] == str(tmp_path) and len(body["events"]) == 1
    e = body["events"][0]
    assert e["finding_id"] == "f-1" and e["title"] == "SQL injection in login"
    assert e["lb"] == "lab" and e["namespace"] == "ns" and e["outcome"] == "kept"
    assert e["actor"]  # who made the change


def test_audit_events_on_an_untouched_run_is_empty_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path / "never-scanned")
    r = _client().get("/api/audit-events")
    assert r.status_code == 200 and r.json()["events"] == []


def test_export_downloads_a_named_zip_for_this_run(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    r = _client().get("/api/audit-export?scope=run")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    cd = r.headers["content-disposition"]
    assert cd.startswith("attachment") and "vpcopilot-audit-" in cd and cd.rstrip('"').endswith(".zip")
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert {"manifest.json", "audit.csv", "audit.log", "findings.json"} <= set(z.namelist())
    assert json.loads(z.read("manifest.json"))["events"] == 1


def test_export_defaults_to_this_run(tmp_path, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    assert _client().get("/api/audit-export").status_code == 200


def test_export_all_runs_bundles_each_under_its_own_folder(tmp_path, monkeypatch):
    for name in ("out-a", "out-b"):
        _seed(tmp_path / name)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path / "out-a")
    r = _client().get("/api/audit-export?scope=all")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert "index.json" in z.namelist()
    assert {run["folder"] for run in json.loads(z.read("index.json"))["runs"]} == {"out-a", "out-b"}
    assert "vpcopilot-audit-all-" in r.headers["content-disposition"]


def test_unknown_export_scope_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path)
    assert _client().get("/api/audit-export?scope=everything").status_code == 400


def test_runs_endpoint_lists_what_can_be_exported(tmp_path, monkeypatch):
    _seed(tmp_path / "out-a")
    (tmp_path / "out-empty").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path / "out-a")
    body = _client().get("/api/runs").json()
    names = {Path(r).name for r in body["runs"]}
    assert "out-a" in names and "out-empty" not in names
    assert body["current"] == str(tmp_path / "out-a")


# ---- J2: verifying the bundle this run wrote ----
def test_verify_endpoint_checks_the_runs_own_bundle(tmp_path, monkeypatch):
    from vpcopilot import export
    _seed(tmp_path)
    export.write_bundle(str(tmp_path))
    monkeypatch.setattr(A, "OUT", tmp_path)
    body = _client().get("/api/audit-verify").json()
    assert body["exists"] is True and body["ok"] is True
    assert body["members_checked"] > 0 and body["runs"][0]["signature"] == "absent"


def test_verify_endpoint_reports_a_tampered_member(tmp_path, monkeypatch):
    import io
    import zipfile
    from vpcopilot import export
    _seed(tmp_path)
    p = export.write_bundle(str(tmp_path))
    src = zipfile.ZipFile(p)
    items = [(n, src.read(n)) for n in src.namelist()]
    src.close()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in items:
            z.writestr(n, d + b"x" if n == "audit.log" else d)
    open(p, "wb").write(buf.getvalue())
    monkeypatch.setattr(A, "OUT", tmp_path)
    body = _client().get("/api/audit-verify").json()
    assert body["ok"] is False
    assert any(x["member"] == "audit.log" for x in body["problems"])


def test_verify_endpoint_is_a_hint_not_an_error_before_any_export(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path / "never")
    body = _client().get("/api/audit-verify").json()
    assert body["exists"] is False and "hint" in body


def test_verify_endpoint_takes_no_path_from_the_caller():
    """A verify endpoint accepting a caller-supplied path would be an arbitrary-file reader;
    localhost is not a reason to ship one."""
    import inspect
    assert not inspect.signature(A.audit_verify).parameters
