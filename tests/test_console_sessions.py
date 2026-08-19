"""Named sessions (PR 2): the console makes the active scan workspace explicit — listed, shown in the
header, switchable, creatable — so the session-scoped tabs (Scan/Review/Mitigate/…/the 'this session'
Retire track) can never mix two runs. A session is an `out*` dir; the active one is the OUT the
read/scan endpoints use."""
from __future__ import annotations

import json

from fastapi.testclient import TestClient


def _mk(d, *, verified=None):
    d.mkdir(parents=True, exist_ok=True)
    if verified is not None:
        (d / "findings.json").write_text("[]")
        (d / "summary.json").write_text(json.dumps({"verified": verified, "candidates": verified + 2}))


def test_sessions_lists_workspaces_and_marks_the_active_one(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-alpha", verified=3)
    _mk(tmp_path / "out-beta")                       # exists, no results
    monkeypatch.setattr(A, "OUT", A.Path("out-alpha"))
    r = TestClient(A.app, raise_server_exceptions=False).get("/api/sessions").json()
    assert r["active"] == "out-alpha"
    by = {s["id"]: s for s in r["sessions"]}
    assert by["out-alpha"]["active"] and by["out-alpha"]["verified"] == 3 and by["out-alpha"]["has_results"]
    assert by["out-beta"]["active"] is False and by["out-beta"]["has_results"] is False
    assert r["sessions"][0]["id"] == "out-alpha"     # active sorts first


def test_open_switches_the_active_session(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-a", verified=1)
    _mk(tmp_path / "out-b", verified=2)
    monkeypatch.setattr(A, "OUT", A.Path("out-a"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/session", json={"action": "open", "name": "out-b"})
    assert r.status_code == 200 and r.json()["active"] == "out-b"
    assert str(A.OUT) == "out-b"                     # the global the read endpoints use moved
    assert c.get("/api/sessions").json()["active"] == "out-b"


def test_open_rejects_an_unknown_or_traversal_name(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-a", verified=1)
    monkeypatch.setattr(A, "OUT", A.Path("out-a"))
    c = TestClient(A.app, raise_server_exceptions=False)
    assert c.post("/api/session", json={"action": "open", "name": "../../etc"}).status_code == 404
    assert c.post("/api/session", json={"action": "open", "name": "out-nope"}).status_code == 404
    assert str(A.OUT) == "out-a"                     # unchanged after a rejected open


def test_new_creates_a_named_session_and_makes_it_active(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-a", verified=1)
    monkeypatch.setattr(A, "OUT", A.Path("out-a"))
    c = TestClient(A.app, raise_server_exceptions=False)
    r = c.post("/api/session", json={"action": "new", "name": "Larkspur Prod!"})
    assert r.status_code == 200 and r.json()["active"] == "out-larkspur-prod"   # slugified
    assert str(A.OUT) == "out-larkspur-prod"
    meta = json.loads((tmp_path / "out-larkspur-prod" / "session.json").read_text())
    assert meta["name"] == "Larkspur Prod!" and meta["created_at"]
    # it shows in the list, active, empty, carrying its friendly name
    s = {x["id"]: x for x in r.json()["sessions"]}["out-larkspur-prod"]
    assert s["active"] and s["name"] == "Larkspur Prod!" and s["has_results"] is False


def test_new_requires_a_usable_name(tmp_path, monkeypatch):
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-a", verified=1)
    monkeypatch.setattr(A, "OUT", A.Path("out-a"))
    c = TestClient(A.app, raise_server_exceptions=False)
    assert c.post("/api/session", json={"action": "new", "name": "  !!! "}).status_code == 400  # empty slug
    assert str(A.OUT) == "out-a"


def test_sessions_endpoint_tolerates_a_non_object_sidecar(tmp_path, monkeypatch):
    """A summary.json/session.json that is valid JSON but NOT an object (null / 42 / a list) must not
    500 the whole switcher — /api/sessions skips the damaged file to {}, it doesn't crash for every
    session over one bad one."""
    from vpcopilot.console import app as A
    monkeypatch.chdir(tmp_path)
    _mk(tmp_path / "out-good", verified=2)
    (tmp_path / "out-bad").mkdir()
    (tmp_path / "out-bad" / "findings.json").write_text("[]")
    (tmp_path / "out-bad" / "summary.json").write_text("null")      # valid JSON, not an object
    (tmp_path / "out-bad" / "session.json").write_text("[1, 2, 3]")  # ditto, a list
    monkeypatch.setattr(A, "OUT", A.Path("out-good"))
    r = TestClient(A.app, raise_server_exceptions=False).get("/api/sessions")
    assert r.status_code == 200                                     # not a 500
    by = {s["id"]: s for s in r.json()["sessions"]}
    assert by["out-bad"]["verified"] == 0 and by["out-bad"]["name"] == "out-bad"   # skipped gracefully


def test_the_header_wires_the_session_selector():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "src/vpcopilot/console/static/index.html").read_text()
    assert 'id="sessionSel"' in html and 'id="sessionBar"' in html
    assert "openSession(" in html and "newSession(" in html and "/api/sessions" in html
    assert "loadSessions();" in html                 # actually invoked on load
