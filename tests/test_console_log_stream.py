"""Console log streaming: /api/scan and /api/action serve the FULL transcript with an incremental
`?since=` tail, so a long-running scan or apply can be scrolled end-to-end instead of being clipped
to a sliding window."""
from fastapi.testclient import TestClient

from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


# ---- scan log ----
def test_scan_log_is_served_in_full(monkeypatch):
    monkeypatch.setitem(A._scan, "log", [f"line {i}" for i in range(200)])
    monkeypatch.setitem(A._scan, "state", "running")
    r = _client().get("/api/scan").json()
    assert len(r["log"]) == 200 and r["log_total"] == 200
    assert r["log"][0] == "line 0" and r["log"][-1] == "line 199"


def test_scan_log_since_returns_only_the_new_tail(monkeypatch):
    monkeypatch.setitem(A._scan, "log", [f"line {i}" for i in range(200)])
    r = _client().get("/api/scan?since=180").json()
    assert r["log"] == [f"line {i}" for i in range(180, 200)]
    assert r["log_total"] == 200  # the console advances its cursor from log_total, not len(log)


def test_scan_log_since_past_the_end_is_empty_not_an_error(monkeypatch):
    monkeypatch.setitem(A._scan, "log", ["only"])
    r = _client().get("/api/scan?since=99")
    assert r.status_code == 200 and r.json()["log"] == [] and r.json()["log_total"] == 1


def test_scan_log_negative_since_yields_the_whole_log(monkeypatch):
    monkeypatch.setitem(A._scan, "log", ["a", "b"])
    assert _client().get("/api/scan?since=-5").json()["log"] == ["a", "b"]


# ---- apply/action job log ----
def test_action_log_is_served_in_full_and_supports_since(monkeypatch):
    job = {"state": "running", "log": [f"step {i}" for i in range(120)], "result": None,
           "error": None, "control": "waf", "finding_id": "f-1"}
    monkeypatch.setitem(A._jobs, "job1234", job)
    c = _client()
    full = c.get("/api/action?job=job1234").json()
    assert len(full["log"]) == 120 and full["log_total"] == 120
    tail = c.get("/api/action?job=job1234&since=118").json()
    assert tail["log"] == ["step 118", "step 119"] and tail["job"] == "job1234"


def test_action_status_unknown_job_is_404():
    assert _client().get("/api/action?job=nope").status_code == 404


# ---- bounded sink ----
def test_log_sink_caps_growth_and_says_so_in_band():
    buf: list = []
    for i in range(A.LOG_MAX + 50):
        A._append(buf, f"line {i}")
    assert len(buf) == A.LOG_MAX + 1  # the cap, plus one explanatory line
    assert "capped" in buf[-1] and str(A.LOG_MAX) in buf[-1]
    assert buf[0] == "line 0"  # keeps the HEAD (where a scan's setup/config lines live)
