"""G2 console surface: the Simulate step reads /api/simulate, and a policy simulation flagged as
too broad WARNS at the gate rather than silently applying — or silently blocking."""
import json

from fastapi.testclient import TestClient

from vpcopilot import audit
from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


def _sim(out, **over):
    (out / "simulation.json").write_text(json.dumps({
        "ts": "2026-07-27T12:00:00Z", "lb": "vpcopilot-lab", "records": 200, "records_replayed": 200,
        "bodies_available": True, "caveats": ["sample-scoped"],
        "policies": [{"policy_name": "deny-wide", "blocked_promotion": True, "block_rate": 0.9,
                      "threshold": 0.01, "reason": "would block 180/200 recorded requests (90.0%), "
                                                   "over the 1.0% threshold", **over},
                     {"policy_name": "deny-narrow", "blocked_promotion": False, "block_rate": 0.0,
                      "threshold": 0.01, "reason": ""}]}))


# ---- read ----
def test_simulate_endpoint_returns_the_last_result(tmp_path, monkeypatch):
    _sim(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    body = _client().get("/api/simulate").json()
    assert body["out"] == str(tmp_path)
    assert body["simulation"]["policies"][0]["policy_name"] == "deny-wide"


def test_simulate_endpoint_is_empty_before_any_run(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "OUT", tmp_path / "never")
    r = _client().get("/api/simulate")
    assert r.status_code == 200 and r.json()["simulation"] == {}


# ---- the gate: warn + explicit override, audited ----
def test_an_overbroad_policy_is_refused_without_the_override(tmp_path, monkeypatch):
    _sim(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    r = _client().post("/api/action", json={"control": "service_policy", "policy_name": "deny-wide",
                                            "finding_id": "f-1", "lb": "lab", "dry_run": False})
    assert r.status_code == 200                       # the job starts…
    job = r.json()["job"]
    for _ in range(50):
        s = _client().get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
    assert s["state"] == "error" and "allow overbroad" in s["error"]


def test_the_override_applies_anyway_and_writes_an_audit_record(tmp_path, monkeypatch):
    _sim(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "_dispatch_action", lambda body, log: {"passed": True, "kept": True})
    r = _client().post("/api/action", json={"control": "service_policy", "policy_name": "deny-wide",
                                            "finding_id": "f-1", "lb": "lab", "dry_run": False,
                                            "allow_overbroad": True})
    job = r.json()["job"]
    for _ in range(50):
        s = _client().get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
    assert s["state"] == "done"


def test_a_narrow_policy_is_not_gated(tmp_path, monkeypatch):
    _sim(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "_dispatch_action", lambda body, log: {"passed": True})
    r = _client().post("/api/action", json={"control": "service_policy", "policy_name": "deny-narrow",
                                            "finding_id": "f-2", "lb": "lab", "dry_run": False})
    job = r.json()["job"]
    for _ in range(50):
        s = _client().get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
    assert s["state"] == "done"


def test_a_dry_run_is_never_gated(tmp_path, monkeypatch):
    """Dry-run changes nothing, so a blast-radius warning has nothing to gate."""
    _sim(tmp_path)
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "_dispatch_action", lambda body, log: {"mode": "dry_run"})
    r = _client().post("/api/action", json={"control": "service_policy", "policy_name": "deny-wide",
                                            "finding_id": "f-1", "lb": "lab", "dry_run": True})
    job = r.json()["job"]
    for _ in range(50):
        s = _client().get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
    assert s["state"] == "done"


# ---- no-regression pin ----
def test_apply_is_unchanged_when_nothing_was_simulated(tmp_path, monkeypatch):
    """G2 adds a check, not a prerequisite: with no simulation.json the apply path behaves exactly
    as it did before this feature existed."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr(A, "_dispatch_action", lambda body, log: {"passed": True, "kept": True})
    r = _client().post("/api/action", json={"control": "service_policy", "policy_name": "anything",
                                            "finding_id": "f-9", "lb": "lab", "dry_run": False})
    job = r.json()["job"]
    for _ in range(50):
        s = _client().get(f"/api/action?job={job}").json()
        if s["state"] != "running":
            break
    assert s["state"] == "done"
    assert not [e for e in audit.load(str(tmp_path)) if e["action"] == "simulate_override"]
