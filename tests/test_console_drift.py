"""I2 console surface: `GET /api/drift` answers the pre-apply question read-only, and the apply
endpoints thread `force` so the operator can override from the UI.

The endpoint must stay read-only under every input — it is polled from the browser, so a version
that wrote a snapshot would corrupt the run dir just by someone opening a page."""
import json

from fastapi.testclient import TestClient

from vpcopilot.console import app as A


def _client():
    return TestClient(A.app)


def _artifact(out, name="deny-x", shadowed=False):
    (out / "policies").mkdir(parents=True, exist_ok=True)
    deny = {"action": "DENY", "path": {"exact_values": ["/users/v1/register"]},
            "http_method": {"methods": ["POST"]}}
    allow = {"action": "ALLOW", "path": {"prefix_values": ["/"]}}
    rules = [allow, deny] if shadowed else [deny, allow]
    (out / "policies" / f"service_policy.{name}.json").write_text(json.dumps(
        {"metadata": {"name": name}, "spec": {"rule_list": {"rules": [{"spec": r} for r in rules]}}}))


def _probe(out, fid="f1"):
    (out / "probes.json").write_text(json.dumps(
        [{"finding_id": fid, "exploit": {"method": "POST", "path": "/users/v1/register"}}]))


def test_drift_reports_the_field_level_diff(tmp_path, monkeypatch, fake_xc):
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr("vpcopilot.drift.XC", lambda *a, **k: fake_xc, raising=False)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    from vpcopilot import drift
    drift.save_snapshot(str(tmp_path), "lab", {"spec": {"rate_limit": {"requests": 100}}})
    fake_xc.lb["spec"] = {"rate_limit": {"requests": 5}}
    body = _client().get("/api/drift?lb=lab").json()
    assert body["live_vs_snapshot"]["drifted"] is True
    assert body["live_vs_snapshot"]["changes"] == [
        {"path": "rate_limit.requests", "was": 100, "now": 5}]


def test_drift_picks_up_this_runs_artifact_for_the_shadowing_check(tmp_path, monkeypatch, fake_xc):
    """The browser sends a policy NAME, not a spec. Without the endpoint resolving that to the
    artifact on disk the shadowing check has no rules to walk and silently reports nothing."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    _artifact(tmp_path, shadowed=True)
    _probe(tmp_path)
    body = _client().get("/api/drift?lb=lab&control=service_policy&policy=deny-x&finding=f1").json()
    assert body["conflicts_checked"] is True
    assert body["conflicts"] and body["conflicts"][0]["kind"] == "shadowed_deny"
    assert body["ok_to_apply"] is False


def test_a_correctly_ordered_policy_is_clean(tmp_path, monkeypatch, fake_xc):
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    _artifact(tmp_path)
    _probe(tmp_path)
    body = _client().get("/api/drift?lb=lab&control=service_policy&policy=deny-x&finding=f1").json()
    assert body["ok_to_apply"] is True and not body["conflicts"]


def test_drift_reports_what_applying_would_detach(tmp_path, monkeypatch, fake_xc):
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    fake_xc.service_policies["someone-elses"] = {"spec": {"rule_list": {"rules": [
        {"spec": {"action": "DENY", "path": {"prefix_values": ["/admin"]}}}]}}}
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "someone-elses"}]}}
    _artifact(tmp_path)
    body = _client().get("/api/drift?lb=lab&control=service_policy&policy=deny-x").json()
    assert [d["policy"] for d in body["displaces"]] == ["someone-elses"]


def test_the_endpoint_writes_nothing(tmp_path, monkeypatch, fake_xc):
    """Polled from the browser — a version that wrote a snapshot would corrupt the run dir just by
    someone opening the page."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    _artifact(tmp_path)
    _probe(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    _client().get("/api/drift?lb=lab&control=service_policy&policy=deny-x&finding=f1")
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert fake_xc.put_lb_calls == []


def test_an_unknown_lb_is_a_400_not_a_500(tmp_path, monkeypatch, fake_xc):
    monkeypatch.setattr(A, "OUT", tmp_path)

    def boom(*a, **k):
        raise RuntimeError("404 load balancer not found")
    monkeypatch.setattr(fake_xc, "get_lb", boom)
    monkeypatch.setattr("vpcopilot.xc.XC", lambda *a, **k: fake_xc)
    assert _client().get("/api/drift?lb=nope").status_code == 400


def test_the_apply_endpoints_accept_force(tmp_path, monkeypatch):
    """The console's override has to reach the guard — a UI button wired to a field the request
    model drops would look like it worked and change nothing."""
    monkeypatch.setattr(A, "OUT", tmp_path)
    seen = {}
    monkeypatch.setattr("vpcopilot.refiner.refine_apply_service_policy",
                        lambda *a, **k: seen.update(k) or {"passed": True})
    _artifact(tmp_path)
    r = _client().post("/api/apply", json={"artifact": "service_policy.deny-x.json",
                                           "lb": "lab", "url": "http://x", "force": True})
    assert r.status_code == 200 and seen["force"] is True
