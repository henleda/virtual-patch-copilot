import json


def test_refine_attempts_default(monkeypatch):
    from vpcopilot import refiner
    monkeypatch.delenv("VPCOPILOT_REFINE_ATTEMPTS", raising=False)
    assert refiner.refine_attempts_default() == 3
    monkeypatch.setenv("VPCOPILOT_REFINE_ATTEMPTS", "5")
    assert refiner.refine_attempts_default() == 5
    monkeypatch.setenv("VPCOPILOT_REFINE_ATTEMPTS", "nonsense")
    assert refiner.refine_attempts_default() == 3


def test_refine_loop_converges_and_persists(monkeypatch, tmp_path):
    """First attempt fails (exploit not blocked) -> refine -> second attempt passes.
    The working refined spec is persisted back to the artifact."""
    from vpcopilot import refiner
    from vpcopilot.schemas import RefinedPolicy

    art = tmp_path / "service_policy.deny-x.json"
    art.write_text(json.dumps({"metadata": {"name": "deny-x"}, "spec": {"rule_list": {"rules": []}}}))
    (tmp_path / "findings.json").write_text(json.dumps([{
        "id": "f1", "title": "t", "vuln_class": "other", "severity": "high",
        "file": "a.py", "description": "d", "exploit_sketch": "e"}]))
    (tmp_path / "probes.json").write_text(json.dumps([{
        "finding_id": "f1", "exploit": {"method": "POST", "path": "/x"},
        "legit": {"method": "GET", "path": "/y"}}]))

    class FakeXC:
        ns = "d-henley"
        def get_lb(self, lb):
            return {"metadata": {"name": lb, "namespace": self.ns}, "spec": {"no_service_policies": {}}}
        def put_lb(self, lb, obj):
            pass
        def service_policy_exists(self, n):
            return False
        def create_service_policy(self, b):
            pass
        def put_service_policy(self, n, b):
            pass

    monkeypatch.setattr(refiner, "XC", FakeXC)
    monkeypatch.setattr(refiner, "normalize_service_policy_spec", lambda s: s)
    monkeypatch.setattr(refiner, "_protected_lbs", lambda: set())
    monkeypatch.setattr(refiner, "Harness", lambda cfg=None: object())
    monkeypatch.setattr(refiner.time, "sleep", lambda s: None)

    calls = {"n": 0}
    def fake_val(url, fid, out, fb, log):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True}  # baseline
        if calls["n"] <= 7:
            return {"exploit_status": 401, "exploit_blocked": False, "legit_ok": True}  # attempt 1 (6 polls)
        return {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}        # attempt 2 passes
    monkeypatch.setattr(refiner, "_run_validation", fake_val)
    monkeypatch.setattr(refiner.refine_agent, "run",
                        lambda *a, **k: RefinedPolicy(spec={"rule_list": {"rules": [{"fixed": 1}]}},
                                                      rationale="fixed the path"))

    res = refiner.refine_apply_service_policy(str(art), "lab", "http://x", finding_id="f1",
                                              max_refine=3, out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is True and res["attempts"] == 2
    assert json.loads(art.read_text())["spec"] == {"rule_list": {"rules": [{"fixed": 1}]}}


def test_refine_loop_honest_failure(monkeypatch, tmp_path):
    """If it never blocks, the loop gives up honestly (passed False, reason mentions code fix)."""
    from vpcopilot import refiner
    from vpcopilot.schemas import RefinedPolicy

    art = tmp_path / "service_policy.deny-x.json"
    art.write_text(json.dumps({"metadata": {"name": "deny-x"}, "spec": {"rule_list": {"rules": []}}}))
    (tmp_path / "findings.json").write_text(json.dumps([{
        "id": "f1", "title": "t", "vuln_class": "other", "severity": "high",
        "file": "a.py", "description": "d", "exploit_sketch": "e"}]))
    (tmp_path / "probes.json").write_text(json.dumps([{"finding_id": "f1", "exploit": {"method": "GET", "path": "/x"}}]))

    class FakeXC:
        ns = "d-henley"
        def get_lb(self, lb):
            return {"metadata": {"name": lb, "namespace": self.ns}, "spec": {"no_service_policies": {}}}
        def put_lb(self, lb, obj): pass
        def service_policy_exists(self, n): return False
        def create_service_policy(self, b): pass
        def put_service_policy(self, n, b): pass

    monkeypatch.setattr(refiner, "XC", FakeXC)
    monkeypatch.setattr(refiner, "normalize_service_policy_spec", lambda s: s)
    monkeypatch.setattr(refiner, "_protected_lbs", lambda: set())
    monkeypatch.setattr(refiner, "Harness", lambda cfg=None: object())
    monkeypatch.setattr(refiner.time, "sleep", lambda s: None)
    monkeypatch.setattr(refiner, "_run_validation",
                        lambda *a, **k: {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    monkeypatch.setattr(refiner.refine_agent, "run",
                        lambda *a, **k: RefinedPolicy(spec={"rule_list": {"rules": []}}, rationale="tried"))

    res = refiner.refine_apply_service_policy(str(art), "lab", "http://x", finding_id="f1",
                                              max_refine=2, out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is False and "code fix required" in res["reason"]
