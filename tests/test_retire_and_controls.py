"""D1/D3: the retire mutation path (detach via the registry, ledger→retired) and the remaining
control handlers (rate_limit/bot_defense/data_guard/api_schema/service_policy) end-to-end on FakeXC,
including the oneof invariant (attach leaves exactly one side of the oneof set)."""
import pytest

from vpcopilot import apply, controls, ledger, retire


@pytest.fixture(autouse=True)
def _fast(monkeypatch, noop_sleep):
    import vpcopilot.engine as engine
    real = engine.ApplyContext.__post_init__
    monkeypatch.setattr(engine.ApplyContext, "__post_init__",
                        lambda self: (real(self), setattr(self, "sleep", noop_sleep))[0])
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


def _use(monkeypatch, fake_xc):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)


# ---- D3: retire ----

def test_retire_detaches_and_marks_retired(monkeypatch, fake_xc, tmp_path):
    fake_xc.lb["spec"] = {"app_firewall": {"name": "waf"}}     # a live WAF band-aid
    monkeypatch.setattr(retire, "XC", lambda *a, **k: fake_xc)
    ledger.save(str(tmp_path), {"f1": {"finding_id": "f1", "state": "mitigated",
                                       "mitigation": {"control": "waf", "lb": "lab"}}})
    res = retire.retire_finding(str(tmp_path), "f1", force=True, allow_protected=True, log=lambda m: None)
    assert res["status"] == "retired"
    assert "app_firewall" not in fake_xc.lb["spec"] and fake_xc.lb["spec"]["disable_waf"] == {}
    assert ledger.load(str(tmp_path))["f1"]["state"] == "retired"


def test_retire_noops_without_mitigation(tmp_path):
    ledger.save(str(tmp_path), {"f1": {"finding_id": "f1", "state": "found", "mitigation": None}})
    res = retire.retire_finding(str(tmp_path), "f1", force=True, log=lambda m: None)
    assert "no live band-aid" in res["status"]


# ---- D1: remaining controls on FakeXC ----

def test_rate_limit_config_keep_and_rollback(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    res = apply.apply_rate_limit("lab", requests=10, keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["kept"] is True
    assert fake_xc.lb["spec"]["rate_limit"]["rate_limiter"]["total_number"] == 10


def test_bot_defense_default_rolls_back(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    res = apply.apply_bot_defense("lab", keep=False, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["rolled_back"] is True
    assert "bot_defense" not in fake_xc.lb["spec"]  # restored


def test_data_guard_keep(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    res = apply.apply_data_guard("lab", keep=True, finding_id="f1", out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True
    assert fake_xc.lb["spec"]["data_guard_rules"] and fake_xc.lb["spec"].get("app_firewall")


def test_api_schema_pass_keeps(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    res = apply.apply_api_schema("lab", target_url="http://x", keep=True, finding_id="f1",
                                 out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is True
    assert fake_xc.lb["spec"].get("api_specification")


def test_oneof_invariant_waf_pops_disable(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    fake_xc.lb["spec"] = {"disable_waf": {}}  # start disabled
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    apply.apply_waf("lab", target_url="http://x", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    spec = fake_xc.lb["spec"]
    assert "app_firewall" in spec and "disable_waf" not in spec  # exactly one side of the oneof


def test_service_policy_from_scan_creates_and_attaches(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    import json
    art = tmp_path / "service_policy.deny-x.json"
    art.write_text(json.dumps({"metadata": {"name": "deny-x"}, "spec": {"rule_list": {"rules": [
        {"spec": {"action": "DENY", "path": {"prefix_values": ["/x"]}}},
        {"spec": {"action": "ALLOW", "path": {"prefix_values": ["/"]}}}]}}}))
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    res = apply.apply_from_scan(str(art), "lab", "http://x", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is True
    assert "deny-x" in fake_xc.service_policies                 # created
    assert fake_xc.lb["spec"]["active_service_policies"]["policies"][0]["name"] == "deny-x"


def test_all_controls_have_detach_registered():
    # D1: every declared control can be detached (rollback/retire never hits an unknown control)
    for c in controls.ALL_CONTROLS:
        spec = {}
        controls.detach_control(spec, c)
        assert spec  # produced a disable/empty oneof
