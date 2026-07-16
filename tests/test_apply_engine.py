"""B1/B3: the apply_* handlers, now on the shared engine, exercised end-to-end against FakeXC —
attach → validate → keep or verified-rollback — with no real tenant and no wall-clock waits."""
import pytest

from vpcopilot import apply


@pytest.fixture(autouse=True)
def _fast(monkeypatch, noop_sleep):
    # every ApplyContext gets the no-op sleep so polls don't wait
    import vpcopilot.engine as engine
    real_init = engine.ApplyContext.__post_init__
    def patched(self):
        real_init(self)
        self.sleep = noop_sleep
    monkeypatch.setattr(engine.ApplyContext, "__post_init__", patched)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")  # 'lab' is not protected


def _use(monkeypatch, fake_xc):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)


# ---- config-validated control (malicious_user): attach + keep + rollback ----

def test_malicious_user_keep_attaches(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    res = apply.apply_malicious_user("lab", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["kept"] is True and res["rolled_back"] is False
    assert "enable_malicious_user_detection" in fake_xc.lb["spec"]  # left live


def test_malicious_user_default_rolls_back(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    res = apply.apply_malicious_user("lab", keep=False, out_dir=str(tmp_path), log=lambda m: None)
    assert res["kept"] is False and res["rolled_back"] is True
    assert "enable_malicious_user_detection" not in fake_xc.lb["spec"]  # restored to snapshot


# ---- config-validated control (waf): attaching a blocking WAF is 'applied' (defense-in-depth) ----

def test_waf_config_validated_keeps_and_marks_ledger(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    # even a signature MISS (exploit not blocked) is 'applied' — WAF is validated by readback, not the block
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    res = apply.apply_waf("lab", target_url="http://x", keep=True, finding_id="f1",
                          out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["kept"] is True
    assert fake_xc.lb["spec"].get("app_firewall")            # left attached
    from vpcopilot import ledger
    assert ledger.load(str(tmp_path)).get("f1", {}).get("state") == "mitigated"


def test_waf_rolls_back_when_not_kept(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    res = apply.apply_waf("lab", target_url="http://x", keep=False, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["rolled_back"] is True
    # rollback restores the EXACT pre-apply snapshot (not retire's detach form)
    assert fake_xc.lb["spec"] == {"no_service_policies": {}}


def test_apply_control_routes_via_registry(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    # service_policy is not LB-wide -> apply_control refuses it (points to the from-scan path)
    with pytest.raises(RuntimeError, match="apply_from_scan"):
        apply.apply_control("service_policy", "lab")
    with pytest.raises(RuntimeError, match="unknown control"):
        apply.apply_control("nonsense", "lab")


def test_self_test_failure_aborts_before_change(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    fake_xc.fail_put_lb = True
    with pytest.raises(RuntimeError, match="self-test failed"):
        apply.apply_malicious_user("lab", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert fake_xc.lb["spec"] == {"no_service_policies": {}}  # untouched
