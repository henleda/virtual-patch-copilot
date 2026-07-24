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


# ---- data_guard MUST NOT clobber an already-attached, differently-named WAF (A5 safety gate) ----

def test_data_guard_reuses_attached_waf_and_does_not_clobber(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    # LB already carries the LIVE banknimbus-dev-waf; apply_data_guard defaults to vpcopilot-lab-waf
    fake_xc.lb["spec"] = {"app_firewall": {"namespace": "test-ns", "name": "banknimbus-dev-waf",
                                           "tenant": "test-tenant"}}
    fake_xc.app_firewalls["banknimbus-dev-waf"] = {"spec": {"blocking": {}}}
    res = apply.apply_data_guard("lab", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and res["kept"] is True
    # (a) the attached WAF is STILL the live one — not replaced by vpcopilot-lab-waf
    assert fake_xc.lb["spec"]["app_firewall"]["name"] == "banknimbus-dev-waf"
    assert "vpcopilot-lab-waf" not in fake_xc.app_firewalls  # the default WAF was never created
    # (b) Data Guard rules are present and non-empty
    assert fake_xc.lb["spec"].get("data_guard_rules")


def test_data_guard_explicit_app_firewall_passthrough(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    # no WAF attached, and names match the explicit request -> the requested WAF is attached as-is
    res = apply.apply_data_guard("lab", app_firewall="banknimbus-dev-waf", template="nimbus-waf",
                                 keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True
    assert fake_xc.lb["spec"]["app_firewall"]["name"] == "banknimbus-dev-waf"
    assert fake_xc.lb["spec"].get("data_guard_rules")


# ---- api_schema must validate HEADERS + QUERY, not just the body (A1) ----

def _emitted_validation_props(fake_xc):
    return (fake_xc.lb["spec"]["api_specification"]["validation_all_spec_endpoints"]
            ["validation_mode"]["validation_mode_active"]["request_validation_properties"])


def test_api_schema_validates_headers_and_query_by_default(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    res = apply.apply_api_schema("lab", target_url="http://x", keep=True,
                                 out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is True
    props = _emitted_validation_props(fake_xc)
    # a credential on a bodyless GET (e.g. an auth/payment header) is only enforced if headers +
    # query params are validated — body-only validation would enforce nothing
    assert "PROPERTY_HTTP_HEADERS" in props and "PROPERTY_QUERY_PARAMETERS" in props
    assert props == ["PROPERTY_HTTP_HEADERS", "PROPERTY_QUERY_PARAMETERS", "PROPERTY_HTTP_BODY"]


def test_api_schema_validation_properties_override(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    apply.apply_api_schema("lab", target_url="http://x", keep=True,
                           request_validation_properties=["PROPERTY_HTTP_BODY"],
                           out_dir=str(tmp_path), log=lambda m: None)
    assert _emitted_validation_props(fake_xc) == ["PROPERTY_HTTP_BODY"]  # caller wins


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
