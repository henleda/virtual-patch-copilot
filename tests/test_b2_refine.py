"""B2: per-control refine strategies over the registry — spec (service_policy/api_schema),
param (rate_limit tightens the threshold), none (waf → config-validated defense-in-depth,
nothing to refine)."""
import pytest

from vpcopilot import apply, controls


@pytest.fixture(autouse=True)
def _fast(monkeypatch, noop_sleep):
    import vpcopilot.engine as engine
    real = engine.ApplyContext.__post_init__
    monkeypatch.setattr(engine.ApplyContext, "__post_init__",
                        lambda self: (real(self), setattr(self, "sleep", noop_sleep))[0])
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


def test_registry_declares_strategies():
    assert controls.refine_strategy("service_policy") == "spec"
    assert controls.refine_strategy("api_schema") == "spec"
    assert controls.refine_strategy("rate_limit") == "param"
    assert controls.refine_strategy("waf") == "none"
    assert controls.refine_strategy("bot_defense") == "none"


def test_rate_limit_param_refine_tightens_until_it_bites(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    # first burst isn't limited; after the threshold is tightened, the second one is
    seq = iter([{"sent": 30, "limited": 0, "passed": 30, "codes": {"200": 30}},
                {"sent": 30, "limited": 22, "passed": 8, "codes": {"200": 8, "429": 22}}])
    import vpcopilot.probe as probe
    monkeypatch.setattr(probe, "probe_rate_limit", lambda *a, **k: next(seq))
    res = apply.apply_rate_limit("lab", requests=100, behavioral=True, keep=True, max_refine=3,
                                 target_url="http://x", out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is True and res["unfixable"] is False
    assert res["behavioral"]["limited"] == 22
    assert fake_xc.lb["spec"]["rate_limit"]["rate_limiter"]["total_number"] == 50  # 100 -> 50, then bit


def test_rate_limit_param_refine_gives_up_honestly(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    import vpcopilot.probe as probe
    monkeypatch.setattr(probe, "probe_rate_limit",
                        lambda *a, **k: {"sent": 30, "limited": 0, "passed": 30, "codes": {"200": 30}})
    res = apply.apply_rate_limit("lab", requests=4, behavioral=True, keep=True, max_refine=3,
                                 target_url="http://x", out_dir=str(tmp_path), log=lambda m: None)
    assert res["passed"] is False and res["unfixable"] is True and "code fix" in res["recommend"]


def test_waf_config_validated_not_unfixable(monkeypatch, fake_xc, tmp_path):
    # WAF is config-validated defense-in-depth: attaching a blocking WAF is 'applied' even if a given
    # payload doesn't trip a signature — there is nothing to refine and it is NOT 'unfixable'.
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True})
    res = apply.apply_waf("lab", target_url="http://x", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True and "unfixable" not in res


def test_waf_config_enabled_when_signature_hits(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    res = apply.apply_waf("lab", target_url="http://x", keep=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["config_enabled"] is True
