"""The BIG-IP live-apply loop, offline: attach the AWAF band-aid → validate against the exploit →
keep or roll back → retire. FakeBigIP stands in for the appliance; validation is patched to reflect
the deployed state (a WAF that is attached blocks the exploit), so these exercise the real
emit → wrap → deploy → validate → rollback wiring without a box."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vpcopilot import bigip_apply, ledger
from vpcopilot.bigip_lab import LabRefused

TENANT, APP = "vpcopilot_lab", "lab"

# exploit/legit differ by ONE numeric field, so `service_policy` emits a real AWAF value-constraint
NEG_PAY_PROBE = {
    "finding_id": "f-neg",
    "exploit": {"method": "POST", "path": "/api/transfer", "headers": {"Content-Type": "application/json"},
                "json_body": {"from": "A", "to": "B", "amount_cents": -50000}},
    "legit": {"method": "POST", "path": "/api/transfer", "headers": {"Content-Type": "application/json"},
              "json_body": {"from": "A", "to": "C", "amount_cents": 2500}},
}


def _seed(out: Path, control="service_policy", probe=NEG_PAY_PROBE):
    out.mkdir(parents=True, exist_ok=True)
    (out / "policies.json").write_text(json.dumps(
        [{"finding_id": "f-neg", "control": control, "policy_name": "deny-neg-pay"}]))
    (out / "probes.json").write_text(json.dumps([probe] if probe else []))


def _waf_on(fake) -> bool:
    app = fake._adc[TENANT][APP]
    return "policyWAF" in app.get("serviceMain", {}) and bigip_apply.WAF_REF in app


def _patch_validate(monkeypatch, fake, *, blocks_when_waf=True):
    """Validation reflects the appliance: an attached WAF blocks the exploit (unless told otherwise)."""
    def fake_validate(url, finding_id, out_dir, fallback, log, **kw):
        blocked = _waf_on(fake) and blocks_when_waf
        return {"exploit_status": 403 if blocked else 200, "exploit_blocked": blocked, "legit_ok": True}
    monkeypatch.setattr(bigip_apply, "_run_validation", fake_validate)


def test_apply_attaches_waf_validates_and_keeps(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip)
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["applied"] and res["passed"] and res["kept"] and not res["rolled_back"]
    assert _waf_on(fake_bigip)                                       # the WAF is left enforcing
    assert ledger.load(str(tmp_path))["f-neg"]["state"] == "mitigated"
    assert fake_bigip.dry_runs and fake_bigip.deployed              # self-test dry-run, then real deploy


def test_rollback_when_the_waf_does_not_block(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip, blocks_when_waf=False)  # attaches but fails to block
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["applied"] and not res["passed"] and not res["kept"] and res["rolled_back"]
    assert not _waf_on(fake_bigip)                                   # rolled back to clean-slate
    assert "f-neg" not in ledger.load(str(tmp_path))                # nothing mitigated


def test_keep_off_rolls_back_after_a_passing_smoke(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip)
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=False,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["passed"] and not res["kept"] and res["rolled_back"]
    assert not _waf_on(fake_bigip)                                   # a smoke: proved, then removed


def test_dry_run_changes_nothing(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip)
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", dry_run=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["dry_run"] and not res.get("applied")
    assert fake_bigip.dry_runs and not fake_bigip.deployed          # AS3 previewed; nothing deployed
    assert not _waf_on(fake_bigip)


def test_unsupported_control_declines_without_deploying(tmp_path, fake_bigip):
    _seed(tmp_path, control="rate_limit")                            # no AWAF band-aid exists
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x",
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["applied"] is False and res["emitted"] is False and res["reason"]
    assert not fake_bigip.deployed and not fake_bigip.dry_runs      # never touched the appliance


def test_protected_tenant_is_refused(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_BIGIP_TENANTS", TENANT)
    with pytest.raises(LabRefused, match="protected"):
        bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x",
                                out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert not fake_bigip.deployed


def test_missing_tenant_is_a_clear_error(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip)
    with pytest.raises(RuntimeError, match="not found"):
        bigip_apply.apply_bigip("f-neg", tenant="no_such_tenant", app=APP, url="http://x",
                                out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)


def test_retire_detaches_the_waf(tmp_path, fake_bigip, monkeypatch):
    _seed(tmp_path)
    _patch_validate(monkeypatch, fake_bigip)
    bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                            out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert _waf_on(fake_bigip)
    bigip_apply.retire_bigip("f-neg", tenant=TENANT, app=APP, out_dir=str(tmp_path),
                             client=fake_bigip, log=lambda *_: None)
    assert not _waf_on(fake_bigip)
    assert ledger.load(str(tmp_path))["f-neg"]["state"] == "retired"
