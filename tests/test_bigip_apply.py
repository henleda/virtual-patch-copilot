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


# a response-masking finding: no numeric field, a `leak` request whose response carries the secret
DG_PROBE = {
    "finding_id": "f-neg",
    "setup": [{"method": "POST", "path": "/api/login", "json_body": {"u": "x"}}],
    "leak": {"method": "GET", "path": "/api/profile"},
    "leak_secrets": ["4111111111111111", "078-05-1120"],
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


def test_apply_data_guard_masking_band_aid_attaches_and_keeps(tmp_path, fake_bigip, monkeypatch):
    """A `waf_data_guard` finding emits a response-masking policy (no numeric derivation, no exploit/
    legit pair) — it must attach and keep exactly like the value form when validation reports the leak
    masked. `_patch_validate`'s "an attached WAF blocks" stands in for "an attached WAF masks": the
    keep predicate (exploit_blocked && legit_ok) is identical, which is the whole point of the mapping."""
    _seed(tmp_path, control="waf_data_guard", probe=DG_PROBE)
    _patch_validate(monkeypatch, fake_bigip)
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["applied"] and res["passed"] and res["kept"]
    assert res["policy_name"] == "deny-neg-pay"                      # the masking policy was emitted…
    app = fake_bigip._adc[TENANT][APP]
    assert app[bigip_apply.WAF_REF]["class"] == "WAF_Policy"         # …wrapped and attached as AS3
    assert ledger.load(str(tmp_path))["f-neg"]["state"] == "mitigated"


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


def test_apply_deploys_clean_slate_first_so_the_baseline_and_import_are_honest(tmp_path, fake_bigip, monkeypatch):
    """Live-box bug: WAF_Policy carries ignoreChanges:true, so a NEW band-aid posted under the same
    `vpcopilot_waf` ref while an old one lingers is silently ignored — and the `before` baseline would
    validate against that stale WAF, hiding whether the new policy helps. apply must deploy the
    clean-slate FIRST. Here a stale band-aid of ours is already on the app at entry; the baseline must
    still measure the app UNDEFENDED, and the new band-aid must land."""
    _seed(tmp_path)
    app = fake_bigip._adc[TENANT][APP]                          # a stale band-aid of ours, pre-attached
    app["serviceMain"]["policyWAF"] = {"use": bigip_apply.WAF_REF}
    app[bigip_apply.WAF_REF] = {"class": "WAF_Policy", "policy": {"base64": "c3RhbGU="}}
    assert _waf_on(fake_bigip)
    _patch_validate(monkeypatch, fake_bigip)                    # blocked iff a WAF is on at validate time
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=lambda *_: None)
    assert res["before"]["exploit_blocked"] is False           # baseline saw the app undefended (clean-first)
    assert res["passed"] and res["kept"] and _waf_on(fake_bigip)   # the new band-aid landed and enforces


def test_unobserved_leak_is_surfaced_honestly_not_as_masked(tmp_path, fake_bigip, monkeypatch):
    """A response-masking finding whose leak request never returned an observable body (4xx / edge
    block) must not be read as 'masked' — the absent secret only means we didn't see the response.
    apply_bigip fails closed (rolls back) AND names the cause, mirroring the auth_failed path."""
    _seed(tmp_path, control="waf_data_guard", probe=DG_PROBE)
    monkeypatch.setattr(bigip_apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 401, "exploit_blocked": False,
                                         "legit_ok": False, "leak": True, "leak_observed": False})
    logs: list[str] = []
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=logs.append)
    assert res["applied"] and not res["passed"] and res["rolled_back"]   # fail closed
    assert not _waf_on(fake_bigip)
    blob = "\n".join(logs).lower()
    assert "observe the leak" in blob and "still succeed" not in blob


def test_auth_failed_validation_is_surfaced_honestly_not_as_exploit_succeeds(tmp_path, fake_bigip, monkeypatch):
    """The live spike's real bug: stale VPCOPILOT_PROBE_* creds made validation return `auth_failed`
    (the probe never logged in). apply_bigip must NOT render that as 'exploit STILL succeeds' — which
    tells a user their WAF failed when the probe simply could not authenticate. It fails closed (rolls
    back, since a block was never confirmed) AND says WHY, so the fix (set the right creds) is
    discoverable rather than a false 'the band-aid does not work'."""
    _seed(tmp_path)
    monkeypatch.setattr(bigip_apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": None, "exploit_blocked": None,
                                         "legit_ok": None, "auth_failed": True})
    logs: list[str] = []
    res = bigip_apply.apply_bigip("f-neg", tenant=TENANT, app=APP, url="http://x", keep=True,
                                  out_dir=str(tmp_path), client=fake_bigip, log=logs.append)
    assert res["applied"] and not res["passed"] and res["rolled_back"]   # fail-closed
    assert not _waf_on(fake_bigip)
    blob = "\n".join(logs).lower()
    assert "authenticate" in blob                       # names the real cause…
    assert "still succeed" not in blob                  # …never the misleading rendering


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
