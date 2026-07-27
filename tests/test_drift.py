"""I2 — drift and conflict detection: what is on the LB now, versus what the last run left, versus
what is about to be pushed.

Read-only throughout: `drift` never PUTs, never writes a snapshot, and never touches the run's
artifacts. Offline against FakeXC."""
import json

import pytest

from vpcopilot import drift

EXPLOIT = {"method": "POST", "path": "/users/v1/register"}


def _policy(*rules):
    return {"metadata": {"name": "p"}, "spec": {"rule_list": {"rules": [{"spec": r} for r in rules]}}}


DENY_REGISTER = {"action": "DENY", "path": {"exact_values": ["/users/v1/register"]},
                 "http_method": {"methods": ["POST"]}}
ALLOW_ALL = {"action": "ALLOW", "path": {"prefix_values": ["/"]}}


# ---- live vs the last snapshot: did someone hand-edit the LB? ----
def test_no_snapshot_yet_is_not_drift(fake_xc, tmp_path):
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)
    assert r["live_vs_snapshot"]["drifted"] is False
    assert r["live_vs_snapshot"]["snapshot"] is None


def test_an_unchanged_lb_shows_no_drift(fake_xc, tmp_path):
    drift.save_snapshot(str(tmp_path), "lab", fake_xc.get_lb("lab"))
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)
    assert r["live_vs_snapshot"]["drifted"] is False and not r["live_vs_snapshot"]["changes"]


def test_a_hand_edit_since_the_last_apply_is_a_field_level_diff(fake_xc, tmp_path):
    drift.save_snapshot(str(tmp_path), "lab", fake_xc.get_lb("lab"))
    fake_xc.lb["spec"]["app_firewall"] = {"name": "someone-added-this"}   # edited in the XC console
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)
    assert r["live_vs_snapshot"]["drifted"] is True
    ch = r["live_vs_snapshot"]["changes"]
    assert any(c["path"] == "app_firewall" and c["was"] is None for c in ch)


def test_a_removed_field_is_reported_too(fake_xc, tmp_path):
    fake_xc.lb["spec"]["rate_limit"] = {"requests": 5}
    drift.save_snapshot(str(tmp_path), "lab", fake_xc.get_lb("lab"))
    del fake_xc.lb["spec"]["rate_limit"]
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)
    assert any(c["path"] == "rate_limit" and c["now"] is None
               for c in r["live_vs_snapshot"]["changes"])


def test_a_nested_change_reports_the_dotted_path(fake_xc, tmp_path):
    fake_xc.lb["spec"]["rate_limit"] = {"requests": 100, "unit": "MINUTE"}
    drift.save_snapshot(str(tmp_path), "lab", fake_xc.get_lb("lab"))
    fake_xc.lb["spec"]["rate_limit"]["requests"] = 5
    ch = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)["live_vs_snapshot"]["changes"]
    assert any(c["path"] == "rate_limit.requests" and c["was"] == 100 and c["now"] == 5 for c in ch)


# ---- live vs proposed: is this already what is on the LB? ----
def test_reapplying_the_same_service_policy_is_no_change(fake_xc, tmp_path):
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc,
                    control="service_policy", policy_name="deny-x")
    assert r["proposed"]["no_change"] is True


def test_applying_a_different_policy_is_a_change(fake_xc, tmp_path):
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-other"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc,
                    control="service_policy", policy_name="deny-x")
    assert r["proposed"]["no_change"] is False


def test_an_lb_wide_control_reports_presence_but_never_claims_no_change(fake_xc, tmp_path):
    """Presence is not parameter equality: a rate_limit already attached at 100/MINUTE would read
    as 'unchanged' while you push 5/MINUTE. Silently skipping a real change is worse than the bug
    this item fixes, so these are reported and NOT auto-skipped."""
    fake_xc.lb["spec"]["rate_limit"] = {"requests": 100, "unit": "MINUTE"}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="rate_limit")
    assert r["proposed"]["already_attached"] is True
    assert r["proposed"]["no_change"] is False
    assert "parameter" in r["proposed"]["note"].lower()


# ---- displacement: what applying COSTS ----
# The roadmap wrote this as "an earlier ALLOW on an attached policy shadows the new DENY". A live
# run disproved it: both attach paths replace `active_service_policies` with exactly one policy, so
# two are never attached at once and there is no earlier policy to be shadowed by. What the
# replacement DOES do is silently detach whatever was there — which nothing reported until now.
def test_applying_reports_the_policy_it_will_detach(fake_xc, tmp_path):
    fake_xc.service_policies["existing"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "existing"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT)
    assert [d["policy"] for d in r["displaces"]] == ["existing"]
    assert r["displaces"][0] == {"policy": "existing", "rules": 2, "denies": 1,
                                 "protects_exploit": True}


def test_displacement_never_blocks_the_apply(fake_xc, tmp_path):
    """Replacing the previous band-aid IS the normal flow — refusing would break every second
    apply. It is warned and audited, not vetoed."""
    fake_xc.service_policies["existing"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "existing"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT)
    assert r["ok_to_apply"] is True and not r["conflicts"]


def test_a_displaced_policy_that_does_not_block_the_exploit_says_so(fake_xc, tmp_path):
    fake_xc.service_policies["existing"] = _policy(ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "existing"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT)
    assert r["displaces"][0]["protects_exploit"] is False


def test_replacing_a_policy_with_itself_displaces_nothing(fake_xc, tmp_path):
    fake_xc.service_policies["deny-x"] = _policy(ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT)
    assert r["displaces"] == [] and not r["conflicts"]


# ---- shadowing, in its only true scope: inside the policy being applied ----
def test_an_allow_before_the_deny_in_the_proposed_policy_is_a_conflict(fake_xc, tmp_path):
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT,
                    spec={"rule_list": {"rules": [{"spec": ALLOW_ALL}, {"spec": DENY_REGISTER}]}})
    assert r["conflicts"] and r["conflicts"][0]["kind"] == "shadowed_deny"
    assert r["ok_to_apply"] is False


def test_the_right_rule_order_is_not_a_conflict(fake_xc, tmp_path):
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT,
                    spec={"rule_list": {"rules": [{"spec": DENY_REGISTER}, {"spec": ALLOW_ALL}]}})
    assert not r["conflicts"] and r["ok_to_apply"] is True


def test_shadowing_agrees_with_the_linter(fake_xc, tmp_path):
    """drift reuses `lint_service_policy` rather than re-deriving FIRST_MATCH, so the two can never
    disagree about what shadows what."""
    from vpcopilot.apply import lint_service_policy
    spec = {"rule_list": {"rules": [{"spec": ALLOW_ALL}, {"spec": DENY_REGISTER}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT, spec=spec)
    assert r["conflicts"][0]["reason"] in lint_service_policy(spec, EXPLOIT)


def test_no_exploit_means_no_shadowing_claim(fake_xc, tmp_path):
    """Shadowing is relative to a concrete request. Without one there is nothing to decide, and
    guessing would be worse than saying so."""
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x",
                    spec={"rule_list": {"rules": [{"spec": ALLOW_ALL}, {"spec": DENY_REGISTER}]}})
    assert not r["conflicts"] and r["conflicts_checked"] is False


def test_an_unreadable_attached_policy_is_reported_not_raised(fake_xc, tmp_path):
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "vanished"}]}}
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                    policy_name="deny-x", exploit=EXPLOIT)
    assert any("vanished" in w for w in r["warnings"])


# ---- read-only ----
def test_drift_never_writes_and_never_puts(fake_xc, tmp_path):
    drift.save_snapshot(str(tmp_path), "lab", fake_xc.get_lb("lab"))
    before = sorted(p.name for p in tmp_path.rglob("*"))
    drift.check("lab", out_dir=str(tmp_path), xc=fake_xc, control="service_policy",
                policy_name="deny-x", exploit=EXPLOIT)
    assert sorted(p.name for p in tmp_path.rglob("*")) == before
    assert fake_xc.put_lb_calls == []


def test_it_reads_the_newest_snapshot(fake_xc, tmp_path):
    snaps = tmp_path / "snapshots"
    snaps.mkdir()
    (snaps / "lab-20260101T000000.json").write_text(json.dumps({"spec": {"old": True}}))
    (snaps / "lab-20260727T120000.json").write_text(json.dumps({"spec": {"no_service_policies": {}}}))
    (snaps / "other-20260727T130000.json").write_text(json.dumps({"spec": {"wrong-lb": True}}))
    r = drift.check("lab", out_dir=str(tmp_path), xc=fake_xc)
    assert r["live_vs_snapshot"]["snapshot"].endswith("lab-20260727T120000.json")
    assert r["live_vs_snapshot"]["drifted"] is False


# ---- the matcher extracted from the linter must behave identically ----
def test_rule_matches_is_the_same_logic_the_linter_uses():
    from vpcopilot.apply import lint_service_policy, rule_matches
    assert rule_matches(DENY_REGISTER, EXPLOIT) is True
    assert rule_matches({"action": "DENY", "path": {"exact_values": ["/other"]}}, EXPLOIT) is False
    # the linter still catches an ALLOW shadowing the exploit inside one spec
    bad = {"rule_list": {"rules": [{"spec": ALLOW_ALL}, {"spec": DENY_REGISTER}]}}
    assert lint_service_policy(bad, EXPLOIT)


# ---- the pre-apply guard ----
def _artifact(tmp_path, name="deny-x"):
    art = tmp_path / f"service_policy.{name}.json"
    art.write_text(json.dumps({"metadata": {"name": name}, "spec": {"rule_list": {"rules": [
        {"spec": DENY_REGISTER}, {"spec": ALLOW_ALL}]}}}))
    return str(art)


def _guard_env(monkeypatch, fake_xc, noop_sleep):
    from vpcopilot import apply as A
    import vpcopilot.engine as engine
    real = engine.ApplyContext.__post_init__

    def patched(self):
        real(self)
        self.sleep = noop_sleep
    monkeypatch.setattr(engine.ApplyContext, "__post_init__", patched)
    monkeypatch.setattr(A, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")
    return A


def test_reapplying_the_attached_policy_reports_no_change_and_writes_nothing(
        monkeypatch, fake_xc, tmp_path, noop_sleep):
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    fake_xc.service_policies["deny-x"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    res = A.apply_from_scan(_artifact(tmp_path), "lab", "http://x", out_dir=str(tmp_path),
                            log=lambda m: None)
    assert res["mode"] == "no_change"
    assert fake_xc.put_lb_calls == []                       # nothing pushed
    assert not (tmp_path / "snapshots").exists()            # and no snapshot written
    assert not (tmp_path / "lb_snapshot.json").exists()


def test_force_reapplies_a_policy_that_is_already_attached(monkeypatch, fake_xc, tmp_path, noop_sleep):
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    monkeypatch.setattr(A, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    fake_xc.service_policies["deny-x"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    res = A.apply_from_scan(_artifact(tmp_path), "lab", "http://x", out_dir=str(tmp_path),
                            force=True, log=lambda m: None)
    assert res["mode"] != "no_change" and fake_xc.put_lb_calls


def test_a_shadowed_deny_blocks_the_apply(monkeypatch, fake_xc, tmp_path, noop_sleep):
    """Rule order that makes the band-aid a no-op is caught before the policy is even created —
    not after a live attach, a validate, and a rollback."""
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    (tmp_path / "probes.json").write_text(json.dumps([{"finding_id": "f1", "exploit": EXPLOIT}]))
    art = tmp_path / "service_policy.shadowed.json"
    art.write_text(json.dumps({"metadata": {"name": "shadowed"}, "spec": {"rule_list": {"rules": [
        {"spec": ALLOW_ALL}, {"spec": DENY_REGISTER}]}}}))
    with pytest.raises(RuntimeError, match="FIRST_MATCH"):
        A.apply_from_scan(str(art), "lab", "http://x", finding_id="f1",
                          out_dir=str(tmp_path), log=lambda m: None)
    assert fake_xc.put_lb_calls == []
    assert "shadowed" not in fake_xc.service_policies   # nor a stray object left in the tenant


def test_displacement_warns_but_still_applies(monkeypatch, fake_xc, tmp_path, noop_sleep):
    """No regressions: an LB that already carries someone else's policy must still be mitigable."""
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    monkeypatch.setattr(A, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    fake_xc.service_policies["someone-elses"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "someone-elses"}]}}
    res = A.apply_from_scan(_artifact(tmp_path), "lab", "http://x", out_dir=str(tmp_path),
                            log=lambda m: None)
    assert res["mode"] != "no_change" and fake_xc.put_lb_calls
    assert "policy_displaced" in _actions(tmp_path)


def test_a_dry_run_is_never_gated(monkeypatch, fake_xc, tmp_path, noop_sleep):
    """Dry-run changes nothing, so there is nothing for a pre-apply guard to prevent."""
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    fake_xc.service_policies["deny-x"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    res = A.apply_from_scan(_artifact(tmp_path), "lab", "http://x", dry_run=True,
                            out_dir=str(tmp_path), log=lambda m: None)
    assert res["mode"] != "no_change"


def test_an_unrelated_attached_policy_does_not_trigger_no_change(monkeypatch, fake_xc, tmp_path, noop_sleep):
    A = _guard_env(monkeypatch, fake_xc, noop_sleep)
    monkeypatch.setattr(A, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    fake_xc.service_policies["something-else"] = _policy(DENY_REGISTER)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "something-else"}]}}
    res = A.apply_from_scan(_artifact(tmp_path), "lab", "http://x", out_dir=str(tmp_path),
                            log=lambda m: None)
    assert res["mode"] != "no_change"


# ---- the shared preflight, and the audit trail it leaves ----
def _actions(tmp_path):
    from vpcopilot import audit
    return [e["action"] for e in audit.load(str(tmp_path))]


def test_the_refiner_is_gated_too(monkeypatch, fake_xc, tmp_path, noop_sleep):
    """The refiner — not apply_from_scan — is the default path for both `--from-scan` and the
    console's Mitigate button. A guard the primary UX skips is not a guard."""
    import vpcopilot.refiner as R
    monkeypatch.setattr(R, "XC", lambda *a, **k: fake_xc)
    drift.save_snapshot(str(tmp_path), "lab", {"spec": {}})
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}
    res = R.refine_apply_service_policy(_artifact(tmp_path), "lab", "http://x",
                                        out_dir=str(tmp_path), log=lambda m: None)
    assert res["mode"] == "no_change" and fake_xc.put_lb_calls == []
    assert "drift_detected" in _actions(tmp_path)


def test_the_refiner_warns_about_a_shadowed_deny_instead_of_refusing(fake_xc, tmp_path):
    """Reordering rules is exactly what the refine loop exists to do. Refusing on the refine path
    would break the default flow to protect it from a problem it already fixes."""
    lines = []
    assert drift.preflight("lab", "deny-x", out_dir=str(tmp_path), exploit=EXPLOIT, refine=True,
                           spec={"rule_list": {"rules": [{"spec": ALLOW_ALL},
                                                         {"spec": DENY_REGISTER}]}},
                           xc=fake_xc, log=lines.append) is None
    assert any("refine will reorder" in ln for ln in lines)
    assert "drift_block" not in _actions(tmp_path)


def test_a_refusal_is_audited(fake_xc, tmp_path):
    with pytest.raises(RuntimeError):
        drift.preflight("lab", "deny-x", out_dir=str(tmp_path), exploit=EXPLOIT,
                        spec={"rule_list": {"rules": [{"spec": ALLOW_ALL},
                                                      {"spec": DENY_REGISTER}]}},
                        xc=fake_xc, log=lambda m: None)
    assert "drift_block" in _actions(tmp_path)


def test_forcing_past_a_conflict_is_audited(fake_xc, tmp_path):
    """Overriding is allowed; overriding silently is not — the whole point of the audit trail."""
    assert drift.preflight("lab", "deny-x", out_dir=str(tmp_path), exploit=EXPLOIT, force=True,
                           spec={"rule_list": {"rules": [{"spec": ALLOW_ALL},
                                                         {"spec": DENY_REGISTER}]}},
                           xc=fake_xc, log=lambda m: None) is None
    acts = _actions(tmp_path)
    assert "drift_override" in acts and "drift_block" not in acts


def test_displacing_a_live_policy_is_audited(fake_xc, tmp_path):
    fake_xc.service_policies["someone-elses"] = _policy(DENY_REGISTER, ALLOW_ALL)
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "someone-elses"}]}}
    assert drift.preflight("lab", "deny-x", out_dir=str(tmp_path), exploit=EXPLOIT,
                           xc=fake_xc, log=lambda m: None) is None
    from vpcopilot import audit
    ev = [e for e in audit.load(str(tmp_path)) if e["action"] == "policy_displaced"]
    assert ev and ev[0]["displaced"] == "someone-elses" and ev[0]["protects_exploit"] is True


def test_a_skip_and_hand_edited_drift_are_both_audited(fake_xc, tmp_path):
    drift.save_snapshot(str(tmp_path), "lab", {"spec": {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}}})
    fake_xc.lb["spec"] = {"active_service_policies": {"policies": [
        {"namespace": fake_xc.ns, "name": "deny-x"}]}, "rate_limit": {"requests": 5}}
    rep = drift.preflight("lab", "deny-x", out_dir=str(tmp_path), xc=fake_xc, log=lambda m: None)
    assert rep is not None and rep["proposed"]["no_change"]
    acts = _actions(tmp_path)
    assert "apply_skipped_no_change" in acts and "drift_detected" in acts


def test_preflight_still_writes_no_lb_change(fake_xc, tmp_path):
    drift.preflight("lab", "deny-x", out_dir=str(tmp_path), exploit=EXPLOIT,
                    xc=fake_xc, log=lambda m: None)
    assert fake_xc.put_lb_calls == [] and not (tmp_path / "snapshots").exists()
