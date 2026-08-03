"""Live: the SafeApply spine against a real XC load balancer.

The claim the whole demo rests on — *"every apply snapshots the LB and rolls back on validation
failure (or by default)"* — and until now it was only ever proven by hand. This is the backlog
item's first candidate: *create → attach → validate → rollback, asserting the LB returns to its
snapshot.*

**This one mutates a shared estate, not a box built for it**, which is why the target is an explicit
allowlist rather than a name passed in. `VPCOPILOT_LIVE_LB` must be set, must not be a protected LB,
and the test refuses to run against anything else — a live test that guessed which load balancer to
mutate would be the exact failure `guard_lb` exists to prevent, committed by the test suite itself.

Every test here captures the live spec first and restores it in a `finally`, so a crash mid-apply
cannot leave the tenant changed.
"""
from __future__ import annotations

import copy
import json

import pytest

from tests.live import requires, restoring
from vpcopilot.engine import META_KEYS, ApplyContext, protected_lbs, safe_rollback

pytestmark = pytest.mark.live


@pytest.fixture
def lb_name():
    """The allowlist. Named explicitly, and refused if protected — belt and braces, because this is
    the one suite that writes to an estate someone else's demo also uses."""
    env = requires("VPCOPILOT_LIVE_LB", "XC_API_URL", "XC_API_TOKEN")
    lb = env["VPCOPILOT_LIVE_LB"]
    if lb in protected_lbs():
        pytest.fail(f"refusing to run a live mutation test against protected LB {lb!r} — "
                    f"VPCOPILOT_LIVE_LB must name a lab LB")
    return lb


@pytest.fixture
def xc(lb_name):
    """Depends on `lb_name` **on purpose**, so the credential check runs first.

    Without that dependency pytest is free to build this fixture before the one that skips, and
    `XC()` raises on a missing `XC_API_URL` — turning a clean skip into an ERROR. That is the
    harness's own rule ("absent is a skip, never a pass, never a failure") broken by the suite
    written to enforce it, and it is the second time this exact shape has appeared, so it is worth
    naming: a skip guard only works if nothing can be constructed ahead of it."""
    from vpcopilot.xc import XC
    return XC()


@pytest.fixture
def pristine(xc, lb_name):
    """Capture the live spec, hand it over, and put it back no matter what the test did.

    The restore is unconditional rather than only-on-failure: a test that *thinks* it rolled back
    is exactly the test whose cleanup you want to run anyway."""
    before = copy.deepcopy(xc.get_lb(lb_name))
    yield before
    # META_KEYS is imported rather than retyped: the restore must rebuild metadata exactly the way
    # `ApplyContext.put` does, or the cleanup writes back a subtly different object than the one the
    # spine would have written — a test whose own teardown mutates the tenant differently from the
    # code under test is worse than no cleanup, because it looks correct.
    meta = {k: before["metadata"][k] for k in META_KEYS if k in before.get("metadata", {})}
    restoring(xc.put_lb, lb_name, {"metadata": meta, "spec": before["spec"]})


def _spec(xc, lb):
    return xc.get_lb(lb).get("spec", {})


def test_the_put_self_test_is_genuinely_idempotent(xc, lb_name, pristine, evidence, tmp_path):
    """The spine's first move: prove GET→PUT round-trips *before* changing anything, so an auth or
    shape problem surfaces while the LB is still in its original state. "Idempotent" is the whole
    claim, and only a real tenant can test it — XC normalises what you send, so a spec that
    round-trips in a fake may not round-trip here."""
    before = copy.deepcopy(pristine["spec"])
    ctx = ApplyContext(xc=xc, lb=lb_name, out_dir=str(tmp_path), log=lambda m: None).load()
    ctx.self_test()
    after = _spec(xc, lb_name)
    assert after == before, (
        "the idempotent self-test PUT CHANGED the load balancer — the one thing it must not do. "
        f"differing keys: {sorted(set(before) ^ set(after)) or 'same keys, different values'}")
    evidence.record(f"self-test PUT round-tripped {lb_name} with no change ({len(before)} spec keys)")


def test_the_snapshot_on_disk_matches_the_live_load_balancer(xc, lb_name, pristine, evidence, tmp_path):
    """Rollback restores *from this file*, so a snapshot that does not match the live LB is a
    rollback that would silently write the wrong state back. Checkable only against a real tenant."""
    ctx = ApplyContext(xc=xc, lb=lb_name, out_dir=str(tmp_path), log=lambda m: None).load()
    flat = json.loads((tmp_path / "lb_snapshot.json").read_text())
    assert flat["spec"] == pristine["spec"], "lb_snapshot.json does not match the live LB"
    assert ctx.spec == pristine["spec"], "the in-memory snapshot does not match the live LB"

    stamped = sorted((tmp_path / "snapshots").glob(f"{lb_name}-*.json"))
    assert stamped, "no timestamped snapshot was written — B7's per-LB history is missing"
    assert json.loads(stamped[-1].read_text())["spec"] == pristine["spec"]
    evidence.record(f"snapshot on disk matches the live LB, flat + {len(stamped)} timestamped")


def test_an_apply_with_rollback_returns_the_lb_byte_identical(xc, lb_name, pristine, evidence, tmp_path):
    """**The claim the demo rests on.** A real control is attached to a real load balancer and then
    rolled back, and the LB must come back byte-identical — not "close", not "the control is off",
    identical to what was there before anyone touched it.

    `malicious_user` is the control under test because it is config-validated: it exercises
    snapshot → self-test → attach → validate → rollback without needing a generated policy artifact
    or a live exploit, so what this test measures is the *spine*, not one control's semantics."""
    from vpcopilot.apply import apply_malicious_user

    before = copy.deepcopy(pristine["spec"])
    res = apply_malicious_user(lb_name, dry_run=False, keep=False, out_dir=str(tmp_path),
                               finding_id="live-spine-test", log=lambda m: None)
    evidence.record(f"applied malicious_user: config_enabled={res.get('config_enabled')} "
                    f"from={res.get('diff', {}).get('from')} rolled_back={res.get('rolled_back')}")

    # ---- the three assertions below exist because the first draft of this test was VACUOUS ----
    # Found by adversarial review. Asserting only `rolled_back` and byte-identity passes perfectly
    # on a run where the control NEVER ATTACHED: `rolled` is set unconditionally in apply.py's
    # `else` branch regardless of the readback, and "the LB is unchanged" is trivially true when
    # nothing was ever written. That is precisely the vacuous pass `tests/live.py` was written to
    # eliminate, committed by the test meant to prove the safety spine.

    # 1. The LB must have STARTED clean, or a working attach is itself a no-op and the whole test
    #    proves nothing — a hole that opens with no code change at all after any `--keep` demo.
    assert res.get("diff", {}).get("from") == "disabled", (
        f"{lb_name} already had malicious-user detection enabled, so this test cannot prove an "
        f"attach happened. Disable it and re-run: {res.get('diff')}")
    # 2. The control actually went live — the readback the apply already performs, which is the one
    #    fact that distinguishes a real attach from a silent no-op.
    assert res.get("config_enabled") is True, \
        f"the control never attached, so the rollback below proves nothing: {res}"
    # 3. …and only then is the rollback meaningful.
    assert res.get("rolled_back") is True, \
        f"the apply reported no rollback despite keep=False: {res}"
    after = _spec(xc, lb_name)
    assert after == before, (
        "the LB did NOT return to its pre-apply state after rollback — this is the safety claim "
        "the whole demo rests on. "
        f"keys now differing: {[k for k in set(before) | set(after) if before.get(k) != after.get(k)]}")
    evidence.record("LB returned byte-identical to the pre-apply snapshot")

    # …and the change was recorded, because an apply nobody can account for is not a safe apply.
    from vpcopilot import audit
    actions = [e["action"] for e in audit.load(str(tmp_path))]
    assert "apply_malicious_user" in actions, f"the apply wrote no audit record: {actions}"
    evidence.record(f"audit trail records {actions}")


def test_safe_rollback_verifies_rather_than_assuming(xc, lb_name, pristine, evidence, tmp_path):
    """`safe_rollback` takes a `verify` callable and must actually consult it — a rollback that
    reports success without confirming is the "silent half-rollback" the module docstring calls the
    worst outcome on a live LB. Here the verify is made to fail, so the function must NOT report
    success, and must raise rather than returning quietly."""
    from vpcopilot.engine import RollbackError

    ctx = ApplyContext(xc=xc, lb=lb_name, out_dir=str(tmp_path), log=lambda m: None,
                       sleep=lambda *_a: None).load()
    with pytest.raises(RollbackError):
        safe_rollback(ctx, retries=2, verify=lambda _spec: False)   # never satisfied
    evidence.record("safe_rollback raised RollbackError when verify never passed")

    # The LB itself is still fine — the failure was the *verifier*, not the restore.
    assert _spec(xc, lb_name) == pristine["spec"]

    # …and the un-restorable case is the one entry that must never be anonymous.
    from vpcopilot import audit
    rb = [e for e in audit.load(str(tmp_path)) if e["action"] == "rollback_failed"]
    assert rb and rb[0].get("lb") == lb_name and rb[0].get("actor"), \
        f"rollback_failed must be recorded with an actor and the LB: {rb}"
    evidence.record("rollback_failed audited with actor + lb")


def test_the_protected_lb_guard_names_an_lb_that_really_exists(xc, evidence):
    """The guard is unit-tested against fakes. What only a tenant can tell you is whether the
    protected name still *matches something* — a `VPCOPILOT_PROTECTED_LBS` entry that no longer
    corresponds to a real LB is a guard protecting nothing, and it would look identical to a working
    one from offline.

    (An earlier version of this test claimed to check "against the real tenant" while touching
    nothing but an env var. It passed without credentials, which is how I noticed.)"""
    from vpcopilot.engine import guard_lb
    prot = protected_lbs()
    assert prot, "no protected LBs configured — VPCOPILOT_PROTECTED_LBS should not be empty"

    live_names = {it.get("name") for it in xc.list_http_loadbalancers().get("items", [])}
    matched = sorted(prot & live_names)
    assert matched, (
        f"none of the protected names {sorted(prot)} exists on this tenant {sorted(live_names)} — "
        f"the guard is protecting nothing")
    for name in matched:
        with pytest.raises(RuntimeError, match="refusing to mutate protected"):
            guard_lb(name, allow_protected=False, dry_run=False)
    evidence.record(f"protected names that exist and are refused: {matched}")
