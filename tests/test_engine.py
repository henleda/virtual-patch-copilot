"""B1/B3: the SafeApply spine — snapshot/self-test, poll_until, and *verified* rollback."""
import json

import pytest

from vpcopilot import engine
from vpcopilot.engine import ApplyContext, RollbackError, poll_until, safe_rollback


def _ctx(fake_xc, tmp_path, noop_sleep):
    return ApplyContext(xc=fake_xc, lb="lab", out_dir=str(tmp_path), log=lambda m: None, sleep=noop_sleep).load()


def test_load_snapshots_and_caches(fake_xc, tmp_path, noop_sleep):
    ctx = _ctx(fake_xc, tmp_path, noop_sleep)
    assert ctx.spec == {"no_service_policies": {}}
    assert (tmp_path / "lb_snapshot.json").exists()
    assert json.loads((tmp_path / "lb_snapshot.json").read_text())["spec"] == {"no_service_policies": {}}


def test_self_test_aborts_on_put_failure(fake_xc, tmp_path, noop_sleep):
    ctx = _ctx(fake_xc, tmp_path, noop_sleep)
    fake_xc.fail_put_lb = True
    with pytest.raises(RuntimeError, match="self-test failed"):
        ctx.self_test()


def test_poll_until_stops_at_predicate(noop_sleep):
    seq = iter([{"ok": False}, {"ok": False}, {"ok": True}, {"ok": False}])
    calls = {"n": 0}
    def produce():
        calls["n"] += 1
        return next(seq)
    res = poll_until(produce, lambda r: r["ok"], attempts=5, wait_seconds=0, sleep=noop_sleep)
    assert res == {"ok": True} and calls["n"] == 3  # stopped as soon as predicate held


def test_poll_until_returns_last_on_exhaustion(noop_sleep):
    res = poll_until(lambda: {"ok": False}, lambda r: r["ok"], attempts=3, wait_seconds=0, sleep=noop_sleep)
    assert res == {"ok": False}


def test_safe_rollback_restores_and_verifies(fake_xc, tmp_path, noop_sleep):
    ctx = _ctx(fake_xc, tmp_path, noop_sleep)
    # simulate an attach: LB now has a band-aid
    ctx.put({"active_service_policies": {"policies": [{"name": "x"}]}})
    assert "active_service_policies" in fake_xc.lb["spec"]
    seen = []
    ok = safe_rollback(ctx, verify=lambda back: seen.append(back) or
                       "active_service_policies" not in back)
    assert ok and fake_xc.lb["spec"] == {"no_service_policies": {}}  # back to the snapshot
    assert seen, "safe_rollback reported success without calling verify at all"


def test_safe_rollback_refuses_to_call_an_unrestored_lb_restored(fake_xc, tmp_path, noop_sleep):
    """The "verifies" half of the guarantee, which the test above CANNOT prove on its own.

    `FakeXC` genuinely applies the PUT, so the restore succeeds by itself and `verify` returns True
    whatever it does — delete the `verify` call from `safe_rollback` entirely and that test still
    passes. It was asserting the behaviour of the fake, not of the code.

    The failure that matters is an appliance that ACCEPTS the rollback PUT and does not apply it —
    a 200 that changed nothing, which is exactly what a partially-degraded control plane looks
    like. Without the verify step, `safe_rollback` returns True and the caller reports a clean
    rollback while the band-aid is still attached to a live load balancer. That is the "silent
    half-rollback" the module docstring calls the worst outcome on a live LB."""
    ctx = _ctx(fake_xc, tmp_path, noop_sleep)
    ctx.put({"active_service_policies": {"policies": [{"name": "x"}]}})

    # Accept every subsequent PUT, apply none of them.
    fake_xc.put_lb = lambda name, body: {"metadata": {"name": name}, "spec": fake_xc.lb["spec"]}

    with pytest.raises(RollbackError, match="could not restore"):
        safe_rollback(ctx, retries=2, verify=lambda back: "active_service_policies" not in back)

    assert "active_service_policies" in fake_xc.lb["spec"], \
        "the LB was never restored — which is precisely why this must raise"
    from vpcopilot import audit
    assert any(a["action"] == "rollback_failed" for a in audit.load(str(tmp_path))), \
        "a rollback that could not be confirmed must leave a loud, attributable audit record"


def test_safe_rollback_raises_when_put_keeps_failing(fake_xc, tmp_path, noop_sleep):
    ctx = _ctx(fake_xc, tmp_path, noop_sleep)
    ctx.put({"active_service_policies": {}})
    fake_xc.fail_put_lb = True
    with pytest.raises(RollbackError):
        safe_rollback(ctx, retries=2)
    # a loud audit record was written
    from vpcopilot import audit
    assert any(a["action"] == "rollback_failed" for a in audit.load(str(tmp_path)))


def test_guard_lb(monkeypatch):
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")
    with pytest.raises(RuntimeError, match="protected LB"):
        engine.guard_lb("nimbus-www", allow_protected=False, dry_run=False)
    engine.guard_lb("nimbus-www", allow_protected=True, dry_run=False)   # override ok
    engine.guard_lb("nimbus-www", allow_protected=False, dry_run=True)   # dry-run ok
    engine.guard_lb("other-lb", allow_protected=False, dry_run=False)    # unprotected ok
