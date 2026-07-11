"""B1/B3/B4: the shared SafeApply spine. Seven apply_* handlers used to re-implement the same
sequence — snapshot → idempotent self-test PUT → attach → validate → keep or rollback — each with
its own subtly-different rollback. This centralizes the spine so every control gets the SAME safe
behavior, and makes rollback *verified*: it retries and confirms the LB was restored, raising
RollbackError loudly if it can't (a silent half-rollback is the worst outcome on a live LB).

Dependency injection (xc, sleep) lives on ApplyContext so the engine is testable without a real
tenant or wall-clock waits (see tests/conftest.py FakeXC)."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

META_KEYS = ("name", "namespace", "labels", "annotations", "description", "disable")


class RollbackError(RuntimeError):
    """The LB could not be confirmed restored to its pre-apply snapshot. Raised loudly on purpose."""


def protected_lbs() -> set[str]:
    return {s.strip() for s in os.environ.get("VPCOPILOT_PROTECTED_LBS", "nimbus-www").split(",") if s.strip()}


def guard_lb(lb: str, *, allow_protected: bool, dry_run: bool) -> None:
    """The one protected-LB guardrail every mutating path shares."""
    if lb in protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(
            f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-lb) or edit VPCOPILOT_PROTECTED_LBS to override."
        )


@dataclass
class ApplyContext:
    """Everything the spine needs, injected once. Carrying `log` here kills the class of
    NameError bugs where a nested helper referenced a `log` that wasn't in scope."""
    xc: object
    lb: str
    out_dir: str = "out"
    log: Callable = print
    sleep: Callable = None            # DI: tests pass a no-op so polls don't wait
    lb_obj: dict = field(default_factory=dict)
    spec: dict = field(default_factory=dict)
    base_meta: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.sleep is None:
            import time
            self.sleep = time.sleep

    def load(self) -> "ApplyContext":
        """GET the LB, cache spec + metadata, and write the snapshot to disk. B7: keep a
        per-LB timestamped snapshot under out/snapshots/ (the flat lb_snapshot.json is overwritten
        on every apply and clobbers a prior LB's snapshot) so any apply can be traced/undone."""
        self.lb_obj = self.xc.get_lb(self.lb)
        self.spec = self.lb_obj.get("spec", {})
        self.base_meta = {k: self.lb_obj["metadata"][k] for k in META_KEYS if k in self.lb_obj.get("metadata", {})}
        blob = json.dumps(self.lb_obj, indent=2)
        Path(self.out_dir).mkdir(parents=True, exist_ok=True)
        Path(self.out_dir, "lb_snapshot.json").write_text(blob)  # latest (back-compat)
        snaps = Path(self.out_dir, "snapshots")
        snaps.mkdir(exist_ok=True)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        (snaps / f"{self.lb}-{ts}.json").write_text(blob)
        return self

    def put(self, new_spec: dict):
        return self.xc.put_lb(self.lb, {"metadata": self.base_meta, "spec": new_spec})

    def self_test(self) -> None:
        """Prove GET→PUT round-trips before changing anything — catches auth/shape problems while
        the LB is still in its original state."""
        try:
            self.put(copy.deepcopy(self.spec))
            self.log("PUT self-test (idempotent) ok — GET->PUT round trip is safe")
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    def current_spec(self) -> dict:
        return self.xc.get_lb(self.lb).get("spec", {})


def poll_until(produce: Callable[[], dict], predicate: Callable[[dict], bool], *,
               attempts: int, wait_seconds: int, sleep: Callable, log: Callable = lambda m: None,
               waiting: str = "") -> dict | None:
    """Call produce() up to `attempts` times, sleeping between, until predicate(result). Returns the
    last result (predicate may still be False — the caller decides pass/fail). Centralizes the
    'wait for config→edge propagation' loop the live-validated controls all share."""
    res = None
    for i in range(1, attempts + 1):
        sleep(wait_seconds)
        res = produce()
        if predicate(res):
            return res
        if waiting:
            log(f"  attempt {i}/{attempts}: {waiting}")
    return res


def safe_rollback(ctx: ApplyContext, *, retries: int = 3, verify: Callable[[dict], bool] | None = None) -> bool:
    """Restore the pre-apply snapshot, retrying on failure, and (if `verify` is given) confirm the
    LB actually came back before declaring success. Raises RollbackError after a loud audit if the
    LB can't be restored — never returns having left the LB in a changed, unreported state."""
    last = None
    for i in range(1, retries + 1):
        try:
            ctx.put(copy.deepcopy(ctx.spec))
            if verify is None or verify(ctx.current_spec()):
                ctx.log("rolled back · LB restored to the pre-apply snapshot")
                return True
            last = "post-rollback verify failed — LB not restored to snapshot"
        except Exception as e:  # noqa: BLE001
            last = str(e)
        ctx.log(f"  rollback attempt {i}/{retries} failed: {last}")
        if i < retries:
            ctx.sleep(2)
    from . import audit
    audit.record(ctx.out_dir, "rollback_failed", lb=ctx.lb, reason=last)
    ctx.log(f"!! ROLLBACK FAILED after {retries} tries: {last} — the LB may be in a changed state")
    raise RollbackError(f"could not restore {ctx.lb} to snapshot after {retries} tries: {last}")
