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
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

META_KEYS = ("name", "namespace", "labels", "annotations", "description", "disable")


class RollbackError(RuntimeError):
    """The LB could not be confirmed restored to its pre-apply snapshot. Raised loudly on purpose."""


def protected_lbs() -> set[str]:
    return {s.strip() for s in os.environ.get("VPCOPILOT_PROTECTED_LBS", "nimbus-www").split(",") if s.strip()}


# An XC object name is a plain identifier. Anything else is refused rather than normalized —
# quietly "fixing" a name would mean acting on an object the operator did not type.
_XC_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$")


def validate_xc_name(name: str, kind: str = "load balancer") -> str:
    """Parse an XC object name BEFORE any protected-name check. This is part of the guard.

    A set-membership test is only worth as much as the parsing in front of it. `guard_lb` used to
    compare the raw string, so every one of these sailed straight past it and then addressed the
    protected object anyway, because the name is interpolated into the request path and the URL is
    normalized on the way out:

        './nimbus-www'  -> guard passes -> wire path .../http_loadbalancers/nimbus-www
        'nimbus-www/'   -> guard passes -> trailing segment, same object
        ' nimbus-www'   -> guard passes
        'NIMBUS-WWW'    -> guard passes

    `bigip_lab.validate_tenant` has done this since L2 for exactly the same reason; the XC side
    never got it. A name carrying `/` is the sharp one — it sits in the request path and can
    address a different object entirely.

    NOTE this NARROWS what the tool accepts: a name with a dot, a slash or surrounding whitespace
    is now refused where it previously reached XC. That is the point of the fix, and no such name
    can be created in XC anyway (object names are DNS-style identifiers).
    """
    raw = name if isinstance(name, str) else ""
    stripped = raw.strip()
    if not stripped:
        raise RuntimeError(f"{kind} name is required")
    if stripped != raw:
        raise RuntimeError(
            f"{kind} name {raw!r} has leading or trailing whitespace — refusing rather than "
            f"trimming it, because {stripped!r} may not be the object you meant.")
    if not _XC_NAME_RE.match(stripped):
        raise RuntimeError(
            f"refusing {kind} name {raw!r}: an XC object name must be letters, digits, '-' or '_', "
            f"starting and ending alphanumeric. A name carrying '/', '.' or whitespace can address "
            f"a different object than the one you typed.")
    return stripped


def guard_lb(lb: str, *, allow_protected: bool, dry_run: bool, out_dir: str | None = None) -> None:
    """The one protected-LB guardrail every mutating path shares.

    `out_dir` is optional only so existing callers keep working; pass it wherever you have it. An
    override that is not recorded is not an audited override — see below.
    """
    lb = validate_xc_name(lb)
    # Case-insensitive, like the BIG-IP tenant guard: XC object names are lowercase by
    # construction, so an upper-case spelling cannot be a *different* object — only a way past a
    # guard that compared exactly.
    is_protected = lb.lower() in {p.lower() for p in protected_lbs()}
    if is_protected and not allow_protected and not dry_run:
        raise RuntimeError(
            f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-lb) or edit VPCOPILOT_PROTECTED_LBS to override."
        )
    if is_protected and allow_protected and not dry_run and out_dir:
        # This project prefers warn-with-audited-override to a machine veto — but the audited half
        # was missing. The resulting apply record was byte-identical to an ordinary LB mutation, so
        # the single most sensitive action the tool can take left no trace that a rail was crossed.
        # Recorded as its OWN event rather than a field, so it cannot be missed by a reader
        # scanning for it, and so it survives any change to the per-control record shapes.
        try:
            from . import audit
            audit.record(out_dir, "protected_lb_override", lb=lb,
                         protected_set=sorted(protected_lbs()),
                         note="operator overrode the protected-LB rail with allow_protected")
        except Exception:  # noqa: BLE001 - never let the audit trail break the operation it records
            pass


@dataclass
class ApplyContext:
    """Everything the spine needs, injected once. Carrying `log` here kills the class of
    NameError bugs where a nested helper referenced a `log` that wasn't in scope."""
    xc: object
    lb: str
    out_dir: str = "out"
    log: Callable = print
    finding_id: str | None = None     # the vuln this change is justified by — carried for the audit trail
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
    # The one entry that MUST be attributable: the LB may be left in a changed state.
    audit.record(ctx.out_dir, "rollback_failed", finding_id=ctx.finding_id, lb=ctx.lb,
                 namespace=getattr(ctx.xc, "ns", None), reason=last)
    ctx.log(f"!! ROLLBACK FAILED after {retries} tries: {last} — the LB may be in a changed state")
    raise RollbackError(f"could not restore {ctx.lb} to snapshot after {retries} tries: {last}")
