"""C2 — retire a band-aid once its code-fix PR merges.

Closes the ledger loop found → mitigated → remediated → **retired**: when a finding's cure PR
is merged, detach its temporary XC control from the LB (the inverse of apply) and mark the ledger
retired, so a band-aid never silently outlives the real fix. `--force` retires without the merge
check (manual retire); the same protected-LB guardrail as apply applies."""
from __future__ import annotations

import copy
import re
from typing import Callable

from . import inventory, ledger
from .apply import META_KEYS
from .controls import detach_control as _detach_control  # B4: single source of truth for detach
from .xc import XC


def _pr_ref(pr_url: str | None):
    m = re.search(r"github\.com/([^/]+/[^/]+)/pull/(\d+)", pr_url or "")
    return (m.group(1), int(m.group(2))) if m else (None, None)


def pr_is_merged(pr_url: str | None) -> bool:
    repo, num = _pr_ref(pr_url)
    if not repo:
        return False
    from github import Github

    from .pr import _resolve_token
    return bool(Github(_resolve_token()).get_repo(repo).get_pull(num).merged)


def retire_finding(out_dir: str, finding_id: str, *, lb: str | None = None, force: bool = False,
                   dry_run: bool = False, allow_protected: bool = False, log: Callable = print) -> dict:
    # The global inventory is the source of truth for a live band-aid — a re-scan may have pruned this
    # finding from its session ledger, but the patch is still on the LB and must stay retire-able. A
    # finding_id is not unique across apps, so address the exact band-aid by (lb, finding_id) when the
    # caller knows the LB; without it, one live match is unambiguous, several needs the LB named, and
    # none falls back to this session's ledger for a pre-split entry the migration has not reached.
    if lb is not None:
        e = inventory.get(finding_id, lb)
    else:
        matches = inventory.entries_for(finding_id)
        if len(matches) > 1:
            return {"finding_id": finding_id, "status": "ambiguous — specify the load balancer",
                    "lbs": sorted((m.get("mitigation") or {}).get("lb") for m in matches)}
        e = matches[0] if matches else ledger.load(out_dir).get(finding_id)
    if not e:
        return {"finding_id": finding_id, "status": "no ledger entry"}
    if e.get("state") == "retired":
        return {"finding_id": finding_id, "status": "already retired"}
    mit = e.get("mitigation")
    if not mit:
        return {"finding_id": finding_id, "status": "no live band-aid to retire"}
    cure = e.get("cure") or {}

    if not force:
        if e.get("state") != "remediated":
            return {"finding_id": finding_id, "status": f"skipped — state '{e.get('state')}', no open cure PR"}
        if not pr_is_merged(cure.get("pr_url")):
            return {"finding_id": finding_id, "status": "skipped — cure PR not merged yet"}

    lb, control = mit["lb"], mit["control"]
    # Third copy of the protected-LB check, and it had the same unparsed-name bypass as the other
    # two. Delegate to the shared guard so there is ONE answer — a rail re-implemented per module
    # is a rail that holds in some modules.
    from .engine import guard_lb
    guard_lb(lb, allow_protected=allow_protected, dry_run=dry_run, out_dir=out_dir)
    if dry_run:
        return {"finding_id": finding_id, "status": "would retire", "control": control, "lb": lb}

    xc = XC()
    lb_obj = xc.get_lb(lb)
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}
    new_spec = copy.deepcopy(lb_obj.get("spec", {}))
    _detach_control(new_spec, control)
    xc.put_lb(lb, {"metadata": base_meta, "spec": new_spec})
    log(f"detached {control} band-aid from {lb}")
    inventory.mark_retired(finding_id, lb)   # authoritative: the band-aid is off the LB
    # Sync the session's own progress track only if it actually holds this finding — never mint a
    # cross-session entry in a session that does not own it (ledger.mark_retired would setdefault one).
    if finding_id in ledger.load(out_dir):
        ledger.mark_retired(out_dir, finding_id)
    from . import audit
    audit.record(out_dir, "retire", finding_id=finding_id, control=control, lb=lb,
                 namespace=xc.ns, forced=force)
    return {"finding_id": finding_id, "status": "retired", "control": control, "lb": lb,
            "cure_pr": cure.get("pr_url")}


def retire_all(out_dir: str, *, force: bool = False, dry_run: bool = False,
               allow_protected: bool = False, log: Callable = print) -> list[dict]:
    """Retire every live band-aid whose cure PR merged (or all, with force) — across every session,
    since the inventory is global. Each finding is retired in the context of the session it was
    applied from (its audit trail), falling back to `out_dir` for a pre-split entry."""
    out = []
    for e in inventory.live().values():   # keyed by lb::finding_id — address each by its own lb
        mit = e.get("mitigation") or {}
        out.append(retire_finding(e.get("session") or out_dir, e.get("finding_id"), lb=mit.get("lb"),
                                  force=force, dry_run=dry_run, allow_protected=allow_protected, log=log))
    return out
