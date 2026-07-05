"""C2 — retire a band-aid once its code-fix PR merges.

Closes the ledger loop found → mitigated → remediated → **retired**: when a finding's cure PR
is merged, detach its temporary XC control from the LB (the inverse of apply) and mark the ledger
retired, so a band-aid never silently outlives the real fix. `--force` retires without the merge
check (manual retire); the same protected-LB guardrail as apply applies."""
from __future__ import annotations

import copy
import re
from typing import Callable

from . import ledger
from .apply import META_KEYS, SP_ONEOF, _protected_lbs
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


def _detach_control(new_spec: dict, control: str) -> None:
    """Undo a control on an LB spec copy (inverse of the apply_* mutation)."""
    if control == "service_policy":
        for k in SP_ONEOF:
            new_spec.pop(k, None)
        new_spec["no_service_policies"] = {}
    elif control == "waf":
        new_spec.pop("app_firewall", None)
        new_spec["disable_waf"] = {}
    elif control == "waf_data_guard":
        new_spec["data_guard_rules"] = []  # leave the WAF; drop only the masking rules
    elif control == "rate_limit":
        new_spec.pop("rate_limit", None)
        new_spec["disable_rate_limit"] = {}
    elif control == "malicious_user":
        new_spec.pop("enable_malicious_user_detection", None)
        new_spec["disable_malicious_user_detection"] = {}
    elif control == "bot_defense":
        new_spec.pop("bot_defense", None)
        new_spec["disable_bot_defense"] = {}
    elif control == "api_schema":
        new_spec.pop("api_specification", None)
        new_spec["disable_api_definition"] = {}
    else:
        raise RuntimeError(f"don't know how to retire control '{control}'")


def retire_finding(out_dir: str, finding_id: str, *, force: bool = False, dry_run: bool = False,
                   allow_protected: bool = False, log: Callable = print) -> dict:
    e = ledger.load(out_dir).get(finding_id)
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
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    if dry_run:
        return {"finding_id": finding_id, "status": "would retire", "control": control, "lb": lb}

    xc = XC()
    lb_obj = xc.get_lb(lb)
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}
    new_spec = copy.deepcopy(lb_obj.get("spec", {}))
    _detach_control(new_spec, control)
    xc.put_lb(lb, {"metadata": base_meta, "spec": new_spec})
    log(f"detached {control} band-aid from {lb}")
    ledger.mark_retired(out_dir, finding_id)
    from . import audit
    audit.record(out_dir, "retire", finding_id=finding_id, control=control, lb=lb, forced=force)
    return {"finding_id": finding_id, "status": "retired", "control": control, "lb": lb,
            "cure_pr": cure.get("pr_url")}


def retire_all(out_dir: str, *, force: bool = False, dry_run: bool = False,
               allow_protected: bool = False, log: Callable = print) -> list[dict]:
    """Retire every mitigated finding whose cure PR merged (or all, with force)."""
    out = []
    for fid, e in ledger.load(out_dir).items():
        if e.get("mitigation") and e.get("state") in ("mitigated", "remediated"):
            out.append(retire_finding(out_dir, fid, force=force, dry_run=dry_run,
                                      allow_protected=allow_protected, log=log))
    return out
