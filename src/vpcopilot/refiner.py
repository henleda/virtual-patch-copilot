"""The validate → refine → retry loop: apply a policy, and if it doesn't actually block the
exploit (or it over-blocks legit traffic), diagnose + refine the spec + retry — up to max_refine.
A finding is only marked mitigated when a policy genuinely PASSED live validation; otherwise it
stays 'found' with an honest reason ('code fix required'). This is why the copilot never claims a
band-aid works when it doesn't."""
from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Callable

from . import audit, ledger
from .agents import refine as refine_agent
from .apply import (META_KEYS, PROTECTED_POLICIES, SP_ONEOF, _load_probe, _log_baseline,
                    _protected_lbs, _run_validation, lint_service_policy, normalize_service_policy_spec)
from .harness import Harness
from .probe import probe_negative_pay
from .schemas import Finding
from .xc import XC, XCError


def refine_attempts_default() -> int:
    try:
        return max(1, int(os.environ.get("VPCOPILOT_REFINE_ATTEMPTS", "3")))
    except ValueError:
        return 3


def _load_finding(out_dir: str, finding_id: str | None) -> Finding | None:
    p = Path(out_dir) / "findings.json"
    if finding_id and p.exists():
        for f in json.loads(p.read_text()):
            if f.get("id") == finding_id:
                return Finding(**f)
    return None


def _sim_threshold_default() -> float:
    from .simulate import DEFAULT_THRESHOLD
    try:
        return float(os.environ.get("VPCOPILOT_SIM_THRESHOLD", DEFAULT_THRESHOLD))
    except ValueError:
        return DEFAULT_THRESHOLD


def _resolve_records(records, log: Callable):
    """The sample the second gate measures against: an explicit list, else `VPCOPILOT_SIM_LOGS`.
    With neither there is no gate — fail-soft, because a missing or unreadable sample must never
    turn a working refine loop into a failure."""
    if records:
        return records
    path = (os.environ.get("VPCOPILOT_SIM_LOGS") or "").strip()
    if not path:
        return None
    try:
        from .traffic import load
        recs, _ = load(path)
        log(f"blast-radius gate: {len(recs)} record(s) from {path}")
        return recs or None
    except Exception as e:  # noqa: BLE001
        log(f"  ⚠ could not read the traffic sample at {path}: {e} — refining without the gate")
        return None


def refine_apply_service_policy(artifact_path: str, lb: str, target_url: str, *,
                                finding_id: str | None = None, name: str | None = None,
                                max_refine: int | None = None, keep: bool = False,
                                allow_protected: bool = False, config_path: str | None = None,
                                retries: int = 6, wait_seconds: int = 8,
                                records: list | None = None, sim_threshold: float | None = None,
                                force: bool = False, allow_overbroad: bool = False,
                                out_dir: str = "out", log: Callable = print) -> dict:
    """Create/attach a service policy, validate it live, and refine-until-it-works (or give up
    honestly). Returns passed + attempts + before/after; persists the WORKING spec to the artifact.

    G3 — with a traffic sample, "works" means two things, not one: the policy blocks the exploit
    **and** stays under the blast-radius threshold. Without that second gate a refinement that
    widens the policy far enough to catch the exploit has nothing telling it it went too far, and
    the loop happily accepts a rule that would deny production. An over-broad result is fed back as
    the `over_block` diagnosis the refine agent already understands.

    `records` (or `VPCOPILOT_SIM_LOGS`) supplies the sample. With neither, the second gate is
    skipped entirely and this behaves exactly as it did before G3.

    I2 — the same read-only pre-apply drift check `apply_from_scan` runs happens here too, because
    this (not `apply_from_scan`) is the default path for both the CLI's `--from-scan` and the
    console's Mitigate button. A guard the primary UX skips is not a guard. `force=True` bypasses
    it."""
    if lb in _protected_lbs() and not allow_protected:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    max_refine = max_refine or refine_attempts_default()

    art = json.loads(Path(artifact_path).read_text())
    spec = art["spec"] if isinstance(art.get("spec"), dict) and art["spec"] else art
    src_meta = art.get("metadata") or {}
    stem = Path(artifact_path).stem
    policy_name = name or src_meta.get("name") or (stem.split(".", 1)[1] if "." in stem else stem)
    if policy_name in PROTECTED_POLICIES:
        raise RuntimeError(f"refusing to create/overwrite protected policy '{policy_name}'")
    finding_id = finding_id or ledger.find_finding_for_policy(out_dir, policy_name)
    finding = _load_finding(out_dir, finding_id)
    probe = _load_probe(out_dir, finding_id)

    # G2 — this is the DEFAULT path for both the CLI's `--from-scan` and the console's Mitigate
    # button, so the blast-radius gate has to be here as well as in `apply_from_scan`; a guard the
    # primary UX skips is not a guard. Same reasoning as the drift preflight below.
    #
    # BEFORE `XC()`, and CI is what proved that matters. Every refusal above this line is a pure disk
    # read, but `XC.__init__` raises when `XC_API_URL`/`XC_API_TOKEN` are unset — so constructing the
    # client first meant an over-broad policy was refused for the wrong reason on any machine without
    # tenant credentials, which is every CI runner. The cheap, credential-free refusals belong first:
    # an over-broad policy should be refused whether or not a tenant is reachable.
    from .simulate import promotion_gate
    promotion_gate(out_dir, policy_name, allow_overbroad=allow_overbroad,
                   finding_id=finding_id, lb=lb, log=log)

    xc = XC()
    from .drift import preflight
    d = preflight(lb, policy_name, out_dir=out_dir, force=force, xc=xc, log=log, spec=spec,
                  exploit=(probe or {}).get("exploit"), refine=True)
    if d is not None:
        return {"passed": None, "mode": "no_change", "policy": policy_name, "attempts": 0,
                "drift": d}

    lb_obj = xc.get_lb(lb)
    orig_spec = lb_obj.get("spec", {})
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    def _put_lb(s):
        xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    def attach():
        ns = copy.deepcopy(orig_spec)
        for k in SP_ONEOF:
            ns.pop(k, None)
        ns["active_service_policies"] = {"policies": [{"namespace": xc.ns, "name": policy_name}]}
        _put_lb(ns)

    def detach():
        _put_lb(copy.deepcopy(orig_spec))

    records = _resolve_records(records, log)
    threshold = sim_threshold if sim_threshold is not None else _sim_threshold_default()

    h = Harness(config_path) if finding else None
    exploit = (probe or {}).get("exploit")
    before = _run_validation(target_url, finding_id, out_dir, probe_negative_pay, log)
    _log_baseline(before, log)
    spec = normalize_service_policy_spec(spec)
    diagnosis, result = "exploit_not_blocked", before

    for attempt in range(1, max_refine + 1):
        # A3: deterministic lint BEFORE any LB touch — if the policy can't possibly block the
        # exploit (bad rule order / path mismatch), refine offline instead of wasting a live cycle.
        lint = lint_service_policy(spec, exploit)
        if lint and attempt < max_refine and h and finding:
            log(f"attempt {attempt}/{max_refine}: pre-apply lint — {'; '.join(lint)}; refining before attach")
            refined = refine_agent.run(h, finding, "service_policy", spec, probe,
                                       {"exploit_status": None, "exploit_blocked": False,
                                        "legit_ok": True, "lint": lint}, "exploit_not_blocked")
            log(f"  refined (lint): {refined.rationale}" + (" [UNFIXABLE]" if refined.unfixable else ""))
            if refined.unfixable:
                detach()
                audit.record(out_dir, "refine_apply", finding_id=finding_id, namespace=xc.ns, control="service_policy", policy=policy_name,
                             lb=lb, passed=False, attempts=attempt, unfixable=True, recommend=refined.recommend)
                return {"mode": "refine_apply", "control": "service_policy", "policy": policy_name,
                        "passed": False, "attempts": attempt, "unfixable": True,
                        "recommend": refined.recommend, "reason": f"lint: {'; '.join(lint)}",
                        "before_after": {"before": before, "after": before}}
            spec = normalize_service_policy_spec(refined.spec)
            continue

        body = {"metadata": {"name": policy_name, "namespace": xc.ns}, "spec": spec}
        try:
            if xc.service_policy_exists(policy_name):
                xc.put_service_policy(policy_name, body)   # update with the refined spec
            else:
                xc.create_service_policy(body)
            attach()
        except XCError as e:  # XC rejected the spec itself (bad field shape / missing required key) —
            diagnosis = "xc_rejected"                       # self-heal via the refiner, don't crash
            log(f"attempt {attempt}/{max_refine}: XC rejected the policy spec — {e}")
            if attempt == max_refine or not (h and finding):
                break
            refined = refine_agent.run(h, finding, "service_policy", spec, probe,
                                       {"xc_error": str(e), "exploit_status": None,
                                        "exploit_blocked": False, "legit_ok": True}, "xc_rejected")
            log(f"  refined (xc-rejected): {refined.rationale}" + (" [UNFIXABLE]" if refined.unfixable else ""))
            if refined.unfixable:
                audit.record(out_dir, "refine_apply", finding_id=finding_id, namespace=xc.ns, control="service_policy", policy=policy_name, lb=lb,
                             passed=False, attempts=attempt, unfixable=True, recommend=refined.recommend)
                return {"mode": "refine_apply", "control": "service_policy", "policy": policy_name,
                        "passed": False, "attempts": attempt, "unfixable": True,
                        "recommend": refined.recommend, "reason": f"xc_rejected; {refined.rationale}",
                        "before_after": {"before": before, "after": before}}
            spec = normalize_service_policy_spec(refined.spec)
            continue
        log(f"attempt {attempt}/{max_refine}: attached '{policy_name}' — validating…")

        result = None
        for _ in range(retries):
            time.sleep(wait_seconds)
            result = _run_validation(target_url, finding_id, out_dir, probe_negative_pay, log)
            if result["exploit_blocked"] and result["legit_ok"]:
                break

        blast = None
        if result["exploit_blocked"] and result["legit_ok"] and records:
            # The policy is attached and confirmed enforcing right now — measure it here rather
            # than paying a second attach + propagation wait on another LB.
            from .simulate import measure_attached
            blast = measure_attached(records, target_url, policy_name=policy_name,
                                     finding_id=finding_id or "", threshold=threshold, log=log)
            log(f"  blast radius: would block {blast['would_block']}/{blast['evaluated']} "
                f"recorded request(s) ({blast['block_rate']:.1%})")

        if result["exploit_blocked"] and result["legit_ok"] and not (blast and blast["blocked_promotion"]):
            log(f"validation PASS on attempt {attempt} ✓")
            Path(artifact_path).write_text(json.dumps({"metadata": {"name": policy_name}, "spec": spec}, indent=2))
            rolled = False
            if keep and finding_id:
                ledger.mark_mitigated(out_dir, finding_id, control="service_policy", policy_name=policy_name, lb=lb)
            if not keep:
                detach()
                rolled = True
            audit.record(out_dir, "refine_apply", finding_id=finding_id, namespace=xc.ns, control="service_policy", policy=policy_name, lb=lb,
                         passed=True, attempts=attempt, rolled_back=rolled,
                         before_after={"before": before, "after": result}, blast_radius=blast)
            out = {"mode": "refine_apply", "control": "service_policy", "policy": policy_name,
                   "passed": True, "attempts": attempt, "rolled_back": rolled, "kept": keep,
                   "before_after": {"before": before, "after": result}}
            if blast:
                out["blast_radius"] = blast
            return out

        # failed this attempt — detach, diagnose, refine
        detach()
        agent_result = result
        if blast and blast["blocked_promotion"]:
            diagnosis = "over_block"
            agent_result = {**result, "blast_radius": blast}
            log(f"attempt {attempt}: FAIL (over_block — {blast['reason']})")
        else:
            diagnosis = "exploit_not_blocked" if not result["exploit_blocked"] else "over_block"
            log(f"attempt {attempt}: FAIL ({diagnosis}, exploit_status={result['exploit_status']})")
        if attempt == max_refine or not (h and finding):
            break
        refined = refine_agent.run(h, finding, "service_policy", spec, probe, agent_result, diagnosis)
        log(f"  refined: {refined.rationale}" + (" [UNFIXABLE]" if refined.unfixable else ""))
        if refined.unfixable:
            audit.record(out_dir, "refine_apply", finding_id=finding_id, namespace=xc.ns, control="service_policy", policy=policy_name, lb=lb,
                         passed=False, attempts=attempt, unfixable=True, recommend=refined.recommend)
            return {"mode": "refine_apply", "control": "service_policy", "policy": policy_name,
                    "passed": False, "attempts": attempt, "unfixable": True, "recommend": refined.recommend,
                    "reason": f"{diagnosis}; {refined.rationale}",
                    "before_after": {"before": before, "after": result}}
        spec = normalize_service_policy_spec(refined.spec)

    detach()
    reason = f"no working policy after {max_refine} attempt(s) ({diagnosis}) — code fix required"
    audit.record(out_dir, "refine_apply", finding_id=finding_id, namespace=xc.ns, control="service_policy", policy=policy_name, lb=lb,
                 passed=False, attempts=max_refine, reason=reason)
    return {"mode": "refine_apply", "control": "service_policy", "policy": policy_name,
            "passed": False, "attempts": max_refine, "reason": reason,
            "before_after": {"before": before, "after": result}}
