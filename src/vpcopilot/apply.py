"""Gated apply of a service-policy band-aid to a live LB, with snapshot, an idempotent
PUT self-test, validation on the live LB, and auto-rollback. The deterministic 'hands' —
agents never call this; it runs only after human approval."""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Callable

from .probe import probe_negative_pay
from .xc import XC

# The LB's service-policy choice is a oneof; snapshot/restore must handle whichever is set.
SP_ONEOF = ("no_service_policies", "active_service_policies", "service_policies_from_namespace")
META_KEYS = ("name", "namespace", "labels", "annotations", "description", "disable")


def _sp_block(spec: dict) -> dict:
    return {k: spec[k] for k in SP_ONEOF if k in spec}


def apply_service_policy(lb: str, policy_name: str, target_url: str, *,
                         dry_run: bool = False, keep: bool = False,
                         retries: int = 8, wait_seconds: int = 8,
                         out_dir: str = "out", log: Callable = print) -> dict:
    xc = XC()
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    snap_sp = _sp_block(spec)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    log(f"snapshot saved · current LB service-policy = {list(snap_sp) or ['(none set)']}")

    if not xc.service_policy_exists(policy_name):
        raise RuntimeError(f"service policy '{policy_name}' not found in namespace {xc.ns}")
    log(f"policy '{policy_name}' present in {xc.ns}")

    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(new_spec: dict):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": new_spec})

    # diff we would apply
    diff = {"from": list(snap_sp) or ["(none set)"],
            "to": f"active_service_policies: {policy_name}"}

    if dry_run:
        res = probe_negative_pay(target_url, log=log)
        log(f"DRY-RUN — no mutation. would attach: {diff}")
        return {"mode": "dry_run", "snapshot_sp": list(snap_sp), "diff": diff,
                "probe_current": res}

    # --- idempotent PUT self-test: prove GET->PUT round-trips before changing anything ---
    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok — GET->PUT round trip is safe")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    # --- attach ---
    new_spec = copy.deepcopy(spec)
    for k in SP_ONEOF:
        new_spec.pop(k, None)
    new_spec["active_service_policies"] = {"policies": [{"namespace": xc.ns, "name": policy_name}]}
    put_spec(new_spec)
    log(f"attached '{policy_name}' to {lb}")

    def rollback():
        put_spec(copy.deepcopy(spec))  # restore the full original spec verbatim
        after = _sp_block(xc.get_lb(lb).get("spec", {}))
        log(f"rolled back · LB service-policy = {list(after) or ['(none set)']}")

    # --- validate on the live LB, polling for config->edge propagation ---
    res = None
    for attempt in range(1, retries + 1):
        time.sleep(wait_seconds)
        try:
            res = probe_negative_pay(target_url, log=log)
        except Exception as e:  # noqa: BLE001
            rollback()
            raise RuntimeError(f"validation error; rolled back: {e}")
        if res["neg_blocked"] and res["legit_ok"]:
            break
        log(f"  attempt {attempt}/{retries}: not enforced yet — waiting for propagation")

    passed = bool(res and res["neg_blocked"] and res["legit_ok"])
    log(f"validation -> {'PASS' if passed else 'FAIL'} "
        f"(neg_blocked={res['neg_blocked']} legit_ok={res['legit_ok']})")

    if passed and keep:
        log("validation passed · keeping policy attached (--keep)")
        rolled = False
    else:
        rollback()
        rolled = True
    return {"mode": "apply", "diff": diff, "validation": res, "passed": passed,
            "rolled_back": rolled, "kept": passed and keep}
