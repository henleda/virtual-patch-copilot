"""Gated apply of a service-policy band-aid to a live LB, with snapshot, an idempotent
PUT self-test, validation on the live LB, and auto-rollback. The deterministic 'hands' —
agents never call this; it runs only after human approval."""
from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Callable

from .probe import probe_negative_pay
from .xc import XC

# The LB's service-policy choice is a oneof; snapshot/restore must handle whichever is set.
SP_ONEOF = ("no_service_policies", "active_service_policies", "service_policies_from_namespace")
META_KEYS = ("name", "namespace", "labels", "annotations", "description", "disable")

# Guardrails: never create/overwrite/delete these policies, and never mutate these LBs
# without an explicit override. Protects live demo objects from accidental changes.
PROTECTED_POLICIES = {
    "nimbus-bizlogic-policy", "nimbus-evasion-policy", "nimbus-evasion-policy-allowlist",
}


def _protected_lbs() -> set[str]:
    return {s.strip() for s in os.environ.get("VPCOPILOT_PROTECTED_LBS", "nimbus-www").split(",") if s.strip()}


def _sp_block(spec: dict) -> dict:
    return {k: spec[k] for k in SP_ONEOF if k in spec}


# Full per-rule field set XC's create API requires (from the validated demo policy). The
# generate agent emits only the semantic fields (action/path/method/matchers); this fills
# the rest with safe defaults so the object validates. LLM decides WHAT; code guarantees VALID.
_RULE_DEFAULTS = {
    "action": "DENY",
    "any_client": {},
    "label_matcher": {"keys": []},
    "path": {"prefix_values": ["/"], "exact_values": [], "regex_values": [], "suffix_values": [], "transformers": [], "invert_matcher": False},
    "headers": [],
    "query_params": [],
    "http_method": {"methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], "invert_matcher": False},
    "any_ip": {}, "any_asn": {},
    "additional_api_group_matchers": [],
    "body_matcher": {"exact_values": [], "regex_values": [], "transformers": []},
    "arg_matchers": [], "cookie_matchers": [],
    "waf_action": {"none": {}},
    "domain_matcher": {"exact_values": [], "regex_values": [], "transformers": []},
    "rate_limiter": [], "forwarding_class": [], "scheme": [],
    "challenge_action": "DEFAULT_CHALLENGE",
    "bot_action": {"none": {}},
    "mum_action": {"default": {}},
    "user_identity_matcher": {"exact_values": [], "regex_values": []},
    "segment_policy": {"src_any": {}},
    "origin_server_subsets_action": {},
    "jwt_claims": [],
}
_NESTED = ("path", "http_method", "body_matcher", "domain_matcher", "label_matcher", "user_identity_matcher")


def normalize_service_policy_spec(spec: dict) -> dict:
    """Fill the required XC fields a minimal generated service-policy spec omits."""
    spec = copy.deepcopy(spec)
    spec.setdefault("algo", "FIRST_MATCH")
    spec.setdefault("any_server", {})
    rules = spec.setdefault("rule_list", {}).setdefault("rules", [])
    for i, r in enumerate(rules):
        meta = r.setdefault("metadata", {})
        meta.setdefault("name", f"rule-{i + 1}")
        meta.setdefault("disable", False)
        rs = r.get("spec", {})
        merged = {**_RULE_DEFAULTS, **rs}
        for key in _NESTED:  # nested-merge matchers so partial values keep required sub-keys
            if isinstance(rs.get(key), dict):
                merged[key] = {**_RULE_DEFAULTS[key], **rs[key]}
        r["spec"] = merged
    return spec


def apply_service_policy(lb: str, policy_name: str, target_url: str, *,
                         dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                         retries: int = 8, wait_seconds: int = 8,
                         out_dir: str = "out", log: Callable = print) -> dict:
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(
            f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-lb) or edit VPCOPILOT_PROTECTED_LBS to override."
        )
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


def apply_from_scan(artifact_path: str, lb: str, target_url: str, *, name: str | None = None,
                    create_only: bool = False, dry_run: bool = False, keep: bool = False,
                    allow_protected: bool = False, retries: int = 8, wait_seconds: int = 8,
                    out_dir: str = "out", log: Callable = print) -> dict:
    """End-to-end from a generated artifact: create the policy in XC (if missing), then
    attach -> validate -> rollback via apply_service_policy. Guarded against clobbering a
    protected policy."""
    xc = XC()
    art = json.loads(Path(artifact_path).read_text())
    # Normalize to an XC create body: {metadata:{name,namespace,...}, spec:{...}}.
    # Generated artifacts vary — some are full {metadata, spec} objects, some a bare spec.
    if isinstance(art.get("spec"), dict) and art["spec"]:
        spec, src_meta = art["spec"], (art.get("metadata") or {})
    else:
        spec, src_meta = art, {}
    spec = normalize_service_policy_spec(spec)  # fill required XC fields
    fname = Path(artifact_path).stem
    fname = fname.split(".", 1)[1] if "." in fname else fname  # drop the "<control>." prefix
    policy_name = name or src_meta.get("name") or fname
    if not policy_name:
        raise RuntimeError(f"no policy name for {artifact_path}; pass name=...")
    if policy_name in PROTECTED_POLICIES:
        raise RuntimeError(f"refusing to create/overwrite protected policy '{policy_name}'")
    body = {"metadata": {"name": policy_name, "namespace": xc.ns}, "spec": spec}
    for k in ("labels", "annotations", "description", "disable"):
        if src_meta.get(k) is not None:
            body["metadata"][k] = src_meta[k]

    if xc.service_policy_exists(policy_name):
        log(f"policy '{policy_name}' already exists — not overwriting")
    elif dry_run:
        log(f"[dry-run] would create service policy '{policy_name}'")
    else:
        xc.create_service_policy(body)
        log(f"created service policy '{policy_name}'")

    if create_only:
        return {"mode": "create_only", "policy": policy_name, "created": not dry_run}

    return apply_service_policy(lb, policy_name, target_url, dry_run=dry_run, keep=keep,
                               allow_protected=allow_protected, retries=retries,
                               wait_seconds=wait_seconds, out_dir=out_dir, log=log)
