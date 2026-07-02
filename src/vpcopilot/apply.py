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

# A valid default Bot Defense policy (flag-only mitigation on all paths) — the exact shape XC
# requires (protected endpoint + flow-label choice + mitigation), taken from a live LB config.
# Used when apply_bot_defense is given no explicit policy.
_DEFAULT_BOT_POLICY = {
    "disable_mobile_sdk": {},
    "javascript_mode": "ASYNC_JS_NO_CACHING",
    "js_download_path": "/common.js",
    "js_insert_all_pages": {"javascript_location": "AFTER_HEAD"},
    "protected_app_endpoints": [{
        "metadata": {"name": "protect-all"},
        "any_domain": {}, "path": {"prefix": "/"},
        "http_methods": ["METHOD_ANY"], "protocol": "BOTH",
        "web": {}, "undefined_flow_label": {},
        "mitigation": {"flag": {"no_headers": {}}},
        "mitigate_good_bots": {},
    }],
}


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

    res = apply_service_policy(lb, policy_name, target_url, dry_run=dry_run, keep=keep,
                              allow_protected=allow_protected, retries=retries,
                              wait_seconds=wait_seconds, out_dir=out_dir, log=log)
    if res.get("kept"):
        from . import ledger
        fid = ledger.find_finding_for_policy(out_dir, policy_name)
        if fid:
            ledger.mark_mitigated(out_dir, fid, control="service_policy",
                                  policy_name=policy_name, lb=lb)
            log(f"ledger: {fid} -> mitigated (service_policy)")
    return res


def apply_malicious_user(lb: str, *, dry_run: bool = False, keep: bool = False,
                         allow_protected: bool = False, finding_id: str | None = None,
                         out_dir: str = "out", log: Callable = print) -> dict:
    """Enable XC Malicious-User Detection on the LB. This is a per-user BEHAVIORAL control
    set on the LB itself (a oneof: enable/disable), not a separate policy object. Validation
    is CONFIG-LEVEL (readback) — behavioral mitigation (flagging abusive users) builds over
    time from real attack traffic, so it is not single-request testable. Snapshot + PUT
    self-test + rollback, same safety spine as the service-policy path."""
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(
            f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-lb) or edit VPCOPILOT_PROTECTED_LBS to override."
        )
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    already = "enable_malicious_user_detection" in spec
    has_user_id = ("user_id_client_ip" in spec) or ("user_identification" in spec)
    log(f"snapshot saved · malicious-user detection currently "
        f"{'ENABLED' if already else 'disabled'} · user identification "
        f"{'set' if has_user_id else 'MISSING (will set user_id_client_ip)'}")
    diff = {"from": "enabled" if already else "disabled", "to": "enable_malicious_user_detection"}

    if dry_run:
        log(f"DRY-RUN — no mutation. would set: {diff}")
        return {"mode": "dry_run", "already_enabled": already, "user_id": has_user_id, "diff": diff}

    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(new_spec):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": new_spec})

    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok — GET->PUT round trip is safe")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_malicious_user_detection", None)
    new_spec["enable_malicious_user_detection"] = {}
    new_spec.setdefault("user_id_client_ip", {})  # per-user tracking needs a user identifier
    put_spec(new_spec)
    log("enabled malicious-user detection on the LB")

    def rollback():
        put_spec(copy.deepcopy(spec))
        after = xc.get_lb(lb).get("spec", {})
        log(f"rolled back · detection {'ENABLED' if 'enable_malicious_user_detection' in after else 'disabled'}")

    back = xc.get_lb(lb).get("spec", {})
    enabled = "enable_malicious_user_detection" in back
    log(f"validation (config readback) -> {'PASS' if enabled else 'FAIL'} (detection enabled={enabled})")
    log("note: behavioral mitigation flags abusive users over time from real attack traffic "
        "— not single-request testable")

    if enabled and keep:
        log("keeping malicious-user detection enabled (--keep)")
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="malicious_user",
                                  policy_name="(LB malicious-user detection)", lb=lb)
            log(f"ledger: {finding_id} -> mitigated (malicious_user)")
    else:
        rollback()
        rolled = True
    return {"mode": "apply_malicious_user", "diff": diff, "config_enabled": enabled,
            "validation": "config-level (readback)", "rolled_back": rolled, "kept": enabled and keep}


def apply_rate_limit(lb: str, *, requests: int = 100, unit: str = "MINUTE", burst: int = 1,
                     dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                     finding_id: str | None = None, out_dir: str = "out", log: Callable = print) -> dict:
    """Enable XC rate limiting on the LB (oneof: disable_rate_limit -> rate_limit). Config-level
    validation (readback) + snapshot + self-test + rollback + guardrails."""
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    already = "rate_limit" in spec
    diff = {"from": "enabled" if already else "disabled", "to": f"{requests}/{unit} (burst x{burst})"}
    log(f"snapshot saved · rate limiting currently {'ENABLED' if already else 'disabled'}")
    if dry_run:
        log(f"DRY-RUN — no mutation. would set: {diff}")
        return {"mode": "dry_run", "already_enabled": already, "diff": diff}

    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(s):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_rate_limit", None)
    new_spec["rate_limit"] = {
        "rate_limiter": {"total_number": requests, "unit": unit, "burst_multiplier": burst},
        "no_policies": {}, "no_ip_allowed_list": {},
    }
    put_spec(new_spec)
    log(f"enabled rate limiting ({requests}/{unit}, burst x{burst})")

    def rollback():
        put_spec(copy.deepcopy(spec))
        after = xc.get_lb(lb).get("spec", {})
        log(f"rolled back · rate limiting {'ENABLED' if 'rate_limit' in after else 'disabled'}")

    enabled = "rate_limit" in xc.get_lb(lb).get("spec", {})
    log(f"validation (config readback) -> {'PASS' if enabled else 'FAIL'} (rate_limit enabled={enabled})")
    if enabled and keep:
        log("keeping rate limiting enabled (--keep)")
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="rate_limit",
                                  policy_name=f"{requests}/{unit}", lb=lb)
    else:
        rollback()
        rolled = True
    return {"mode": "apply_rate_limit", "diff": diff, "config_enabled": enabled,
            "rolled_back": rolled, "kept": enabled and keep}


def apply_bot_defense(lb: str, *, policy: dict | None = None, regional_endpoint: str = "US",
                      dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                      finding_id: str | None = None, out_dir: str = "out", log: Callable = print) -> dict:
    """Enable XC Bot Defense on the LB (oneof: disable_bot_defense -> bot_defense). Needs the
    Bot Defense add-on on the tenant. Uses a default flag-only policy (all paths) if none is
    given; pass `policy` to override. Same safety spine (snapshot, self-test, rollback,
    guardrails); config-level validation (readback)."""
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    already = bool(spec.get("bot_defense"))  # disabled state may carry a null bot_defense key
    log(f"bot_defense currently {'ENABLED' if already else 'disabled'}")
    if dry_run:
        return {"mode": "dry_run", "already_enabled": already,
                "note": "will enable Bot Defense with a flag-only policy (all paths) unless a policy is given"}
    policy = policy or _DEFAULT_BOT_POLICY
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(s):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    try:
        put_spec(copy.deepcopy(spec))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_bot_defense", None)
    new_spec["bot_defense"] = {"regional_endpoint": regional_endpoint, "timeout": 1000,
                               "policy": policy, "enable_cors_support": {}}
    put_spec(new_spec)
    log("enabled bot_defense on the LB")

    def rollback():
        put_spec(copy.deepcopy(spec))
        log("rolled back bot_defense")

    enabled = bool(xc.get_lb(lb).get("spec", {}).get("bot_defense"))
    if enabled and keep:
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="bot_defense",
                                  policy_name="(LB bot defense)", lb=lb)
    else:
        rollback()
        rolled = True
    return {"mode": "apply_bot_defense", "config_enabled": enabled, "rolled_back": rolled,
            "kept": enabled and keep}


def apply_control(control: str, lb: str, **kw) -> dict:
    """A0 dispatcher: route an LB-setting control to its handler. (service_policy uses the
    create+attach path apply_from_scan / apply_service_policy, not this.)"""
    handlers = {
        "malicious_user": apply_malicious_user,
        "rate_limit": apply_rate_limit,
        "bot_defense": apply_bot_defense,
    }
    if control == "service_policy":
        raise RuntimeError("service_policy uses apply_from_scan / apply_service_policy")
    if control not in handlers:
        raise RuntimeError(f"apply not implemented for control '{control}'")
    return handlers[control](lb, **kw)
