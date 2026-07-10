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

from .probe import normalize, probe_negative_pay
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


def lint_service_policy(spec: dict, exploit: dict | None) -> list[str]:
    """Deterministic pre-apply lint — catch a service_policy that won't actually block the exploit,
    BEFORE any live LB round-trip. Under FIRST_MATCH the FIRST rule whose path+method match the
    exploit decides its fate; if that's an ALLOW (a bad rule order, or a DENY whose path is a wrong
    guess so an allow-all catches the exploit first), the exploit sails through. Returns issue
    strings ([] = looks correct)."""
    import re
    rules = (spec.get("rule_list") or {}).get("rules") or []
    if not any((r.get("spec") or {}).get("action") == "DENY" for r in rules):
        return ["no DENY rule"]
    if not exploit:
        return []
    path = exploit.get("path", "") or ""
    method = (exploit.get("method") or "GET").upper()

    def _matches(rs: dict) -> bool:
        p = rs.get("path") or {}
        ok = any(path == v or path.startswith(v)
                 for v in (p.get("prefix_values") or []) + (p.get("exact_values") or []))
        for rx in (p.get("regex_values") or []):
            try:
                if re.search(rx, path):
                    ok = True
            except re.error:
                pass
        methods = [m.upper() for m in ((rs.get("http_method") or {}).get("methods") or [])]
        return ok and (not methods or method in methods)

    for r in rules:  # FIRST_MATCH: the first path+method match decides
        rs = r.get("spec") or {}
        if _matches(rs):
            if rs.get("action") == "ALLOW":
                return [f"an ALLOW rule matches the exploit {method} {path} before any DENY — "
                        "FIRST_MATCH lets it through (fix the rule order or the DENY path)"]
            return []  # first match is a DENY — good
    return []  # no rule matches → XC default-denies the exploit — fine


def _load_probe(out_dir: str, finding_id) -> dict | None:
    """A finding's derived ExploitProbe (dict) from the scan's probes.json, if present."""
    if not finding_id:
        return None
    p = Path(out_dir) / "probes.json"
    if not p.exists():
        return None
    for pr in json.loads(p.read_text()):
        if pr.get("finding_id") == finding_id:
            return pr
    return None


def _run_validation(target_url: str, finding_id, out_dir: str, fallback, log) -> dict:
    """Normalized {exploit_status, exploit_blocked, legit_ok}. Prefers the finding's derived probe
    (works on any app); falls back to the Nimbus-specific probe when none exists (demo stays green)."""
    from .probe import probe_from_spec
    spec = _load_probe(out_dir, finding_id)
    if spec:
        return probe_from_spec(target_url, spec, log=log)
    return normalize(fallback(target_url, log=log))


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

    from . import ledger as _ledger
    fid = _ledger.find_finding_for_policy(out_dir, policy_name)
    exists = xc.service_policy_exists(policy_name)
    if not exists and not dry_run:  # a from-scan policy is created on the live apply, not in dry-run
        raise RuntimeError(f"service policy '{policy_name}' not found in namespace {xc.ns}")
    log(f"policy '{policy_name}' {'present' if exists else 'not yet created (dry-run preview)'} in {xc.ns}")

    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(new_spec: dict):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": new_spec})

    # diff we would apply
    diff = {"from": list(snap_sp) or ["(none set)"],
            "to": f"active_service_policies: {policy_name}"}

    if dry_run:
        res = _run_validation(target_url, fid, out_dir, probe_negative_pay, log)
        log(f"DRY-RUN — no mutation. would attach: {diff}")
        return {"mode": "dry_run", "snapshot_sp": list(snap_sp), "diff": diff,
                "probe_current": res}

    # --- idempotent PUT self-test: prove GET->PUT round-trips before changing anything ---
    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok — GET->PUT round trip is safe")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    # E4 baseline: fire the exploit BEFORE attaching, to capture before/after impact (fid computed above)
    before = _run_validation(target_url, fid, out_dir, probe_negative_pay, log)
    log(f"baseline (before): exploit {'blocked' if before['exploit_blocked'] else 'ALLOWED'} "
        f"(status {before['exploit_status']})")

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
            res = _run_validation(target_url, fid, out_dir, probe_negative_pay, log)
        except Exception as e:  # noqa: BLE001
            rollback()
            raise RuntimeError(f"validation error; rolled back: {e}")
        if res["exploit_blocked"] and res["legit_ok"]:
            break
        log(f"  attempt {attempt}/{retries}: not enforced yet — waiting for propagation")

    passed = bool(res and res["exploit_blocked"] and res["legit_ok"])
    log(f"validation -> {'PASS' if passed else 'FAIL'} "
        f"(exploit_blocked={res['exploit_blocked']} legit_ok={res['legit_ok']})")

    if passed and keep:
        log("validation passed · keeping policy attached (--keep)")
        rolled = False
    else:
        rollback()
        rolled = True
    before_after = {"before": before, "after": res}
    from . import audit
    audit.record(out_dir, "apply_service_policy", lb=lb, policy=policy_name, passed=passed,
                 rolled_back=rolled, kept=(passed and keep), before_after=before_after)
    return {"mode": "apply", "diff": diff, "validation": res, "before_after": before_after,
            "passed": passed, "rolled_back": rolled, "kept": passed and keep}


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
        from . import audit
        audit.record(out_dir, "create_service_policy", policy=policy_name, namespace=xc.ns)

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
    from . import audit
    audit.record(out_dir, "apply_malicious_user", lb=lb, enabled=enabled, rolled_back=rolled,
                 kept=(enabled and keep))
    return {"mode": "apply_malicious_user", "diff": diff, "config_enabled": enabled,
            "validation": "config-level (readback)", "rolled_back": rolled, "kept": enabled and keep}


def apply_rate_limit(lb: str, *, requests: int = 100, unit: str = "MINUTE", burst: int = 1,
                     behavioral: bool = False, target_url: str = "https://lab.banknimbus.com",
                     behavioral_path: str = "/login", wait_seconds: int = 8,
                     dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                     finding_id: str | None = None, out_dir: str = "out", log: Callable = print) -> dict:
    """Enable XC rate limiting on the LB (oneof: disable_rate_limit -> rate_limit). Config-level
    validation (readback) + snapshot + self-test + rollback + guardrails. With behavioral=True
    (B3), also drive a burst above the limit and confirm the excess is rate-limited (429), proving
    the control mitigates real traffic rather than just being configured."""
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

    # B3 behavioral validation: drive a burst above the limit and confirm the excess is 429'd
    behavioral_res = None
    passed = enabled
    if behavioral and enabled:
        from .probe import probe_rate_limit
        time.sleep(wait_seconds)  # let the limit propagate to the edge
        burst = max(requests * 3, 30)
        behavioral_res = probe_rate_limit(target_url, count=burst, path=behavioral_path, log=log)
        behaved = behavioral_res["limited"] > 0
        passed = enabled and behaved
        log(f"behavioral validation -> {'PASS' if behaved else 'FAIL'} "
            f"({behavioral_res['limited']}/{burst} requests rate-limited)")

    if passed and keep:
        log("keeping rate limiting enabled (--keep)")
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="rate_limit",
                                  policy_name=f"{requests}/{unit}", lb=lb)
    else:
        rollback()
        rolled = True
    from . import audit
    audit.record(out_dir, "apply_rate_limit", lb=lb, enabled=enabled, passed=passed, rolled_back=rolled,
                 kept=(passed and keep), rate=f"{requests}/{unit}", behavioral=behavioral_res)
    return {"mode": "apply_rate_limit", "diff": diff, "config_enabled": enabled,
            "behavioral": behavioral_res, "passed": passed, "rolled_back": rolled,
            "kept": passed and keep}


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
    from . import audit
    audit.record(out_dir, "apply_bot_defense", lb=lb, enabled=enabled, rolled_back=rolled,
                 kept=(enabled and keep))
    return {"mode": "apply_bot_defense", "config_enabled": enabled, "rolled_back": rolled,
            "kept": enabled and keep}


def _ensure_blocking_waf(xc, app_firewall: str, template: str, out_dir: str, log: Callable) -> None:
    """Create a Blocking app_firewall (cloned from `template`) if `app_firewall` is missing."""
    if xc.app_firewall_exists(app_firewall):
        return
    tspec = copy.deepcopy(xc.get_app_firewall(template)["spec"])
    tspec.pop("monitoring", None)
    tspec["blocking"] = {}
    xc.create_app_firewall({"metadata": {"name": app_firewall, "namespace": xc.ns}, "spec": tspec})
    log(f"created Blocking app_firewall '{app_firewall}'")
    from . import audit
    audit.record(out_dir, "create_app_firewall", name=app_firewall, mode="blocking")


def _waf_ref(xc, lb_obj: dict, app_firewall: str) -> dict:
    """Fully-qualified app_firewall ref (name+namespace+tenant); XC needs the tenant to enforce."""
    ref = {"namespace": xc.ns, "name": app_firewall}
    tenant = lb_obj.get("system_metadata", {}).get("tenant")
    if tenant:
        ref["tenant"] = tenant
    return ref


def apply_waf(lb: str, *, app_firewall: str = "vpcopilot-lab-waf", template: str = "nimbus-waf",
              target_url: str = "https://lab.banknimbus.com", dry_run: bool = False, keep: bool = False,
              allow_protected: bool = False, finding_id: str | None = None,
              retries: int = 8, wait_seconds: int = 8, out_dir: str = "out", log: Callable = print) -> dict:
    """Enable WAF (App Firewall) BLOCKING on the LB. Creates a Blocking app_firewall (cloned
    from `template`) if `app_firewall` doesn't exist, attaches it, validates by firing a SQLi
    (expect blocked) + a legit login (expect pass), and rolls back on failure/default."""
    from .probe import probe_sqli
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    if not xc.app_firewall_exists(app_firewall):
        if dry_run:
            log(f"[dry-run] would create Blocking app_firewall '{app_firewall}' from '{template}'")
        else:
            _ensure_blocking_waf(xc, app_firewall, template, out_dir, log)

    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    already = bool(spec.get("app_firewall"))
    diff = {"from": "on" if already else "off", "to": f"app_firewall:{app_firewall}"}
    log(f"snapshot saved · WAF currently {'ON' if already else 'off'}")
    if dry_run:
        return {"mode": "dry_run", "already_on": already, "diff": diff}

    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(s):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    before = _run_validation(target_url, finding_id, out_dir, probe_sqli, log)  # E4 baseline
    log(f"baseline (before): exploit {'blocked' if before['exploit_blocked'] else 'ALLOWED'} "
        f"(status {before['exploit_status']})")

    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_waf", None)  # WAF is a oneof: disable_waf vs app_firewall
    new_spec["app_firewall"] = _waf_ref(xc, lb_obj, app_firewall)
    put_spec(new_spec)
    log(f"attached WAF '{app_firewall}' to {lb}")

    def rollback():
        put_spec(copy.deepcopy(spec))
        after = xc.get_lb(lb).get("spec", {})
        log(f"rolled back · WAF {'ON' if after.get('app_firewall') else 'off'}")

    res = None
    for attempt in range(1, retries + 1):
        time.sleep(wait_seconds)
        try:
            res = _run_validation(target_url, finding_id, out_dir, probe_sqli, log)
        except Exception as e:  # noqa: BLE001
            rollback()
            raise RuntimeError(f"validation error; rolled back: {e}")
        if res["exploit_blocked"] and res["legit_ok"]:
            break
        log(f"  attempt {attempt}/{retries}: WAF not enforcing yet — waiting for propagation")

    passed = bool(res and res["exploit_blocked"] and res["legit_ok"])
    log(f"validation -> {'PASS' if passed else 'FAIL'} (exploit_blocked={res['exploit_blocked']} legit_ok={res['legit_ok']})")
    if passed and keep:
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="waf", policy_name=app_firewall, lb=lb)
    else:
        rollback()
        rolled = True
    before_after = {"before": before, "after": res}
    from . import audit
    audit.record(out_dir, "apply_waf", lb=lb, app_firewall=app_firewall, passed=passed,
                 rolled_back=rolled, before_after=before_after)
    return {"mode": "apply_waf", "diff": diff, "before_after": before_after, "passed": passed,
            "rolled_back": rolled, "kept": passed and keep}


def apply_data_guard(lb: str, *, app_firewall: str = "vpcopilot-lab-waf", template: str = "nimbus-waf",
                     dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                     finding_id: str | None = None, out_dir: str = "out", log: Callable = print) -> dict:
    """Enable WAF Data Guard on the LB — mask structured secrets (CCN/SSN/token) in responses on
    all paths. Data Guard is a WAF feature (XC rejects it when WAF is disabled), so this also
    ensures a Blocking WAF is attached. Config-level validation (readback)."""
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    already = bool(spec.get("data_guard_rules"))
    if dry_run:
        return {"mode": "dry_run", "already_on": already,
                "to": "WAF (blocking) + data_guard_rules: mask all paths"}
    if not xc.app_firewall_exists(app_firewall):
        _ensure_blocking_waf(xc, app_firewall, template, out_dir, log)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(s):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    try:
        put_spec(copy.deepcopy(spec))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_waf", None)  # Data Guard requires WAF enabled
    new_spec["app_firewall"] = _waf_ref(xc, lb_obj, app_firewall)
    new_spec["data_guard_rules"] = [{
        "metadata": {"name": "mask-sensitive"}, "any_domain": {},
        "path": {"prefix": "/"}, "apply_data_guard": {},
    }]
    put_spec(new_spec)
    log("enabled WAF + Data Guard (mask sensitive data in responses)")

    def rollback():
        put_spec(copy.deepcopy(spec))
        log("rolled back Data Guard")

    after = xc.get_lb(lb).get("spec", {})
    enabled = bool(after.get("data_guard_rules")) and bool(after.get("app_firewall"))
    log(f"validation (config readback) -> {'PASS' if enabled else 'FAIL'}")
    if enabled and keep:
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="waf_data_guard", policy_name="data-guard", lb=lb)
    else:
        rollback()
        rolled = True
    from . import audit
    audit.record(out_dir, "apply_data_guard", lb=lb, enabled=enabled, rolled_back=rolled)
    return {"mode": "apply_data_guard", "config_enabled": enabled, "rolled_back": rolled,
            "kept": enabled and keep}


_DEFAULT_OPENAPI = {
    "openapi": "3.0.1",
    "info": {"title": "Nimbus API", "version": "1.0"},
    "paths": {"/api/pay": {"post": {
        "requestBody": {"required": True, "content": {"application/json": {"schema": {
            "type": "object",
            "required": ["from_account", "to_account_number", "amount"],
            "properties": {
                "from_account": {"type": "integer"},
                "to_account_number": {"type": "string"},
                # OpenAPI 3.0.x: exclusiveMinimum is a boolean paired with minimum (amount > 0)
                "amount": {"type": "number", "minimum": 0, "exclusiveMinimum": True},
            },
        }}}},
        "responses": {"200": {"description": "ok"}},
    }}},
}


def apply_api_schema(lb: str, *, openapi: dict | None = None, swagger_name: str | None = None,
                     apidef_name: str | None = None, target_url: str = "https://lab.banknimbus.com",
                     dry_run: bool = False, keep: bool = False, allow_protected: bool = False,
                     finding_id: str | None = None, retries: int = 10, wait_seconds: int = 8,
                     out_dir: str = "out", log: Callable = print) -> dict:
    """Enable XC OpenAPI request-schema validation (block mode) on the LB: upload the OpenAPI to the
    object store -> create an api_definition -> attach api_specification with
    validation_all_spec_endpoints(enforcement_block). Validate that a negative-amount payment is
    blocked as a schema violation while a legit payment passes; roll back on failure/default."""
    from .probe import normalize, probe_negative_pay
    xc = XC()
    if lb in _protected_lbs() and not allow_protected and not dry_run:
        raise RuntimeError(f"refusing to mutate protected LB '{lb}'. Pass allow_protected=True to override.")
    openapi = openapi or _DEFAULT_OPENAPI
    swagger_name = swagger_name or f"{lb}-swagger"   # per-LB objects so apps don't collide
    apidef_name = apidef_name or f"{lb}-apidef"
    lb_obj = xc.get_lb(lb)
    spec = lb_obj.get("spec", {})
    already = bool(spec.get("api_specification"))
    if dry_run:
        return {"mode": "dry_run", "already_on": already,
                "to": f"api_specification(validation block) via {apidef_name}"}

    # 1. upload OpenAPI to the object store; 2. create/replace the api_definition
    url = xc.put_swagger(swagger_name, openapi)
    log(f"uploaded OpenAPI -> …/{url.rsplit('/', 1)[-1]}")
    if xc.api_definition_exists(apidef_name):
        xc.delete_api_definition(apidef_name)
    xc.create_api_definition({"metadata": {"name": apidef_name, "namespace": xc.ns},
                              "spec": {"swagger_specs": [url], "default_api_groups_builders": [{
                                  "metadata": {"name": "all-operations", "disable": False},
                                  "path_filter": ".*", "label_filter": {"expressions": ["path"]},
                                  "included_operations": [], "excluded_operations": []}]}})
    log(f"created api_definition '{apidef_name}'")
    from . import audit
    audit.record(out_dir, "create_api_definition", name=apidef_name, swagger=swagger_name)

    # 3. snapshot + attach the validation-block api_specification
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(out_dir, "lb_snapshot.json").write_text(json.dumps(lb_obj, indent=2))
    base_meta = {k: lb_obj["metadata"][k] for k in META_KEYS if k in lb_obj.get("metadata", {})}

    def put_spec(s):
        return xc.put_lb(lb, {"metadata": base_meta, "spec": s})

    try:
        put_spec(copy.deepcopy(spec))
        log("PUT self-test (idempotent) ok")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"PUT self-test failed; aborting before any change: {e}")

    before = _run_validation(target_url, finding_id, out_dir, probe_negative_pay, log)  # E4 baseline
    log(f"baseline (before): exploit {'blocked' if before['exploit_blocked'] else 'ALLOWED'} "
        f"(status {before['exploit_status']})")

    ref = {"namespace": xc.ns, "name": apidef_name}
    tenant = lb_obj.get("system_metadata", {}).get("tenant")
    if tenant:
        ref["tenant"] = tenant
    new_spec = copy.deepcopy(spec)
    new_spec.pop("disable_api_definition", None)  # api_specification vs disable_api_definition oneof
    new_spec["api_specification"] = {
        "api_definition": ref,
        "validation_all_spec_endpoints": {
            "validation_mode": {"validation_mode_active": {
                "request_validation_properties": ["PROPERTY_HTTP_BODY"], "enforcement_block": {}}},
            "fall_through_mode": {"fall_through_mode_allow": {}}},
    }
    put_spec(new_spec)
    log("attached api_specification (OpenAPI validation, block mode)")

    def rollback():
        put_spec(copy.deepcopy(spec))
        log("rolled back api_specification")

    # 4. validate: negative-amount payment blocked as a schema violation, legit payment passes
    res = None
    for attempt in range(1, retries + 1):
        time.sleep(wait_seconds)
        try:
            res = _run_validation(target_url, finding_id, out_dir, probe_negative_pay, log)
        except Exception as e:  # noqa: BLE001
            rollback()
            raise RuntimeError(f"validation error; rolled back: {e}")
        if res["exploit_blocked"] and res["legit_ok"]:
            break
        log(f"  attempt {attempt}/{retries}: schema validation not enforcing yet — waiting")

    passed = bool(res and res["exploit_blocked"] and res["legit_ok"])
    log(f"validation -> {'PASS' if passed else 'FAIL'} (exploit_blocked={res['exploit_blocked']} legit_ok={res['legit_ok']})")
    if passed and keep:
        rolled = False
        if finding_id:
            from . import ledger
            ledger.mark_mitigated(out_dir, finding_id, control="api_schema", policy_name=apidef_name, lb=lb)
    else:
        rollback()
        rolled = True
    before_after = {"before": before, "after": res}
    audit.record(out_dir, "apply_api_schema", lb=lb, apidef=apidef_name, passed=passed,
                 rolled_back=rolled, before_after=before_after)
    return {"mode": "apply_api_schema", "before_after": before_after, "passed": passed,
            "rolled_back": rolled, "kept": passed and keep}


def apply_control(control: str, lb: str, **kw) -> dict:
    """A0 dispatcher: route an LB-setting control to its handler. (service_policy uses the
    create+attach path apply_from_scan / apply_service_policy, not this.)"""
    handlers = {
        "malicious_user": apply_malicious_user,
        "rate_limit": apply_rate_limit,
        "bot_defense": apply_bot_defense,
        "waf": apply_waf,
        "waf_data_guard": apply_data_guard,
        "api_schema": apply_api_schema,
    }
    if control == "service_policy":
        raise RuntimeError("service_policy uses apply_from_scan / apply_service_policy")
    if control not in handlers:
        raise RuntimeError(f"apply not implemented for control '{control}'")
    return handlers[control](lb, **kw)
