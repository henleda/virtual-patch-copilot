"""B4: the single registry of XC band-aid controls. Everything that used to hard-code the list of
controls — the apply dispatcher, the retire detach logic, the LB-wide set, the console/CLI menus —
derives from CONTROLS here, so a new control is added in exactly one place and the attach/detach
inverse can never drift apart.

`detach` is the inverse of each control's attach mutation (what retire and rollback apply). The
attach mutation itself stays in apply.py because it needs per-call params (policy name, WAF ref,
rate), but the oneof keys it touches are declared here so detach and attach stay symmetric."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# The LB's service-policy choice is a oneof; snapshot/restore must handle whichever is set.
SP_ONEOF = ("no_service_policies", "active_service_policies", "service_policies_from_namespace")


def _detach_service_policy(spec: dict) -> None:
    for k in SP_ONEOF:
        spec.pop(k, None)
    spec["no_service_policies"] = {}


def _detach_waf(spec: dict) -> None:
    spec.pop("app_firewall", None)
    spec["disable_waf"] = {}


def _detach_data_guard(spec: dict) -> None:
    spec["data_guard_rules"] = []  # leave the WAF; drop only the masking rules


def _detach_rate_limit(spec: dict) -> None:
    spec.pop("rate_limit", None)
    spec["disable_rate_limit"] = {}


def _detach_malicious_user(spec: dict) -> None:
    spec.pop("enable_malicious_user_detection", None)
    spec["disable_malicious_user_detection"] = {}


def _detach_bot_defense(spec: dict) -> None:
    spec.pop("bot_defense", None)
    spec["disable_bot_defense"] = {}


def _detach_api_schema(spec: dict) -> None:
    spec.pop("api_specification", None)
    spec["disable_api_definition"] = {}


@dataclass(frozen=True)
class ControlMeta:
    key: str
    audit_action: str          # audit-log action + result "mode" (kept stable — tests/report depend on it)
    detach: Callable[[dict], None]   # inverse of attach — used by rollback + retire
    lb_wide: bool              # True = a setting on the LB (apply_control path); False = a policy object (from-scan)
    validation: str            # "live" (fire the exploit) | "config" (readback) | "behavioral" (burst)
    display: str               # human label for menus
    # B2: how a failed validation can self-heal.
    #   "spec"  = the policy has a spec to correct (service_policy: the refiner; api_schema: the OpenAPI)
    #   "param" = a knob to tighten and retry (rate_limit: lower the threshold)
    #   "none"  = a toggle with nothing to refine — a validation fail means the band-aid can't cover
    #             this flaw, so the honest outcome is "code fix required" (unfixable)
    refine_strategy: str = "none"


CONTROLS: dict[str, ControlMeta] = {
    "service_policy": ControlMeta("service_policy", "apply_service_policy", _detach_service_policy,
                                  lb_wide=False, validation="live", display="Service policy",
                                  refine_strategy="spec"),
    "waf": ControlMeta("waf", "apply_waf", _detach_waf,
                       # config-validated (readback), NOT live: a WAF is defense-in-depth whose block
                       # of a single request is signature/payload-dependent, not a deterministic DENY.
                       lb_wide=True, validation="config", display="WAF (App Firewall)",
                       refine_strategy="none"),
    "waf_data_guard": ControlMeta("waf_data_guard", "apply_data_guard", _detach_data_guard,
                                  lb_wide=True, validation="config", display="WAF Data Guard",
                                  refine_strategy="none"),
    "api_schema": ControlMeta("api_schema", "apply_api_schema", _detach_api_schema,
                              lb_wide=True, validation="live", display="API schema validation",
                              refine_strategy="spec"),
    "rate_limit": ControlMeta("rate_limit", "apply_rate_limit", _detach_rate_limit,
                              lb_wide=True, validation="behavioral", display="Rate limit",
                              refine_strategy="param"),
    "malicious_user": ControlMeta("malicious_user", "apply_malicious_user", _detach_malicious_user,
                                  lb_wide=True, validation="config", display="Malicious-user detection",
                                  refine_strategy="none"),
    "bot_defense": ControlMeta("bot_defense", "apply_bot_defense", _detach_bot_defense,
                               lb_wide=True, validation="config", display="Bot defense",
                               refine_strategy="none"),
}


def refine_strategy(control: str) -> str:
    m = CONTROLS.get(control)
    return m.refine_strategy if m else "none"

# Derived views — every consumer reads these instead of re-listing controls.
LB_WIDE = {k for k, m in CONTROLS.items() if m.lb_wide}
ALL_CONTROLS = tuple(CONTROLS)


def detach_control(new_spec: dict, control: str) -> None:
    """Undo a control on an LB spec copy (inverse of the apply_* mutation). Single source of truth
    shared by retire and rollback."""
    m = CONTROLS.get(control)
    if not m:
        raise RuntimeError(f"don't know how to detach control '{control}'")
    m.detach(new_spec)
