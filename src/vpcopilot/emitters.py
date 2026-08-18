"""L1 — one finding, every enforcement point.

`generate` produces an F5 Distributed Cloud config object. This emits the *same finding* as a
**declarative WAF policy**, which BIG-IP Advanced WAF and F5 WAF for NGINX (App Protect) both
consume — so a finding covers the XC control it already generates **and** the enforcement points a
customer already owns.

**XC is an emitter too.** The abstraction is proven by the backend that already works: `xc` passes
the generated spec through unchanged, so "adding a target touches only this module" is testable on
day one and the XC path stays byte-identical.

**The emitted rule is sometimes MORE faithful than the one we started from, and that is the point.**
XC expresses the negative-amount finding as `body_matcher.regex_values: ["amount[^0-9-]*-[0-9]"]` —
a regex approximating "a minus sign near the word amount". A declarative WAF policy expresses the
constraint itself:

    {"name": "amount", "dataType": "integer", "checkMinValue": true, "minimumValue": 0}

**And that constraint is derived by CODE, not by a model.** The two recorded probe requests are the
evidence: the exploit sends `amount: -100000`, the legit request sends `amount: 10`, so the field
that differs, its type, and the bound between them are all facts. "Agents reason, code acts" — a
number an operator will act on should not come from a prompt.

Four traps, each of which would ship a policy that blocks nothing — the G2 canary's failure mode:

1. **`dataType: "integer"` does not reject `-500`.** F5 defines integer as whole numbers only;
   `-500` is a whole number. The sign rejection comes entirely from `minimumValue`.
2. **A constraint only ALARMS unless its violation is armed.** `VIOL_PARAMETER_NUMERIC_VALUE` must
   be `block: true` in `policy.blocking-settings.violations`.
3. **`parameterLocation` has no `json` value** (`[any, cookie, form-data, header, path, query]` —
   verified in both schemas). A JSON body value is reached only via a `json-profile` with
   `handleJsonValuesAsParameters: true`, attached through `urls[].urlContentProfiles`; the extracted
   values then flow through the ordinary parameter engine.
4. **The schemas cannot catch any of the above.** `additionalProperties` is absent from all 127 NAP
   and 173 BIG-IP object nodes, and `violations[].name` is a free string in both — so a misspelled
   violation, an invented section or a wrong location validates green. Schema validation is a
   necessary check and a weak one; the live appliance is the proof.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- targets


@dataclass(frozen=True)
class Target:
    """One enforcement point. The divergences between the declarative-WAF targets are
    parameterized here, so adding a target is a row in `TARGETS` and nothing else."""
    key: str
    display: str
    kind: str                     # "xc" | "declarative-waf"
    template_name: str = ""       # declarative-waf only: policy.template.name
    schema_fixture: str = ""      # the vendored schema a test validates against
    note: str = ""


TARGETS: dict[str, Target] = {
    "xc": Target(
        "xc", "F5 Distributed Cloud", "xc",
        note="the control `generate` already produces; emitted unchanged so the XC path is "
             "byte-identical and the abstraction is proven by the backend that works"),
    "bigip-awaf": Target(
        "bigip-awaf", "BIG-IP Advanced WAF", "declarative-waf",
        # NOT the NGINX name, deliberately. NAP constrains template.name to a single-value enum
        # while BIG-IP leaves it a free string, so a policy carrying the NGINX name would pass BOTH
        # schemas and the portability test would prove nothing. Emitting the BIG-IP name means the
        # pre-swap object genuinely fails NAP, which is the only thing the schemas can establish.
        template_name="POLICY_TEMPLATE_FUNDAMENTAL",
        schema_fixture="bigip-awaf-v17_1.json"),
    "nginx-app-protect": Target(
        "nginx-app-protect", "F5 WAF for NGINX (App Protect)", "declarative-waf",
        template_name="POLICY_TEMPLATE_NGINX_BASE",
        schema_fixture="nginx-app-protect-policy.json",
        note="the same policy object with only template.name swapped"),
}

DECLARATIVE_TARGETS = tuple(k for k, t in TARGETS.items() if t.kind == "declarative-waf")

# The BIG-IP Advanced-WAF band-aid forms that ship today, control -> a short human name for the
# form. Each was BUILT and live-proven on a real BIG-IP (v17.5, AS3 3.56, 2026-08-18). This is the
# single source of truth for the form NAMES: the report's BIG-IP section reads them from here, so a
# form added to `emit` below is named in one place. `emit` remains the authority on whether a given
# finding actually yields one. See docs/design/bigip-apply.md and bigip-data-guard.md.
AWAF_FORMS: dict[str, str] = {
    "service_policy": "value-constraint",
    "waf_data_guard": "response-masking",
    "api_schema": "API-contract",
}

# Why `waf` (attack signatures) is declined on BIG-IP — a module constant so `emit` returns it and
# any legend that names it reads the same string, stated once. ASM keeps freshly-imported signatures
# in staging (log-only) regardless of the declarative knobs, so a signature-based virtual patch
# would "look applied and block nothing".
WAF_STAGING_REASON = (
    "an attack-signature policy imports cleanly but ASM keeps freshly-imported "
    "signatures in staging (log-only) — verified on a live BIG-IP that it does not "
    "block immediately, so it is unsuitable as a virtual patch; use a value-constraint "
    "(service_policy), response-masking (waf_data_guard), or API-contract (api_schema) "
    "band-aid instead")

# Controls with no declarative-WAF equivalent. Each carries the reason, because "we did not emit
# this" and "this needs nothing" must never render the same way.
UNSUPPORTED: dict[str, str] = {
    "rate_limit": (
        "a declarative WAF policy has no request-rate construct — the abuse is a property of the "
        "request *stream*, not of any single request a policy can match. On BIG-IP this is an LTM "
        "rate-limiting profile or an iRule, which is a different object entirely."),
    "malicious_user": (
        "per-user behavioural risk scoring is a stateful judgement across many requests, which a "
        "declarative policy — evaluated per request — cannot express at all."),
    "bot_defense": (
        "bot detection needs client interrogation (JS challenge, telemetry, device signals) that "
        "lives in a separate subscription product, not in the policy document."),
}


class EmitError(RuntimeError):
    """The emitter could not build a policy from what it was given — distinct from a control that
    *has* no declarative equivalent, which is `supported=False` and a normal answer."""


@dataclass
class EmitResult:
    """Deliberately NOT an empty list for the unsupported case. `GeneratedArtifacts.items` already
    carries `min_length=1` for the same reason (schemas.py) — an empty collection is how a missing
    band-aid silently becomes an absent one."""
    target: str
    control: str
    supported: bool
    reason: str = ""
    policy_name: str = ""
    policy: dict | None = None
    derived_from: dict = field(default_factory=dict)   # what code read to build the constraint

    def to_dict(self) -> dict:
        d = {"target": self.target, "control": self.control, "supported": self.supported,
             "reason": self.reason, "policy_name": self.policy_name}
        if self.policy is not None:
            d["policy"] = self.policy
        if self.derived_from:
            d["derived_from"] = self.derived_from
        return d


# ---------------------------------------------------------------- deriving the constraint


def _numbers(body: Any, prefix: str = "") -> dict[str, float]:
    """Flatten a JSON body to {dotted-path: number}. Nested paths are recorded so a caller can see
    the depth; whether ASM can *address* a nested key is a separate question, answered below."""
    out: dict[str, float] = {}
    if isinstance(body, dict):
        for k, v in body.items():
            p = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, bool):
                continue                      # bool is an int in Python; not a numeric constraint
            if isinstance(v, (int, float)):
                out[p] = v
            else:
                out.update(_numbers(v, p))
    elif isinstance(body, list):
        for i, v in enumerate(body):
            out.update(_numbers(v, f"{prefix}[{i}]"))
    return out


def derive_numeric_constraint(exploit: dict, legit: dict) -> dict | None:
    """The load-bearing derivation, and it is pure code over two recorded requests.

    Compares the exploit body against the legit body and returns the single numeric field whose
    value the exploit drove out of range, plus the bound that separates them. Returns `None` when
    the evidence does not support exactly one such field — refusing to guess is the point: a policy
    built on the wrong parameter blocks nothing and looks applied.
    """
    ex, lg = _numbers(exploit.get("json_body") or {}), _numbers(legit.get("json_body") or {})
    shared = sorted(set(ex) & set(lg))
    # Only fields where the exploit is negative and the legit request is not: that is the flaw this
    # constraint describes. A field that merely differs (an account id, a timestamp) is not it.
    candidates = [k for k in shared if ex[k] < 0 <= lg[k]]
    if len(candidates) != 1:
        return None
    name = candidates[0]
    return {
        "parameter": name,
        "exploit_value": ex[name],
        "legit_value": lg[name],
        "minimum": 0,
        # ALWAYS `decimal`, and this is the one place the emitter deliberately does NOT generalise
        # from the samples. Two coincidentally-whole values do not establish that the field is
        # integral, and `integer` (F5: whole numbers only) contributes **nothing** to the negative
        # rejection — that comes entirely from `minimum`. So narrowing the type is cost with no
        # benefit, and the cost is measured: against this repo's own G2 traffic corpus, 30 of 61
        # recorded legitimate `/api/pay` requests carry a fractional amount (17.5, 32.5, …), so
        # `integer` would declare **49%** of known-good traffic illegal — 49× G2's own blast-radius
        # threshold. `checkMinValue` is valid for `decimal` too, so the floor is unchanged.
        "data_type": "decimal",
        "samples_were_whole": float(ex[name]).is_integer() and float(lg[name]).is_integer(),
        "nested": "." in name or "[" in name,
    }


_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    return _SLUG.sub("-", str(s).lower()).strip("-") or "policy"


# ---------------------------------------------------------------- the declarative WAF policy


def _declarative_policy(target: Target, *, name: str, url_path: str, method: str,
                        constraint: dict, protocol: str = "http") -> dict:
    """Build the policy. Every element below is load-bearing; see the module docstring for the four
    traps, three of which are invisible to schema validation."""
    param = constraint["parameter"]
    # TRAP 3: `parameterLocation` has no `json` value, so a JSON body value is NOT addressable as a
    # parameter directly. It becomes one only by extracting it with a json-profile.
    json_profile = f"vpcopilot-{_slug(name)}-json"
    return {
        "policy": {
            "name": name,
            "template": {"name": target.template_name},
            "applicationLanguage": "utf-8",
            # A policy in transparent mode observes and never blocks — the exact "looks applied and
            # is not" state the G2 canary exists to catch.
            "enforcementMode": "blocking",
            "blocking-settings": {
                "violations": [
                    # TRAP 2: without block:true the constraint only ALARMS. The violation name is a
                    # free string in both schemas, so nothing but the appliance will catch a typo.
                    {"name": "VIOL_PARAMETER_NUMERIC_VALUE", "block": True, "alarm": True},
                ],
            },
            "json-profiles": [
                {
                    "name": json_profile,
                    # …this is what makes the body value reachable by the parameter engine.
                    "handleJsonValuesAsParameters": True,
                    "defenseAttributes": {"maximumArrayLength": "any",
                                          "maximumStructureDepth": "any"},
                },
            ],
            "urls": [
                {
                    "name": url_path,
                    "method": method,
                    "type": "explicit",
                    # TRAP 5: the protocol is part of the URL's IDENTITY, not a hint. An `https`
                    # entry does not match `http` traffic, so hardcoding either one yields a policy
                    # that imports cleanly and matches nothing. Derived from the target URL.
                    "protocol": protocol,
                    "urlContentProfiles": [
                        # TRAP 6, and the appliance is the only thing that says so: ASM REFUSES a
                        # URL whose content-profile list omits the default `*:*` entry —
                        # "[fatal] Could not add the URL … The default URL Content Profile (*:*) is
                        # mandatory." Neither schema requires it (nothing is closed), so this is
                        # invisible until import. It must come FIRST; the JSON profile then
                        # overrides it for the JSON content type.
                        {"headerName": "*", "headerValue": "*", "type": "do-nothing"},
                        {"headerName": "Content-Type", "headerValue": "application/json",
                         "type": "json", "contentProfile": {"name": json_profile}},
                    ],
                },
            ],
            "parameters": [
                {
                    "name": param,
                    "type": "explicit",
                    "valueType": "user-input",
                    # TRAP 1: `integer` is whole-numbers-only and does NOT reject a negative…
                    "dataType": constraint["data_type"],
                    "parameterLocation": "any",
                    # …the sign rejection is entirely this pair.
                    "checkMinValue": True,
                    "minimumValue": constraint["minimum"],
                    "isCookie": False,
                    "isHeader": False,
                },
            ],
        },
    }


def _data_guard_policy(target: Target, *, name: str) -> dict:
    """The response-masking form — the band-aid for a `waf_data_guard` finding, where the request is
    legitimate and the caller authorised but the *response* carries more than it should (a full PAN,
    an SSN). Data Guard intercepts responses and masks the sensitive substrings on the way out.

    Three properties matter, and all three were confirmed against a live BIG-IP (v17.5, AS3 3.56):
      - It derives NOTHING from the probe — the sensitive-data classes are fixed — so it routes before
        the exploit/legit numeric derivation, the same place the (declined) signature form would have.
      - It is response interception, NOT an attack signature, so it sidesteps the staging trap that
        sank the `waf` form: masking is enforced the instant the policy attaches, no staging period.
      - TRAP (invisible to schema, found only on the box): `VIOL_DATA_GUARD` must be **alarm-only**,
        NOT block. Data Guard has two actions — MASK the sensitive substrings on egress, or BLOCK the
        whole response — and the violation's `block` flag chooses. The FUNDAMENTAL template defaults
        it to `block:true`, so a policy that merely enables Data Guard (schema-valid, `maskData:true`)
        REJECTS the response with an ASM block page instead of masking it. Forcing `block:false,
        alarm:true` is what makes it actually mask. Verified: with it, `card_pan` came back
        `************1111` in a 200 response; without it, an ASM "Request Rejected" page.

    `enforcementMode: "ignore-urls-in-list"` with an empty list means "enforce Data Guard on ALL URLs"
    (the list is the *exception* set) — the protect-everything default a band-aid wants. `creditCardNumbers`
    masks the PAN; `usSocialSecurityNumbers` masks an SSN-formatted value (live-confirmed on `078-05-1120`).
    A site whose secret matches no built-in class would add a PCRE to `customPatternsList`."""
    return {
        "policy": {
            "name": name,
            "template": {"name": target.template_name},
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "data-guard": {
                "enabled": True,
                "maskData": True,
                "creditCardNumbers": True,
                "usSocialSecurityNumbers": True,
                "enforcementMode": "ignore-urls-in-list",
            },
            # alarm-only => MASK on egress. block:true (the template default) would REJECT the whole
            # response instead — schema-valid, and the exact "looks applied, does the wrong thing" trap.
            "blocking-settings": {"violations": [{"name": "VIOL_DATA_GUARD", "block": False, "alarm": True}]},
        },
    }


def _api_schema_policy(target: Target, *, name: str, url_path: str) -> dict:
    """The API-contract form for an `api_schema` finding — a `code_only` orphan: an endpoint the code
    serves that the documented OpenAPI contract never declares (see `inputs/openapi.py`).

    XC enforces the whole spec as a positive model (block ANY off-contract request). BIG-IP cannot do
    that self-contained — ASM rejects a disallowed pure wildcard (`[fatal] … Pure wildcard must be
    allowed`, live-verified), and a real OpenAPI import (`open-api-files`) needs the spec hosted at a
    `link` ASM fetches or a file pre-placed on the box, neither of which the copilot can provide. So
    the BIG-IP band-aid disallows the SPECIFIC off-contract endpoint the finding names — a targeted
    negative entry with the identical effect for THIS finding: the off-contract request is blocked and
    every documented endpoint still passes.

    Load-bearing, and live-verified (2026-08-18): `isAllowed:false` on an explicit URL + `VIOL_URL`
    block, with `performStaging:false` + `enforcementReadinessPeriod:0`, blocks the instant the policy
    attaches — the disallowed URL is NOT subject to the signature-staging trap. `method:"*"` disallows
    the whole path (a code_only orphan is off-contract for every verb); no `protocol` is set so the
    block applies regardless of scheme (a disallow should never be narrower than the traffic)."""
    return {
        "policy": {
            "name": name,
            "template": {"name": target.template_name},
            "applicationLanguage": "utf-8",
            "enforcementMode": "blocking",
            "general": {"enforcementReadinessPeriod": 0},
            "urls": [
                {"name": url_path, "method": "*", "type": "explicit",
                 "isAllowed": False, "performStaging": False},
            ],
            "blocking-settings": {"violations": [{"name": "VIOL_URL", "block": True, "alarm": True}]},
        },
    }


# ---------------------------------------------------------------- the emitter interface


def emit(*, target: str, control: str, policy_name: str, spec: dict | None = None,
         probe: dict | None = None, url_path: str = "", method: str = "POST",
         protocol: str = "http") -> EmitResult:
    """Emit one finding's band-aid for one enforcement point.

    `spec` is the XC object `generate` produced (passed through for the `xc` target). `probe` is the
    recorded exploit/legit pair, which is what the declarative targets derive their constraint from.
    `protocol` must match the virtual server the policy will hang off — it is part of the URL's
    identity in ASM, not a hint (see TRAP 5).
    """
    t = TARGETS.get(target)
    if not t:
        raise EmitError(f"unknown target {target!r} — known: {', '.join(sorted(TARGETS))}")

    if t.kind == "xc":
        # The backend that already works, emitted unchanged. This is what makes "adding a target
        # touches only this module" testable rather than asserted.
        if spec is None:
            raise EmitError("the xc target emits the generated spec, and none was given")
        return EmitResult(target, control, True, policy_name=policy_name, policy=spec)

    if control in UNSUPPORTED:
        # A named reason, and NO policy. Emitting an empty document here would be the failure this
        # whole project exists to prevent: a band-aid that looks present and blocks nothing.
        return EmitResult(target, control, False, reason=UNSUPPORTED[control],
                          policy_name=policy_name)
    if control not in ("service_policy", "api_schema", "waf", "waf_data_guard"):
        return EmitResult(target, control, False,
                          reason=f"no declarative-WAF mapping is implemented for control "
                                 f"{control!r}", policy_name=policy_name)
    if control == "waf_data_guard":
        # Response-masking form — BUILT and live-proven on a real BIG-IP (v17.5, AS3 3.56, 2026-08-18):
        # a leaked PAN/SSN comes back masked the instant the policy attaches. It derives nothing from
        # the probe, so it routes here before the exploit/legit derivation. See _data_guard_policy and
        # docs/design/bigip-data-guard.md.
        return EmitResult(target, control, True, policy_name=policy_name,
                          policy=_data_guard_policy(t, name=policy_name))
    if control == "api_schema":
        # API-contract form — BUILT and live-proven on a real BIG-IP (v17.5, AS3 3.56, 2026-08-18):
        # disallow the specific off-contract endpoint the finding names (a `code_only` orphan). It
        # needs the endpoint, taken from the probe's exploit (or an explicit url_path). See
        # _api_schema_policy for why this is the self-contained BIG-IP equivalent of enforcing the
        # OpenAPI contract for this finding, and docs/design/bigip-apply.md.
        exploit = (probe or {}).get("exploit") or {}
        path = url_path or exploit.get("path")
        if not path:
            return EmitResult(target, control, False,
                              reason="an api_schema band-aid disallows the specific off-contract "
                                     "endpoint the finding names, and this finding records no exploit "
                                     "path to identify it", policy_name=policy_name)
        return EmitResult(target, control, True, policy_name=policy_name,
                          policy=_api_schema_policy(t, name=policy_name, url_path=path))
    if control == "waf":
        # Honest scope: this maps to a declarative policy in principle (a signature set) but is
        # declined. Saying so is better than emitting a policy that is shaped right and enforces
        # nothing.
        #
        # `waf` (attack signatures) was BUILT and tested against a live BIG-IP (v17.5, AS3 3.56,
        # 2026-08-18) and deliberately reverted: the policy imports cleanly and is attached in
        # blocking mode, but ASM places every freshly-imported signature in STAGING (log-only, never
        # blocks) and keeps it there — `signatureStaging:false`, `placeSignaturesInStaging:false`,
        # `enforcementReadinessPeriod:0`, and even a follow-up apply-policy task all leave
        # performStaging=True. A SQLi that the policy is meant to stop sails straight through to the
        # app. Un-staging is a stateful, per-signature operation outside the declarative model, so a
        # virtual patch built on signatures would "look applied and block nothing" — exactly the
        # failure this project exists to prevent. The value-constraint (service_policy), response-
        # masking (waf_data_guard), and API-contract (api_schema) forms are all NOT signatures and do
        # not have this problem. See docs/design/bigip-apply.md.
        return EmitResult(target, control, False, reason=WAF_STAGING_REASON, policy_name=policy_name)

    probe = probe or {}
    exploit, legit = probe.get("exploit") or {}, probe.get("legit") or {}
    if not exploit or not legit:
        return EmitResult(target, control, False,
                          reason="a declarative constraint is derived from the recorded exploit "
                                 "and legit requests, and this finding has no recorded pair",
                          policy_name=policy_name)

    constraint = derive_numeric_constraint(exploit, legit)
    if not constraint:
        return EmitResult(target, control, False,
                          reason="no single numeric field separates the recorded exploit from the "
                                 "recorded legit request, so there is no value constraint to "
                                 "express — refusing to guess one",
                          policy_name=policy_name)

    path = url_path or exploit.get("path") or "/"
    policy = _declarative_policy(t, name=policy_name, url_path=path,
                                 method=(exploit.get("method") or method).upper(),
                                 constraint=constraint, protocol=protocol)
    res = EmitResult(target, control, True, policy_name=policy_name, policy=policy,
                     derived_from=constraint)
    if constraint["nested"]:
        # Open question, recorded rather than guessed: F5 documents no rule for how ASM names a
        # parameter extracted from a NESTED JSON key. Top-level `amount` is unambiguous; a nested
        # one may need the flat leaf name or a JSON-pointer path, and getting it wrong yields a
        # policy that validates and matches nothing.
        res.reason = (f"parameter {constraint['parameter']!r} is nested; ASM's naming rule for "
                      f"parameters extracted from nested JSON is undocumented — verify on the "
                      f"appliance before relying on this policy")
    return res


def emit_all(*, control: str, policy_name: str, spec: dict | None = None,
             probe: dict | None = None) -> list[EmitResult]:
    """Every target, so a caller sees the whole hybrid-fabric answer — including the targets that
    decline, which is the half a summary would otherwise drop."""
    return [emit(target=k, control=control, policy_name=policy_name, spec=spec, probe=probe)
            for k in TARGETS]


def swap_target(policy: dict, target: str) -> dict:
    """The portability claim, executable: the same policy object with only `template.name` swapped.

    Returns a copy — mutating the caller's policy would make "the same object" quietly false.
    """
    t = TARGETS.get(target)
    if not t or t.kind != "declarative-waf":
        raise EmitError(f"{target!r} is not a declarative-WAF target")
    out = json.loads(json.dumps(policy))
    out["policy"]["template"]["name"] = t.template_name
    return out
