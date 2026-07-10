"""Refine agent — fix an XC policy that FAILED live validation, so the copilot never claims a
band-aid works when it doesn't. Given the exact exploit request that must be blocked and the
benign request that must pass, it corrects the policy spec to match reality."""
from __future__ import annotations

import json

from ..harness import Harness
from ..schemas import Finding, RefinedPolicy

SYSTEM = """You correct an F5 Distributed Cloud policy that FAILED live validation. The policy was
attached to the load balancer and the copilot fired the REAL exploit request plus a benign request,
then measured what actually happened.

You are given: the finding, the CURRENT policy spec (which did not work), the exact EXPLOIT request
the policy MUST block (method, path, body), the benign LEGIT request that MUST still pass, and a
measured result + diagnosis.

Diagnosis meanings:
- exploit_not_blocked: the exploit still reached the app — XC did not deny it, so the policy's match
  is WRONG. Rewrite the DENY rule so its path (prefix_values or regex_values), http_method, and any
  body_matcher EXACTLY match the exploit request's method + FULL path as sent (e.g.
  "/identity/management/admin/lockUser" — use the complete path, not a guessed shorter one), while
  leaving the legit request unmatched.
- over_block: the policy blocked the LEGIT request too. Narrow the rule so it blocks only the exploit
  (tighten the path/method, or add a body_matcher only the exploit hits). If the exploit and legit
  are indistinguishable at L7 (same method+path, differing only by which user owns the resource — a
  BOLA/IDOR), set unfixable=true and recommend the right control ("malicious_user" or "code_fix_only").

Return the FULL corrected spec (same JSON shape/keys as the current one — keep metadata/name, the
rule_list structure, and the trailing allow-all rule), a one-line rationale, and unfixable/recommend
if applicable. Keep FIRST_MATCH ordering: the DENY rule MUST come before any allow-all."""


def run(h: Harness, finding: Finding, control: str, current_spec: dict, probe: dict | None,
        result: dict, diagnosis: str) -> RefinedPolicy:
    exploit = (probe or {}).get("exploit", {})
    legit = (probe or {}).get("legit") or {}
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CONTROL: {control}\n\n"
        f"CURRENT POLICY SPEC (did NOT work):\n{json.dumps(current_spec, indent=2)}\n\n"
        f"EXPLOIT request that MUST be blocked:\n{json.dumps(exploit, indent=2)}\n\n"
        f"LEGIT request that MUST still pass:\n{json.dumps(legit, indent=2)}\n\n"
        f"MEASURED RESULT: {json.dumps(result)}\nDIAGNOSIS: {diagnosis}\n\n"
        "Return the corrected spec so the exploit is blocked and the legit request passes."
    )
    return h.run("refine", SYSTEM, user, RefinedPolicy)
