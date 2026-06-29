"""Generate agent — emit the XC config object(s) that virtually patch a finding.
The system prompt carries the hard-won, demo-proven rules for valid XC specs."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Finding, GeneratedArtifacts, TriageDecision

# A trimmed, working service-policy example (the negative-amount patch we proved live).
# Giving the model a concrete, correct shape is what makes its output paste-ready.
SERVICE_POLICY_EXAMPLE = """{
  "metadata": {"name": "deny-negative-pay", "namespace": "<tenant-namespace>"},
  "spec": {
    "algo": "FIRST_MATCH",
    "any_server": {},
    "rule_list": {"rules": [
      {"metadata": {"name": "deny-negative-amount"},
       "spec": {"action": "DENY", "any_client": {},
         "path": {"prefix_values": ["/api/pay"]},
         "http_method": {"methods": ["POST"]},
         "body_matcher": {"regex_values": ["amount[^0-9-]*-[0-9]"]}}},
      {"metadata": {"name": "allow-all"},
       "spec": {"action": "ALLOW", "any_client": {},
         "path": {"prefix_values": ["/"]},
         "http_method": {"methods": ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"]}}}
    ]}
  }
}"""

SYSTEM = f"""You generate F5 Distributed Cloud config to virtually patch a vulnerability.
Return the `spec` field as the XC config OBJECT (a JSON dict), plus a kebab-case policy_name.

SERVICE POLICY (per-request) — proven rules, follow them exactly:
- algo FIRST_MATCH; a specific DENY rule FIRST, then a catch-all ALLOW LAST. XC
  default-denies on no-match, so the trailing allow-all is REQUIRED or legit traffic 403s.
- Match precisely: path prefix + http_method, and the offending value via
  query_params[].item.regex_values (query) or body_matcher.regex_values (JSON body).
- A regex placed in the PATH field must start with an alphanumeric character.
- body_matcher inspects the request body; to catch a negative JSON amount use a regex
  that starts with a letter, e.g. `amount[^0-9-]*-[0-9]`.
- rule action is DENY; the catch-all action is ALLOW with all methods.
Example service policy:
{SERVICE_POLICY_EXAMPLE}

MALICIOUS USER (per-user behavioral) — emit a detection+mitigation spec: enable user
identification, set the threat-level thresholds, and the mitigation action (e.g. JS
challenge then block) suited to the behavioral abuse (credential stuffing, enumeration,
scraping, velocity).

Return ONE artifact per control needed (TWO when control == both): the service_policy
artifact and/or the malicious_user artifact."""


def run(h: Harness, finding: Finding, decision: TriageDecision) -> GeneratedArtifacts:
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CONTROL: {decision.control.value}\n"
        f"RATIONALE: {decision.rationale}\n\n"
        "Generate the XC config object(s) to virtually patch this."
    )
    return h.run("generate", SYSTEM, user, GeneratedArtifacts)
