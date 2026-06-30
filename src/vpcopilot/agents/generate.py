"""Generate agent — emit the XC config for ONE chosen band-aid control. The system
prompt carries the demo-proven service-policy rules plus per-control guidance."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Control, Finding, GeneratedArtifacts

# A trimmed, working service-policy example (the negative-amount patch we proved live).
# A concrete, correct shape is what makes the model's output paste-ready.
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

SYSTEM = f"""You generate the F5 Distributed Cloud config for ONE chosen band-aid control.
Return the `spec` field as the XC config OBJECT (a JSON dict) plus a kebab-case
policy_name. Emit config for the requested CONTROL only.

CONTROL = service_policy (per-request positive security) — follow these proven rules:
- algo FIRST_MATCH; a specific DENY rule FIRST, then a catch-all ALLOW LAST. XC
  default-denies on no-match, so the trailing allow-all is REQUIRED or legit traffic 403s.
- Match precisely: path prefix + http_method, and the offending value via
  query_params[].item.regex_values (query) or body_matcher.regex_values (JSON body).
- A regex placed in the PATH field must start with an alphanumeric character.
- To catch a negative JSON amount use a regex starting with a letter: amount[^0-9-]*-[0-9].
- service_policy is REQUEST-side ONLY: never generate a rule that matches or strips a
  RESPONSE body. For response data masking use waf_data_guard instead.
Example:
{SERVICE_POLICY_EXAMPLE}

CONTROL = api_schema — emit an OpenAPI fragment (paths/components) for the affected
endpoint(s) with the constraints that fix the flaw (types, exclusiveMinimum/maximum,
required, additionalProperties:false for mass-assignment), and a short note that XC API
Security enforces it once the spec is imported.

CONTROL = waf or waf_data_guard — emit the XC config: for waf, enable AI WAF blocking on
the affected path (and any specific signatures); for waf_data_guard, the response data-
masking rule (which path, which secret pattern: credit-card / SSN / token).

CONTROL = malicious_user — emit the detection+mitigation config: enable user
identification, set threat-level thresholds, and the mitigation action (e.g. JS challenge
then block) suited to the behavioral abuse.

CONTROL = bot_defense — emit the protected endpoint(s) + the mitigation action for the
automation threat (credential stuffing / ATO / scraping).

CONTROL = rate_limit — emit the rate-limit policy (scope, threshold, window, action).

Return ONE artifact for the requested control (occasionally two if the control needs a
paired object). policy_name must be kebab-case and descriptive."""


def run(h: Harness, finding: Finding, control: Control, rationale: str) -> GeneratedArtifacts:
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CONTROL TO GENERATE: {control.value}\n"
        f"WHY THIS CONTROL: {rationale}\n\n"
        "Generate the XC config object for this control."
    )
    return h.run("generate", SYSTEM, user, GeneratedArtifacts)
