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

# api_schema is CONSUMED live: the spec is uploaded verbatim to XC's object store, so it must be a
# COMPLETE, valid OpenAPI object (version + info + paths) — a bare fragment is rejected on upload.
API_SCHEMA_EXAMPLE = """{
  "openapi": "3.0.0",
  "info": {"title": "vpcopilot-lab", "version": "1.0.0"},
  "paths": {
    "/api/pay": {"post": {"requestBody": {"required": true, "content": {"application/json": {"schema": {
      "type": "object", "additionalProperties": false, "required": ["amount", "to"],
      "properties": {"amount": {"type": "number", "exclusiveMinimum": 0}, "to": {"type": "string"}}}}}},
      "responses": {"200": {"description": "ok"}}}}
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
- USE THE FINDING'S `endpoint` AS THE PATH. If a concrete EXPLOIT REQUEST is given below,
  your DENY rule MUST match its EXACT method and FULL path — a `prefix_values` MUST be a
  true prefix of the full endpoint (NEVER a shortened guess like "/users/register" for
  "/users/v1/register"), or use `path.exact_values` for the exact path. The DENY MUST NOT
  match the given LEGIT request. Build the policy to block that exact exploit and nothing
  legitimate; the DENY rule MUST come before the trailing allow-all.
- A regex placed in the PATH field must start with an alphanumeric character.
- To catch a negative JSON amount use a regex starting with a letter: amount[^0-9-]*-[0-9].
- service_policy is REQUEST-side ONLY: never generate a rule that matches or strips a
  RESPONSE body. For response data masking use waf_data_guard instead.
Example:
{SERVICE_POLICY_EXAMPLE}

CONTROL = api_schema (CONSUMED LIVE — uploaded verbatim to XC) — emit a COMPLETE, valid
OpenAPI 3.0 object: top-level `openapi`, `info`, and `paths` for the affected endpoint(s),
with the constraints that fix the flaw (types, exclusiveMinimum/maximum, required,
additionalProperties:false for mass-assignment). NOT a bare fragment — XC rejects an upload
that lacks the version/info/paths envelope. Use the FINDING's endpoint as the path key.
Example:
{API_SCHEMA_EXAMPLE}

The controls below are PARAMETERIZED by the apply engine — emit the spec so the operative
knobs the engine consumes are explicit and reconcilable:
CONTROL = waf or waf_data_guard — for waf: {{"app_firewall_enable": true, "path": "<endpoint>"}}
(AI WAF blocking on the affected path, plus any specific signatures). For waf_data_guard: the
response data-masking rule {{"path": "<endpoint>", "secret": "credit-card|ssn|token"}}.

CONTROL = malicious_user — {{"enable_user_identification": true, "threat_level": "HIGH",
"mitigation": "block"}} (or js_challenge then block) suited to the behavioral abuse.

CONTROL = bot_defense — {{"endpoints": ["<endpoint>"], "action": "block"}} for the automation
threat (credential stuffing / ATO / scraping).

CONTROL = rate_limit — {{"requests": <int>, "unit": "MINUTE|SECOND|HOUR", "burst": <int>,
"action": "block"}} (scope, threshold, window, action).

Return ONE artifact for the requested control (occasionally two if the control needs a
paired object). policy_name must be kebab-case and descriptive."""


def run(h: Harness, finding: Finding, control: Control, rationale: str,
        exploit: dict | None = None, legit: dict | None = None) -> GeneratedArtifacts:
    import json
    ex = f"\nCONCRETE EXPLOIT REQUEST the policy MUST block:\n{json.dumps(exploit, indent=2)}\n" if exploit else ""
    lg = f"LEGIT request the policy MUST NOT block:\n{json.dumps(legit, indent=2)}\n" if legit else ""
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CONTROL TO GENERATE: {control.value}\n"
        f"WHY THIS CONTROL: {rationale}\n"
        f"{ex}{lg}\n"
        "Generate the XC config object for this control."
    )
    return h.run("generate", SYSTEM, user, GeneratedArtifacts)
