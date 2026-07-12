"""D3: golden-replay — recorded agent outputs must still validate against the current schemas, so a
field rename/removal that would break real LLM responses fails a test instead of a live run."""

from vpcopilot.schemas import (ExploitProbe, FindingList, GeneratedArtifacts, RefinedPolicy,
                               RemediationPlan, TriageBatch, Verdict)

GOLDEN = {
    FindingList: """{"findings": [
      {"id": "sqli-001", "title": "SQLi in login", "vuln_class": "sqli", "severity": "critical",
       "file": "login.py", "line": 42, "endpoint": "/api/login", "http_method": "POST",
       "description": "email concatenated into the query", "exploit_sketch": "' OR 1=1 --",
       "code_snippet": "q = 'SELECT ...' + email"}]}""",
    Verdict: """{"finding_id": "sqli-001", "is_real": true, "confidence": 0.92, "rationale": "reachable"}""",
    TriageBatch: """{"decisions": [
      {"finding_id": "sqli-001", "no_bandaid": false, "residual_risk": "", "code_cure_required": true,
       "bandaids": [{"control": "service_policy", "coverage": "full", "recommended": true, "rationale": "r"}]}]}""",
    GeneratedArtifacts: """{"items": [
      {"finding_id": "sqli-001", "control": "service_policy", "policy_name": "deny-login-sqli",
       "spec": {"rule_list": {"rules": []}}, "notes": ""}]}""",
    RemediationPlan: """{"finding_id": "sqli-001", "summary": "parameterize", "file": "login.py",
       "diff": "--- a\\n+++ b", "patched_content": "fixed", "pr_title": "Fix SQLi", "pr_body": "body"}""",
    ExploitProbe: """{"finding_id": "sqli-001", "note": "",
       "setup": [{"method": "POST", "path": "/api/login", "json_body": {"email": "a@b.c"}}],
       "exploit": {"method": "POST", "path": "/api/login", "json_body": {"email": "' OR 1=1 --"}},
       "legit": {"method": "POST", "path": "/api/login", "json_body": {"email": "a@b.c"}}}""",
    RefinedPolicy: """{"spec": {"rule_list": {"rules": []}}, "rationale": "fixed", "unfixable": false,
       "recommend": ""}""",
}


def test_golden_agent_outputs_still_validate():
    for model, raw in GOLDEN.items():
        obj = model.model_validate_json(raw)
        assert obj is not None
        # round-trips back to JSON without loss of the required fields
        assert model.model_validate_json(obj.model_dump_json()) is not None
