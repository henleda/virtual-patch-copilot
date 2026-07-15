"""Typed I/O for every agent. Pydantic v2 models are the contract that makes the
pipeline behave the same across models: each agent must return one of these, and the
harness enforces it (validate + repair) regardless of provider."""
from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class VulnClass(str, Enum):
    sqli = "sqli"
    xss = "xss"
    command_injection = "command_injection"
    ssrf = "ssrf"
    business_logic = "business_logic"          # e.g. missing amount>0 invariant
    broken_object_authz = "broken_object_authz"  # BOLA / IDOR
    broken_auth = "broken_auth"
    mass_assignment = "mass_assignment"
    sensitive_data = "sensitive_data"
    rate_abuse = "rate_abuse"
    other = "other"


class Control(str, Enum):
    """An F5 Distributed Cloud band-aid control (the toolbox)."""
    waf = "waf"                        # signatures + AI WAF: injection & common attacks (request)
    waf_data_guard = "waf_data_guard"  # mask structured secrets (CCN/SSN/token) in RESPONSES
    service_policy = "service_policy"   # per-request L7 allow/deny — surgical positive security
    api_schema = "api_schema"           # import OpenAPI + XC API Security enforcement — systemic
    malicious_user = "malicious_user"   # per-user behavioral risk scoring + mitigation
    bot_defense = "bot_defense"         # automation: credential stuffing, ATO, scraping, carding
    rate_limit = "rate_limit"           # brute force / enumeration scale / velocity


class Coverage(str, Enum):
    full = "full"        # the band-aid blocks the exploit path entirely
    partial = "partial"  # it contains/limits the abuse but leaves residual risk


class Finding(BaseModel):
    id: str = Field(..., description="stable short id, e.g. 'neg-pay-001'")
    title: str
    vuln_class: VulnClass
    severity: Severity
    file: str = Field("", description="repo-relative path (set by the pipeline)")
    line: int = Field(0, description="best-effort line number")
    endpoint: str = Field(
        "", description="the EFFECTIVE HTTP request path a client calls, INCLUDING every router/"
        "blueprint/mount/file-route prefix (e.g. /users/v1/register) — not just the local handler string")
    http_method: str = Field("", description="the HTTP method(s) for that endpoint, e.g. POST")
    description: str
    exploit_sketch: str = Field(..., description="how an attacker would exploit it")
    code_snippet: str = Field("", description="the offending code")


class FindingList(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class Verdict(BaseModel):
    finding_id: str
    is_real: bool = Field(..., description="true iff genuinely exploitable; must agree with confidence")
    confidence: float = Field(
        ..., ge=0, le=1,
        description="calibrated P(genuinely exploitable by an external attacker): 0.9+ you traced "
        "attacker-controlled input to the sink with no effective guard; ~0.5 plausible but you could "
        "not confirm reachability; <0.3 likely a false positive. Must be consistent with is_real.")
    rationale: str


class BandaidOption(BaseModel):
    control: Control
    coverage: Coverage
    recommended: bool = Field(..., description="the primary pick(s) to deploy now")
    rationale: str


class TriageDecision(BaseModel):
    """A finding's band-aid coverage. Band-aids are always temporary; a code cure is
    always produced (code_cure_required is always true). no_bandaid is rare."""
    finding_id: str
    bandaids: list[BandaidOption] = Field(
        default_factory=list,
        description="XC band-aids that mitigate this finding (single or a stack); empty iff no_bandaid",
    )
    no_bandaid: bool = Field(
        False, description="true ONLY when no control or combination can mitigate (rare)"
    )
    residual_risk: str = Field("", description="what the band-aid(s) do NOT cover")
    code_cure_required: bool = Field(
        True, description="always true — every finding gets a code-fix PR; band-aids are temporary"
    )


class TriageBatch(BaseModel):
    decisions: list[TriageDecision] = Field(default_factory=list)


class GeneratedArtifact(BaseModel):
    finding_id: str
    control: Control
    policy_name: str = Field(..., description="kebab-case XC object name")
    spec: dict = Field(..., description="XC config object for this control")
    notes: str = ""


class GeneratedArtifacts(BaseModel):
    # Require ≥1 artifact: a chosen control MUST yield a spec. Without this, a weaker model can
    # satisfy the schema with an empty list — instructor accepts it on the first try and the
    # band-aid silently vanishes (seen with local models). min_length makes instructor retry
    # until the model actually emits the config.
    items: list[GeneratedArtifact] = Field(..., min_length=1)


class RemediationPlan(BaseModel):
    finding_id: str
    summary: str
    file: str
    diff: str = Field(..., description="unified diff (for the PR description / human review)")
    patched_content: str = Field(
        ..., description="the COMPLETE corrected file, written verbatim to a branch to open the PR"
    )
    pr_title: str
    pr_body: str


class ProbeRequest(BaseModel):
    method: str = Field("GET", description="HTTP method: GET/POST/PUT/DELETE/PATCH")
    path: str = Field(..., description="path relative to the target host, e.g. /users/v1/name1/password")
    headers: dict[str, str] = Field(default_factory=dict, description="extra request headers")
    json_body: dict | None = Field(None, description="JSON request body, if the request has one")


class ExploitProbe(BaseModel):
    """A finding-derived validation probe: fire the exploit and confirm the XC band-aid blocks it,
    while a benign request still passes. App-agnostic — XC's block page is detected the same way
    regardless of the backend. Generated per finding so apply/validate isn't tied to one app."""
    finding_id: str
    setup: list[ProbeRequest] = Field(
        default_factory=list,
        description="requests to run first over a shared session (e.g. a login to get a cookie)",
    )
    exploit: ProbeRequest = Field(..., description="the malicious request the band-aid should block")
    legit: ProbeRequest | None = Field(
        None, description="a benign request that should still succeed after the band-aid is applied"
    )
    note: str = ""


class RefinedPolicy(BaseModel):
    """A corrected policy spec produced after a policy FAILED live validation — so the copilot
    never claims a band-aid works when it doesn't actually block the exploit + pass legit traffic."""
    spec: dict = Field(..., description="the FULL corrected XC policy spec (same shape as the failed artifact)")
    rationale: str = Field(..., description="one line: what changed and why")
    unfixable: bool = Field(
        False, description="true only if this control genuinely cannot block the exploit without over-blocking"
    )
    recommend: str = Field("", description="if unfixable: the control to use instead, or 'code_fix_only'")
