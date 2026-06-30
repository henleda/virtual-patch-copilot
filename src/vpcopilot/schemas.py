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
    description: str
    exploit_sketch: str = Field(..., description="how an attacker would exploit it")
    code_snippet: str = Field("", description="the offending code")


class FindingList(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class Verdict(BaseModel):
    finding_id: str
    is_real: bool
    confidence: float = Field(..., ge=0, le=1)
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
    items: list[GeneratedArtifact] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    finding_id: str
    summary: str
    file: str
    diff: str = Field(..., description="unified diff implementing the real code fix")
    pr_title: str
    pr_body: str
