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
    sensitive_data = "sensitive_data"
    rate_abuse = "rate_abuse"
    other = "other"


class Control(str, Enum):
    """Where a finding gets handled."""
    service_policy = "service_policy"   # per-request L7 rule (positive security)
    malicious_user = "malicious_user"   # per-user behavioral mitigation
    both = "both"                       # constrain the request AND catch the actor
    waf = "waf"                         # injection — the AI WAF already handles it
    code_fix_only = "code_fix_only"     # not expressible as an L7 rule


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


class TriageDecision(BaseModel):
    finding_id: str
    control: Control
    rationale: str
    temporary: bool = Field(
        True, description="virtual patches are temporary mitigations, not cures"
    )


class TriageBatch(BaseModel):
    decisions: list[TriageDecision] = Field(default_factory=list)


class GeneratedArtifact(BaseModel):
    finding_id: str
    control: Control
    policy_name: str = Field(..., description="kebab-case XC object name")
    spec: dict = Field(..., description="XC config object (service_policy or malicious_user)")
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
