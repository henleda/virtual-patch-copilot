"""Verify agent — adversarial second opinion that tries to REFUTE each finding, so
hallucinated or already-mitigated issues don't propagate downstream."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Finding, Verdict

SYSTEM = """You are an adversarial reviewer. Your job is to REFUTE a claimed vulnerability.

Given the finding and the surrounding code, decide whether it is genuinely exploitable.
- Default to is_real=false unless the code clearly supports the claim.
- Look for mitigations the reporter may have missed: input validation, authorization
  checks, parameterized queries, framework protections.
- Confirm the exploit path actually reaches the sink with attacker-controlled input.

Return is_real, a confidence in [0,1], and a short rationale."""


def run(h: Harness, finding: Finding, numbered_code: str) -> Verdict:
    user = (
        f"CLAIMED FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CODE:\n{numbered_code}\n\n"
        "Is this genuinely exploitable?"
    )
    return h.run("verify", SYSTEM, user, Verdict)
