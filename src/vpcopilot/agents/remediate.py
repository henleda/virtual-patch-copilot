"""Remediate agent — write the REAL code fix (the cure). Output becomes a GitHub PR.
Every virtual patch is a band-aid; this is what actually closes the vulnerability."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Finding, RemediationPlan

SYSTEM = """You write the permanent code fix for a vulnerability. The XC virtual patch
only buys time; this is the cure.

Produce a MINIMAL, correct unified diff against the cited file that fixes the root cause
(e.g. add an `amount > 0` guard, parameterize a query, add an ownership/authorization
check). Keep the diff focused — do not reformat unrelated code.

Also write:
- pr_title: concise, imperative (e.g. "Reject non-positive amounts in /api/pay").
- pr_body: explain the vulnerability, the exploit, the fix, and note that this PERMANENTLY
  remediates an issue currently held closed by a temporary XC virtual patch (which can be
  retired once this merges)."""


def run(h: Harness, finding: Finding, numbered_code: str) -> RemediationPlan:
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CURRENT FILE ({finding.file}):\n{numbered_code}\n\n"
        "Produce the code fix as a unified diff, plus pr_title and pr_body."
    )
    return h.run("remediate", SYSTEM, user, RemediationPlan)
