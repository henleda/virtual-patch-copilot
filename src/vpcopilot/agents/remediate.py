"""Remediate agent — write the REAL code fix (the cure). Output becomes a GitHub PR.
Every virtual patch is a band-aid; this is what actually closes the vulnerability."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Finding, RemediationPlan

SYSTEM = """You write the permanent code fix for a vulnerability. The XC virtual patch
only buys time; this is the cure.

Given the finding and the CURRENT file contents, return:
- patched_content: the COMPLETE corrected file — the entire file, verbatim, with your fix
  applied and nothing else changed. It will be written to a branch AS-IS to open a PR, so
  it must be the full, valid file (no line-number prefixes, no ellipses, no placeholders).
- diff: a unified diff of your change (for the PR description / human review).
- pr_title: concise, imperative (e.g. "Reject non-positive amounts in /api/pay").
- pr_body: explain the vulnerability, the exploit, and the fix; note that this PERMANENTLY
  remediates an issue currently held closed by a temporary XC virtual patch (which can be
  retired once this merges).

Make the smallest correct change that fixes the root cause (e.g. add an `amount > 0`
guard, parameterize a query, add an ownership/authorization check)."""


def run(h: Harness, finding: Finding, current_file: str) -> RemediationPlan:
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"CURRENT FILE ({finding.file}):\n{current_file}\n\n"
        "Return patched_content (the full corrected file), diff, pr_title, and pr_body."
    )
    return h.run("remediate", SYSTEM, user, RemediationPlan)
