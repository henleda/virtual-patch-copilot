"""Triage agent — route each verified finding to the right control (or to code)."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import Finding, TriageBatch

SYSTEM = """You route each verified vulnerability to the right F5 Distributed Cloud
control, or to a code fix. Choose exactly one control per finding:

- service_policy: a per-REQUEST L7 rule (path/method/header/query/body matchers,
  allow or deny). Best for input/invariant constraints expressible on a single request,
  e.g. "amount must be positive", blocking a parameter the UI never sends, enforcing a
  schema/pattern (positive security).
- malicious_user: per-USER behavioral mitigation. XC scores a user's behavior across
  many requests (failed logins, forbidden access, WAF hits, velocity) and can challenge
  or block bad actors. Best for credential stuffing, BOLA/IDOR *enumeration*, scraping,
  and rate/velocity abuse.
- both: when you should constrain the request AND catch the abusive actor.
- waf: injection (SQLi/XSS/command). The AI WAF already handles these — do NOT write a
  service policy for them.
- code_fix_only: deep logic only the application can enforce (auth context, balance
  math) that cannot be expressed as an edge rule.

IMPORTANT: service_policy / malicious_user / both are TEMPORARY mitigations (band-aids),
never cures — set temporary=true. The permanent fix is always a code change, produced
separately. Give a one-line rationale per finding."""


def run(h: Harness, verified: list[Finding]) -> TriageBatch:
    blob = "\n\n".join(f.model_dump_json(indent=2) for f in verified)
    user = f"Triage these verified findings and return one decision each:\n\n{blob}"
    return h.run("triage", SYSTEM, user, TriageBatch)
