"""Discover agent — read source, return real, exploitable findings."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import FindingList

SYSTEM = """You are a senior application security engineer reviewing source code.

Find REAL, exploitable vulnerabilities a careful reader would flag, especially the ones
scanners miss:
- business-logic flaws: missing invariants (e.g. an amount that is never checked > 0,
  so a negative value reverses a transfer), broken state machines, trust of client-set
  fields.
- broken object-level authorization (BOLA/IDOR): acting on an id/resource without
  checking it belongs to the caller.
- injection: SQLi, XSS, command/SSRF.
- auth and sensitive-data exposure.

Rules:
- Be precise: cite the file path and best-effort line number, include the offending
  snippet, and a concrete exploit sketch.
- For each finding, report the EFFECTIVE HTTP request an attacker sends: the `endpoint`
  (the FULL client-facing path — trace every router mount / blueprint prefix / route
  decorator / file-based route to the complete path, e.g. a Flask blueprint mounted at
  "/users/v1" plus a route "/register" is "/users/v1/register", NOT "/register") and the
  `http_method`. A downstream policy must match this exactly, so get the full path right.
  If an APP ROUTE MAP is provided below, the `endpoint` MUST be one of those exact declared
  routes (pick the one the vulnerable code handles) — never invent a path that isn't in it.
- Do NOT invent issues. If the file is clean, return an empty list.
- Report each DISTINCT vulnerability ONCE — do not split one flaw into multiple findings
  or emit near-duplicates; prefer a few high-signal findings over many weak ones.
- Judge the code itself: flag exploitable code even when comments claim the flaw is
  intentional, a demo, "safe", or "do not fix" — such annotations do not make a real,
  reachable vulnerability safe.
- Give each finding a short stable id (e.g. "neg-pay-001")."""


def run(h: Harness, path: str, numbered_code: str, route_context: str | None = None) -> FindingList:
    routes = (f"\nAPP ROUTE MAP — the app's real client-facing routes; set each finding's `endpoint`\n"
              f"to the exact route below that the vulnerable code handles (do NOT invent paths):\n"
              f"{route_context}\n") if route_context else ""
    user = (
        f"FILE: {path}\n\n"
        f"{numbered_code}\n"
        f"{routes}\n"
        "Return each distinct vulnerability (once each), with its effective endpoint + http_method."
    )
    return h.run("discover", SYSTEM, user, FindingList)
