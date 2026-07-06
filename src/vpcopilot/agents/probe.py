"""Probe agent — turn a finding into a concrete, executable exploit request so apply/validate
works on ANY app, not just the Nimbus demo. The generated `exploit` request is what the XC
band-aid should block; the `legit` request should still pass (proving no over-block)."""
from __future__ import annotations

from ..harness import Harness
from ..schemas import ExploitProbe, Finding

SYSTEM = """You convert a security finding into a concrete HTTP request that reproduces the exploit,
so an automated check can confirm an F5 XC virtual patch blocks it.

Return an ExploitProbe:
- exploit: the SINGLE malicious request that demonstrates the vulnerability (method, path, headers,
  json_body). `path` is relative to the app host, e.g. "/users/v1/name1/password" — no scheme/host.
  Make it the request the band-aid is meant to block, matching the finding's endpoint + technique.
- setup: requests to run FIRST over the SAME session (e.g. a login POST to get an auth cookie/token).
  Empty if the exploit is unauthenticated. Infer credentials/ids from the code or exploit_sketch;
  prefer values the app seeds (a demo/test user visible in the code).
- legit: ONE benign request to the same app that should still succeed after the patch (to prove the
  band-aid doesn't over-block) — usually a normal read on a nearby endpoint.

Base everything on the finding's file, code_snippet, and exploit_sketch. Use realistic values, paths
only (no host), and minimal but valid JSON bodies."""


def run(h: Harness, finding: Finding, current_file: str = "") -> ExploitProbe:
    user = (
        f"FINDING:\n{finding.model_dump_json(indent=2)}\n\n"
        f"FILE ({finding.file}):\n{current_file[:6000]}\n\n"
        f"Return an ExploitProbe (exploit + optional setup + legit) with finding_id={finding.id!r}."
    )
    probe = h.run("probe", SYSTEM, user, ExploitProbe)
    probe.finding_id = finding.id  # authoritative
    return probe
