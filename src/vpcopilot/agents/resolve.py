"""Resolve agent — turn a security advisory into an exploitation profile, or decline.

The facts (package, affected range, fixed version, CVSS, CWE) are fetched from OSV by code and
handed to this agent already assembled; it never touches the network and never produces a version
number. What it contributes is the one thing OSV does not carry: **what this vulnerability looks
like in an HTTP request** — which paths, which parameters, which headers. That is the input the
existing triage and generate stages need in order to propose a virtual patch.

The most important thing this agent does is refuse. A great many advisories cannot be virtually
patched at a load balancer — a deserialization bug reachable only from a local file, a malicious
build-time dependency, a memory-corruption issue with no request signature. For those the honest
answer is `network_observable=false`, and the pipeline routes them to `no_bandaid` with the
residual risk stated. An agent that obligingly invents a plausible path for every CVE would make
the whole input path worse than useless: it would produce confident band-aids that block nothing
and hide vulnerabilities behind a green check."""
from __future__ import annotations

import json

from ..harness import Harness
from ..schemas import ExploitationProfile

SYSTEM = """You are a vulnerability analyst. Given a security advisory, describe how the
vulnerability manifests IN AN HTTP REQUEST — or state plainly that it cannot be seen in one.

Set network_observable=true ONLY when the advisory describes something a proxy could identify
in a request: a specific URL path or pattern, a parameter, a header, a body shape, a method.
Then fill paths / http_methods / parameters / headers / example_requests with what the
advisory ACTUALLY SUPPORTS.

Set network_observable=false — and this is a correct, expected, frequent answer — when:
- the advisory describes the flaw only in terms of internal functions, classes or config
- exploitation needs local file access, a malicious package at build time, or a crafted file
- it is memory corruption, a crypto weakness, or a denial of service with no request signature
- the text is too vague to name a path, parameter or header
- you are simply not sure

HARD PROHIBITIONS. Violating any of these makes the output actively harmful:
- Do NOT invent a path, parameter or header the advisory does not name or clearly imply.
- Do NOT infer an exploitation pattern from what the package generally does. "It is a web
  framework, so probably /admin" is exactly the reasoning that produces a band-aid which
  blocks nothing while a real vulnerability stays open.
- Do NOT state or guess version numbers. Those are supplied to you and are not yours to edit.
- Do NOT choose a mitigating control. Never say WAF, service policy, rate limit or schema —
  a later stage decides that. Describe the exploit only.
- Do NOT fabricate a file path, line number or code snippet. There is no source code here.

`reason` is required and must justify your network_observable verdict by pointing at what the
advisory does or does not say. "Not enough information" with nothing further is not acceptable;
say WHAT is missing.

`confidence` is your calibrated confidence in the profile: 0.9+ = the advisory names the request
shape explicitly; ~0.5 = you inferred it from a clear description; <0.3 = weak. When
network_observable is false, confidence expresses how sure you are that it CANNOT be observed.

Paths are app-relative and contain no scheme or host (e.g. /static/../../etc/passwd)."""


def run(h: Harness, advisory: dict) -> ExploitationProfile:
    """`advisory` is the normalized OSV record from `inputs.osv.resolve` — already fetched, so the
    agent reasons over facts rather than retrieving them."""
    facts = {k: advisory.get(k) for k in
             ("id", "aliases", "summary", "details", "cwe_ids", "cvss", "affected", "references")}
    user = (
        f"ADVISORY (from OSV.dev, verbatim):\n{json.dumps(facts, indent=2)}\n\n"
        "Describe how this is exploited over HTTP, or state that it cannot be observed in a "
        "request. Remember that declining is a correct answer."
    )
    prof = h.run("resolve", SYSTEM, user, ExploitationProfile)
    prof.advisory_id = advisory.get("id") or prof.advisory_id   # authoritative, as probe.py does
    if not prof.network_observable:
        # Belt and braces: the prompt forbids it, but a model that says "cannot be observed" and
        # then lists paths anyway must not have those paths reach `generate`.
        prof.paths, prof.http_methods = [], []
        prof.parameters, prof.headers, prof.example_requests = [], [], []
    return prof
