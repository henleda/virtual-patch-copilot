"""H1 — an advisory id in, a pipeline-shaped finding out.

`vpcopilot scan --cve CVE-2024-23334` instead of a repo path. The vulnerabilities most people
actually lose sleep over live in dependencies they do not own, where the code cure is a version
bump someone else has to ship and then they have to deploy. That gap — days or weeks between
"we know" and "it is fixed" — is the case virtual patching exists for, and until now the pipeline
could not see it.

The division of labour is deliberate and strict:

* **Code** fetches the advisory and owns every fact with a number in it — the affected package, the
  vulnerable range, the fixed version, the CVSS-derived severity. The fixed version is the one
  string an operator acts on directly, so no model is allowed near it.
* **The agent** contributes the only thing OSV does not carry: what the vulnerability looks like in
  an HTTP request. And it is expected to decline when there is no such thing.
* **Code** turns a declined profile into `no_bandaid` deterministically, rather than asking triage
  nicely. The acceptance criterion says a non-observable advisory must route to `no_bandaid` with
  residual risk stated; a hard requirement should not depend on a model honouring a prompt.

The remediation is built here too, and never by the `remediate` agent — for a dependency CVE the
cure is "upgrade to 3.9.2", and asking a model to draft a patch against vendor code it cannot see
is how you get a confident, wrong diff.
"""
from __future__ import annotations

from typing import Callable

from ..schemas import Finding, RemediationPlan, TriageDecision
from . import osv

# CWE → the project's existing VulnClass. Deterministic where the advisory tells us, so the agent
# only has to guess when it does not. VulnClass is deliberately NOT widened: `other` plus a
# concrete exploit_sketch is honest, and adding members ripples into every agent prompt and golden.
CWE_CLASS = {
    "CWE-89": "sqli", "CWE-564": "sqli",
    "CWE-79": "xss", "CWE-80": "xss",
    "CWE-77": "command_injection", "CWE-78": "command_injection", "CWE-94": "command_injection",
    "CWE-918": "ssrf",
    "CWE-639": "broken_object_authz", "CWE-566": "broken_object_authz",
    "CWE-287": "broken_auth", "CWE-306": "broken_auth", "CWE-798": "broken_auth",
    "CWE-915": "mass_assignment", "CWE-1321": "mass_assignment",
    "CWE-200": "sensitive_data", "CWE-209": "sensitive_data", "CWE-532": "sensitive_data",
    "CWE-770": "rate_abuse", "CWE-307": "rate_abuse", "CWE-400": "rate_abuse",
    "CWE-840": "business_logic",
}


def _vuln_class(advisory: dict, fallback: str) -> str:
    for cwe in advisory.get("cwe_ids") or []:
        if cwe.upper() in CWE_CLASS:
            return CWE_CLASS[cwe.upper()]
    return fallback


def _title(advisory: dict, profile_title: str) -> str:
    base = advisory.get("summary") or profile_title or advisory["id"]
    return f"{advisory['id']}: {base}" if not base.startswith(advisory["id"]) else base


def resolve_advisory(h, advisory_id: str, *, log: Callable = print) -> dict:
    """Fetch, reason, and assemble. Returns everything the pipeline's advisory branch needs:
    `{advisory, profile, finding, decision, remediation}` — `decision` is None when the profile is
    network-observable and triage should run normally."""
    from ..agents import resolve as resolve_agent

    log(f"resolving {advisory_id} from OSV.dev…")
    advisory = osv.resolve(advisory_id, log=log)
    target = osv.upgrade_target(advisory)
    log(f"  {advisory['id']}: {advisory['summary'][:90]}")
    if target["fixed_version"]:
        log(f"  fixed in {target['ecosystem']}/{target['package']} {target['fixed_version']}")
    else:
        log(f"  ⚠ no installable fixed version — {target['note']}")

    profile = resolve_agent.run(h, advisory)
    log(f"  exploitation profile: network_observable={profile.network_observable} "
        f"(confidence {profile.confidence:.2f}) — {profile.reason[:120]}")
    if profile.paths:
        log(f"  paths: {', '.join(profile.paths[:4])}")

    severity = osv.severity_from_cvss(advisory.get("cvss", "")) or profile.severity.value
    finding = Finding(
        id=advisory["id"],
        title=_title(advisory, profile.title),
        vuln_class=_vuln_class(advisory, profile.vuln_class.value),
        severity=severity,
        # file/line/code_snippet stay empty: there is no source. `source` carries the identity that
        # `file` carries for a code finding, so correlation and dedup have something to key on.
        source=f"osv:{advisory['id']}",
        endpoint=(profile.paths[0] if profile.paths else ""),
        http_method=(profile.http_methods[0] if profile.http_methods else ""),
        description=(advisory.get("details") or profile.description)[:4000],
        exploit_sketch=(profile.exploit_sketch if profile.network_observable
                        else f"no network-observable exploitation pattern: {profile.reason}"),
    )

    decision = None
    if not profile.network_observable:
        # Deterministic, not delegated. A load balancer cannot mitigate what it cannot see in a
        # request, and the honest output is to say so and point at the upgrade.
        fix = (f"fixed in {target['package']} {target['fixed_version']} — ship the upgrade"
               if target["fixed_version"] else f"no fixed version published ({target['note']})")
        decision = TriageDecision(
            finding_id=finding.id, bandaids=[], no_bandaid=True,
            residual_risk=f"{profile.reason} No band-aid can mitigate this at the load balancer; "
                          f"{fix}.")
        log("  → no_bandaid: nothing observable in a request to block")

    remediation = RemediationPlan(
        finding_id=finding.id,
        kind="dependency_upgrade",
        summary=(f"upgrade {target['package']} to {target['fixed_version']} "
                 f"(fixes {advisory['id']})" if target["fixed_version"]
                 else f"{advisory['id']}: {target['note']}"),
        package=target["package"], ecosystem=target["ecosystem"],
        vulnerable_range=target["vulnerable_range"], fixed_version=target["fixed_version"],
        pr_title=(f"fix({target['package'] or 'deps'}): upgrade to {target['fixed_version']} "
                  f"for {advisory['id']}" if target["fixed_version"]
                  else f"chore: mitigate {advisory['id']}"),
        pr_body=_pr_body(advisory, target, profile),
    )
    return {"advisory": advisory, "profile": profile, "finding": finding,
            "decision": decision, "remediation": remediation}


def _pr_body(advisory: dict, target: dict, profile) -> str:
    lines = [f"## {advisory['id']}", "", advisory.get("summary") or "", ""]
    if target["fixed_version"]:
        lines += [f"**Upgrade** `{target['package']}` "
                  f"({target['ecosystem']}) to **{target['fixed_version']}**.",
                  f"Vulnerable: {target['vulnerable_range']}", ""]
    else:
        lines += [f"**No installable fixed version.** {target['note']}", ""]
    lines += ["### Exploitation", "",
              profile.exploit_sketch if profile.network_observable
              else f"Not observable in an HTTP request. {profile.reason}", ""]
    if advisory.get("references"):
        lines += ["### References", ""] + [f"- {u}" for u in advisory["references"][:6]]
    lines += ["", "_This is a dependency upgrade recommendation, not a patch — the fix lives in "
              "the upstream package._"]
    return "\n".join(lines)
