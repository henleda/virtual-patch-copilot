"""H2 — dependency manifests in, one band-aid per exploitable advisory out.

H1 answers "here is a CVE, can a load balancer hold the line until the upgrade ships". H2 asks the
same question of every dependency you actually have installed, which is the form the question
normally arrives in: nobody hands you a CVE id, they hand you a `requirements.txt` and a scanner
report. The stages after this one are H1's, unchanged — the resolve agent, the deterministic
`no_bandaid` route for anything not observable in a request, and the OSV-sourced upgrade target.

What is genuinely new is that the input is now **unbounded**, and that changes what correctness
means. `aiohttp` pinned at 3.9.1 alone returns 70 OSV records from one query. A modest manifest
reaches several hundred. Three consequences, all measured against the live API on 2026-07-29:

* **Deduplication is correctness, not thrift.** Those 70 records are 35 advisories — OSV publishes a
  GHSA and a PYSEC entry for each, cross-linked by `aliases` and carrying different ids. Resolving
  both means two model calls and two band-aids for one hole, and the duplicate does not look like
  one. `osv.alias_groups` collapses them before anything is spent.
* **The expensive stage has to be bounded, and the listing must not be.** Every parsed package and
  every advisory found is written to `dependencies.json` whatever happens next — that is the
  acceptance criterion, and it costs one HTTP request per vulnerable package. Only the *agent* stage
  is filtered, by severity and by an explicit cap, and every advisory that filtering held back is
  written out carrying the reason it was held back. "We did not look at this" and "this is fine"
  must never render the same way.
* **A skipped package is a reported package.** A version this tool cannot pin is never guessed at —
  see `manifest.py` for what OSV does with a version string it cannot parse — so `skipped` is part
  of the answer, not debris from producing it.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from ..schemas import Finding, RemediationPlan, TriageDecision
from . import manifest, osv
from .cve import CWE_CLASS

SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_MIN_SEVERITY = "high"
DEFAULT_MAX_ADVISORIES = 25


def _vuln_class(advisory: dict, fallback: str) -> str:
    for cwe in advisory.get("cwe_ids") or []:
        if cwe.upper() in CWE_CLASS:
            return CWE_CLASS[cwe.upper()]
    return fallback


def survey(paths: list[str], *, include_dev: bool = False, log: Callable = print) -> dict:
    """Parse and resolve, with no model and no judgement — the read-only half of H2.

    Everything here is code and HTTP: which packages are installed, which of them OSV knows an
    advisory for, how bad each one is and what version fixes it. This is what `vpcopilot deps`
    prints and what `run_pipeline` hands to the agent stage, and it is deliberately runnable on its
    own: it needs no model, no credentials and no tenant."""
    parsed = manifest.parse_all(paths)
    pkgs = parsed["packages"]
    for e in parsed["errors"]:
        log(f"  ⚠ {e['path']}: {e['error']}")
    considered = [p for p in pkgs if include_dev or p["scope"] == "runtime"]
    excluded = [p for p in pkgs if p not in considered]
    log(f"parsed {len(pkgs)} pinned package(s) from {len(parsed['files'])} manifest(s); "
        f"{len(parsed['skipped'])} entry(ies) could not be pinned")
    if excluded:
        log(f"  {len(excluded)} dev/test-scoped package(s) excluded (--include-dev to include them)")

    hits: dict[str, list[str]] = {}
    if considered:
        log(f"asking OSV about {len(considered)} coordinate(s) in one batch query…")
        hits = osv.query_batch(considered, log=log)
    vulnerable = [p for p in considered if hits.get(osv._coord_key(p))]
    log(f"  {len(vulnerable)} package(s) have at least one advisory")

    records: list[dict] = []
    per_package: dict[str, list[dict]] = {}
    for p in vulnerable:
        try:
            recs = osv.query_package(p, log=log)
        except Exception as e:  # noqa: BLE001 — one package's failure is not the manifest's
            log(f"  ⚠ could not read advisories for {osv._coord_key(p)}: {e}")
            p["error"] = str(e)
            continue
        per_package[osv._coord_key(p)] = recs
        records += recs

    # One candidate per (advisory, package): two packages hit by one advisory are two upgrades
    # somebody has to ship. The resolve agent still runs once per advisory — see `resolve_all`.
    candidates: list[dict] = []
    by_group: dict[str, list[dict]] = {}
    for coord, recs in per_package.items():
        pkg = next(p for p in vulnerable if osv._coord_key(p) == coord)
        for group in osv.alias_groups(recs):
            rec = osv.preferred_record(group)
            adv = osv.normalize_record(rec, group)
            by_group.setdefault(adv["id"], group)
            target = osv.upgrade_target_for(adv, pkg["name"], pkg["ecosystem"], pkg["version"])
            candidates.append({
                "advisory_id": adv["id"], "aliases": adv["aliases"], "advisory": adv,
                "package": pkg["name"], "ecosystem": pkg["ecosystem"],
                "installed": pkg["version"], "scope": pkg["scope"], "manifest": pkg["source"],
                "summary": adv["summary"], "cvss": adv["cvss"],
                "severity": osv.severity_from_cvss(adv["cvss"]),
                "withdrawn": adv.get("withdrawn") or "",
                "fixed_version": target["fixed_version"], "fix_note": target["note"],
                "vulnerable_range": target["vulnerable_range"],
                "references": adv["references"][:4],
                "disposition": "", "reason": "",
            })
    candidates.sort(key=lambda c: (osv.SEVERITY_RANK.get(c["severity"], 9), c["package"],
                                   c["advisory_id"]))
    log(f"  {len(records)} OSV record(s) → {len({c['advisory_id'] for c in candidates})} distinct "
        f"advisory(ies) across {len({c['package'] for c in candidates})} package(s)")
    return {"files": parsed["files"], "errors": parsed["errors"], "packages": pkgs,
            "considered": considered, "dev_excluded": excluded, "skipped": parsed["skipped"],
            "vulnerable": vulnerable, "candidates": candidates, "_groups": by_group,
            "records": len(records)}


def select(candidates: list[dict], *, min_severity: str = DEFAULT_MIN_SEVERITY,
           max_advisories: int = DEFAULT_MAX_ADVISORIES, log: Callable = print) -> list[dict]:
    """Decide which advisories reach the agent, stamping every one that does not with why.

    The filters are ordered so the stamped reason is the *first* thing that disqualified it, which
    is the one a reader needs. Nothing is dropped from the list — `disposition` is set in place, and
    `dependencies.json` carries all of it.

    **The cap is shared out across packages, not consumed in sort order.** The first live run made
    the reason obvious: `aiohttp 3.9.1` alone carries 35 advisories, and a flat
    `(severity, package, id)` ordering handed it 23 of the 25 slots — every other package in the
    manifest was competing with one dependency's back catalogue for the remainder, and a package
    sorting later in the alphabet would have been capped out by advisories no worse than its own.
    So the budget is dealt round-robin: every vulnerable package gives up its worst advisory before
    any package gives up its second. Depth on one dependency is never worth breadth across the tree.
    """
    floor = osv.SEVERITY_RANK.get(min_severity, 1)
    eligible: list[dict] = []
    for c in candidates:
        if c["withdrawn"]:
            c["disposition"], c["reason"] = "withdrawn", f"OSV withdrew this advisory ({c['withdrawn']})"
        elif osv.SEVERITY_RANK.get(c["severity"], 9) > floor:
            c["disposition"] = "below_severity"
            c["reason"] = (f"{c['severity']} is below --min-severity {min_severity}; listed here, "
                           "not resolved")
        else:
            eligible.append(c)

    by_pkg: dict[str, list[dict]] = {}
    for c in eligible:                      # `candidates` arrives severity-sorted, so each queue is
        by_pkg.setdefault(c["package"], []).append(c)   # already worst-first within its package
    chosen: list[dict] = []
    queues = list(by_pkg.values())
    while queues and (not max_advisories or len(chosen) < max_advisories):
        for q in list(queues):
            if max_advisories and len(chosen) >= max_advisories:
                break
            chosen.append(q.pop(0))
            if not q:
                queues.remove(q)
    chosen.sort(key=lambda c: (osv.SEVERITY_RANK.get(c["severity"], 9), c["package"],
                               c["advisory_id"]))
    picked = {id(c) for c in chosen}    # identity, not equality: dicts compare by value
    for c in eligible:
        if id(c) not in picked:
            c["disposition"] = "capped"
            c["reason"] = (f"--max-advisories {max_advisories} reached; {c['package']} had "
                           f"{len(by_pkg[c['package']])} eligible advisory(ies) and the cap is "
                           "shared across packages. Listed here, not resolved")
    for name, label in (("withdrawn", "withdrawn"), ("below_severity", f"below {min_severity}"),
                        ("capped", "over the cap")):
        n = sum(1 for c in candidates if c["disposition"] == name)
        if n:
            log(f"  {n} advisory(ies) {label} — listed in dependencies.json, not resolved")
    return chosen


def resolve_all(h, chosen: list[dict], groups: dict, *, concurrency: int = 8,
                log: Callable = print) -> None:
    """Run the resolve agent once per distinct advisory and stamp the outcome on each candidate.

    Once per *advisory*, not per candidate: the profile answers "what does this vulnerability look
    like in a request", which does not depend on which of the affected packages you happen to have
    installed. Two packages hit by one advisory therefore cost one model call, and — more
    importantly — cannot receive two different verdicts."""
    wanted = list(dict.fromkeys(c["advisory_id"] for c in chosen))
    if not wanted:
        return
    log(f"resolving {len(wanted)} advisory(ies) with the resolve agent "
        f"({len(chosen)} package/advisory pair(s))…")
    adv_by_id = {c["advisory_id"]: c["advisory"] for c in chosen}
    profiles: dict[str, object] = {}

    def _one(aid):
        from ..agents import resolve as resolve_agent
        try:
            return aid, resolve_agent.run(h, adv_by_id[aid]), ""
        except Exception as e:  # noqa: BLE001 — one advisory must not end the manifest run
            return aid, None, str(e)

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for aid, prof, err in ex.map(_one, wanted):
            profiles[aid] = prof
            if err:
                log(f"  ⚠ resolve failed for {aid}: {err} — no band-aid proposed for it")
                for c in chosen:
                    if c["advisory_id"] == aid:
                        c["disposition"], c["reason"] = "resolve_failed", err
    for c in chosen:
        prof = profiles.get(c["advisory_id"])
        if prof is None:
            continue
        c["profile"] = prof
        c["disposition"] = "exploitable" if prof.network_observable else "declined"
        c["reason"] = prof.reason
        c["confidence"] = round(float(prof.confidence), 2)
        c["paths"] = list(prof.paths)
    n_ok = sum(1 for c in chosen if c["disposition"] == "exploitable")
    log(f"  {n_ok} exploitable over HTTP, {sum(1 for c in chosen if c['disposition'] == 'declined')} "
        "declined (nothing a load balancer can see)")


def _finding(c: dict, used: set[str]) -> Finding:
    prof = c["profile"]
    fid = c["advisory_id"]
    n = 1
    while fid in used:      # one advisory hitting two installed packages is two upgrades to ship
        n += 1
        fid = f"{c['advisory_id']}-{n}"
    used.add(fid)
    coord = f"{c['ecosystem']}/{c['package']}@{c['installed']}"
    return Finding(
        id=fid,
        title=f"{c['advisory_id']} in {c['package']} {c['installed']}: "
              f"{c['summary'] or prof.title}"[:300],
        vuln_class=_vuln_class(c["advisory"], prof.vuln_class.value),
        severity=c["severity"],
        # No file, no line: the vulnerable code is in a package we do not own. `source` carries the
        # identity `file` carries for a repo finding, and it names the *installed coordinate* rather
        # than just the advisory — two packages hit by one advisory must not collide.
        source=f"osv:{c['advisory_id']}@{coord}",
        endpoint=(prof.paths[0] if prof.paths else ""),
        http_method=(prof.http_methods[0] if prof.http_methods else ""),
        description=(f"{coord} (from {c['manifest']}) is affected by {c['advisory_id']}. "
                     + (c["advisory"].get("details") or prof.description))[:4000],
        exploit_sketch=(prof.exploit_sketch if prof.network_observable
                        else f"no network-observable exploitation pattern: {prof.reason}"),
    )


def _remediation(c: dict, fid: str) -> RemediationPlan:
    """The cure, built from OSV. `remediate` is never called on this path — see `inputs/cve.py`."""
    fixed, coord = c["fixed_version"], f"{c['package']} {c['installed']}"
    lines = [f"## {c['advisory_id']}", "", c["summary"] or "", "",
             f"`{c['ecosystem']}/{c['package']}` is pinned at **{c['installed']}** in "
             f"`{c['manifest']}`.", ""]
    if fixed:
        lines += [f"**Upgrade to {fixed}.**", f"Vulnerable from: {c['vulnerable_range']}", ""]
    else:
        lines += [f"**No upgrade available.** {c['fix_note']}", ""]
    prof = c.get("profile")
    if prof is not None:
        lines += ["### Exploitation", "",
                  prof.exploit_sketch if prof.network_observable
                  else f"Not observable in an HTTP request. {prof.reason}", ""]
    if c["references"]:
        lines += ["### References", ""] + [f"- {u}" for u in c["references"]]
    lines += ["", "_This is a dependency upgrade recommendation, not a patch — the fix lives in "
              "the upstream package._"]
    return RemediationPlan(
        finding_id=fid, kind="dependency_upgrade",
        summary=(f"upgrade {c['package']} {c['installed']} → {fixed} (fixes {c['advisory_id']})"
                 if fixed else f"{c['advisory_id']} in {coord}: {c['fix_note']}"),
        package=c["package"], ecosystem=c["ecosystem"],
        vulnerable_range=c["vulnerable_range"], fixed_version=fixed,
        pr_title=(f"fix({c['package']}): upgrade to {fixed} for {c['advisory_id']}" if fixed
                  else f"chore: mitigate {c['advisory_id']} in {c['package']}"),
        pr_body="\n".join(lines))


def build(chosen: list[dict]) -> dict:
    """Resolved candidates → the findings, forced decisions and remediations the pipeline consumes.

    A declined advisory becomes a `no_bandaid` decision **here, in code**, exactly as H1 does it: a
    load balancer cannot mitigate what it cannot see in a request, and the acceptance criterion for
    that must not depend on a model honouring a prompt."""
    findings: list[Finding] = []
    decisions: dict[str, TriageDecision] = {}
    remediations: dict[str, RemediationPlan] = {}
    used: set[str] = set()
    for c in chosen:
        if c["disposition"] not in ("exploitable", "declined"):
            continue
        f = _finding(c, used)
        # J5 — advisory tier, same reasoning as H1 (see weakness.py).
        from ..weakness import stamp
        stamp(f, c.get("advisory"))
        c["finding_id"] = f.id
        findings.append(f)
        remediations[f.id] = _remediation(c, f.id)
        if c["disposition"] == "declined":
            fix = (f"upgrade {c['package']} to {c['fixed_version']}" if c["fixed_version"]
                   else f"no fixed version published ({c['fix_note']})")
            decisions[f.id] = TriageDecision(
                finding_id=f.id, bandaids=[], no_bandaid=True,
                residual_risk=f"{c['reason']} No band-aid can mitigate this at the load balancer; "
                              f"{fix}.")
    return {"findings": findings, "decisions": decisions, "remediations": remediations}


def report(surveyed: dict, chosen: list[dict], *, min_severity: str, max_advisories: int,
           include_dev: bool) -> dict:
    """`dependencies.json` — the whole answer, including the parts that cost nothing.

    Every package parsed, every entry refused and why, every advisory found and what became of it.
    The acceptance asks for "affected packages, resolved advisories, and one band-aid per
    exploitable advisory"; the first two are complete here whatever the agent stage did or did not
    reach, so a bounded run still says truthfully what it saw."""
    cands = surveyed["candidates"]
    counts = {d: sum(1 for c in cands if c["disposition"] == d)
              for d in ("exploitable", "declined", "below_severity", "capped", "withdrawn",
                        "resolve_failed", "would_resolve", "")}
    # A package OSV could not be asked about — the batch said it has advisories and the follow-up
    # query failed, or the coordinate could not be checked at all. It was previously visible only
    # as an `error` key buried in `packages[]`: it contributed no advisory rows, no funnel counter
    # and no rendered warning, so it read exactly like a package that came back clean. That is the
    # one confusion this whole module is built to prevent, so it gets its own list and counter.
    unchecked = [{"ecosystem": p.get("ecosystem", ""), "name": p.get("name", ""),
                  "version": p.get("version", ""), "error": p["error"]}
                 for p in surveyed["packages"] if p.get("error")]
    return {
        "manifests": surveyed["files"],
        "errors": surveyed["errors"],
        "unchecked": unchecked,
        "settings": {"min_severity": min_severity, "max_advisories": max_advisories,
                     "include_dev": include_dev},
        "funnel": {
            "packages_parsed": len(surveyed["packages"]),
            "packages_unpinned": len(surveyed["skipped"]),
            "packages_dev_excluded": len(surveyed["dev_excluded"]),
            "packages_queried": len(surveyed["considered"]),
            "packages_unchecked": len(unchecked),
            "packages_vulnerable": len(surveyed["vulnerable"]),
            "osv_records": surveyed["records"],
            "advisories_distinct": len({c["advisory_id"] for c in cands}),
            "package_advisory_pairs": len(cands),
            "resolved": len(chosen),
            # `would_resolve` is the read-only surface's answer: `vpcopilot deps` reaches the same
            # verdict about WHICH advisories a scan would spend a model call on without spending one.
            "would_resolve": counts["would_resolve"],
            "exploitable": counts["exploitable"],
            "declined": counts["declined"],
            "resolve_failed": counts["resolve_failed"],
            "packages_with_a_resolved_advisory": len({c["package"] for c in chosen}),
            "not_resolved": counts["below_severity"] + counts["capped"] + counts["withdrawn"],
        },
        "packages": [{k: v for k, v in p.items() if k != "note"} | {"note": p.get("note", "")}
                     for p in surveyed["packages"]],
        "unpinned": surveyed["skipped"],
        "advisories": [{k: v for k, v in c.items()
                        if k not in ("advisory", "profile")} for c in cands],
    }


def survey_report(paths: list[str], *, min_severity: str = DEFAULT_MIN_SEVERITY,
                  max_advisories: int = DEFAULT_MAX_ADVISORIES, include_dev: bool = False,
                  log: Callable = print) -> dict:
    """Everything H2 can say without a model: `vpcopilot deps` and `GET /api/deps` both call this.

    Same shape as the `dependencies.json` a full scan writes, with each advisory that *would* be
    resolved marked `would_resolve` instead of the verdict only the agent can give. Runs with no
    model configured and no credentials of any kind — the parse-and-list half of the acceptance
    criterion is answerable from OSV alone, and being able to see the funnel before paying for it
    is what makes the severity floor and the cap tunable rather than mysterious."""
    surveyed = survey(paths, include_dev=include_dev, log=log)
    chosen = select(surveyed["candidates"], min_severity=min_severity,
                    max_advisories=max_advisories, log=log)
    for c in chosen:
        c["disposition"] = c["disposition"] or "would_resolve"
    return report(surveyed, chosen, min_severity=min_severity, max_advisories=max_advisories,
                  include_dev=include_dev)


def resolve_manifests(h, paths: list[str], *, min_severity: str = DEFAULT_MIN_SEVERITY,
                      max_advisories: int = DEFAULT_MAX_ADVISORIES, include_dev: bool = False,
                      concurrency: int = 8, log: Callable = print) -> dict:
    """The whole of H2: manifests in, pipeline-shaped artifacts out."""
    surveyed = survey(paths, include_dev=include_dev, log=log)
    chosen = select(surveyed["candidates"], min_severity=min_severity,
                    max_advisories=max_advisories, log=log)
    resolve_all(h, chosen, surveyed["_groups"], concurrency=concurrency, log=log)
    built = build(chosen)
    return {**built, "report": report(surveyed, chosen, min_severity=min_severity,
                                      max_advisories=max_advisories, include_dev=include_dev),
            "candidates": surveyed["candidates"]}
