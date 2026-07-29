"""The deterministic spine: discover -> verify -> triage -> generate + remediate.

The agents reason and return typed artifacts; this code orchestrates and (for now)
writes results to disk. No XC or GitHub writes happen here — that is the next increment,
behind a human approval gate with snapshot/rollback and live-LB validation.

Every verified finding gets a code-fix PR (the cure); band-aids are temporary."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import correlate, runmeta
from .agents import discover, generate, remediate, triage, verify
from .config import AGENT_NAMES
from .routes import collect_route_context
from .harness import Harness
from .repo_scan import collect_files, read_numbered


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev(f):
    return f.severity.value if hasattr(f.severity, "value") else f.severity


def _vclass(f):
    return f.vuln_class.value if hasattr(f.vuln_class, "value") else f.vuln_class


def _dedup_findings(findings, log, counter: dict | None = None):
    """A6: collapse duplicate findings for one vuln — keyed on (file, vuln_class, endpoint-or-line);
    keeps the highest-severity representative so one vuln yields one band-aid + one code-fix PR.

    `counter` receives the number dropped, so the count reaches `metrics.json` instead of only the
    log — the residue the old `BACKLOG.md` per-stage-metrics item left behind."""
    kept, seen = [], {}
    for f in sorted(findings, key=lambda f: _SEV_RANK.get(_sev(f), 9)):
        # `f.file` is always set on the repo path (pipeline sets it after discover), so the
        # fallback is structurally unreachable there — advisory findings, which have no file,
        # would otherwise all key on ("", class, "L0") and silently collapse into one.
        ident = f.file or getattr(f, "source", "") or f.id
        key = (ident, _vclass(f), (getattr(f, "endpoint", "") or f"L{f.line}"))
        if key in seen:
            log(f"  dedup: {f.id} duplicates {seen[key]} ({ident} {key[1]} {key[2]}) — dropped")
            continue
        seen[key] = f.id
        kept.append(f)
    if counter is not None:
        counter["duplicates_dropped"] = len(findings) - len(kept)
    return kept


def run_pipeline(
    repo_path: str | None = None,
    out_dir: str = "out",
    config_path: str | None = None,
    min_confidence: float = 0.5,
    concurrency: int = 8,
    max_files: int = 200,
    max_bytes: int = 60_000,
    draft_code_fixes: bool = True,   # off = skip remediation (band-aids only); saves ~half the tokens
    log: Callable[[str], None] = print,
    advisory: str | None = None,     # H1: appended AFTER log so no positional call can shift
    spec_path: str | None = None,    # H3: an OpenAPI spec — alone, or alongside a repo
) -> dict:
    # H1 — exactly one input. Deliberately a hard error rather than a silent no-op: today
    # `run_pipeline("/does/not/exist")` completes and writes a full set of empty artifacts, and
    # that is the failure mode not to extend.
    # H1/H3 — repo and advisory are alternatives; a spec is additive. `--spec` alone scans the
    # contract; `--spec` with a repo also cross-checks the two for orphans, which needs both.
    if advisory and (repo_path or spec_path):
        raise ValueError("--cve scans one advisory; it cannot be combined with a repo or --spec")
    if not (repo_path or advisory or spec_path):
        raise ValueError("pass a repo path, an advisory id (--cve), or an OpenAPI spec (--spec)")
    h = Harness(config_path)
    h.warmup()   # B6: warm instructor's mode registry before ANY fan-out — both inputs need it
    t0, started = time.perf_counter(), runmeta.utc_now()
    dedup_counter: dict = {}
    root = Path(repo_path) if repo_path else None
    files, skipped = [], []
    file_code: dict[str, str] = {}
    file_raw: dict[str, str] = {}
    route_ctx = None
    findings: list = []
    spec_code: dict[str, str] = {}      # H3: spec name -> the text handed to discover
    spec_orphans: dict | None = None
    forced_decision = forced_remediation = None
    advisory_meta: dict | None = None

    if advisory:
        # H1 — an advisory produces ONE finding and then joins the ordinary stages. There is no
        # repo to walk, nothing to verify a second time (OSV already asserts the vulnerability is
        # real; re-litigating it against source we do not have would only invent doubt), so the
        # branch supplies `findings` directly and everything from triage down runs unchanged.
        from .inputs.cve import resolve_advisory
        res = resolve_advisory(h, advisory, log=log)
        findings = [res["finding"]]
        forced_decision, forced_remediation = res["decision"], res["remediation"]
        advisory_meta = {"id": res["advisory"]["id"], "source": "osv",
                         "consulted": res["advisory"]["consulted"],
                         "network_observable": res["profile"].network_observable,
                         "fixed_version": res["remediation"].fixed_version}
        discover_s = time.perf_counter() - t0
    else:
        if repo_path:
            files, skipped = collect_files(repo_path, max_bytes=max_bytes, max_files=max_files)
        log(f"scanning {len(files)} files (caps: --max-files {max_files}, --max-bytes {max_bytes}; "
            f"{len(skipped)} skipped)")
        for reason in ("max-files-reached", "too-large"):
            n = sum(1 for _, r in skipped if r == reason)
            if n:
                log(f"  ⚠ {n} file(s) skipped ({reason}) — raise --max-files/--max-bytes to include them")

        # Ground endpoints in the app's DECLARED routes (OpenAPI spec / framework registrations) so a
        # weaker model looks a finding's path up instead of hallucinating it — and warn loudly if none.
        route_ctx = collect_route_context(repo_path) if repo_path else None
        if spec_path:
            # H3 — the spec is fed to `discover` as one more file rather than through a fourth
            # agent. Its whole job is "read this and tell me what is wrong with it", and routing
            # the spec through the existing stage means these findings verify, triage and generate
            # exactly like a code finding, with no parallel path to keep in step.
            from .inputs.openapi import as_scan_input, load_spec, orphans
            spec_name, spec_text = as_scan_input(spec_path)
            spec_code[spec_name] = spec_text
            log(f"reading OpenAPI spec {spec_path} as a discovery input")
            if repo_path and route_ctx:
                o = orphans(load_spec(spec_path), route_ctx.splitlines())
                spec_orphans = o
                log(f"  spec vs code: {len(o['matched'])} matched, "
                    f"{len(o['spec_only'])} declared-but-unserved, {len(o['code_only'])} undeclared")
        if route_ctx:
            log("route context: found the app's declared routes — grounding finding endpoints (no guessing)")
        else:
            log("  ⚠ NO app route context found (no OpenAPI/Swagger spec or route registrations detected) "
                "— finding endpoints are INFERRED and may be inaccurate")

    # 1) discover (per file, parallel) --------------------------------------
    def _discover(p):
        rel = str(p.relative_to(root))
        try:
            code = read_numbered(p)
            return rel, code, p.read_text(errors="replace"), discover.run(h, rel, code, route_context=route_ctx)
        except Exception as e:  # noqa: BLE001 — B6: one bad file must not kill the whole scan
            log(f"  ⚠ discover failed on {rel}: {e} — skipping this file")
            from .schemas import FindingList
            return rel, "", "", FindingList(findings=[])

    # B6: instructor's mode registry is warmed at the top of run_pipeline (its lazy init isn't
    # thread-safe) — discover every file in parallel with per-file error isolation. ex.map
    # preserves order.
    disc_results = []
    if files:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            disc_results.extend(ex.map(_discover, files))
    for spec_name, spec_text in spec_code.items():
        # The spec joins the same result list, so it flows through verify/triage/generate unchanged.
        try:
            disc_results.append((spec_name, spec_text, spec_text,
                                 discover.run(h, spec_name, spec_text, route_context=route_ctx)))
        except Exception as e:  # noqa: BLE001 — a bad spec must not kill a repo scan alongside it
            from .schemas import FindingList
            log(f"  ⚠ discover failed on {spec_name}: {e} — skipping the spec")
            disc_results.append((spec_name, spec_text, spec_text, FindingList(findings=[])))
    used_ids: set[str] = set()  # A4: the pipeline owns finding ids — a model may reuse one across files
    for rel, code, raw, res in disc_results:
        file_code[rel] = code
        file_raw[rel] = raw
        for f in res.findings:
            if rel in spec_code:
                # H3 — a spec is ONE file declaring MANY endpoints, so `file` is the wrong identity
                # for it: `endpoint_of("pay-api.yaml")` is the same string for every finding, and
                # all six would collapse onto one service_policy coverage key with five of them
                # logged "already covered". Leave `file` empty and let the endpoint be the identity,
                # exactly as an advisory does.
                f.source, f.file, f.line = f"openapi:{rel}", "", 0
            else:
                f.file = rel
            base, fid, n = (f.id or "finding"), (f.id or "finding"), 1
            while fid in used_ids:
                n += 1
                fid = f"{base}-{n}"
            f.id = fid
            used_ids.add(fid)
            findings.append(f)
        if res.findings:
            log(f"  {rel}: {len(res.findings)} candidate finding(s)")
    if not advisory:
        discover_s = time.perf_counter() - t0
        log(f"discovered {len(findings)} candidate finding(s)")

    # 2) verify (adversarial, per finding, parallel) ------------------------
    t_verify = time.perf_counter()
    verified = []
    refuted = dropped = 0
    confidences: list[float] = []

    def _verify(f):
        try:
            return f, verify.run(h, f, file_code.get(f.file, ""), route_context=route_ctx)
        except Exception as e:  # noqa: BLE001 — B6: a failed verify drops that finding, not the scan
            log(f"  ⚠ verify failed on {f.id}: {e} — dropping (fail-closed)")
            return f, None

    # A7: severity-weighted gate — critical/high get a lower bar (miss cost is high),
    # medium/low a higher bar (noise cost dominates), both anchored on min_confidence.
    def _threshold(f):
        shift = -0.1 if _sev(f) in ("critical", "high") else 0.1
        return max(0.0, min(1.0, min_confidence + shift))

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        # H1 — an advisory run has no source to read, and verify's entire method is reading the
        # offending code. OSV already asserts the vulnerability is real; re-litigating it against
        # code we do not have would only manufacture doubt. The resolve agent's own confidence is
        # the gate instead, applied in inputs/cve.py.
        for f, v in (ex.map(_verify, findings) if not advisory else []):
            if v is None:  # B6: verify errored — count as dropped, keep going
                dropped += 1
                continue
            thr = _threshold(f)
            if v.is_real and v.confidence >= thr:
                verified.append(f)
                confidences.append(v.confidence)
                log(f"  verify {f.id}: REAL ({v.confidence:.2f} ≥ {thr:.2f} for {_sev(f)})")
            elif v.is_real:
                dropped += 1
                log(f"  verify {f.id}: REAL but below {thr:.2f} ({_sev(f)}) — dropped ({v.confidence:.2f})")
            else:
                refuted += 1
                log(f"  verify {f.id}: refuted ({v.confidence:.2f})")
    if spec_orphans and (spec_orphans["spec_only"] or spec_orphans["code_only"]):
        # Deterministic, no agent: this is a comparison of two documents. Both directions matter and
        # they fail differently — a declared-but-unserved endpoint is dead documentation or a shadow
        # API, while a served-but-undeclared route is what an api_schema band-aid built from this
        # spec would start rejecting the moment it is applied.
        from .schemas import Finding
        so, co = spec_orphans["spec_only"], spec_orphans["code_only"]
        bits = []
        if so:
            bits.append("declared in the spec but served by no route in the code: "
                        + ", ".join(so[:15]) + (f" (+{len(so) - 15} more)" if len(so) > 15 else ""))
        if co:
            bits.append("served by the code but absent from the spec: "
                        + ", ".join(co[:15]) + (f" (+{len(co) - 15} more)" if len(co) > 15 else ""))
        orphan = Finding(
            id="undocumented_or_orphaned",
            title="Spec and code disagree about which endpoints exist",
            vuln_class="other", severity="medium", source=f"openapi:{Path(spec_path).name}",
            description="; ".join(bits) + ". "
            + ("An endpoint nobody serves is dead documentation or a shadow API that was removed "
               "from one place and not the other. " if so else "")
            + ("An endpoint the spec does not declare is outside whatever a schema-based control "
               "enforces — and applying an api_schema band-aid built from this spec would begin "
               "rejecting it." if co else ""),
            exploit_sketch=("Undeclared routes are the surface an attacker reaches that a "
                            "schema-based control never sees." if co
                            else "Declared-but-unserved endpoints indicate the spec and the "
                                 "deployment have drifted; the schema may not describe what is "
                                 "actually exposed."))
        # Appended AFTER verify, to both lists: this is a comparison of two documents, not a claim
        # about code. Sending it through the verify agent asked a reviewer to confirm a
        # vulnerability in source it cannot see, and it duly refuted it at 0.10 confidence.
        findings.append(orphan)
        verified.append(orphan)
        log(f"  undocumented_or_orphaned: {len(so)} declared-but-unserved, "
            f"{len(co)} served-but-undeclared")

    if advisory:
        verified = list(findings)
    verify_s = time.perf_counter() - t_verify
    if not advisory:
        log(f"{len(verified)} finding(s) verified real (min-confidence {min_confidence})")

    # 3-5) triage -> generate band-aids -> remediate (code cure) ------------
    t_synth = time.perf_counter()
    decisions, artifacts, remediations, correlations, probes = [], [], [], [], []
    seen_keys: dict[str, str] = {}  # coverage_key -> owning finding_id (B1)
    if verified:
        from .apply import lint_generated_spec
        from .agents import probe as probe_agent

        # A6: collapse duplicate findings so one vuln -> one band-aid + one code-fix PR
        verified = _dedup_findings(verified, log, dedup_counter)
        by_id = {f.id: f for f in verified}

        # 3) triage — band-aid coverage per finding. Chunk the batch so a big app (dozens of
        # findings) never sends one giant call that blows the per-call timeout; chunks run in
        # parallel and their decisions are concatenated.
        TRIAGE_CHUNK = 12
        if forced_decision is not None:
            # H1 — the advisory has no network-observable exploitation pattern, so no control at a
            # load balancer can mitigate it. That is a fact about the advisory, not a judgement
            # call, and the acceptance requires it: routing it to `no_bandaid` in code rather than
            # asking triage nicely is what makes it a guarantee instead of a hope.
            decisions = [forced_decision]
        elif len(verified) <= TRIAGE_CHUNK:
            decisions = triage.run(h, verified).decisions
        else:
            chunks = [verified[i:i + TRIAGE_CHUNK] for i in range(0, len(verified), TRIAGE_CHUNK)]
            log(f"triaging {len(verified)} findings in {len(chunks)} batches of ≤{TRIAGE_CHUNK}")

            def _triage(ch):
                try:
                    return triage.run(h, ch).decisions
                except Exception as e:  # noqa: BLE001 — one bad batch shouldn't lose the rest
                    log(f"  ⚠ triage batch failed ({e}); routing those {len(ch)} to code-only")
                    from .schemas import TriageDecision
                    return [TriageDecision(finding_id=f.id, bandaids=[], no_bandaid=True,
                                           residual_risk="triage failed — code fix only") for f in ch]

            decisions = []
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                for ds in ex.map(_triage, chunks):
                    decisions.extend(ds)

        # A2: derive validation probes BEFORE generate, so each band-aid is built against the
        # finding's CONCRETE exploit (exact method + full path) and spares its legit request.
        bandaided = [by_id[d.finding_id] for d in decisions if not d.no_bandaid and d.finding_id in by_id]

        def _probe(f):
            try:
                return probe_agent.run(h, f, file_raw.get(f.file, "")).model_dump()
            except Exception:  # noqa: BLE001
                return None

        if bandaided:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                probes = [p for p in ex.map(_probe, bandaided) if p]
            log(f"generated {len(probes)} finding-derived validation probe(s)")
        probe_by_id = {p["finding_id"]: p for p in probes}

        # 4) generate recommended band-aid(s), skipping ones an earlier finding covers
        for d in decisions:
            f = by_id.get(d.finding_id)
            if not f:
                continue
            if d.no_bandaid:
                log(f"  triage {d.finding_id} -> NO BAND-AID (code cure only)")
                continue
            tags = ", ".join(
                f"{b.control.value}({b.coverage.value}{'*' if b.recommended else ''})"
                for b in d.bandaids
            )
            log(f"  triage {d.finding_id} -> {tags}")
            pr = probe_by_id.get(d.finding_id) or {}
            exploit, legit = pr.get("exploit"), pr.get("legit")
            for b in [b for b in d.bandaids if b.recommended] or d.bandaids:
                key = correlate.coverage_key(b.control.value, f.file,
                                             identity=f.endpoint or getattr(f, "source", "") or f.id)
                if key in seen_keys:
                    correlations.append({"finding_id": d.finding_id, "control": b.control.value,
                                         "covered_by": seen_keys[key], "coverage_key": key})
                    log(f"  correlate {d.finding_id}: {b.control.value} already covered by "
                        f"{seen_keys[key]} — skip duplicate band-aid")
                    continue
                seen_keys[key] = d.finding_id
                try:  # B6: a model that can't emit this band-aid must not kill the scan (or vanish silently)
                    arts = generate.run(h, f, b.control, b.rationale, exploit=exploit, legit=legit).items
                except Exception as e:  # noqa: BLE001
                    seen_keys.pop(key, None)  # coverage wasn't established — let a sibling finding retry it
                    log(f"    ⚠ generate produced no {b.control.value} band-aid for {d.finding_id}: {e} "
                        f"— code fix only")
                    continue
                for a in arts:  # A3/A9: lint the consumed-spec controls now; refiner corrects at apply
                    iss = lint_generated_spec(a.control.value, a.spec, exploit)
                    if iss:
                        log(f"    ⚠ lint {a.policy_name}: {'; '.join(iss)} — refine will correct at apply")
                artifacts.extend(arts)

        # 5) every verified finding gets a real code fix (band-aid != cure) — A5: over ALL
        # verified findings, in parallel, not only those triage handed a band-aid. Skippable
        # (draft_code_fixes) to save the biggest chunk of tokens when only band-aids are wanted.
        if forced_remediation is not None:
            # H1 — the cure for a dependency CVE is a version bump in someone else's package.
            # There is no file of ours to patch, and asking a model to draft a diff against vendor
            # code it cannot see is how you get a confident, wrong patch. The version comes from
            # OSV; `remediate` is never called on this path.
            remediations = [forced_remediation]
            log(f"cure: {forced_remediation.summary}")
        elif draft_code_fixes:
            def _remediate(f):
                return remediate.run(h, f, file_raw.get(f.file, ""))

            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                remediations = list(ex.map(_remediate, verified))
        else:
            log(f"skipping code-fix drafting for {len(verified)} finding(s) (draft_code_fixes=off)")
    synth_s = time.perf_counter() - t_synth

    # D2) per-stage metrics: timing, discovery, verify precision, dedup ------
    metrics = {
        "timing_s": {"discover": round(discover_s, 2), "verify": round(verify_s, 2),
                     "synthesize": round(synth_s, 2), "total": round(time.perf_counter() - t0, 2)},
        "discovery": {"files": len(files), "skipped_files": len(skipped), "candidates": len(findings),
                      "duplicates_dropped": dedup_counter.get("duplicates_dropped", 0)},
        "verify": {"candidates": len(findings), "verified": len(verified), "refuted": refuted,
                   "dropped_low_confidence": dropped,
                   "confirm_rate": round(len(verified) / len(findings), 2) if findings else 0.0,
                   "avg_confidence": round(sum(confidences) / len(confidences), 2) if confidences else 0.0,
                   "min_confidence": min_confidence},
        "synthesize": {"policies": len(artifacts), "dupe_bandaids_collapsed": len(correlations),
                       "code_fix_prs": len(remediations)},
    }
    summary = _write_out(out_dir, findings, verified, decisions, artifacts, remediations,
                         correlations, skipped, metrics, probes)
    # F3) run manifest — what was scanned, at which commit, by whom, with which models and caps.
    # Every audit entry carries this run_id, so an exported bundle explains its own provenance.
    # Fail-soft: provenance is evidence, not a gate — never fail a completed scan over it.
    try:
        cfg = getattr(h, "cfg", None)
        runmeta.write_manifest(
            out_dir, repo=str(root.resolve()) if root else None, advisory=advisory_meta,
            input_kind=("advisory" if advisory else
                        ("repo+spec" if (repo_path and spec_path) else
                         ("spec" if spec_path else "repo"))),
            spec=str(Path(spec_path).resolve()) if spec_path else None,
            config_path=config_path, started=started,
            models={a: cfg.for_agent(a).model for a in AGENT_NAMES} if cfg else None,
            caps={"min_confidence": min_confidence, "max_files": max_files, "max_bytes": max_bytes,
                  "draft_code_fixes": draft_code_fixes},
            counts={"candidates": len(findings), "verified": len(verified), "policies": len(artifacts),
                    "code_fix_prs": len(remediations)},
            finished=runmeta.utc_now(), **(runmeta.git_provenance(root) if root else {}))
    except Exception as e:  # noqa: BLE001
        log(f"  ⚠ could not write the run manifest (run.json): {e} — an audit export will lack provenance")
    from . import report  # E3: drop a standalone shareable HTML dashboard of the results
    log(f"wrote {report.write_report(out_dir)}")
    return summary


def _write_out(out_dir, findings, verified, decisions, artifacts, remediations, correlations,
               skipped, metrics=None, probes=None) -> dict:
    out = Path(out_dir)
    (out / "policies").mkdir(parents=True, exist_ok=True)
    (out / "remediations").mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    (out / "triage.json").write_text(json.dumps([d.model_dump() for d in decisions], indent=2))
    (out / "remediations.json").write_text(json.dumps([r.model_dump() for r in remediations], indent=2))
    (out / "correlations.json").write_text(json.dumps(correlations, indent=2))
    (out / "probes.json").write_text(json.dumps(probes or [], indent=2))  # finding-derived exploit probes
    for a in artifacts:
        (out / "policies" / f"{a.control.value}.{a.policy_name}.json").write_text(
            json.dumps(a.spec, indent=2)
        )
    (out / "policies.json").write_text(json.dumps(  # index: policy -> finding, for apply/ledger linkage
        [{"finding_id": a.finding_id, "control": a.control.value, "policy_name": a.policy_name} for a in artifacts],
        indent=2))
    for r in remediations:
        (out / "remediations" / f"{r.finding_id}.patch").write_text(r.diff)
        (out / "remediations" / f"{r.finding_id}.pr.md").write_text(f"# {r.pr_title}\n\n{r.pr_body}\n")

    (out / "metrics.json").write_text(json.dumps(metrics or {}, indent=2))
    summary = {
        "candidates": len(findings),
        "verified": len(verified),
        "metrics": metrics or {},
        "triage": {
            d.finding_id: ([b.control.value for b in d.bandaids] or "no_bandaid")
            for d in decisions
        },
        "no_bandaid": [d.finding_id for d in decisions if d.no_bandaid],
        "policies": [f"{a.control.value}/{a.policy_name}" for a in artifacts],
        "code_fix_prs": [r.finding_id for r in remediations],
        "correlations": [f"{c['finding_id']} covered-by {c['covered_by']} ({c['control']})" for c in correlations],
        "skipped_files": len(skipped),
        "out_dir": str(out),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    from . import ledger  # seed the remediation ledger (found)
    ledger.init_from_scan(out_dir, [f.model_dump() for f in findings],
                          [d.model_dump() for d in decisions],
                          [r.model_dump() for r in remediations])
    return summary
