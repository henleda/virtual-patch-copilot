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

from . import correlate
from .agents import discover, generate, remediate, triage, verify
from .harness import Harness
from .repo_scan import collect_files, read_numbered


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev(f):
    return f.severity.value if hasattr(f.severity, "value") else f.severity


def _vclass(f):
    return f.vuln_class.value if hasattr(f.vuln_class, "value") else f.vuln_class


def _dedup_findings(findings, log):
    """A6: collapse duplicate findings for one vuln — keyed on (file, vuln_class, endpoint-or-line);
    keeps the highest-severity representative so one vuln yields one band-aid + one code-fix PR."""
    kept, seen = [], {}
    for f in sorted(findings, key=lambda f: _SEV_RANK.get(_sev(f), 9)):
        key = (f.file, _vclass(f), (getattr(f, "endpoint", "") or f"L{f.line}"))
        if key in seen:
            log(f"  dedup: {f.id} duplicates {seen[key]} ({f.file} {key[1]} {key[2]}) — dropped")
            continue
        seen[key] = f.id
        kept.append(f)
    return kept


def run_pipeline(
    repo_path: str,
    out_dir: str = "out",
    config_path: str | None = None,
    min_confidence: float = 0.5,
    concurrency: int = 8,
    max_files: int = 200,
    max_bytes: int = 60_000,
    log: Callable[[str], None] = print,
) -> dict:
    h = Harness(config_path)
    root = Path(repo_path)
    files, skipped = collect_files(repo_path, max_bytes=max_bytes, max_files=max_files)
    log(f"scanning {len(files)} files (caps: --max-files {max_files}, --max-bytes {max_bytes}; "
        f"{len(skipped)} skipped)")
    for reason in ("max-files-reached", "too-large"):
        n = sum(1 for _, r in skipped if r == reason)
        if n:
            log(f"  ⚠ {n} file(s) skipped ({reason}) — raise --max-files/--max-bytes to include them")
    t0 = time.perf_counter()

    # 1) discover (per file, parallel) --------------------------------------
    findings = []
    file_code: dict[str, str] = {}
    file_raw: dict[str, str] = {}

    def _discover(p):
        rel = str(p.relative_to(root))
        try:
            code = read_numbered(p)
            return rel, code, p.read_text(errors="replace"), discover.run(h, rel, code)
        except Exception as e:  # noqa: BLE001 — B6: one bad file must not kill the whole scan
            log(f"  ⚠ discover failed on {rel}: {e} — skipping this file")
            from .schemas import FindingList
            return rel, "", "", FindingList(findings=[])

    # B6: warm instructor's mode-registry once (its lazy init isn't thread-safe) before the fan-out,
    # then discover every file in parallel with per-file error isolation. ex.map preserves order.
    h.warmup()
    disc_results = []
    if files:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            disc_results.extend(ex.map(_discover, files))
    used_ids: set[str] = set()  # A4: the pipeline owns finding ids — a model may reuse one across files
    for rel, code, raw, res in disc_results:
        file_code[rel] = code
        file_raw[rel] = raw
        for f in res.findings:
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
    discover_s = time.perf_counter() - t0
    log(f"discovered {len(findings)} candidate finding(s)")

    # 2) verify (adversarial, per finding, parallel) ------------------------
    t_verify = time.perf_counter()
    verified = []
    refuted = dropped = 0
    confidences: list[float] = []

    def _verify(f):
        try:
            return f, verify.run(h, f, file_code.get(f.file, ""))
        except Exception as e:  # noqa: BLE001 — B6: a failed verify drops that finding, not the scan
            log(f"  ⚠ verify failed on {f.id}: {e} — dropping (fail-closed)")
            return f, None

    # A7: severity-weighted gate — critical/high get a lower bar (miss cost is high),
    # medium/low a higher bar (noise cost dominates), both anchored on min_confidence.
    def _threshold(f):
        shift = -0.1 if _sev(f) in ("critical", "high") else 0.1
        return max(0.0, min(1.0, min_confidence + shift))

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for f, v in ex.map(_verify, findings):
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
    verify_s = time.perf_counter() - t_verify
    log(f"{len(verified)} finding(s) verified real (min-confidence {min_confidence})")

    # 3-5) triage -> generate band-aids -> remediate (code cure) ------------
    t_synth = time.perf_counter()
    decisions, artifacts, remediations, correlations, probes = [], [], [], [], []
    seen_keys: dict[str, str] = {}  # coverage_key -> owning finding_id (B1)
    if verified:
        from .apply import lint_generated_spec
        from .agents import probe as probe_agent

        # A6: collapse duplicate findings so one vuln -> one band-aid + one code-fix PR
        verified = _dedup_findings(verified, log)
        by_id = {f.id: f for f in verified}

        # 3) triage — band-aid coverage per finding. Chunk the batch so a big app (dozens of
        # findings) never sends one giant call that blows the per-call timeout; chunks run in
        # parallel and their decisions are concatenated.
        TRIAGE_CHUNK = 12
        if len(verified) <= TRIAGE_CHUNK:
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
                key = correlate.coverage_key(b.control.value, f.file)
                if key in seen_keys:
                    correlations.append({"finding_id": d.finding_id, "control": b.control.value,
                                         "covered_by": seen_keys[key], "coverage_key": key})
                    log(f"  correlate {d.finding_id}: {b.control.value} already covered by "
                        f"{seen_keys[key]} — skip duplicate band-aid")
                    continue
                seen_keys[key] = d.finding_id
                arts = generate.run(h, f, b.control, b.rationale, exploit=exploit, legit=legit).items
                for a in arts:  # A3/A9: lint the consumed-spec controls now; refiner corrects at apply
                    iss = lint_generated_spec(a.control.value, a.spec, exploit)
                    if iss:
                        log(f"    ⚠ lint {a.policy_name}: {'; '.join(iss)} — refine will correct at apply")
                artifacts.extend(arts)

        # 5) every verified finding gets a real code fix (band-aid != cure) — A5: over ALL
        # verified findings, in parallel, not only those triage handed a band-aid.
        def _remediate(f):
            return remediate.run(h, f, file_raw.get(f.file, ""))

        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            remediations = list(ex.map(_remediate, verified))
    synth_s = time.perf_counter() - t_synth

    # D2) per-stage metrics: timing, discovery, verify precision, dedup ------
    metrics = {
        "timing_s": {"discover": round(discover_s, 2), "verify": round(verify_s, 2),
                     "synthesize": round(synth_s, 2), "total": round(time.perf_counter() - t0, 2)},
        "discovery": {"files": len(files), "skipped_files": len(skipped), "candidates": len(findings)},
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
