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


def run_pipeline(
    repo_path: str,
    out_dir: str = "out",
    config_path: str | None = None,
    min_confidence: float = 0.5,
    concurrency: int = 8,
    log: Callable[[str], None] = print,
) -> dict:
    h = Harness(config_path)
    root = Path(repo_path)
    files, skipped = collect_files(repo_path)
    log(f"scanning {len(files)} files ({len(skipped)} skipped)")
    t0 = time.perf_counter()

    # 1) discover (per file, parallel) --------------------------------------
    findings = []
    file_code: dict[str, str] = {}
    file_raw: dict[str, str] = {}

    def _discover(p):
        rel = str(p.relative_to(root))
        code = read_numbered(p)
        return rel, code, p.read_text(errors="replace"), discover.run(h, rel, code)

    # First call runs solo to warm instructor's mode registry (its lazy init isn't
    # thread-safe); the rest run in parallel. ex.map preserves input order.
    disc_results = []
    if files:
        disc_results.append(_discover(files[0]))
        if len(files) > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                disc_results.extend(ex.map(_discover, files[1:]))
    for rel, code, raw, res in disc_results:
        file_code[rel] = code
        file_raw[rel] = raw
        for f in res.findings:
            f.file = rel
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
        return f, verify.run(h, f, file_code.get(f.file, ""))

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for f, v in ex.map(_verify, findings):
            if v.is_real and v.confidence >= min_confidence:
                verified.append(f)
                confidences.append(v.confidence)
                log(f"  verify {f.id}: REAL ({v.confidence:.2f})")
            elif v.is_real:
                dropped += 1
                log(f"  verify {f.id}: REAL but below min-confidence {min_confidence} — dropped ({v.confidence:.2f})")
            else:
                refuted += 1
                log(f"  verify {f.id}: refuted ({v.confidence:.2f})")
    verify_s = time.perf_counter() - t_verify
    log(f"{len(verified)} finding(s) verified real (min-confidence {min_confidence})")

    # 3-5) triage -> generate band-aids -> remediate (code cure) ------------
    t_synth = time.perf_counter()
    decisions, artifacts, remediations, correlations = [], [], [], []
    seen_keys: dict[str, str] = {}  # coverage_key -> owning finding_id (B1)
    if verified:
        # 3) triage (batch) — band-aid coverage per finding -----------------
        decisions = triage.run(h, verified).decisions
        by_id = {f.id: f for f in verified}

        for d in decisions:
            f = by_id.get(d.finding_id)
            if not f:
                continue
            if d.no_bandaid:
                log(f"  triage {d.finding_id} -> NO BAND-AID (code cure only)")
            else:
                tags = ", ".join(
                    f"{b.control.value}({b.coverage.value}{'*' if b.recommended else ''})"
                    for b in d.bandaids
                )
                log(f"  triage {d.finding_id} -> {tags}")
                # 4) generate recommended band-aid(s), skipping ones an earlier finding covers
                for b in [b for b in d.bandaids if b.recommended] or d.bandaids:
                    key = correlate.coverage_key(b.control.value, f.file)
                    if key in seen_keys:
                        correlations.append({"finding_id": d.finding_id, "control": b.control.value,
                                             "covered_by": seen_keys[key], "coverage_key": key})
                        log(f"  correlate {d.finding_id}: {b.control.value} already covered by "
                            f"{seen_keys[key]} — skip duplicate band-aid")
                        continue
                    seen_keys[key] = d.finding_id
                    artifacts.extend(generate.run(h, f, b.control, b.rationale).items)
            # 5) every verified finding gets a real code fix (band-aid != cure)
            remediations.append(remediate.run(h, f, file_raw.get(f.file, "")))
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
                         correlations, skipped, metrics)
    from . import report  # E3: drop a standalone shareable HTML dashboard of the results
    log(f"wrote {report.write_report(out_dir)}")
    return summary


def _write_out(out_dir, findings, verified, decisions, artifacts, remediations, correlations,
               skipped, metrics=None) -> dict:
    out = Path(out_dir)
    (out / "policies").mkdir(parents=True, exist_ok=True)
    (out / "remediations").mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    (out / "triage.json").write_text(json.dumps([d.model_dump() for d in decisions], indent=2))
    (out / "remediations.json").write_text(json.dumps([r.model_dump() for r in remediations], indent=2))
    (out / "correlations.json").write_text(json.dumps(correlations, indent=2))
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
