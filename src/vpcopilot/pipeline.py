"""The deterministic spine: discover -> verify -> triage -> generate + remediate.

The agents reason and return typed artifacts; this code performs the orchestration and
(for now) writes results to disk. No XC or GitHub writes happen here — that is the next
increment, behind a human approval gate with snapshot/rollback and live-LB validation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from .agents import discover, generate, remediate, triage, verify
from .harness import Harness
from .repo_scan import collect_files, read_numbered
from .schemas import Control


def run_pipeline(
    repo_path: str,
    out_dir: str = "out",
    config_path: str | None = None,
    log: Callable[[str], None] = print,
) -> dict:
    h = Harness(config_path)
    root = Path(repo_path)
    files, skipped = collect_files(repo_path)
    log(f"scanning {len(files)} files ({len(skipped)} skipped)")

    # 1) discover (per file) ------------------------------------------------
    findings = []
    file_code: dict[str, str] = {}
    for p in files:
        rel = str(p.relative_to(root))
        code = read_numbered(p)
        file_code[rel] = code
        res = discover.run(h, rel, code)
        for f in res.findings:
            f.file = rel
            findings.append(f)
        if res.findings:
            log(f"  {rel}: {len(res.findings)} candidate finding(s)")
    log(f"discovered {len(findings)} candidate finding(s)")

    # 2) verify (adversarial, per finding) ----------------------------------
    verified = []
    for f in findings:
        v = verify.run(h, f, file_code.get(f.file, ""))
        log(f"  verify {f.id}: {'REAL' if v.is_real else 'refuted'} ({v.confidence:.2f})")
        if v.is_real:
            verified.append(f)
    log(f"{len(verified)} finding(s) verified real")

    decisions, artifacts, remediations = [], [], []
    if verified:
        # 3) triage (batch) -------------------------------------------------
        decisions = triage.run(h, verified).decisions
        by_control = {d.finding_id: d for d in decisions}
        by_id = {f.id: f for f in verified}

        # 4) generate policies + 5) draft code-fix PRs ----------------------
        for d in decisions:
            f = by_id.get(d.finding_id)
            if not f:
                continue
            log(f"  triage {d.finding_id} -> {d.control.value}")
            if d.control in (Control.service_policy, Control.malicious_user, Control.both):
                artifacts.extend(generate.run(h, f, d).items)
            # every verified finding gets a real code fix (band-aid != cure)
            remediations.append(remediate.run(h, f, file_code.get(f.file, "")))

    return _write_out(out_dir, findings, verified, decisions, artifacts, remediations, skipped)


def _write_out(out_dir, findings, verified, decisions, artifacts, remediations, skipped) -> dict:
    out = Path(out_dir)
    (out / "policies").mkdir(parents=True, exist_ok=True)
    (out / "remediations").mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(
        json.dumps([f.model_dump() for f in findings], indent=2)
    )
    (out / "triage.json").write_text(
        json.dumps([d.model_dump() for d in decisions], indent=2)
    )
    for a in artifacts:
        (out / "policies" / f"{a.policy_name}.json").write_text(json.dumps(a.spec, indent=2))
    for r in remediations:
        (out / "remediations" / f"{r.finding_id}.patch").write_text(r.diff)
        (out / "remediations" / f"{r.finding_id}.pr.md").write_text(
            f"# {r.pr_title}\n\n{r.pr_body}\n"
        )

    summary = {
        "candidates": len(findings),
        "verified": len(verified),
        "triage": {d.finding_id: d.control.value for d in decisions},
        "policies": [a.policy_name for a in artifacts],
        "code_fix_prs": [r.finding_id for r in remediations],
        "skipped_files": len(skipped),
        "out_dir": str(out),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary
