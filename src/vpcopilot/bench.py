"""Benchmark: run the scan against a labeled answer key and score it.

Measures discovery recall (did we find each known vuln), triage accuracy (did a
recommended control intersect the acceptable set, or no_bandaid when expected), and
flags extra findings not in the key. Lets us tell whether a prompt change helped.

Matching is BEST-match: among findings that fit a key entry's file + class, prefer one
whose triage satisfies the expectation (so two same-class findings in one file don't get
mis-paired)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import yaml

from .pipeline import run_pipeline

# The agent's class label varies; accept compatible labels per expected class.
COMPAT = {
    "broken_auth": {"broken_auth", "broken_object_authz", "other"},
    "broken_object_authz": {"broken_object_authz", "broken_auth", "other"},
    "rate_abuse": {"rate_abuse", "broken_auth", "other"},
    "sensitive_data": {"sensitive_data", "other"},
    "mass_assignment": {"mass_assignment", "sqli", "other"},
    "ssrf": {"ssrf", "other"},
    "business_logic": {"business_logic", "other"},
    "sqli": {"sqli"},
}


def _policy_quality(out: Path) -> tuple[int, int]:
    """(generated, lint-flagged) over the policies a run actually emitted.

    Beyond the stated G4 acceptance, and added because the first real four-way run proved the table
    would otherwise mislead: one model scored precision 1.00 and triage 1.00 while emitting `{}` as
    the spec for three of its policies. Recall, precision and triage all say the routing was right;
    none of them notice that the artifact is unusable. This reuses `lint_generated_spec`, which the
    pipeline already runs — no new judgement, just a count that reaches the scorecard.

    Counted from THIS run's `policies.json` index, not from the files on disk: a re-scan into an
    existing out dir leaves the previous run's artifacts in `policies/` (32 files for 9 generated
    policies, on the run that surfaced this), so globbing the directory would score a model against
    someone else's leftovers."""
    from .apply import artifact_spec, lint_generated_spec
    idx = out / "policies.json"
    if not idx.exists():
        return 0, 0
    try:
        entries = json.loads(idx.read_text())
    except json.JSONDecodeError:
        return 0, 0
    total = flagged = 0
    for a in entries:
        control, name = a.get("control", ""), a.get("policy_name", "")
        f = out / "policies" / f"{control}.{name}.json"
        total += 1
        if not f.exists():
            flagged += 1
            continue
        try:
            spec = artifact_spec(json.loads(f.read_text()))
        except json.JSONDecodeError:
            flagged += 1
            continue
        if lint_generated_spec(control, spec, None):
            flagged += 1
    return total, flagged


def _precision(*, used: int, verified: int) -> float:
    """Verify precision — the false-positive filter rate the old `BACKLOG.md` item asked for.

    Real over reported: a verified finding that matched a key entry or a bonus entry is real,
    everything else the verifier let through is noise. Distinct from `discovery_recall`, which asks
    whether the KNOWN vulns were found — a run can ace one and fail the other, which is exactly why
    both belong in the scorecard."""
    return round(used / verified, 2) if verified else 0.0


def _tail(path: str) -> str:
    return path.split("/api/", 1)[-1] if "/api/" in path else path


def _class_ok(expected: str, produced: str) -> bool:
    return produced == expected or produced in COMPAT.get(expected, {expected})


def _file_ok(expected_file: str, produced_file: str) -> bool:
    e, p = _tail(expected_file), _tail(produced_file)
    return e == p or e.endswith(p) or p.endswith(e)


def run_bench(repo, key_path, out_dir="out", config_path=None, log: Callable = print,
              scan: bool = True, min_confidence: float = 0.5, concurrency: int = 8) -> dict:
    if scan:
        run_pipeline(repo, out_dir=out_dir, config_path=config_path, min_confidence=min_confidence,
                     concurrency=concurrency, log=log)
    out = Path(out_dir)
    findings = {f["id"]: f for f in json.loads((out / "findings.json").read_text())}
    decisions = {d["finding_id"]: d for d in json.loads((out / "triage.json").read_text())}
    verified = [findings[i] for i in decisions if i in findings]
    key_doc = yaml.safe_load(Path(key_path).read_text())
    expected = key_doc["expected"]

    def _triage_ok(exp, f) -> bool:
        d = decisions[f["id"]]
        if exp.get("no_bandaid"):
            return bool(d["no_bandaid"])
        controls = {b["control"] for b in d["bandaids"] if b["recommended"]} or {
            b["control"] for b in d["bandaids"]
        }
        return (not d["no_bandaid"]) and bool(controls & set(exp.get("acceptable_controls", [])))

    rows, used = [], set()
    for exp in expected:
        candidates = [
            f for f in verified
            if f["id"] not in used
            and _file_ok(exp["file"], f["file"])
            and _class_ok(exp["vuln_class"], f["vuln_class"])
        ]
        # best-match: prefer a candidate whose triage satisfies the expectation
        match = next((f for f in candidates if _triage_ok(exp, f)), None) or (
            candidates[0] if candidates else None
        )
        triage_ok = _triage_ok(exp, match) if match else None
        if match:
            used.add(match["id"])
        rows.append({
            "key": exp["key"],
            "found": match is not None,
            "triage_ok": triage_ok,
            "matched": match["id"] if match else None,
            "want": ["<no_bandaid>"] if exp.get("no_bandaid") else exp.get("acceptable_controls", []),
        })

    # bonus: credit real findings beyond the core key (thorough), not counted as noise
    bonus = key_doc.get("bonus", [])
    bonus_found = 0
    for b in bonus:
        m = next((f for f in verified if f["id"] not in used
                  and _file_ok(b["file"], f["file"]) and _class_ok(b["vuln_class"], f["vuln_class"])), None)
        if m:
            used.add(m["id"])
            bonus_found += 1

    n = len(expected)
    found = sum(r["found"] for r in rows)
    triage_correct = sum(1 for r in rows if r["triage_ok"])
    noise = [f["id"] for f in verified if f["id"] not in used]
    metrics = {}
    mp = out / "metrics.json"
    if mp.exists():
        try:
            metrics = json.loads(mp.read_text())
        except json.JSONDecodeError:
            metrics = {}
    pol_total, pol_flagged = _policy_quality(out)
    score = {
        "expected": n,
        "found": found,
        "discovery_recall": round(found / n, 2) if n else 0.0,
        "triage_correct": triage_correct,
        "triage_accuracy": round(triage_correct / found, 2) if found else 0.0,
        "bonus_found": bonus_found,
        "bonus_total": len(bonus),
        "noise": len(noise),
        "verified": len(verified),
        "verify_precision": _precision(used=len(used), verified=len(verified)),
        "duplicates_dropped": (metrics.get("discovery") or {}).get("duplicates_dropped", 0),
        "policies": pol_total,
        "policies_flagged": pol_flagged,
        "wall_time_s": (metrics.get("timing_s") or {}).get("total", 0.0),
    }
    return {"rows": rows, "score": score, "noise": noise}
