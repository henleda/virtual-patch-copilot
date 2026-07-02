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


def _tail(path: str) -> str:
    return path.split("/api/", 1)[-1] if "/api/" in path else path


def _class_ok(expected: str, produced: str) -> bool:
    return produced == expected or produced in COMPAT.get(expected, {expected})


def _file_ok(expected_file: str, produced_file: str) -> bool:
    e, p = _tail(expected_file), _tail(produced_file)
    return e == p or e.endswith(p) or p.endswith(e)


def run_bench(repo, key_path, out_dir="out", config_path=None, log: Callable = print,
              scan: bool = True, min_confidence: float = 0.5) -> dict:
    if scan:
        run_pipeline(repo, out_dir=out_dir, config_path=config_path, min_confidence=min_confidence, log=log)
    out = Path(out_dir)
    findings = {f["id"]: f for f in json.loads((out / "findings.json").read_text())}
    decisions = {d["finding_id"]: d for d in json.loads((out / "triage.json").read_text())}
    verified = [findings[i] for i in decisions if i in findings]
    expected = yaml.safe_load(Path(key_path).read_text())["expected"]

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

    n = len(expected)
    found = sum(r["found"] for r in rows)
    triage_correct = sum(1 for r in rows if r["triage_ok"])
    extras = [f["id"] for f in verified if f["id"] not in used]
    score = {
        "expected": n,
        "found": found,
        "discovery_recall": round(found / n, 2) if n else 0.0,
        "triage_correct": triage_correct,
        "triage_accuracy": round(triage_correct / found, 2) if found else 0.0,
        "extra_findings": len(extras),
    }
    return {"rows": rows, "score": score, "extras": extras}
