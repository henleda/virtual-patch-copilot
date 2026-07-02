"""Remediation ledger: per-finding lifecycle so a temporary band-aid never silently
becomes permanent.

State: found → mitigated (XC band-aid live) → remediated (code-fix PR open) → retired
(cure merged + band-aid removed). Persisted as `<out>/ledger.json`, keyed by finding_id.
The pipeline seeds `found`; apply marks `mitigated`; pr marks `remediated`; C2 will mark
`retired` when the PR merges."""
from __future__ import annotations

import json
from pathlib import Path

STATES = ("found", "mitigated", "remediated", "retired")
_ORDER = {s: i for i, s in enumerate(STATES)}


def _path(out_dir) -> Path:
    return Path(out_dir) / "ledger.json"


def load(out_dir) -> dict:
    p = _path(out_dir)
    return json.loads(p.read_text()) if p.exists() else {}


def save(out_dir, entries: dict):
    _path(out_dir).write_text(json.dumps(entries, indent=2))


def _advance(entry: dict, state: str):
    """Only move the state forward (found→mitigated→remediated→retired)."""
    if _ORDER[state] > _ORDER.get(entry.get("state", "found"), 0):
        entry["state"] = state


def init_from_scan(out_dir, findings: list[dict], decisions: list[dict],
                   remediations: list[dict]) -> dict:
    """Seed/refresh ledger entries for verified findings, preserving any existing
    mitigation/cure state across re-scans (keyed by finding_id)."""
    entries = load(out_dir)
    tri = {d["finding_id"]: d for d in decisions}
    has_cure = {r["finding_id"] for r in remediations}
    by_id = {f["id"]: f for f in findings}
    for fid, d in tri.items():
        f = by_id.get(fid, {})
        e = entries.get(fid, {"state": "found", "mitigation": None, "cure": None})
        e.update({
            "finding_id": fid, "file": f.get("file"), "vuln_class": f.get("vuln_class"),
            "severity": f.get("severity"), "title": f.get("title"),
            "bandaids": [b["control"] for b in d.get("bandaids", [])],
            "no_bandaid": d.get("no_bandaid", False),
            "has_cure": fid in has_cure,
        })
        e.setdefault("state", "found")
        entries[fid] = e
    save(out_dir, entries)
    return entries


def mark_mitigated(out_dir, finding_id: str, *, control: str, policy_name: str, lb: str) -> dict:
    entries = load(out_dir)
    e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
    e["mitigation"] = {"control": control, "policy_name": policy_name, "lb": lb}
    _advance(e, "mitigated")
    save(out_dir, entries)
    return e


def mark_remediated(out_dir, finding_id: str, *, pr_url: str, pr_number) -> dict:
    entries = load(out_dir)
    e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
    e["cure"] = {"pr_url": pr_url, "pr_number": pr_number}
    _advance(e, "remediated")
    save(out_dir, entries)
    return e


def find_finding_for_policy(out_dir, policy_name: str) -> str | None:
    """Map a generated policy back to its finding via the scan's policies.json index."""
    p = Path(out_dir) / "policies.json"
    if not p.exists():
        return None
    for a in json.loads(p.read_text()):
        if a.get("policy_name") == policy_name:
            return a.get("finding_id")
    return None
