"""Remediation ledger: per-finding lifecycle so a temporary band-aid never silently
becomes permanent.

State: found → mitigated (XC band-aid live) → remediated (code-fix PR open) → retired
(cure merged + band-aid removed). Persisted as `<out>/ledger.json`, keyed by finding_id.
The pipeline seeds `found`; apply marks `mitigated`; pr marks `remediated`; C2 will mark
`retired` when the PR merges.

I1 adds two top-level keys, neither of them a state: `ttl` (when this band-aid was applied and
when it expires) and `reconcile` (what the last reconcile pass observed). They are data, not
lifecycle positions — a finding past its TTL is still `mitigated`, and one whose merged cure did
not actually fix the bug is still `remediated`. Modelling those as extra states would have forced
a fifth entry into a strictly forward-only machine that four other modules order by index."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

STATES = ("found", "mitigated", "remediated", "retired")

# I1 — a band-aid's default lifetime. Seven days is long enough that a normal review cycle closes
# the cure first, and short enough that a forgotten patch surfaces inside a sprint.
DEFAULT_TTL_HOURS = 168
_ORDER = {s: i for i, s in enumerate(STATES)}
_LOCK = threading.Lock()  # B7: serialize read-modify-write from the console's parallel apply jobs


def _path(out_dir) -> Path:
    return Path(out_dir) / "ledger.json"


def load(out_dir) -> dict:
    p = _path(out_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:  # B7: never let a half-written ledger crash a read
        return {}


def save(out_dir, entries: dict):
    """B7: atomic write — serialize to a temp file in the same dir, then os.replace (atomic on
    POSIX/Windows) so a crash mid-write can't leave a truncated, unparseable ledger."""
    p = _path(out_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".json.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(entries, indent=2))
    os.replace(tmp, p)


def _advance(entry: dict, state: str):
    """Only move the state forward (found→mitigated→remediated→retired)."""
    if _ORDER[state] > _ORDER.get(entry.get("state", "found"), 0):
        entry["state"] = state


def init_from_scan(out_dir, findings: list[dict], decisions: list[dict],
                   remediations: list[dict]) -> dict:
    """Seed/refresh ledger entries for verified findings, preserving any existing
    mitigation/cure state across re-scans (keyed by finding_id)."""
    with _LOCK:   # the only read-modify-write that was not serialized with its four siblings
        return _init_from_scan(out_dir, findings, decisions, remediations)


def _init_from_scan(out_dir, findings: list[dict], decisions: list[dict],
                    remediations: list[dict]) -> dict:
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
    # Scope the ledger to THIS scan's findings — drop entries from a prior/different app so the
    # ledger never mixes targets (e.g. VAmPI + crAPI).
    #
    # I1 — but NEVER drop an entry whose band-aid is still live. A control attached to an LB is a
    # fact about the tenant, not about the scan: pruning it orphaned a live patch where `reconcile`
    # could no longer find it, and left it to outlive its cure silently — the exact failure this
    # ledger exists to prevent. Cross-target mixing is still prevented, because a finding from
    # another app has no mitigation of ours.
    for fid in [k for k in entries if k not in tri]:
        e = entries[fid]
        if e.get("mitigation") and e.get("state") in ("mitigated", "remediated"):
            continue
        del entries[fid]
    save(out_dir, entries)
    return entries


def default_ttl_hours() -> int:
    raw = (os.environ.get("VPCOPILOT_DEFAULT_TTL_HOURS") or "").strip()
    try:
        return int(raw) if raw else DEFAULT_TTL_HOURS
    except ValueError:
        return DEFAULT_TTL_HOURS


def mark_mitigated(out_dir, finding_id: str, *, control: str, policy_name: str, lb: str,
                   ttl_hours: int | None = None) -> dict:
    """I1 — every applied control gets a TTL here, at the one chokepoint all eight apply paths
    already call, so "give every applied control a TTL at apply time" needs no edit at any of them.

    `ttl` is a TOP-LEVEL key, deliberately not nested inside `mitigation`: `report.py` renders
    `mitigation` with `html.escape(str(dict))`, so a new key in there would rewrite the committed
    demo report fixture. A re-apply legitimately resets the clock."""
    with _LOCK:  # B7: atomic read-modify-write (parallel apply jobs share this file)
        entries = load(out_dir)
        e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
        e["mitigation"] = {"control": control, "policy_name": policy_name, "lb": lb}
        hours = default_ttl_hours() if ttl_hours is None else int(ttl_hours)
        applied = datetime.now(timezone.utc)
        # Pre-serialized as strings: audit.record json.dumps()es **detail with no `default=`, so a
        # datetime reaching a record would raise AFTER the LB was already mutated.
        e["ttl"] = {"applied_at": applied.isoformat(), "ttl_hours": hours,
                    "expires_at": (applied + timedelta(hours=hours)).isoformat()}
        _advance(e, "mitigated")
        save(out_dir, entries)
        return e


def record_reconcile(out_dir, finding_id: str, **fields) -> dict:
    """Merge one reconcile pass's observations into the entry's top-level `reconcile` block.

    Merge, not replace: a pass that only re-checked the PR must not erase the probe result from
    the pass that actually fired one."""
    with _LOCK:
        entries = load(out_dir)
        e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
        e.setdefault("reconcile", {}).update(fields)
        save(out_dir, entries)
        return e


def mark_remediated(out_dir, finding_id: str, *, pr_url: str, pr_number) -> dict:
    with _LOCK:
        entries = load(out_dir)
        e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
        e["cure"] = {"pr_url": pr_url, "pr_number": pr_number}
        _advance(e, "remediated")
        save(out_dir, entries)
        return e


def mark_retired(out_dir, finding_id: str) -> dict:
    """Band-aid detached from the LB after its code cure merged (C2)."""
    with _LOCK:
        entries = load(out_dir)
        e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
        _advance(e, "retired")  # impact/controls_live already treat 'retired' as no-longer-live
        save(out_dir, entries)
        return e


def policy_index(out_dir) -> dict[str, str]:
    """`{policy_name: finding_id}` from the scan's `policies.json`.

    THE one place this lookup lives. It had grown a second copy in `export.build_audit_events`,
    which built the same dict inline; J4 would have made a third. Two copies of a mapping is one
    copy that eventually stops matching.

    **This index is rewritten by every scan** (`pipeline._write_out`), so it describes the LATEST
    run and not the run an old audit entry belongs to. That is what J4's sidecar exists to freeze —
    see `backfill.py`.

    Semantics are the OLD `find_finding_for_policy`'s, exactly, because four apply-path callers
    depend on them and a consolidation that quietly changes behaviour is worse than the duplication
    it removes. Three differences were measured against the previous implementation and all three
    are deliberately preserved here:

    - **First match wins.** A dict comprehension would let a later duplicate overwrite an earlier
      one. `policies.json` should not contain duplicate names, but "should not" is not "does not",
      and silently changing which finding an apply validates against is not a refactor.
    - **A falsy `finding_id` is returned as-is**, not filtered out. Callers all write
      `finding_id or find_finding_for_policy(...)`, so `""` and `None` behave identically to them —
      but the *backfill* wants them treated as unresolved, and that belongs at its call site rather
      than in a lookup four other paths share.
    - **A corrupt file raises**, as it did before. The apply paths use this to decide which probe
      validates a band-aid; proceeding with no finding because the index would not parse means
      applying with weaker validation and no explanation. `export` catches it instead, because a
      read-only report should not explode on a damaged artifact."""
    p = Path(out_dir) / "policies.json"
    if not p.exists():
        return {}
    idx: dict[str, str] = {}
    for a in json.loads(p.read_text()):
        name = a.get("policy_name")
        if name is not None and name not in idx:
            idx[name] = a.get("finding_id")
    return idx


def find_finding_for_policy(out_dir, policy_name: str) -> str | None:
    """Map a generated policy back to its finding via the scan's policies.json index."""
    return policy_index(out_dir).get(policy_name)
