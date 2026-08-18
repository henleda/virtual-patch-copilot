"""Global live-band-aid inventory — the cross-session record of what is physically attached to which
load balancer / appliance right now, decoupled from any one scan session.

Why this exists (the split). A scan *session* owns ephemeral artifacts — findings, triage, policies,
report — in its own out dir. A live band-aid is not a fact about a scan; it is a fact about the
tenant's infrastructure that outlives the scan and must stay retire-able no matter how many other
apps are scanned afterwards. Keeping live patches in the per-session ledger forced `init_from_scan`
to leak them across scans (the old "never orphan a live patch" keep-block) so `reconcile` could still
find them — and that leak is exactly what mixed a 5-day-old mitigation into a later scan's Retire
view. Inventory is the single, session-independent source of truth for live band-aids: written on
apply, cure attached on remediate, observations merged on reconcile, `retired` on retire. Retire and
reconcile read it, always; a re-scan can now scope the session ledger strictly to its own findings
because a live patch can no longer be orphaned — it lives here, not there.

Storage: one JSON file at `<VPCOPILOT_INVENTORY_DIR or cwd>/inventory.json`, keyed by finding_id (the
same key apply/retire/reconcile already use). An entry mirrors a ledger entry
(state / mitigation / ttl / cure / reconcile + finding metadata) so the reconcile machinery reads it
unchanged, plus one field that makes it self-contained across sessions: `session` — the out dir the
band-aid was applied from, so reconcile can still load that finding's probe spec and write its audit
trail there. Entries are populated by write-through from `ledger.mark_*`, so no apply path calls this
module directly."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

# States that mean a band-aid is physically in front of the app. `retired` stays in the file (for the
# post-retire reconcile record) but is filtered out of every live view — "cleared on retire" to a
# reader, without deleting the row a still-running reconcile pass is about to write to.
_LIVE = ("mitigated", "remediated")
_ORDER = {s: i for i, s in enumerate(("found", "mitigated", "remediated", "retired"))}
_LOCK = threading.Lock()  # serialize read-modify-write (the console runs applies on parallel threads)


def inventory_dir() -> Path:
    """Where the global inventory + reconcile lock live. Env-overridable so tests (and a user who
    keeps state outside the repo) can point it somewhere isolated; defaults to the cwd, the same
    place the `out*` session dirs live."""
    return Path((os.environ.get("VPCOPILOT_INVENTORY_DIR") or "").strip() or ".")


def _path() -> Path:
    return inventory_dir() / "inventory.json"


def exists() -> bool:
    return _path().exists()


def load() -> dict:
    p = _path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:   # never let a half-written inventory crash a read (cf. ledger.load)
        return {}


def save(entries: dict) -> None:
    """Atomic write — temp file in the same dir, then os.replace. pid+tid in the temp name so two
    apply threads in one process never race on the same temp path (the ledger.save fix, mirrored)."""
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".json.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(json.dumps(entries, indent=2))
    os.replace(tmp, p)


def _advance(entry: dict, state: str) -> None:
    if _ORDER[state] > _ORDER.get(entry.get("state", "found"), 0):
        entry["state"] = state


_META_KEYS = ("title", "severity", "vuln_class", "file", "cwe", "owasp", "cwe_source")


def record_mitigated(finding_id: str, *, control: str, policy_name: str, lb: str,
                     ttl: dict | None, session: str, meta: dict | None = None) -> dict:
    """Upsert the live band-aid. Called by `ledger.mark_mitigated`'s write-through, which already
    holds the finding's metadata and its freshly-computed TTL — both passed in so inventory and the
    session ledger never disagree on the clock. A re-apply legitimately updates in place."""
    with _LOCK:
        entries = load()
        e = entries.setdefault(finding_id, {"finding_id": finding_id, "state": "found"})
        e["mitigation"] = {"control": control, "policy_name": policy_name, "lb": lb}
        if ttl is not None:
            e["ttl"] = ttl
        e["session"] = session
        for k in _META_KEYS:
            if meta and meta.get(k) is not None:
                e[k] = meta[k]
        _advance(e, "mitigated")
        save(entries)
        return e


def record_remediated(finding_id: str, *, pr_url: str, pr_number) -> dict | None:
    """Attach the cure PR — but only to a band-aid we already track. A finding routed to code-cure-
    only never had a band-aid applied, so it is not in the inventory and must not be minted here (that
    was the exact bug the impact 'mitigated live' honesty test guards against)."""
    with _LOCK:
        entries = load()
        e = entries.get(finding_id)
        if e is None:
            return None
        e["cure"] = {"pr_url": pr_url, "pr_number": pr_number}
        _advance(e, "remediated")
        save(entries)
        return e


def record_reconcile(finding_id: str, **fields) -> dict | None:
    """Merge one reconcile pass's observations into the entry's `reconcile` block (merge, not replace
    — a pass that only re-checked the PR must not erase an earlier pass's probe result). No-op for a
    finding the inventory does not track."""
    with _LOCK:
        entries = load()
        e = entries.get(finding_id)
        if e is None:
            return None
        e.setdefault("reconcile", {}).update(fields)
        save(entries)
        return e


def mark_retired(finding_id: str) -> dict | None:
    """Band-aid detached. State advances to `retired`; the row stays (so the retire pass's follow-up
    `record_reconcile` still lands) but drops out of every live view."""
    with _LOCK:
        entries = load()
        e = entries.get(finding_id)
        if e is None:
            return None
        _advance(e, "retired")
        save(entries)
        return e


def live() -> dict:
    """Just the band-aids currently in front of an app — what Retire and reconcile act on."""
    return {fid: e for fid, e in load().items()
            if e.get("mitigation") and e.get("state") in _LIVE}


def migrate_from_dirs(out_dirs) -> int:
    """One-time seed: pull live mitigations out of existing per-session `ledger.json` files into the
    inventory, so patches applied before the split (e.g. a band-aid still on a load balancer from last
    week) remain visible in Retire and reachable by reconcile. Keyed by finding_id; an entry already
    in the inventory is never overwritten by a stale ledger copy. Idempotent. Returns how many it
    added."""
    from . import ledger
    added = 0
    with _LOCK:
        entries = load()
        for d in out_dirs:
            try:
                led = ledger.load(str(d))
            except Exception:  # noqa: BLE001 — a damaged session ledger must not abort the migration
                continue
            for fid, e in led.items():
                if fid in entries:
                    continue
                if e.get("mitigation") and e.get("state") in _LIVE:
                    entries[fid] = {**e, "session": str(d)}
                    added += 1
        if added:
            save(entries)
    return added
