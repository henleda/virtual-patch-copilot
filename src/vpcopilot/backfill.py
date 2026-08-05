"""J4 — attribution backfill. Freeze the finding an old audit entry belongs to, while it is still
derivable.

**The audit log cannot be rewritten, and should not be.** `audit.log` is append-only, and
`audit.record` strips caller-supplied identity so no caller can claim to be someone else — pinned by
`test_identity_cannot_be_overridden_by_a_caller`. An entry that could not say who made a change is
not an audit record, and a backfill that could edit one would destroy the property that makes the
log worth keeping. So this writes a **sidecar**, `<out>/audit-backfill.json`, that the exporter
consults beside the log. The log stays exactly as it was written.

**Why persist a lookup the exporter already does at read time.** `export.build_audit_events` recovers
a finding from `policies.json` for entries that carry only a policy name. But `policies.json` is
rewritten by **every** scan (`pipeline._write_out`), so it describes the newest run, not the run the
entry belongs to. Two things follow, and the second is the one that matters:

1. Re-scan into the same out dir and the mapping for older entries is simply **gone** — the exporter
   silently stops attributing them.
2. Worse, if the new scan happens to generate a policy with the **same name** and a different
   finding, the lookup still succeeds and attributes the old entry to the **wrong finding**. A
   confident wrong answer, in the artifact whose entire job is to be trustworthy.

The backfill captures the mapping while it is still true, and its answers take precedence over the
live lookup for the entries it covers.

**"Unknown" is sticky, on purpose.** An entry the backfill looked at and could not resolve is
recorded as `unknown`, and that stops the exporter guessing from a later `policies.json`. Having
looked and failed is a fact worth keeping; it is the difference between "we could not establish
this" and "we have not tried", which is the distinction this codebase refuses to blur anywhere else.
"""
from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from pathlib import Path

from . import audit, ledger, runmeta
from . import __version__

SIDECAR = "audit-backfill.json"

# Our own bookkeeping entries. Skipped when backfilling: they name no policy and belong to no
# finding, and including them would make every run differ from the last one — see `backfill()`.
_OWN_ACTION = "audit_backfill"


def _key(e: dict) -> tuple[str, str]:
    """What identifies an entry besides its position. Stored alongside the index so a log that was
    truncated or rebuilt is DETECTED rather than silently mis-keyed: the index would still resolve,
    but to a different entry."""
    return e.get("ts", ""), e.get("action", "")


def derive(out_dir: str, *, keep: dict[int, dict] | None = None) -> list[dict]:
    """The attribution this run dir can still prove, one record per audit entry that lacks one.

    Nothing is invented: the only source is `policies.json`, via the single shared lookup. An entry
    that already carries `finding_id` is not recorded at all — there is nothing to freeze.

    **`keep` makes the sidecar monotonic, and without it this function destroys what it exists to
    protect.** Re-deriving every row from the CURRENT `policies.json` is exactly what the sidecar is
    a defence against: run the command once, re-scan, run it again, and every frozen attribution is
    recomputed against an index that no longer describes those entries — resolved rows collapse to
    `unknown`, and because `unknown` is sticky the loss is permanent. The second use of the feature
    undid the first.

    So a row already on disk is carried forward **verbatim** and never recomputed, resolved or not.
    The sidecar is monotonic in the same way as the log it annotates: entries are added, never
    revised. Genuinely wanting a fresh derivation means deleting the sidecar — an explicit, visible
    act rather than a silent side effect of running a command twice."""
    keep = keep or {}
    entries = audit.load(out_dir)
    index = ledger.policy_index(out_dir)
    rows: list[dict] = []
    for i, e in enumerate(entries):
        if e.get("action") == _OWN_ACTION:
            continue
        if e.get("finding_id") or e.get("finding"):
            continue                      # already attributed; the log is the better source
        if i in keep:
            rows.append(keep[i])          # frozen when it was true; never re-derived
            continue
        ts, action = _key(e)
        policy = e.get("policy") or ""
        # `or None` here, not in `ledger.policy_index`: an empty finding_id is
        # unresolved for OUR purposes, but four apply-path callers share that lookup
        # and expect it to hand back whatever the index holds.
        fid = (index.get(policy) or None) if policy else None
        rows.append({"i": i, "ts": ts, "action": action, "policy": policy,
                     "finding_id": fid,
                     "source": "policies.json" if fid else "unknown"})
    return rows


def load_state(out_dir: str) -> tuple[dict[int, dict], bool]:
    """`(rows, trustworthy)`. `trustworthy` is False when a sidecar EXISTS but cannot be read.

    Absent and unreadable are different answers and the exporter must be able to tell them apart. A
    sidecar that is not there means nobody has frozen anything, so falling back to the live policy
    index is the best available guess. A sidecar that is there and will not parse means somebody DID
    freeze attribution and it is now unreadable — and the live index is, by definition, not the one
    those entries belong to. Guessing from it there can produce a confidently wrong attribution, as
    an adversarial review demonstrated: a torn sidecar plus a re-scan that reused a policy name
    attributed old entries to the wrong finding, in a bundle that then SHA-256s and signs the answer
    as evidence.

    Rows are VERIFIED against the log they describe: one whose `(ts, action)` no longer matches the
    entry at its index is dropped, because the index means something else now. Better to lose an
    attribution than to move it onto the wrong entry."""
    p = Path(out_dir) / SIDECAR
    if not p.is_file():
        return {}, True
    try:
        doc = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}, False
    entries = audit.load(out_dir)
    out: dict[int, dict] = {}
    for row in doc.get("entries") or []:
        i = row.get("i")
        if not isinstance(i, int) or not (0 <= i < len(entries)):
            continue
        if _key(entries[i]) != (row.get("ts", ""), row.get("action", "")):
            continue                      # the log moved under it
        out[i] = row
    return out, True


def load(out_dir: str) -> dict[int, dict]:
    """The verified rows, for callers that do not need to distinguish absent from unreadable."""
    return load_state(out_dir)[0]


def stale_rows(out_dir: str) -> int:
    """How many sidecar rows no longer match the log. Surfaced rather than swallowed — a non-zero
    count means the log was rewritten, which is itself worth knowing about."""
    p = Path(out_dir) / SIDECAR
    if not p.is_file():
        return 0
    try:
        doc = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    return len(doc.get("entries") or []) - len(load(out_dir))


def _same(rows: list[dict], existing: dict) -> bool:
    """Would writing `rows` change anything? Compared on the fields that carry meaning, so a
    re-serialisation or a new `generated` timestamp does not count as a change."""
    old = {r["i"]: r for r in (existing.get("entries") or [])}
    if len(old) != len(rows):
        return False
    for r in rows:
        o = old.get(r["i"])
        if not o or any(o.get(k) != r.get(k) for k in ("ts", "action", "policy",
                                                       "finding_id", "source")):
            return False
    return True


def backfill(out_dir: str = "out", *, dry_run: bool = False, log: Callable = print) -> dict:
    """Persist what is provably derivable. Returns a summary; writes at most one sidecar and one
    audit record.

    A second run is a no-op — nothing written, nothing recorded — which is not merely tidiness. This
    function appends its own `audit_backfill` entry, so without that check every run would see one
    more entry than the last, decide something had changed, and append again: a log that grows by one
    line every time anybody asks whether it needs backfilling. (The I1 precedent: a reconcile pass
    that changes nothing writes nothing.)"""
    out = Path(out_dir)
    if not (out / "audit.log").is_file():
        log(f"no audit.log in {out_dir!r} — nothing to backfill")
        return {"out": out_dir, "entries": 0, "resolved": 0, "unknown": 0, "wrote": False,
                "recorded": False, "reason": "no audit log"}

    # Carry forward whatever is already frozen and verified — see `derive`. Without this,
    # running the command twice with a re-scan in between destroys the attribution.
    #
    # `ledger.policy_index` RAISES on a corrupt `policies.json`, deliberately: the apply paths use it
    # to choose which probe validates a band-aid, and returning nothing there would mean applying
    # with weaker validation and no explanation. This command is not an apply. An unreadable index
    # means it cannot establish anything, which is a decline with a reason — not a traceback out of
    # the CLI and an HTTP 500 out of the console.
    try:
        rows = derive(out_dir, keep=load(out_dir))
    except (OSError, json.JSONDecodeError) as e:
        log(f"cannot read the policy index in {out_dir!r}: {e} — nothing can be attributed from it")
        return {"out": out_dir, "entries": 0, "resolved": 0, "unknown": 0, "wrote": False,
                "recorded": False, "reason": f"unreadable policies.json: {e}"}
    resolved = sum(1 for r in rows if r["source"] == "policies.json")
    unknown = len(rows) - resolved
    stale = stale_rows(out_dir)
    if stale:
        log(f"  ⚠ {stale} existing sidecar row(s) no longer match audit.log and were discarded — "
            "the log was rebuilt or truncated since the last backfill")

    existing: dict = {}
    p = out / SIDECAR
    if p.is_file():
        try:
            existing = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            existing = {}

    res = {"out": out_dir, "entries": len(rows), "resolved": resolved, "unknown": unknown,
           "stale_dropped": stale, "wrote": False, "recorded": False}

    if _same(rows, existing):
        log(f"nothing new to attribute ({resolved} resolved, {unknown} unknown) — writing nothing")
        res["reason"] = "no change"
        return res
    if dry_run:
        log(f"[dry-run] would attribute {resolved} entry(ies) and mark {unknown} unknown")
        res["reason"] = "dry run"
        return res

    # NO actor, NO run_id, NO host anywhere in this file. The acceptance is that no entry gets an
    # invented identity, and the way to guarantee that is to have nowhere to put one: the sidecar
    # carries attribution only. Identity stays where `audit.record` stamps it — on the log.
    doc = {"tool_version": __version__, "generated": runmeta.utc_now(),
           "note": "J4 attribution sidecar. Maps audit.log entries to findings by the policy index "
                   "as it stood when this ran. Carries no actor, run_id or host: identity lives in "
                   "audit.log, which is append-only and never edited.",
           "entries": rows}
    # Atomic: write a temp file in the same directory, then rename over the target. `write_text`
    # truncates first, so a crash or a full disk mid-write leaves a half-written sidecar — and this
    # one is evidence that an exporter reads and a bundle ships. A partial file would be silently
    # unparseable (`load` swallows a JSONDecodeError and returns nothing), so the failure mode is
    # losing every frozen attribution without a word. `os.replace` is atomic within a filesystem.
    # PID *and* thread id — a fixed temp name means two concurrent writers share the path, so
    # the loser's `os.replace` finds it already moved and raises FileNotFoundError. The
    # console exposes this over HTTP (POST /api/audit-backfill), where concurrency is the
    # default rather than the exception. Same fix as `runmeta._save`.
    tmp = p.with_suffix(f".json.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(json.dumps(doc, indent=2))
    os.replace(tmp, p)
    log(f"wrote {p} — {resolved} attributed, {unknown} unknown")
    audit.record(out_dir, _OWN_ACTION, entries=len(rows), resolved=resolved, unknown=unknown,
                 sidecar=SIDECAR)
    res.update(wrote=True, recorded=True, path=str(p))
    return res
