"""Append-only audit log of every mutating action (create/attach/enable/rollback/PR/retire).

One JSON object per line in `<out>/audit.log` with a UTC timestamp, the action, and details — so
there's a durable record of exactly what the copilot changed, when, and the result. Read-only
actions (scan, dry-run) are not recorded: nothing changed, so there is nothing to answer for.

Identity (`run_id` / `actor` / `host` / `tool_version`) is stamped **here** rather than at each call
site, so no mutating path can forget it and no caller can override it — an entry that cannot say who
made the change, from where, and as part of which run is not an audit record.

J3: when `VPCOPILOT_AUDIT_SINK` is set, the same line is also shipped off-box (see `audit_sink`).
The local file is written first and is authoritative; delivery is fail-soft and cannot change the
outcome of the action being recorded."""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__, audit_sink, runmeta

_STAMPED = ("ts", "run_id", "actor", "host", "tool_version")


def record(out_dir, action: str, **detail) -> None:
    detail = {k: v for k, v in detail.items() if k not in _STAMPED}
    entry = {"ts": runmeta.utc_now(), "action": action, "run_id": runmeta.run_id(out_dir),
             "actor": runmeta.actor(), "host": runmeta.host(), "tool_version": __version__, **detail}
    # Serialized ONCE and handed to both destinations, so the shipped copy and the line on disk
    # cannot drift. A non-serializable detail value still raises here, as it always has — before
    # anything is written or sent (`ledger.py` pre-serializes datetimes for exactly this reason).
    line = json.dumps(entry)
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    with open(p / "audit.log", "a") as f:
        f.write(line + "\n")
    # After the local write, never instead of it: an off-box event with no local counterpart could
    # never be reconciled against the run it belongs to.
    audit_sink.emit(line, entry)


def load(out_dir) -> list[dict]:
    p = Path(out_dir) / "audit.log"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
