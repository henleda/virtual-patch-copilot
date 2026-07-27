"""Append-only audit log of every mutating action (create/attach/enable/rollback/PR/retire).

One JSON object per line in `<out>/audit.log` with a UTC timestamp, the action, and details — so
there's a durable record of exactly what the copilot changed, when, and the result. Read-only
actions (scan, dry-run) are not recorded: nothing changed, so there is nothing to answer for.

Identity (`run_id` / `actor` / `host` / `tool_version`) is stamped **here** rather than at each call
site, so no mutating path can forget it and no caller can override it — an entry that cannot say who
made the change, from where, and as part of which run is not an audit record."""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__, runmeta

_STAMPED = ("ts", "run_id", "actor", "host", "tool_version")


def record(out_dir, action: str, **detail) -> None:
    detail = {k: v for k, v in detail.items() if k not in _STAMPED}
    entry = {"ts": runmeta.utc_now(), "action": action, "run_id": runmeta.run_id(out_dir),
             "actor": runmeta.actor(), "host": runmeta.host(), "tool_version": __version__, **detail}
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    with open(p / "audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


def load(out_dir) -> list[dict]:
    p = Path(out_dir) / "audit.log"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
