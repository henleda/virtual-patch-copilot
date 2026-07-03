"""Append-only audit log of every mutating action (create/attach/enable/rollback/PR).

One JSON object per line in `<out>/audit.log` with a UTC timestamp, the action, and
details — so there's a durable record of exactly what the copilot changed, when, and the
result. Read-only actions (scan, dry-run) are not recorded."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def record(out_dir, action: str, **detail) -> None:
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "action": action, **detail}
    p = Path(out_dir)
    p.mkdir(parents=True, exist_ok=True)
    with open(p / "audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


def load(out_dir) -> list[dict]:
    p = Path(out_dir) / "audit.log"
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
