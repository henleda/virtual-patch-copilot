"""Session workspaces (out* dirs) — the small shared helpers the console and the MCP surface both use
to name and create one, so the slug rules and the session.json shape cannot drift between them."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path


def slugify(name: str) -> str:
    """A filesystem-safe session slug: lowercase, non-alphanumerics collapsed to '-', trimmed. Always
    used under an `out-<slug>` prefix, so it can never produce a path outside the workspace root."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")


def create_session(name: str, *, root: str = ".") -> dict:
    """Create `out-<slug>` under `root` plus its `session.json` (friendly name + created_at), and
    return {out, name, path}. Idempotent — an existing session's metadata is never clobbered. Raises
    ValueError on a name that slugifies to nothing."""
    slug = slugify(name)
    if not slug:
        raise ValueError("a session name is required (letters/numbers)")
    d = Path(root) / f"out-{slug}"
    d.mkdir(parents=True, exist_ok=True)
    sj = d / "session.json"
    if not sj.exists():
        sj.write_text(json.dumps(
            {"name": name.strip(), "created_at": datetime.now(timezone.utc).isoformat()}, indent=2))
    return {"out": d.name, "name": name.strip(), "path": str(d)}


def read_meta(dirpath: Path, filename: str) -> dict:
    """Read a session sidecar (summary.json / session.json) as a dict — tolerant of a missing file,
    unparseable JSON, AND valid JSON that is not an object (null/number/string/list): all yield {},
    never an exception, so one damaged file cannot 500 the session list."""
    f = dirpath / filename
    if not f.exists():
        return {}
    try:
        data = json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}
