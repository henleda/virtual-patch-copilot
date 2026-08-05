"""F3 — run identity + provenance: the spine of a defensible audit trail.

An audit entry has to stand on its own: *what* changed, *when*, *who* changed it, and *which run*
it belongs to. This module supplies the last two. `<out>/run.json` is the per-run manifest — the
scanned repo and its commit, the models that produced the findings, the caps the scan ran under —
and `run_id` is the key every audit entry carries back to it, including entries written later by a
separate `vpcopilot apply` process against the same out dir.

Both live inside the run's out dir, so an exported evidence bundle is self-describing."""
from __future__ import annotations

import getpass
import json
import os
import socket
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


_MINT_LOCK = threading.Lock()   # guards the run_id read-modify-write (see `run_id`)


def _path(out_dir) -> Path:
    return Path(out_dir) / "run.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def actor() -> str:
    """Who a change is attributed to. VPCOPILOT_ACTOR wins, so CI or a shared jump host can name the
    engineer who asked for the change rather than the service account it happens to run as."""
    explicit = (os.environ.get("VPCOPILOT_ACTOR") or "").strip()
    if explicit:
        return explicit
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 — no passwd entry (slim containers) must never break an apply
        return "unknown"


def host() -> str:
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "unknown"


def load(out_dir) -> dict:
    p = _path(out_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:  # a half-written manifest must not break a read (cf. ledger.load)
        return {}


def _save(out_dir, meta: dict) -> None:
    p = _path(out_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    # PID *and* thread id. With the pid alone, two threads in one process share the temp path, so
    # the second `os.replace` finds it already moved and raises FileNotFoundError — reproduced 12
    # times out of 12 with 8 threads against a fresh out dir. The console starts every apply on its
    # own daemon thread, and this runs inside `audit.record`, so the loser of that race fails to
    # record a change it already made to a load balancer.
    tmp = p.with_suffix(f".json.tmp.{os.getpid()}.{threading.get_ident()}")
    tmp.write_text(json.dumps(meta, indent=2))
    os.replace(tmp, p)  # atomic — every export joins on this file


def run_id(out_dir) -> str:
    """The stable id for this run dir. Minted on first use and persisted, so a scan and a later
    apply/retire against the same dir all stamp their audit entries with the same run.

    The mint is a read-modify-write, and `audit.record` calls it on the console's per-apply daemon
    threads. Unguarded, each thread read an empty `run.json`, minted its own id and stamped its own
    entry with it — eight concurrent first writes produced eight different run_ids, so seven audit
    entries carried a join key that `run.json` did not contain. The lock makes the mint
    thread-atomic; single-threaded behaviour is unchanged. It is deliberately NOT a cross-process
    guarantee — two processes first-writing the same dir at the same instant can still diverge, and
    a file lock is the wrong trade for a case a scan already serializes."""
    with _MINT_LOCK:
        meta = load(out_dir)
        if meta.get("run_id"):
            return meta["run_id"]
        rid = uuid.uuid4().hex[:12]
        _save(out_dir, {**meta, "run_id": rid, "created": utc_now()})
        return rid


def git_provenance(repo) -> dict:
    """Commit + branch of the scanned repo, so a finding ties back to the exact source it came from.
    Fail-soft: a target that is not a git checkout simply contributes nothing."""
    def _git(*args) -> str:
        try:
            return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                           stderr=subprocess.DEVNULL, timeout=10).strip()
        except Exception:  # noqa: BLE001 — no git, not a repo, slow FS: all non-fatal
            return ""
    sha = _git("rev-parse", "HEAD")
    if not sha:
        return {}
    return {"repo_commit": sha, "repo_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
            "repo_dirty": bool(_git("status", "--porcelain"))}


def write_manifest(out_dir, **fields) -> dict:
    """Merge run facts into run.json, never clobbering an existing run_id (a re-scan of the same dir
    keeps its identity, so the audit entries already on disk stay joinable).

    Under the SAME lock as `run_id()`. This is the identical read-modify-write, and guarding only
    one of the two left the race half-closed: a scan finishing here while any thread minted through
    `run_id()` (which `audit.record` calls on the console's per-apply daemon threads) loses one of
    the two mints, and the loser's audit entries carry a join key `run.json` does not contain.
    Measured at 246 orphaned entries over 40 trials of 8 threads before this.
    """
    with _MINT_LOCK:
        meta = load(out_dir)
        meta.setdefault("run_id", uuid.uuid4().hex[:12])
        meta.setdefault("created", utc_now())
        meta.update({k: v for k, v in fields.items() if v is not None})
        meta.update({"actor": actor(), "host": host(), "tool_version": __version__,
                     "out_dir": str(out_dir)})
        _save(out_dir, meta)
        return meta
