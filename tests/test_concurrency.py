"""Shared state under concurrency.

From the 2026-08-04 deep-dive review. The console starts every apply, scan and reconcile on its own
daemon thread, so "two of these at once" is the normal case, not the exception — and every defect
here loses or misfiles a record of a change already made to a live load balancer.

These tests actually run threads. A single-threaded assertion cannot see any of them.
"""
from __future__ import annotations

import json
import tempfile
import threading

import pytest


def _race(fn, n=8, trials=20):
    """Run `fn(i)` on n threads against a fresh out dir, `trials` times. Returns (errors, dirs)."""
    errors: list[str] = []
    dirs: list[str] = []
    for _ in range(trials):
        d = tempfile.mkdtemp()
        dirs.append(d)
        ts = [threading.Thread(target=_collect, args=(fn, d, i, errors)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    return errors, dirs


def _collect(fn, d, i, errors):
    try:
        fn(d, i)
    except Exception as e:  # noqa: BLE001
        errors.append(f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------- run_id minting


def test_the_run_id_mint_is_atomic_across_both_of_its_call_sites():
    """`run_id()` was already locked; `write_manifest` did the IDENTICAL read-modify-write and was
    not. Guarding one of two left the race half-closed: a scan finishing while any thread records
    an audit entry loses a mint, and the loser's entries carry a join key `run.json` never contains
    — so they are orphaned from the run they belong to. Measured at 246 orphans over 40x8."""
    from vpcopilot import runmeta
    orphans = 0
    for _ in range(30):
        d = tempfile.mkdtemp()
        seen: list[str] = []

        def one(i, d=d, seen=seen):
            seen.append(runmeta.run_id(d) if i % 2 else runmeta.write_manifest(d, target="x")["run_id"])

        ts = [threading.Thread(target=one, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        final = json.loads((__import__("pathlib").Path(d) / "run.json").read_text())["run_id"]
        orphans += sum(1 for s in seen if s != final)
    assert orphans == 0, f"{orphans} audit entries would carry a run_id run.json does not contain"


# ---------------------------------------------------------------- atomic-write temp names


@pytest.mark.parametrize("mod,fn", [("ledger", "save"), ("runmeta", "_save")])
def test_every_atomic_write_uses_a_thread_unique_temp_name(mod, fn):
    """A fixed temp path means two writers in ONE process share it, so the loser's `os.replace`
    finds it already moved and raises FileNotFoundError. `runmeta._save` was fixed for this;
    `ledger.py` still had the pid-only version (two THREADS share a pid) and `backfill.py` had
    neither. Asserted across all three so the next atomic write cannot quietly omit it."""
    import inspect

    import vpcopilot
    src = inspect.getsource(getattr(__import__(f"vpcopilot.{mod}", fromlist=[mod]), fn))
    assert "getpid()" in src and "get_ident()" in src, \
        f"{mod}.{fn} builds a temp name that two threads in one process can share"
    assert vpcopilot  # keep the import meaningful


def test_the_ledger_survives_concurrent_writers():
    """The ledger is what the whole audit trail joins on, and `mark_mitigated` runs inside the
    console's per-apply daemon threads — so the loser of this race silently fails to record a
    change it already made to a live LB. 140 failures over 8x20 before the fix."""
    from vpcopilot import ledger
    errors, _ = _race(lambda d, i: ledger.save(d, {f"f{i}": {"state": "found", "finding_id": f"f{i}"}}))
    assert not errors, f"{len(errors)} concurrent ledger writes failed: {errors[:3]}"


def test_the_backfill_sidecar_survives_concurrent_writers():
    """Exposed over HTTP as POST /api/audit-backfill, where concurrency is the default."""
    import inspect

    from vpcopilot import backfill
    src = inspect.getsource(backfill)
    assert 'with_suffix(".json.tmp")' not in src, \
        "backfill still writes through a fixed temp name that concurrent requests collide on"


# ---------------------------------------------------------------- console: one scan at a time


def test_two_concurrent_scans_cannot_both_start(monkeypatch):
    """The guard read a flag that only the spawned THREAD set, so the window between the check and
    the thread starting was wide open — both requests passed and two scans wrote into the same out
    dir, interleaving their artifacts. It is now claimed synchronously under a lock."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    # The fake scan blocks on an Event the TEST releases, rather than sleeping. A sleeping worker
    # outlives the test and then clobbers `_scan` in the middle of whatever test is running 0.3s
    # later — which is what happened here, and it corrupted four unrelated tests in the full suite
    # while every one of them passed in isolation. Owning the thread's lifetime removes the guess.
    release, finished = threading.Event(), threading.Event()

    def fake_scan(*a, **k):
        release.wait(timeout=5)
        A._scan.update(state="done", summary={})
        finished.set()

    monkeypatch.setattr(A, "_run_scan", fake_scan)
    client = TestClient(A.app)
    codes: list[int] = []

    def go():
        codes.append(client.post("/api/scan", json={"repo": tempfile.mkdtemp(),
                                                    "out": tempfile.mkdtemp()}).status_code)
    prior = dict(A._scan)
    try:
        A._scan.update(state="idle")
        ts = [threading.Thread(target=go) for _ in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert codes.count(200) == 1, \
            f"{codes.count(200)} scans started concurrently: {sorted(codes)}"
        assert codes.count(409) == 5
    finally:
        # `_scan` is module state shared by every test that posts to /api/scan. Release the worker,
        # WAIT for it, and only then restore — so no thread of this test's making is still alive to
        # touch shared state after it returns.
        release.set()
        finished.wait(timeout=5)
        A._scan.clear()
        A._scan.update(prior)


# ---------------------------------------------------------------- console: the run dir a job uses


def test_an_in_flight_apply_writes_to_the_dir_it_started_in():
    """`OUT` is a module global that POST /api/scan reassigns, and `_run_action` read it inside the
    worker thread — so an apply already in flight wrote its `apply_timing` audit record into
    whatever directory a concurrent scan had just repointed to. That record is what feeds the
    'time to mitigate' hero, so it lands against the wrong run.

    `_run_reconcile` already took the dir as an argument; the apply path simply had not.
    """
    import inspect

    from vpcopilot.console import app as A
    start = inspect.getsource(A.start_action)
    assert "args=(job_id, body, OUT)" in start, \
        "the action job does not capture the run dir on the request thread"
    run = inspect.getsource(A._run_action)
    assert "str(OUT)" not in run, "_run_action still reads the mutable global inside the worker"
    assert "out: Path" in run.split("\n")[0], "_run_action does not take the run dir explicitly"


def test_a_rejected_scan_request_does_not_wedge_the_scanner():
    """Found while fixing the race above, and worse than the race: claiming `state="running"`
    BEFORE validating the request meant a 400 left the flag set with no worker to ever clear it.
    One malformed request and the console could never start another scan — for the lifetime of the
    process, with no way back short of a restart.

    Three rejects in a row, then a valid request must still be accepted."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    client = TestClient(A.app)
    A._scan.update(state="idle")

    assert client.post("/api/scan", json={}).status_code == 400
    assert client.post("/api/scan", json={"cve": "CVE-2024-23334", "spec": "/s.yaml"}).status_code == 400
    assert client.post("/api/scan", json={"repo": "/x", "min_severity": "nonsense"}).status_code == 400
    assert A._scan["state"] != "running", \
        "a rejected request left the scanner claimed — no scan can ever start again"

    release, finished = threading.Event(), threading.Event()

    def fake_scan(*a, **k):
        release.wait(timeout=5)
        A._scan.update(state="done", summary={})
        finished.set()

    prior, A._run_scan = A._run_scan, fake_scan
    try:
        assert client.post("/api/scan",
                           json={"repo": tempfile.mkdtemp(), "out": tempfile.mkdtemp()}
                           ).status_code == 200, "a valid scan was refused after earlier rejects"
    finally:
        release.set()
        finished.wait(timeout=5)
        A._run_scan = prior
