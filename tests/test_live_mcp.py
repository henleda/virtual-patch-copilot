"""Live: the MCP server driven over a REAL subprocess pipe.

K1's proof was *"registered with Claude Code, ✔ Connected, tools enumerated, and driven end to end
over a real subprocess pipe"* — and it has never been repeatable. The offline suite calls
`mcp.serve(StringIO, StringIO)`, which exercises the protocol logic but **cannot** test the thing
K1 built the design around: that `stdout` carries protocol frames and nothing else, in a real
process, where a stray `print` anywhere beneath the server would land on the actual stream.

That guarantee is structural rather than conventional — `serve()` reassigns `sys.stdout` to stderr
for its lifetime and writes frames to a private handle — and a StringIO cannot falsify it, because
there is no real stdout to corrupt.

Needs no credential: it spawns this repo's own CLI. It is `live` because it starts a real process
and the backlog lists it as a live candidate; every call is bounded by a timeout so a hung server
fails the test instead of the run.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.live

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 60


def _drive(frames: list[dict], *, write: bool = False) -> tuple[list[dict], str]:
    """Send newline-delimited JSON-RPC to a real `vpcopilot mcp` process; return (frames, stderr).

    Deliberately the real CLI entry point rather than `mcp.serve` in-process: the whole point is
    the process boundary, including whatever the CLI does to streams on the way in."""
    cmd = [sys.executable, "-m", "vpcopilot.cli", "mcp"] + (["--write"] if write else [])
    proc = subprocess.run(
        cmd, input="".join(json.dumps(f) + "\n" for f in frames),
        capture_output=True, text=True, timeout=TIMEOUT, cwd=ROOT,
    )
    out = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        # A non-JSON line on stdout IS the failure this suite exists to catch — surface it as one
        # rather than skipping past it.
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pytest.fail(f"non-protocol bytes on MCP stdout — this corrupts the stream for any "
                        f"client: {line[:200]!r}")
    return out, proc.stderr


def _init() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "vpcopilot-live-test", "version": "0"}}}


def test_a_real_process_completes_the_handshake_and_lists_tools(evidence):
    """K1's `✔ Connected`, as a test. Over a real pipe, not a StringIO."""
    frames, _ = _drive([_init(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    by_id = {f.get("id"): f for f in frames}
    assert 1 in by_id, f"no response to initialize: {frames}"
    assert by_id[1]["result"]["serverInfo"]["name"], "initialize returned no serverInfo"

    tools = by_id[2]["result"]["tools"]
    names = sorted(t["name"] for t in tools)
    assert "scan_result" in names and "ledger" in names, f"expected read tools, got {names}"
    # Every argument documented — pinned offline too, but re-checked here because the schema is
    # what a client actually renders to a human.
    for t in tools:
        for prop, spec in (t["inputSchema"].get("properties") or {}).items():
            assert spec.get("description"), f"{t['name']}.{prop} has no description"
    evidence.record(f"handshake ok over a real pipe; {len(names)} tools listed")


@pytest.fixture
def run_dir(tmp_path):
    """A real run directory the test owns.

    Pointing the tool at the repo's ambient `out/` was a mistake: `impact`/`ledger`/`patches_list`
    **decline** a nonexistent run dir (a K1 review fix), and a decline is still a successful
    `result` — so on any machine without `out/` the tool body never runs and the stdout claim below
    tests nothing. Found by mutation, when the guarantee stayed green in a fresh checkout."""
    (tmp_path / "ledger.json").write_text(json.dumps(
        {"neg-pay-001": {"state": "found", "title": "negative amount", "severity": "high"}}))
    return tmp_path


def test_stdout_carries_only_protocol_frames_in_a_real_process(run_dir, evidence):
    """The structural guarantee. `run_pipeline`, `survey_report` and `drift.check` all default
    `log=print`, and `rprint` is used throughout the CLI, so a stray write is one forgotten
    `log=` away. `serve()` points `sys.stdout` at stderr for its lifetime; only a real process can
    show that it holds."""
    frames, stderr = _drive([
        _init(),
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        # A tool call that reaches real code with real logging behind it.
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "ledger", "arguments": {"out": str(run_dir)}}},
    ])
    # `_drive` already fails on any non-JSON stdout line; this asserts the positive half.
    assert frames, "the server produced no frames at all"
    assert all("jsonrpc" in f for f in frames), \
        f"a stdout line was JSON but not a JSON-RPC frame: {[f for f in frames if 'jsonrpc' not in f]}"

    # …and the tool call must have SUCCEEDED, or this test never reached real tool code and proves
    # nothing about stray writes. The first draft passed `out_dir`, which `validate_args` rejects
    # (`accepted arguments: out`) — so it only ever saw an error frame, which is still valid
    # JSON-RPC. A vacuous pass, caught by mutation: disabling the stdout swap did not fail it.
    call = {f.get("id"): f for f in frames}[3]
    assert "result" in call, \
        f"the tool call errored, so no real tool code ran: {call}"
    body = call["result"]["content"][0]["text"]
    assert "declined" not in body, \
        f"the tool DECLINED rather than running — a decline is still a result, so the "\
        f"stdout claim would be untested: {body[:160]}"
    # It really read the dir this test wrote — `count: 1` and the seeded entry, not an empty shell.
    assert '"count": 1' in body and "negative amount" in body, \
        f"the tool did not read the run dir this test created: {body[:200]}"
    evidence.record(f"{len(frames)} frames on stdout, every one JSON-RPC; "
                    f"{len(stderr.splitlines())} line(s) of stderr (allowed)")


def test_a_malformed_frame_does_not_kill_the_connection(evidence):
    """K1's sharpest review finding: a malformed `tools/call` killed the server outright with zero
    frames written, and the client waited forever on a request that would never be answered. Dying
    silently is the worst available failure for a transport — and a real process is where "the
    server exited" and "the server answered an error" actually look different."""
    frames, _ = _drive([
        _init(),
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": ["positional", "array"]},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},      # must still be answered
    ])
    by_id = {f.get("id"): f for f in frames}
    assert 2 in by_id and "error" in by_id[2], f"the malformed call got no error frame: {frames}"
    assert 3 in by_id and "result" in by_id[3], \
        "the connection died after a malformed frame — every later request is lost with it"
    evidence.record("malformed params answered with an error; the next request still served")


def test_write_tools_are_absent_by_default_and_present_with_write(evidence):
    """K1's acceptance: absent rather than present-and-refusing, because a tool an agent can see is
    a tool it will try. Checked across two real processes, since the flag is a launch-time choice."""
    ro, _ = _drive([_init(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    rw, _ = _drive([_init(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}], write=True)
    ro_names = {t["name"] for t in {f.get("id"): f for f in ro}[2]["result"]["tools"]}
    rw_names = {t["name"] for t in {f.get("id"): f for f in rw}[2]["result"]["tools"]}

    for w in ("apply", "pr", "retire", "reconcile", "simulate"):
        assert w not in ro_names, f"write tool {w!r} is visible WITHOUT --write"
        assert w in rw_names, f"write tool {w!r} is missing WITH --write"
    assert ro_names < rw_names, "--write did not widen the tool set"
    evidence.record(f"read-only exposes {len(ro_names)} tools, --write exposes {len(rw_names)}")
