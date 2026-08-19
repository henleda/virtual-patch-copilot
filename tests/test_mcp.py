"""K1 — MCP server mode. Offline throughout: every test drives the JSON-RPC layer directly or over
StringIO streams. No network, no tenant, no model."""
from __future__ import annotations

import io
import json

import pytest

from vpcopilot import mcp


def _drive(messages: list[dict], *, enable_writes: bool = False, swap_stdout: bool = False) -> list[dict]:
    """Feed newline-delimited JSON-RPC through `serve` and parse what comes back."""
    inp = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    out = io.StringIO()
    mcp.serve(inp, out, enable_writes=enable_writes, swap_stdout=swap_stdout)
    return [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]


def _init() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": mcp.PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}}


def _call(name, args=None, mid=9) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
            "params": {"name": name, "arguments": args or {}}}


# ============================================================ lifecycle
def test_initialize_declares_tools_and_our_protocol_version():
    (r,) = _drive([_init()])
    res = r["result"]
    assert res["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert res["capabilities"]["tools"] is not None
    assert res["serverInfo"]["name"] == "vpcopilot"
    assert res["instructions"]                      # an agent session's only orientation


def test_a_client_asking_for_another_version_gets_ours_not_an_error():
    """The spec: if the server does not support the requested version it MUST respond with one it
    does support, and let the client decide whether to disconnect. Erroring the connection out
    instead would make every future protocol bump a hard break."""
    msg = _init()
    msg["params"]["protocolVersion"] = "1999-01-01"
    (r,) = _drive([msg])
    assert "error" not in r
    assert r["result"]["protocolVersion"] == mcp.PROTOCOL_VERSION


def test_notifications_get_no_reply_at_all():
    """A JSON-RPC notification has no id and MUST NOT be answered. Answering one makes a client
    that is not expecting a frame desynchronise."""
    out = _drive([{"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"jsonrpc": "2.0", "method": "notifications/something/unknown"},
                  _init()])
    assert [r["id"] for r in out] == [1]


def test_ping_is_answered_when_it_is_a_request():
    out = _drive([{"jsonrpc": "2.0", "id": 7, "method": "ping"}])
    assert out == [{"jsonrpc": "2.0", "id": 7, "result": {}}]


# ============================================================ framing
def test_every_frame_is_one_line_of_valid_json_with_no_embedded_newline():
    """stdio framing: messages are newline-delimited and MUST NOT contain embedded newlines. A
    tool result carrying a multi-line log is the obvious way to break this by accident."""
    inp = io.StringIO(json.dumps(_init()) + "\n" + json.dumps(_call("scan_result", {"out": "nope"})) + "\n")
    out = io.StringIO()
    mcp.serve(inp, out, swap_stdout=False)
    raw = out.getvalue()
    assert raw.endswith("\n")
    lines = raw.splitlines()
    assert len(lines) == 2                       # exactly one frame per request
    for ln in lines:
        json.loads(ln)                           # parses standalone


def test_malformed_json_is_a_parse_error_and_the_loop_survives():
    inp = io.StringIO("{not json\n" + json.dumps(_init()) + "\n")
    out = io.StringIO()
    mcp.serve(inp, out, swap_stdout=False)
    got = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert got[0]["error"]["code"] == mcp.PARSE_ERROR and got[0]["id"] is None
    assert got[1]["result"]["protocolVersion"]   # still serving afterwards


def test_a_non_object_request_is_rejected_without_killing_the_server():
    inp = io.StringIO("[1,2,3]\n" + json.dumps(_init()) + "\n")
    out = io.StringIO()
    mcp.serve(inp, out, swap_stdout=False)
    got = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert got[0]["error"]["code"] == mcp.INVALID_REQUEST
    assert len(got) == 2


def test_an_unknown_method_is_method_not_found():
    (r,) = _drive([{"jsonrpc": "2.0", "id": 3, "method": "resources/list"}])
    assert r["error"]["code"] == mcp.METHOD_NOT_FOUND


# ============================================================ stdout is the protocol's
def test_a_tool_that_prints_to_stdout_cannot_corrupt_the_stream(monkeypatch, capsys):
    """The load-bearing guarantee. `run_pipeline`, `survey_report` and `drift.check` all default
    `log=print`, and `rprint` is used throughout the CLI — one stray line on stdout and the client
    drops the connection. Passing `log=` at every call site is a convention; `serve()` reassigning
    `sys.stdout` is a guarantee that also covers a print we did not write."""
    def noisy(**kw):
        print("this would corrupt the protocol stream")
        return {"ok": True}

    monkeypatch.setattr(mcp, "build_tools", lambda **kw: [
        mcp.Tool("noisy", "Noisy", "prints to stdout", {"type": "object", "properties": {}}, noisy)])
    inp = io.StringIO(json.dumps(_call("noisy")) + "\n")
    out = io.StringIO()
    mcp.serve(inp, out, swap_stdout=True)
    # the frame stream holds exactly one clean message…
    (frame,) = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert frame["result"]["structuredContent"] == {"ok": True}
    # …and the stray line went to stderr, which the spec explicitly allows for logging
    assert "corrupt the protocol stream" in capsys.readouterr().err


def test_serve_restores_stdout_afterwards(monkeypatch):
    """A test process (or a CLI that keeps running) must not be left with stdout pointing at
    stderr."""
    import sys
    before = sys.stdout
    mcp.serve(io.StringIO(""), io.StringIO(), swap_stdout=True)
    assert sys.stdout is before


# ============================================================ the tool contract
def test_every_tool_documents_every_argument():
    """Acceptance criterion, made mechanical: "tool schemas document every argument". A schema is
    the only documentation an agent session ever sees, so a missing description is a real defect,
    not a style nit."""
    for t in mcp.build_tools(enable_writes=True):
        d = t.definition()
        assert d["description"].strip(), f"{t.name} has no description"
        assert d["inputSchema"]["type"] == "object"
        for arg, spec in d["inputSchema"]["properties"].items():
            assert spec.get("description", "").strip(), f"{t.name}.{arg} has no description"
            assert spec.get("type"), f"{t.name}.{arg} has no type"


def test_read_only_tools_assert_the_hint_rather_than_relying_on_the_default():
    """`readOnlyHint` defaults to FALSE and `destructiveHint` defaults to TRUE in the MCP schema, so
    an omitted annotation describes the opposite of a read. Every hint here is derived from one
    `Access` value per tool, so the two cannot drift apart."""
    by_name = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    for name in ("scan_result", "patches_list", "ledger", "impact", "deps", "simulation_result",
                 "drift", "verify_bundle", "sessions"):
        ann = by_name[name].definition()["annotations"]
        assert ann["readOnlyHint"] is True, name
        assert ann["destructiveHint"] is False, name
    # a scan writes artifacts into the run dir, so it is not read-only — but it is additive and
    # never touches the tenant, so it is not destructive either
    for name in ("scan_start", "scan_status"):
        ann = by_name[name].definition()["annotations"]
        assert ann["readOnlyHint"] is False, name
        assert ann["destructiveHint"] is False, name


def test_sessions_tool_lists_workspaces_for_agent_native_parity(tmp_path, monkeypatch):
    """Agent-native parity: the console's session switcher is a new user capability, so an agent must
    be able to enumerate the same workspaces. `sessions` lists every out* dir with its findings count
    and friendly name; the agent then targets one via the `out` param the other tools take."""
    import json as _json
    monkeypatch.chdir(tmp_path)
    (tmp_path / "out-alpha").mkdir()
    (tmp_path / "out-alpha" / "findings.json").write_text("[]")
    (tmp_path / "out-alpha" / "summary.json").write_text(_json.dumps({"verified": 4}))
    (tmp_path / "out-beta").mkdir()
    (tmp_path / "out-beta" / "session.json").write_text(_json.dumps({"name": "Beta run"}))
    res = mcp._tool_sessions()
    by = {s["out"]: s for s in res["sessions"]}
    assert res["count"] == 2
    assert by["out-alpha"]["verified"] == 4 and by["out-alpha"]["has_results"] is True
    assert by["out-beta"]["name"] == "Beta run" and by["out-beta"]["has_results"] is False


def test_retire_tool_exposes_the_lb_selector():
    """A finding can be live on more than one LB; the agent must be able to name which band-aid to
    retire, exactly as the CLI --lb / console do."""
    by_name = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    props = by_name["retire"].definition()["inputSchema"]["properties"]
    assert "lb" in props and props["lb"]["description"].strip()


def test_tool_names_are_unique_and_stable():
    names = [t.name for t in mcp.build_tools(enable_writes=True)]
    assert len(names) == len(set(names))
    # the read-only set is the contract an agent session depends on; renaming one is a breaking change
    assert {"scan_result", "patches_list", "ledger", "impact", "deps", "simulation_result",
            "drift", "verify_bundle", "scan_start", "scan_status"} <= set(names)


def test_an_unknown_tool_is_a_protocol_error_not_a_tool_error():
    """The spec puts "unknown tool" under protocol errors. Returning isError instead would make a
    typo indistinguishable from a real failure inside a tool that does exist."""
    out = _drive([_call("no_such_tool")])
    assert out[0]["error"]["code"] == mcp.INVALID_PARAMS
    assert "available" in out[0]["error"]["data"]


def test_an_unknown_argument_is_rejected_rather_than_silently_ignored():
    """Every tool function takes `**_` so it can be handed a `log` sink uniformly, which means an
    unrecognised argument would be swallowed. A client sending `output=` instead of `out=` would then
    get a confident answer about the DEFAULT run directory — a wrong answer wearing the shape of a
    right one. The schema is the gate as well as the documentation."""
    out = _drive([_call("patches_list", {"output": "/somewhere/else"})])
    assert out[0]["error"]["code"] == mcp.INVALID_PARAMS
    assert "unknown argument 'output'" in out[0]["error"]["message"]
    assert "out" in out[0]["error"]["message"]          # names what it should have been


def test_a_missing_required_argument_is_invalid_params():
    out = _drive([_call("drift", {}), _call("verify_bundle", {}, mid=10),
                  _call("scan_status", {}, mid=11)])
    for r in out:
        assert r["error"]["code"] == mcp.INVALID_PARAMS
        assert "missing required argument" in r["error"]["message"]


def test_argument_types_are_checked_against_the_schema():
    cases = [
        ("patches_list", {"out": 7}, "must be a string"),
        ("patches_list", {"expired_only": "yes"}, "must be a boolean"),
        ("scan_start", {"repo": "./a", "max_files": 1.5}, "must be a integer"),
        ("scan_start", {"repo": "./a", "manifest": [1, 2]}, "must be a string"),
        ("deps", {"manifest": ["r.txt"], "min_severity": "urgent"}, "must be one of"),
    ]
    for i, (name, args, expect) in enumerate(cases):
        (r,) = _drive([_call(name, args, mid=100 + i)])
        assert r["error"]["code"] == mcp.INVALID_PARAMS, (name, args)
        assert expect in r["error"]["message"], (name, args, r["error"]["message"])


def test_a_boolean_is_not_accepted_where_a_number_is_required():
    """`bool` is a subclass of `int` in Python, so a naive isinstance check would let
    `max_files=True` through and then use it as the integer 1."""
    (r,) = _drive([_call("scan_start", {"repo": "./a", "max_files": True})])
    assert r["error"]["code"] == mcp.INVALID_PARAMS and "must be a integer" in r["error"]["message"]


def test_valid_arguments_still_pass(tmp_path):
    (r,) = _drive([_call("patches_list", {"out": str(tmp_path), "expired_only": True})])
    assert "error" not in r and r["result"]["isError"] is False


def test_arguments_must_be_an_object():
    out = _drive([{"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": {"name": "patches_list", "arguments": [1, 2]}}])
    assert out[0]["error"]["code"] == mcp.INVALID_PARAMS


# ============================================================ declining, not guessing
def test_reading_a_run_dir_that_holds_no_scan_declines_instead_of_looking_clean(tmp_path):
    """The invariant this project is built on: "we did not check this" must never render the same
    way as "this is clean". An empty summary would have read as a scan that found nothing."""
    out = _drive([_call("scan_result", {"out": str(tmp_path)})])
    res = out[0]["result"]
    assert res["isError"] is True
    assert "declined" in res["content"][0]["text"]
    assert "nothing has been scanned" in res["content"][0]["text"]
    assert "structuredContent" not in res       # nothing that could be mistaken for a result


def test_a_missing_simulation_declines_and_says_why_it_will_not_run_one(tmp_path):
    out = _drive([_call("simulation_result", {"out": str(tmp_path)})])
    txt = out[0]["result"]["content"][0]["text"]
    assert out[0]["result"]["isError"] is True
    assert "no simulation.json" in txt and "throwaway policy" in txt


def test_deps_declines_on_an_empty_manifest_list():
    """`required` is satisfied — the key is present — so the schema lets it through and the module
    guard is what catches it. A bad severity is caught earlier, by the schema's enum."""
    out = _drive([_call("deps", {"manifest": []})])
    assert out[0]["result"]["isError"]
    assert "at least one manifest" in out[0]["result"]["content"][0]["text"]


def test_drift_and_verify_bundle_decline_on_a_blank_value_that_passed_the_schema():
    """The schema catches a MISSING argument; these catch one that is present and empty, which a
    JSON-Schema `required` check waves through. Both guards live in the module, so a direct Python
    caller gets the same answer as an MCP client."""
    out = _drive([_call("drift", {"lb": "   "}), _call("verify_bundle", {"path": ""}, mid=10)])
    assert out[0]["result"]["isError"] and "lb is required" in out[0]["result"]["content"][0]["text"]
    assert out[1]["result"]["isError"] and "path is required" in out[1]["result"]["content"][0]["text"]


def test_a_tool_that_raises_is_reported_not_fatal(monkeypatch):
    def boom(**kw):
        raise RuntimeError("the tenant said no")

    monkeypatch.setattr(mcp, "build_tools", lambda **kw: [
        mcp.Tool("boom", "Boom", "raises", {"type": "object", "properties": {}}, boom)])
    out = _drive([_call("boom"), {"jsonrpc": "2.0", "id": 5, "method": "ping"}])
    assert out[0]["result"]["isError"] is True
    assert "the tenant said no" in out[0]["result"]["content"][0]["text"]
    assert out[1] == {"jsonrpc": "2.0", "id": 5, "result": {}}   # server kept serving


# ============================================================ results carry data twice
def test_a_result_carries_both_structured_and_text_json(tmp_path):
    (tmp_path / "ledger.json").write_text(json.dumps(
        {"f-1": {"finding_id": "f-1", "state": "found"}}))
    out = _drive([_call("ledger", {"out": str(tmp_path)})])
    res = out[0]["result"]
    assert res["structuredContent"]["count"] == 1
    assert json.loads(res["content"][0]["text"])["count"] == 1   # same payload, text form


def test_a_payload_with_an_unserialisable_value_degrades_instead_of_killing_the_frame(monkeypatch):
    class Weird:
        def __repr__(self):
            return "<weird>"

    monkeypatch.setattr(mcp, "build_tools", lambda **kw: [
        mcp.Tool("weird", "Weird", "returns a non-JSON value",
                 {"type": "object", "properties": {}}, lambda **kw: {"v": Weird()})])
    out = _drive([_call("weird")])
    assert "<weird>" in out[0]["result"]["content"][0]["text"]


# ============================================================ the scan job
def test_scan_start_validates_the_input_combination_before_spending_anything():
    """Same rules the CLI and console enforce. Checked here so the answer is a clean decline rather
    than a traceback out of run_pipeline's own guard."""
    out = _drive([_call("scan_start", {}),
                  _call("scan_start", {"repo": "./app", "cve": "CVE-2024-23334"}, mid=11)])
    assert out[0]["result"]["isError"] and "give a repo path" in out[0]["result"]["content"][0]["text"]
    assert out[1]["result"]["isError"]
    assert "cannot be combined" in out[1]["result"]["content"][0]["text"]


def test_scan_status_declines_on_an_unknown_job():
    out = _drive([_call("scan_status", {"job_id": "scan-nope"})])
    assert out[0]["result"]["isError"]
    assert "no such scan job" in out[0]["result"]["content"][0]["text"]


def test_a_scan_runs_in_the_background_and_is_polled(monkeypatch, tmp_path):
    """A scan takes minutes and an MCP call is request/response, so scan_start returns immediately
    and scan_status tails the log — the start-then-poll shape the console already uses."""
    import time

    from vpcopilot import pipeline
    started = {}

    def fake_pipeline(repo=None, **kw):
        started["repo"] = repo
        started["out"] = kw.get("out_dir")
        log = kw["log"]
        log("discovering…")
        log("done")
        return {"candidates": 1, "verified": 1, "out_dir": kw.get("out_dir")}

    monkeypatch.setattr(pipeline, "run_pipeline", fake_pipeline)
    srv = mcp.Server()
    start = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}), srv)
    job_id = start["result"]["structuredContent"]["job_id"]
    assert start["result"]["structuredContent"]["state"] == "running"
    for _ in range(200):                                  # the thread is real; wait for it
        st = mcp.handle(_call("scan_status", {"job_id": job_id}), srv)["result"]["structuredContent"]
        if st["state"] != "running":
            break
        time.sleep(0.01)
    assert st["state"] == "done"
    assert st["summary"]["verified"] == 1
    assert st["log"][:1] == ["discovering…"]
    assert started["repo"] == str(tmp_path)
    # `since` tails without re-reading what was already seen
    tail = mcp.handle(_call("scan_status", {"job_id": job_id, "since": st["log_next"]}),
                      srv)["result"]["structuredContent"]
    assert tail["log"] == []


def test_a_failing_scan_is_a_reported_state_not_a_dead_server(monkeypatch, tmp_path):
    import time

    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no API key")))
    srv = mcp.Server()
    job_id = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}),
                        srv)["result"]["structuredContent"]["job_id"]
    for _ in range(200):
        st = mcp.handle(_call("scan_status", {"job_id": job_id}), srv)["result"]["structuredContent"]
        if st["state"] != "running":
            break
        time.sleep(0.01)
    assert st["state"] == "failed" and "no API key" in st["error"]


def test_the_scan_log_sink_is_never_stdout(monkeypatch, tmp_path, capsys):
    """Independently of the sys.stdout swap: the sink handed to run_pipeline must be a list, so a
    scan's progress lines are returned to the caller rather than written anywhere."""
    import time

    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda *a, **k: (k["log"]("a line"), {"ok": True})[1])
    srv = mcp.Server()
    job_id = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}),
                        srv)["result"]["structuredContent"]["job_id"]
    for _ in range(200):
        st = mcp.handle(_call("scan_status", {"job_id": job_id}), srv)["result"]["structuredContent"]
        if st["state"] != "running":
            break
        time.sleep(0.01)
    assert "a line" in st["log"]
    assert "a line" not in capsys.readouterr().out


# ============================================================ writes are absent by default
def test_write_tools_are_absent_unless_enabled():
    """Acceptance: apply/pr/retire/reconcile are ABSENT from the tool list unless explicitly
    enabled — not present-and-refusing. A tool an agent can see is a tool it will try."""
    read_only = {t.name for t in mcp.build_tools()}
    for forbidden in ("apply", "pr", "retire", "reconcile", "simulate"):
        assert forbidden not in read_only


def test_calling_a_write_tool_that_is_not_enabled_is_an_unknown_tool():
    out = _drive([_call("apply", {"lb": "x"})])
    assert out[0]["error"]["code"] == mcp.INVALID_PARAMS
    assert "apply" not in out[0]["error"]["data"]["available"]


@pytest.mark.parametrize("name", ["scan_result", "patches_list", "ledger", "impact"])
def test_a_read_tool_never_writes_into_an_empty_run_dir(tmp_path, name):
    """Polling a read tool must not create artifacts — an MCP client may call these constantly, and
    a read that writes would corrupt the run dir just by being observed (the same reason I2's drift
    endpoint had to stay read-only)."""
    before = set(p.name for p in tmp_path.iterdir())
    _drive([_call(name, {"out": str(tmp_path)})])
    assert set(p.name for p in tmp_path.iterdir()) == before


# ============================================================ the write surface
WRITE_TOOLS = ("apply", "pr", "retire", "reconcile", "simulate")


def test_the_write_tools_appear_only_when_enabled():
    names = {t.name for t in mcp.build_tools(enable_writes=True)}
    for n in WRITE_TOOLS:
        assert n in names
    assert {t.name for t in mcp.build_tools()}.isdisjoint(WRITE_TOOLS)


def test_write_tools_are_marked_destructive():
    """`destructiveHint` defaults to true in the schema, but these assert it, because a client that
    surfaces a confirmation prompt keys off exactly this."""
    by = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    for n in WRITE_TOOLS:
        ann = by[n].definition()["annotations"]
        assert ann["readOnlyHint"] is False and ann["destructiveHint"] is True, n


def test_simulate_is_classified_as_mutating_not_read_only():
    """The roadmap listed `simulate` among the read-only tools. G2's own implementation creates a
    throwaway `<name>-vpcsim` policy, ATTACHES it to the load balancer, replays through it and
    deletes it. Cleaning up after itself makes it safe, not read-only — so it sits behind the same
    opt-in as apply, and `simulation_result` is the ungated way to read the numbers."""
    by = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    assert by["simulate"].access is mcp.Access.MUTATES
    assert by["simulation_result"].access is mcp.Access.READ


def test_apply_pr_and_retire_default_to_a_dry_run():
    """Every module function defaults `dry_run=False`; the CLI and console each pass a choice a human
    made at a keyboard. An MCP tool call is issued by a MODEL, so the default here has to be the one
    that changes nothing, and applying for real has to be a second explicit call."""
    by = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    for n in ("apply", "pr", "retire"):
        assert by[n].definition()["inputSchema"]["properties"]["dry_run"]["default"] is True, n
    # reconcile's equivalent is `apply`, report-only by default (I1)
    assert by["reconcile"].definition()["inputSchema"]["properties"]["apply"]["default"] is False


def test_every_schema_default_matches_the_function_default():
    """A documented default that the code does not honour is a lie an agent acts on. The schema is
    the only documentation an MCP client sees, so the two are compared rather than trusted."""
    import inspect
    for t in mcp.build_tools(enable_writes=True):
        sig = inspect.signature(t.fn)
        for arg, spec in t.definition()["inputSchema"]["properties"].items():
            if "default" not in spec:
                continue
            assert arg in sig.parameters, f"{t.name}.{arg} is documented but not a parameter"
            actual = sig.parameters[arg].default
            assert actual == spec["default"], \
                f"{t.name}.{arg}: schema says {spec['default']!r}, code says {actual!r}"


def test_every_required_argument_is_a_real_parameter():
    import inspect
    for t in mcp.build_tools(enable_writes=True):
        sig = inspect.signature(t.fn)
        for arg in t.definition()["inputSchema"].get("required", []):
            assert arg in sig.parameters, f"{t.name} requires {arg} but does not accept it"


def test_apply_declines_when_the_named_policy_has_no_artifact(tmp_path):
    """It takes a policy NAME and derives the artifact from the run directory — the J2 precedent: an
    endpoint taking a caller-supplied filesystem path is an arbitrary-file reader, and a tool a model
    invokes is a worse place for one than an endpoint a human drives."""
    out = _drive([_call("apply", {"policy_name": "nope", "lb": "lab", "url": "http://x"})],
                 enable_writes=True)
    assert out[0]["result"]["isError"]
    assert "no generated artifact" in out[0]["result"]["content"][0]["text"]


def test_apply_takes_no_filesystem_path_at_all():
    by = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    props = by["apply"].definition()["inputSchema"]["properties"]
    assert "artifact" not in props and "artifact_path" not in props and "path" not in props


def test_pr_declines_for_a_dependency_advisory(tmp_path):
    """H1/H2: the cure is a version bump in someone else's package. Saying so plainly means the tool
    does not merely look like it failed."""
    (tmp_path / "remediations.json").write_text(json.dumps([
        {"finding_id": "GHSA-x", "kind": "dependency_upgrade",
         "summary": "upgrade aiohttp 3.9.1 -> 3.9.2", "pr_title": "t", "pr_body": "b"}]))
    out = _drive([_call("pr", {"finding_id": "GHSA-x", "repo": "o/n", "out": str(tmp_path)})],
                 enable_writes=True)
    txt = out[0]["result"]["content"][0]["text"]
    assert out[0]["result"]["isError"] and "dependency advisory" in txt and "3.9.2" in txt


def test_pr_declines_when_there_is_no_remediation(tmp_path):
    out = _drive([_call("pr", {"finding_id": "absent", "repo": "o/n", "out": str(tmp_path)})],
                 enable_writes=True)
    assert out[0]["result"]["isError"]
    assert "no remediation" in out[0]["result"]["content"][0]["text"]


def test_reconcile_does_not_expose_force_probe():
    """I1's review found `--force-probe`'s guard living only in the CLI, leaving the console able to
    mass-replay every destructive exploit. Its guard needs a single `--finding`, and a model deciding
    to pass it is exactly the accident the guard exists for — so the argument is absent."""
    by = {t.name: t for t in mcp.build_tools(enable_writes=True)}
    assert "force_probe" not in by["reconcile"].definition()["inputSchema"]["properties"]


def test_reconcile_records_mcp_as_the_trigger(monkeypatch, tmp_path):
    """An audit trail that cannot say an action came from an agent session is missing the fact a
    reviewer most wants."""
    from vpcopilot import reconcile as R
    seen = {}
    monkeypatch.setattr(R, "reconcile",
                        lambda out, **kw: (seen.update(kw), {"checked": 0, "pass_id": "p"})[1])
    _drive([_call("reconcile", {"out": str(tmp_path)})], enable_writes=True)
    assert seen["trigger"] == "mcp"
    assert seen["apply"] is False        # report-only by default


def test_simulate_declines_without_a_traffic_sample(tmp_path):
    out = _drive([_call("simulate", {"lb": "lab", "url": "http://x", "logs": ""},
                        )], enable_writes=True)
    assert out[0]["result"]["isError"]
    assert "logs is required" in out[0]["result"]["content"][0]["text"]


def test_the_write_tools_call_the_same_module_functions_as_the_cli():
    """Acceptance: "the server calls the same module functions as the CLI and console". Checked by
    reading the module source, so a future rewrite that inlines its own tenant call fails here."""
    import inspect
    src = inspect.getsource(mcp)
    for fn in ("refine_apply_service_policy", "apply_from_scan", "open_pr", "retire_finding",
               "reconcile", "simulate_policies"):
        assert fn in src, fn
    # and it must not reach the tenant itself
    assert "from .xc import" not in src and "XC()" not in src


# ============================================================ the launcher
def test_the_cli_exposes_mcp_and_defaults_writes_off(monkeypatch):
    import inspect

    from vpcopilot import cli
    assert "write" in inspect.signature(cli.mcp).parameters
    src = inspect.getsource(cli.mcp)
    assert "VPCOPILOT_MCP_WRITE" in src
    assert "stderr" in src            # the banner must not touch stdout
    assert "rprint" not in src


def test_a_policy_name_cannot_become_a_path(tmp_path):
    """`apply` derives the artifact from `out` + `policy_name`, so a name carrying path separators
    would let the derived path leave the run directory and push an attacker-chosen JSON to the tenant
    as a policy spec. Traversal happens to fail today because the mandatory `service_policy.` prefix
    makes the first segment a directory that must exist — luck, not design. Both the name and the
    resolved path are checked."""
    (tmp_path / "policies").mkdir()
    for bad in ("../../etc/passwd", "a/b", "..", "x/../../../y", "a\\b", "name with spaces"):
        out = _drive([_call("apply", {"policy_name": bad, "lb": "lab", "url": "http://x",
                                      "out": str(tmp_path)})], enable_writes=True)
        res = out[0]["result"]
        assert res["isError"], bad
        assert "not a policy name" in res["content"][0]["text"], bad


def test_a_legitimate_generated_slug_is_accepted(tmp_path):
    """The names `generate` actually emits must still work — the guard must not be so tight that it
    rejects the real thing."""
    d = tmp_path / "policies"
    d.mkdir()
    name = "deny-jndi-log4shell-headers"
    (d / f"service_policy.{name}.json").write_text(json.dumps({"spec": {"rule_list": {"rules": []}}}))
    out = _drive([_call("apply", {"policy_name": name, "lb": "lab", "url": "http://x",
                                  "out": str(tmp_path), "dry_run": True})], enable_writes=True)
    txt = out[0]["result"]["content"][0]["text"]
    assert "not a policy name" not in txt and "no generated artifact" not in txt


# ============================================================ protocol edge cases
@pytest.mark.parametrize("raw,want_id,want_kind", [
    # A falsy-but-valid id is the classic JSON-RPC trap: `msg.get("id")` cannot distinguish 0 or
    # false from absent, so notification detection has to test membership, not truthiness.
    ('{"jsonrpc":"2.0","id":0,"method":"ping"}', 0, "result"),
    ('{"jsonrpc":"2.0","id":false,"method":"ping"}', False, "result"),
    ('{"jsonrpc":"2.0","id":"abc","method":"ping"}', "abc", "result"),
    ('{"jsonrpc":"2.0","id":null,"method":"ping"}', None, "result"),
    # MCP 2025-06-18 has no JSON-RPC batching; an array is not a valid message.
    ('[{"jsonrpc":"2.0","id":1,"method":"ping"}]', None, "error"),
    # `params` absent entirely on a tools/call
    ('{"jsonrpc":"2.0","id":2,"method":"tools/call"}', 2, "error"),
])
def test_protocol_edge_cases(raw, want_id, want_kind):
    out = io.StringIO()
    mcp.serve(io.StringIO(raw + "\n"), out, swap_stdout=False)
    (frame,) = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert frame["id"] == want_id and want_kind in frame


def test_crlf_and_a_final_line_without_a_newline_still_parse():
    """A client on Windows, or one that does not terminate its last frame, must not desynchronise."""
    for raw in ('{"jsonrpc":"2.0","id":1,"method":"ping"}\r\n',
                '{"jsonrpc":"2.0","id":1,"method":"ping"}'):
        out = io.StringIO()
        mcp.serve(io.StringIO(raw), out, swap_stdout=False)
        assert json.loads(out.getvalue())["id"] == 1


def test_a_blank_or_whitespace_only_line_is_skipped_not_answered():
    out = io.StringIO()
    mcp.serve(io.StringIO('\n   \n{"jsonrpc":"2.0","id":4,"method":"ping"}\n'), out,
              swap_stdout=False)
    assert len(out.getvalue().splitlines()) == 1


def test_a_tools_call_with_no_arguments_key_uses_defaults(tmp_path):
    out = io.StringIO()
    mcp.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                      "params": {"name": "ledger"}}) + "\n"),
              out, swap_stdout=False)
    assert "result" in json.loads(out.getvalue())


def test_a_malformed_params_object_never_kills_the_server():
    """Found by adversarial review. JSON-RPC permits positional (array) `params`, and a list is
    truthy — so `params.get(...)` raised straight out of `serve()`'s loop, terminating the process
    with ZERO frames written. The client waits forever on a request that will never be answered and
    every later request is lost with it. Dying silently is the worst available failure for a
    transport. A non-string tool name did the same via an unhashable dict lookup."""
    for raw in ('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[{"name":"impact"}]}',
                '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["impact"]}}',
                '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{}}}',
                '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}'):
        out = io.StringIO()
        mcp.serve(io.StringIO(raw + '\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), out,
                  swap_stdout=False)
        fr = [json.loads(ln) for ln in out.getvalue().splitlines()]
        assert [f.get("id") for f in fr] == [1, 2], raw     # answered, and still serving
        assert fr[0]["error"]["code"] == mcp.INVALID_PARAMS, raw


def test_an_unexpected_error_inside_handle_is_answered_not_fatal(monkeypatch):
    """The structural net, one level above the per-tool guard: it covers bugs not yet written. The
    loop must never end without answering the request in flight."""
    class Broken(mcp.Tool):
        def definition(self):
            raise RuntimeError("definition blew up")

    monkeypatch.setattr(mcp, "build_tools", lambda **kw: [
        Broken("broken", "B", "d", {"type": "object", "properties": {}}, lambda **k: {})])
    out = io.StringIO()
    mcp.serve(io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
                          '{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), out, swap_stdout=False)
    fr = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert fr[0]["error"]["code"] == mcp.INTERNAL_ERROR
    assert "definition blew up" in fr[0]["error"]["message"]
    assert fr[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}    # kept serving


def test_every_documented_property_is_a_real_parameter():
    """This is what makes an argument-binding TypeError unreachable, which is in turn why
    `tools/call` has no `except TypeError` pretending a bug inside a tool is a bad argument."""
    import inspect
    for t in mcp.build_tools(enable_writes=True):
        sig = inspect.signature(t.fn)
        for arg in t.definition()["inputSchema"]["properties"]:
            assert arg in sig.parameters, f"{t.name} documents {arg} but does not accept it"


def test_a_typeerror_inside_a_tool_is_a_tool_error_not_invalid_arguments(monkeypatch):
    def boom(**kw):
        return None + 1          # a genuine bug inside the tool

    monkeypatch.setattr(mcp, "build_tools", lambda **kw: [
        mcp.Tool("boom", "B", "raises TypeError", {"type": "object", "properties": {}}, boom)])
    out = _drive([_call("boom")])
    assert "error" not in out[0]                       # not a protocol error…
    assert out[0]["result"]["isError"] is True         # …a tool-execution error
    assert "TypeError" in out[0]["result"]["content"][0]["text"]


# ============================================================ review findings, pinned
def test_a_notification_is_never_answered_whatever_its_method():
    """Found by adversarial review. The notification check was per-branch, so a request method
    arriving WITHOUT an id — `{"method":"initialize"}` — was answered with an unsolicited `id: null`
    frame. A client not expecting a response desynchronises on the next one it reads."""
    for method in ("initialize", "tools/list", "tools/call", "ping", "notifications/initialized"):
        out = io.StringIO()
        mcp.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n"), out,
                  swap_stdout=False)
        assert out.getvalue() == "", f"{method} answered a notification"


def test_scan_status_never_advances_the_cursor_past_what_it_returned(monkeypatch, tmp_path):
    """Found by adversarial review, proven there with 565 of 20000 polls losing 27622 lines. Reading
    `job["log"]` twice — slicing it, then taking its length for `log_next` — let the worker append
    between the two, so `log_next` counted lines the slice never returned and a client tailing with
    `since=log_next` could never ask for them again."""
    import threading
    import time

    from vpcopilot import pipeline
    stop = threading.Event()

    def chatty(repo=None, **kw):
        log = kw["log"]
        for i in range(4000):
            if stop.is_set():
                break
            log(f"line {i}")
        return {"ok": True}

    monkeypatch.setattr(pipeline, "run_pipeline", chatty)
    srv = mcp.Server()
    jid = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}),
                     srv)["result"]["structuredContent"]["job_id"]
    seen, since, polls = 0, 0, 0
    try:
        while polls < 3000:
            st = mcp.handle(_call("scan_status", {"job_id": jid, "since": since}),
                            srv)["result"]["structuredContent"]
            # the invariant: the cursor may only advance by what we were actually handed
            assert st["log_next"] == st["log_from"] + len(st["log"]), st
            seen += len(st["log"])
            since = st["log_next"]
            polls += 1
            if st["state"] != "running" and since >= st["log_next"]:
                break
            time.sleep(0)
    finally:
        stop.set()
        time.sleep(0.05)


def test_a_second_scan_into_the_same_run_dir_is_refused(monkeypatch, tmp_path):
    """Two pipelines writing one run directory interleave findings.json, triage.json, policies/ and
    the ledger, and the loser's half-written state is indistinguishable from a complete run."""
    import threading
    import time

    from vpcopilot import pipeline
    release = threading.Event()
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda *a, **k: (release.wait(5), {"ok": True})[1])
    srv = mcp.Server()
    first = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}),
                       srv)["result"]["structuredContent"]["job_id"]
    try:
        second = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(tmp_path)}),
                            srv)["result"]
        assert second["isError"]
        assert "already running" in second["content"][0]["text"]
        assert first in second["content"][0]["text"]         # names the job to wait for
        # …and a DIFFERENT out dir is fine
        other = tmp_path / "other"
        other.mkdir()
        ok = mcp.handle(_call("scan_start", {"repo": str(tmp_path), "out": str(other)}),
                        srv)["result"]
        assert not ok["isError"]
    finally:
        release.set()
        time.sleep(0.05)


def test_a_run_dir_that_does_not_exist_declines_rather_than_reporting_zero(tmp_path):
    """`list_patches`, `ledger.load` and `impact` all answer a missing directory with zeros, which
    reads as "no live band-aids" — the most reassuring possible answer to a typo."""
    missing = str(tmp_path / "never-scanned")
    for name in ("patches_list", "ledger", "impact"):
        out = _drive([_call(name, {"out": missing})])
        assert out[0]["result"]["isError"], name
        assert "no run directory" in out[0]["result"]["content"][0]["text"], name


def test_scan_start_refuses_a_path_that_does_not_exist(tmp_path):
    """`run_pipeline`'s own docstring calls a scan of a nonexistent path "the failure mode not to
    extend": it completes and writes a durable summary saying nothing was found."""
    for args in ({"repo": str(tmp_path / "nope")},
                 {"spec": str(tmp_path / "nope.yaml")},
                 {"manifest": [str(tmp_path / "nope.txt")]}):
        out = _drive([_call("scan_start", args)])
        assert out[0]["result"]["isError"], args
        assert "does not exist" in out[0]["result"]["content"][0]["text"], args


def test_the_drift_description_does_not_promise_a_check_it_may_not_run():
    """"Agents reason, code acts": a description is the only thing an agent has to go on, so it must
    not claim a guard that needs an argument the agent was not told to pass."""
    by = {t.name: t for t in mcp.build_tools()}
    desc = by["drift"].definition()["description"]
    assert "Pass `policy`" in desc and "does not run" in desc
