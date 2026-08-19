"""K1 — MCP server mode. The pipeline's read-only surface as Model Context Protocol tools, so an
agent session gets a band-aid proposal inline instead of shelling out to the CLI.

Three things about this module are deliberate and load-bearing.

**No new dependency.** The stdio transport is newline-delimited JSON-RPC 2.0, and the whole surface
K1 needs is `initialize`, `tools/list`, `tools/call` and `ping`. Hand-rolling that is ~150 lines and
means `vpcopilot mcp` works with no extra install — unlike `console`, which needs the `console`
extra — and it is testable offline by feeding frames to `handle()`, with no network and no fakes
beyond the ones `tests/` already has. The official SDK is at 2.0.0; pinning a major-version API
that churns under a committed demo buys interop we can get by testing against a real client.

**stdout belongs to the protocol, and nothing else.** The spec is explicit: the server MUST NOT
write anything to stdout that is not a valid MCP message. This codebase logs to stdout everywhere —
`rprint` throughout `cli.py`, and `run_pipeline`/`survey_report`/`drift.check` all default
`log=print`. One stray line corrupts the stream and the client drops the connection. Passing
`log=` at every call site would be a convention, and a convention is exactly what gets forgotten by
the next call site. So `serve()` reassigns `sys.stdout` to stderr for the life of the process and
keeps a private handle for frames: a stray `print` ANYWHERE beneath us is structurally incapable of
corrupting the protocol. Pinned by a test that prints from inside a tool.

**Read-only is asserted, not assumed.** `readOnlyHint` defaults to *false* and `destructiveHint`
defaults to *true* in the MCP schema, so every hint here is set explicitly from a single
`Access` classification per tool rather than left to a default a reader would have to look up.
"""
from __future__ import annotations

import json
import re
import sys
import threading
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import __version__

# The protocol revision this server implements. On a mismatch the spec says respond with a version
# we DO support rather than erroring, and let the client decide whether to disconnect.
PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "vpcopilot"

# JSON-RPC error codes we actually emit.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# A generated policy name, as `generate` emits and `apply` writes to disk: a slug that starts
# alphanumeric. Used to keep a caller-supplied name from becoming a path. `..` is excluded
# separately — it satisfies the charset (dots are legal inside a slug) but is never a real name.
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _is_safe_name(name: str) -> bool:
    return bool(_SAFE_NAME.fullmatch(name)) and ".." not in name


class Access(Enum):
    """What a tool does to the world. Drives the MCP annotations deterministically, so the hints
    cannot drift from the truth by someone editing one and not the other.

    READ        — reads disk and/or the network; changes nothing anywhere. One documented caveat:
                  `deps` will populate the OSV advisory cache if — and only if — the operator set
                  `VPCOPILOT_ADVISORY_CACHE`. That is an opt-in, idempotent write outside the run
                  directory that cannot affect the tenant, the ledger or any artifact, so the tool
                  still reports `readOnlyHint: true`; marking it mutating would make clients prompt
                  for a dependency lookup, which is worse and less true.
    WRITES_OUT  — writes only into the run directory (a scan). Additive, never destructive, and
                  nothing on the tenant is touched.
    MUTATES     — changes something outside this machine: a load balancer, a GitHub PR, the ledger's
                  live state. Absent from the tool list unless writes are explicitly enabled.
    """

    READ = "read"
    WRITES_OUT = "writes_out"
    MUTATES = "mutates"


@dataclass
class Tool:
    name: str
    title: str
    description: str
    schema: dict
    fn: Callable[..., Any]
    access: Access = Access.READ
    # openWorldHint: does it reach an unbounded external world (OSV, the tenant, GitHub)?
    open_world: bool = False

    def definition(self) -> dict:
        """The `tools/list` entry. Every argument carries a description — an acceptance criterion,
        and the only documentation an agent session ever sees."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": self.access is Access.READ,
                # Meaningful only when readOnlyHint is false. A scan only adds artifacts to a run
                # dir; a MUTATES tool can take protection off a live load balancer.
                "destructiveHint": self.access is Access.MUTATES,
                "idempotentHint": False,
                "openWorldHint": self.open_world,
            },
        }


def _out_schema(extra: dict | None = None, *, required: list[str] | None = None) -> dict:
    """Most tools are "read this run directory". Shared so the wording of `out` is identical in
    every schema rather than retyped eight times."""
    props = {"out": {"type": "string", "default": "out",
                     "description": "run directory written by a previous scan (default: out)"}}
    props.update(extra or {})
    return {"type": "object", "properties": props, "required": required or []}


# --------------------------------------------------------------------------- tool implementations
# Each returns a plain JSON-serialisable dict or list. Each is handed a `log` sink that appends to a
# list, never stdout — belt as well as the braces of the sys.stdout swap in `serve()`.

def _require_run_dir(out: str) -> None:
    """A run directory that does not exist is not an empty one.

    `list_patches`, `ledger.load` and `impact` all answer a missing directory with zeros, which reads
    as "no live band-aids" / "nothing mitigated" — a confident all-clear for a run that was never
    made. A typo'd `out` would have produced the most reassuring possible answer."""
    from pathlib import Path
    if not Path(out).is_dir():
        raise Declined(f"no run directory at {out!r} — that is not the same as a run with nothing "
                       "in it. Check the path, or start one with scan_start.")


def _tool_patches_list(out: str = "out", expired_only: bool = False, **_) -> dict:
    from .reconcile import list_patches
    _require_run_dir(out)
    rows = list_patches(out)
    if expired_only:
        rows = [r for r in rows if r["expired"]]
    return {"out": out, "count": len(rows), "patches": rows}


def _tool_ledger(out: str = "out", **_) -> dict:
    from .ledger import load
    _require_run_dir(out)
    entries = load(out)
    return {"out": out, "count": len(entries), "entries": list(entries.values())}


def _tool_sessions(**_) -> dict:
    """List the scan workspaces (sessions) — the `out*` dirs — so an agent can enumerate what has been
    scanned and choose which one to read or scan into via the `out` param every other tool takes. The
    console's session switcher is UI convenience over exactly this list; an agent targets a session by
    passing its `out`."""
    from pathlib import Path

    from . import sessions as _sessions
    rows = []
    for p in sorted(Path.cwd().glob("out*")):
        if not p.is_dir():
            continue
        summ = _sessions.read_meta(p, "summary.json")   # tolerant: a non-object sidecar yields {}, not a crash
        meta = _sessions.read_meta(p, "session.json")
        rows.append({"out": p.name, "name": meta.get("name") or p.name,
                     "has_results": (p / "findings.json").exists(),
                     "verified": summ.get("verified", 0), "candidates": summ.get("candidates", 0)})
    return {"count": len(rows), "sessions": rows}


def _tool_session_new(name: str = "", **_) -> dict:
    """Create a fresh named session (an out* workspace) — the agent-native twin of the console's
    'New session'. Writes out-<slug>/session.json with the friendly name via the SAME shared helper
    the console uses, so an agent can set the name a user could; then scan into the returned `out`."""
    from . import sessions as _sessions
    if not str(name).strip():
        raise Declined("a session name is required")
    try:
        return _sessions.create_session(name)
    except ValueError as e:
        raise Declined(str(e))


def _tool_impact(out: str = "out", **_) -> dict:
    from .impact import impact
    _require_run_dir(out)
    return impact(out)


def _tool_scan_result(out: str = "out", **_) -> dict:
    """The band-aid proposal itself, read back from a finished run: what was found, how each finding
    was triaged, and which XC config was generated for it. This is the payload K1 exists to put in
    front of an agent session."""
    import json as _json
    from pathlib import Path

    # ABSENT and UNREADABLE are different answers and must not render the same way. A member that is
    # not there is normal — not every run writes every artifact — and gets the default. A member that
    # exists and will not parse is a fact we failed to establish: swallowing the error returned `[]`,
    # which is indistinguishable from a run that genuinely found nothing. That is the same confusion
    # H2 exists to prevent, so an unreadable member becomes `null` (not `[]`) and is named in
    # `unreadable`, where nothing can mistake it for an empty result.
    unreadable: list[dict] = []

    def rj(name, default):
        p = Path(out) / name
        if not p.is_file():
            return default
        try:
            return _json.loads(p.read_text())
        except (OSError, _json.JSONDecodeError) as e:
            unreadable.append({"member": name, "error": str(e)})
            return None

    summary = rj("summary.json", {})
    if not summary:
        # Refusing to guess: an empty dict here would read as "a clean scan", which is the one
        # answer this project never lets a missing input produce.
        raise Declined(
            f"summary.json in {out!r} could not be read: {unreadable[0]['error']}"
            if unreadable else
            f"no scan results in {out!r} — nothing has been scanned into it yet "
            "(run scan_start, or point `out` at a directory that holds summary.json)")
    res = {"out": out, "summary": summary, "findings": rj("findings.json", []),
           "triage": rj("triage.json", []), "policies": rj("policies.json", []),
           "remediations": rj("remediations.json", []),
           "correlations": rj("correlations.json", []),
           "dependencies": rj("dependencies.json", None)}
    if unreadable:
        res["unreadable"] = unreadable
        res["caveat"] = (f"{len(unreadable)} artifact(s) exist but could not be parsed and are null "
                         "below, NOT empty: " + ", ".join(u["member"] for u in unreadable))
    return res


def _tool_deps(manifest: list[str] | None = None, min_severity: str = "high",
               max_advisories: int = 25, include_dev: bool = False, log=None, **_) -> dict:
    from .inputs.deps import survey_report
    paths = [m for m in (manifest or []) if str(m).strip()]
    if not paths:
        raise Declined("give at least one manifest path (requirements.txt, package-lock.json "
                       "or pom.xml)")
    if min_severity not in ("critical", "high", "medium", "low"):
        raise Declined("min_severity must be one of critical, high, medium, low")
    return survey_report(paths, min_severity=min_severity, max_advisories=max_advisories,
                         include_dev=include_dev, log=log or (lambda m: None))


def _tool_simulation_result(out: str = "out", **_) -> dict:
    from .simulate import load_result
    res = load_result(out)
    if not res:
        raise Declined(f"no simulation.json in {out!r} — no blast-radius replay has run for this "
                       "run directory. A simulation attaches a throwaway policy to a spare load "
                       "balancer, so it is not something this server does on its own.")
    return res


def _tool_drift(lb: str = "", out: str = "out", control: str | None = None,
                policy: str | None = None, finding: str | None = None, log=None, **_) -> dict:
    """Read-only by construction: `drift.check` issues no PUT and writes no snapshot (I2)."""
    import json as _json
    from pathlib import Path

    from .drift import check
    if not str(lb).strip():
        raise Declined("lb is required — name the load balancer to inspect")
    exploit = None
    if finding:
        from .apply import _load_probe
        exploit = (_load_probe(out, finding) or {}).get("exploit")
    spec = None
    if policy:
        # Same guard `_tool_apply` uses: a caller-supplied policy is interpolated into a file path,
        # so a name carrying `../` would read an arbitrary local .json. Reject unless it is a real
        # slug AND the derived path stays inside the run's policies dir.
        if not _is_safe_name(policy):
            raise Declined(f"{policy!r} is not a policy name — expected a generated slug of "
                           "letters, digits, dots, dashes and underscores")
        pol_dir = (Path(out) / "policies").resolve()
        art = pol_dir / f"service_policy.{policy}.json"
        if not art.resolve().is_relative_to(pol_dir):
            raise Declined(f"{policy!r} resolves outside {out!r}/policies — refusing")
        if art.is_file():
            spec = _json.loads(art.read_text())
    return check(lb, out_dir=out, control=control, policy_name=policy, exploit=exploit,
                 spec=spec, log=log or (lambda m: None))


def _tool_verify_bundle(path: str = "", pubkey: str | None = None, log=None, **_) -> dict:
    from .export import verify_bundle
    if not str(path).strip():
        raise Declined("path is required — point at an exported evidence bundle (.zip)")
    return verify_bundle(path, pubkey=pubkey, log=log or (lambda m: None))


class Declined(Exception):
    """A tool that cannot establish a fact says so. Surfaced to the client as a tool-execution
    error (`isError: true`) with the reason, never as a traceback and never as an empty result that
    would read like a clean answer."""


# --------------------------------------------------------------------------- the scan job registry
# A scan takes minutes and an MCP tool call is request/response, so `scan_start` returns a job id
# immediately and `scan_status` polls — the same start-then-poll shape the console already uses for
# scan/apply/reconcile, but with none of its FastAPI coupling.

_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


def _tool_scan_start(repo: str | None = None, cve: str | None = None, spec: str | None = None,
                     manifest: list[str] | None = None, out: str = "out",
                     min_confidence: float = 0.5, max_files: int = 200, max_bytes: int = 60_000,
                     draft_code_fixes: bool = True, min_severity: str = "high",
                     max_advisories: int = 25, include_dev: bool = False,
                     config_path: str | None = None, **_) -> dict:
    manifests = [m for m in (manifest or []) if str(m).strip()]
    repo, cve, spec = (str(x).strip() if x else "" for x in (repo, cve, spec))
    # Same input rules the CLI and the console enforce, checked here so the failure is a clean
    # decline rather than a traceback out of run_pipeline's own guard.
    if cve and (repo or spec or manifests):
        raise Declined("a CVE scan cannot be combined with a repo, a spec or a manifest")
    if not (repo or cve or spec or manifests):
        raise Declined("give a repo path, a CVE/GHSA id, an OpenAPI spec, or a dependency manifest")
    # A path that does not exist produced a completed scan with zero findings and a durable
    # summary.json saying so — a clean bill of health for something never read. `run_pipeline`'s own
    # docstring calls this out as "the failure mode not to extend", so it is checked before the job
    # is even started rather than discovered minutes later in a log.
    from pathlib import Path
    for label, p in (("repo", repo), ("spec", spec), *[("manifest", m) for m in manifests]):
        if p and not Path(p).exists():
            raise Declined(f"{label} path {p!r} does not exist — a scan of nothing would write a "
                           "summary saying nothing was found, which is not the same answer")

    job_id = f"scan-{uuid.uuid4().hex[:12]}"
    job = {"id": job_id, "state": "running", "log": [], "summary": None, "error": None,
           "out": out}
    with _JOBS_LOCK:
        # Two scans into ONE run directory interleave their artifacts: both write findings.json,
        # triage.json, policies/ and the ledger, and the loser's half-written state is
        # indistinguishable from a complete run. An agent session polling one job would read the
        # other's numbers. Refusing is the only honest answer, and it names the job to wait for.
        clash = next((j for j in _JOBS.values()
                      if j["state"] == "running" and j["out"] == out), None)
        if clash is not None:
            raise Declined(
                f"a scan is already running into {out!r} (job {clash['id']}) — two scans would "
                "interleave their artifacts in one run directory. Wait for it with scan_status, or "
                "pass a different `out`.")
        _JOBS[job_id] = job

    def run():
        from .pipeline import run_pipeline
        try:
            summary = run_pipeline(
                repo or None, out_dir=out, config_path=config_path,
                min_confidence=min_confidence, max_files=max_files, max_bytes=max_bytes,
                draft_code_fixes=draft_code_fixes,
                # The log sink is a list, never stdout. `serve()` also swaps sys.stdout, so this is
                # the second of two independent guarantees.
                log=lambda m: job["log"].append(str(m)),
                advisory=cve or None, spec_path=spec or None,
                manifest_paths=manifests or None, min_severity=min_severity,
                max_advisories=max_advisories, include_dev=include_dev)
            job["summary"] = summary
            job["state"] = "done"
        except Exception as e:  # noqa: BLE001 — a failed scan is a reported state, not a crash
            job["error"] = f"{type(e).__name__}: {e}"
            job["log"].append(f"scan failed: {job['error']}")
            job["state"] = "failed"

    t = threading.Thread(target=run, name=job_id, daemon=True)
    t.start()
    return {"job_id": job_id, "state": "running", "out": out,
            "note": "poll scan_status with this job_id; a scan spends model calls and usually "
                    "takes minutes"}


def _tool_scan_status(job_id: str = "", since: int = 0, **_) -> dict:
    with _JOBS_LOCK:
        job = _JOBS.get(str(job_id))
    if job is None:
        known = sorted(_JOBS)
        raise Declined(f"no such scan job {job_id!r}"
                       + (f" — known jobs: {', '.join(known)}" if known else
                          " — no scan has been started by this server"))
    # ONE snapshot of the log, and both the slice and the cursor come from it. Reading
    # `job["log"]` twice — slicing it, then taking its length for `log_next` — is a lost-update
    # race: the worker thread appends between the two reads, `log_next` counts lines the slice did
    # not return, and a client tailing with `since=log_next` never sees them. Silently dropping
    # progress lines is the kind of wrong answer nobody notices.
    snap = list(job["log"])
    frm = max(0, int(since))
    state, summary, error = job["state"], job["summary"], job["error"]
    return {"job_id": job["id"], "state": state, "out": job["out"],
            "log_from": frm, "log_next": len(snap), "log": snap[frm:],
            "summary": summary, "error": error}


# --------------------------------------------------------------------------- registry

def build_tools(*, enable_writes: bool = False) -> list[Tool]:
    """The tool list. Write tools are ABSENT unless explicitly enabled — not present-and-refusing,
    because a tool an agent can see is a tool it will try, and the acceptance criterion is absence.
    """
    tools = [
        Tool("scan_result", "Scan result",
             "The band-aid proposal from a finished scan: every verified finding, how triage routed "
             "it to an F5 XC control (or to code only), the generated policy artifacts, the code "
             "cures, and the dependency funnel when the scan used --manifest. Reads a run directory; "
             "spends nothing. Declines if the directory holds no scan.",
             _out_schema(), _tool_scan_result),
        Tool("patches_list", "Live band-aids",
             "Every live band-aid with its age, TTL remaining, cure state and escalation count. A "
             "pure read of the ledger — no tenant call, no GitHub call, no exploit fired — so it is "
             "cheap enough to poll.",
             _out_schema({"expired_only": {"type": "boolean", "default": False,
                                           "description": "only patches past their TTL"}}),
             _tool_patches_list),
        Tool("ledger", "Remediation ledger",
             "The lifecycle of every finding: found -> mitigated -> remediated -> retired, with the "
             "control attached and the cure PR. Pure ledger read.",
             _out_schema(), _tool_ledger),
        Tool("sessions", "List scan workspaces",
             "Every scan session (an out* dir): its findings count and friendly name. The console's "
             "session switcher is UI over this list — an agent targets a session by passing its `out` "
             "to any other tool. Pure filesystem read.",
             {"type": "object", "properties": {}, "additionalProperties": False}, _tool_sessions),
        Tool("impact", "Headline numbers",
             "The numbers the report and console render: exploitable vulns, how many are mitigated "
             "live, mean time to mitigate against normal change-control days, drafted code-fix PRs, "
             "and dependency upgrades that no PR can cover. Pure read of the run dir and ledger.",
             _out_schema(), _tool_impact),
        Tool("deps", "Dependency survey",
             "What a --manifest scan WOULD find, without spending a single model call: parses "
             "requirements.txt / package-lock.json / pom.xml, asks OSV.dev which pinned packages "
             "have advisories, and returns the whole funnel — including every entry it could not "
             "pin and every advisory held back by the filters, each with the reason. Needs no "
             "credentials and no model. Reaches api.osv.dev.",
             {"type": "object",
              "properties": {
                  "manifest": {"type": "array", "items": {"type": "string"},
                               "description": "one or more manifest paths: requirements.txt, "
                                              "package-lock.json, pom.xml"},
                  "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low"],
                                   "default": "high",
                                   "description": "floor a scan would resolve at; below it an "
                                                  "advisory is listed but never sent to an agent"},
                  "max_advisories": {"type": "integer", "default": 25,
                                     "description": "cap a scan would apply to the agent stage "
                                                    "(0 = no cap); shared round-robin across "
                                                    "packages, not consumed in sort order"},
                  "include_dev": {"type": "boolean", "default": False,
                                  "description": "also count dev/test-scoped dependencies, which "
                                                 "are not in the request path"}},
              "required": ["manifest"]},
             _tool_deps, open_world=True),
        Tool("simulation_result", "Blast radius",
             "The would-block result of a previous shadow simulation: per candidate policy, how "
             "many recorded requests it would have blocked, the rate, a sample, and whether it "
             "tripped the blast-radius threshold. Reads simulation.json — running a simulation "
             "attaches a throwaway policy to a spare load balancer, so this server never does it.",
             _out_schema(), _tool_simulation_result),
        Tool("drift", "LB drift and conflicts",
             "What is on the load balancer now, versus what the last run's snapshot recorded, "
             "versus what you are about to push. Reports operator hand-edits as a field-level diff. "
             "Pass `policy` as well to also check the candidate for an ALLOW rule that would shadow "
             "its own DENY — without it there are no rules to walk and that check does not run. "
             "Read-only against the tenant: no PUT, no snapshot written, nothing in the run dir "
             "touched. Needs XC credentials.",
             _out_schema({
                 "lb": {"type": "string", "description": "load balancer to inspect"},
                 "control": {"type": "string",
                             "description": "the control you are about to apply, e.g. "
                                            "service_policy, waf, rate_limit"},
                 "policy": {"type": "string",
                            "description": "service-policy name you are about to attach; also "
                                           "locates the generated artifact for the shadowing check"},
                 "finding": {"type": "string",
                             "description": "use this finding's recorded exploit for the shadowing "
                                            "check"}}, required=["lb"]),
             _tool_drift, open_world=True),
        Tool("verify_bundle", "Verify evidence bundle",
             "Re-read an exported evidence bundle and check every member digest against its own "
             "manifest, plus the minisign signature when a public key is supplied. Reports each "
             "member as ok / mismatch / missing / unlisted. A bundle with no signature verifies its "
             "digests and says the signature is absent rather than failing.",
             {"type": "object",
              "properties": {
                  "path": {"type": "string", "description": "path to the bundle .zip"},
                  "pubkey": {"type": "string",
                             "description": "minisign public key, obtained out of band, to check "
                                            "the signature too"}},
              "required": ["path"]},
             _tool_verify_bundle),
        # Writes only into the run directory: additive, and nothing on the tenant is touched.
        Tool("scan_start", "Start a scan",
             "Run the pipeline: discover -> verify -> triage -> generate XC band-aids -> draft the "
             "code cure. Read-only with respect to the tenant — it never touches a load balancer — "
             "but it SPENDS MODEL CALLS, writes artifacts into the run directory, and usually takes "
             "minutes, so it returns a job_id immediately. Poll scan_status. Inputs: a repo path, a "
             "CVE/GHSA id (exclusive), an OpenAPI spec and/or dependency manifests (additive).",
             {"type": "object",
              "properties": {
                  "repo": {"type": "string",
                           "description": "path to the source directory to scan"},
                  "cve": {"type": "string",
                          "description": "a CVE or GHSA id to scan instead of a repo; cannot be "
                                         "combined with repo, spec or manifest"},
                  "spec": {"type": "string",
                           "description": "path to an OpenAPI spec; alone it scans the contract, "
                                          "with a repo it also reports spec/code drift"},
                  "manifest": {"type": "array", "items": {"type": "string"},
                               "description": "dependency manifests, additive with repo and spec"},
                  "out": {"type": "string", "default": "out",
                          "description": "run directory to write artifacts into"},
                  "min_confidence": {"type": "number", "default": 0.5,
                                     "description": "drop verified findings below this confidence"},
                  "max_files": {"type": "integer", "default": 200,
                                "description": "cap on files read from the repo"},
                  "max_bytes": {"type": "integer", "default": 60000,
                                "description": "cap on bytes read per file"},
                  "draft_code_fixes": {"type": "boolean", "default": True,
                                       "description": "also draft the code cure; off saves roughly "
                                                      "half the tokens and yields band-aids only"},
                  "min_severity": {"type": "string", "enum": ["critical", "high", "medium", "low"],
                                   "default": "high",
                                   "description": "manifest advisories: floor for reaching the "
                                                  "resolve agent"},
                  "max_advisories": {"type": "integer", "default": 25,
                                     "description": "manifest advisories: cap on the agent stage "
                                                    "(0 = no cap)"},
                  "include_dev": {"type": "boolean", "default": False,
                                  "description": "manifest advisories: resolve dev/test-scoped "
                                                 "dependencies too"},
                  "config_path": {"type": "string",
                                  "description": "config/agents*.yaml to run with; omit for the "
                                                 "default model config"}},
              "required": []},
             _tool_scan_start, access=Access.WRITES_OUT, open_world=True),
        Tool("scan_status", "Scan progress",
             "Poll a scan started by scan_start: its state (running / done / failed), the new log "
             "lines since `since`, and the summary once it finishes. Pass log_next back as `since` "
             "to tail without re-reading what you already have.",
             {"type": "object",
              "properties": {
                  "job_id": {"type": "string", "description": "id returned by scan_start"},
                  "since": {"type": "integer", "default": 0,
                            "description": "number of log lines already seen; use log_next from "
                                           "the previous call"}},
              "required": ["job_id"]},
             _tool_scan_status, access=Access.WRITES_OUT),
        Tool("session_new", "Create a named session",
             "Create a fresh named scan workspace (out-<slug> + session.json holding the friendly "
             "name) — the agent-native twin of the console's 'New session'. Writes only into the "
             "local workspace (no tenant, no GitHub); then scan into the returned `out`.",
             {"type": "object",
              "properties": {"name": {"type": "string",
                                      "description": "friendly session name, e.g. 'Larkspur Prod'"}},
              "required": ["name"], "additionalProperties": False},
             _tool_session_new, access=Access.WRITES_OUT),
    ]
    if enable_writes:
        tools += _write_tools()
    return tools


def _tool_apply(policy_name: str = "", lb: str = "", url: str = "", finding_id: str | None = None,
                dry_run: bool = True, keep: bool = False, refine: bool = True,
                allow_protected_lb: bool = False, force: bool = False,
                allow_overbroad: bool = False, out: str = "out", log=None, **_) -> dict:
    """Attach a generated service policy, validate it live, roll back unless it passed and `keep`.

    Two deliberate differences from the CLI, both narrowing:

    `dry_run` defaults to **True** here where every module function defaults it False. The CLI and
    the console each pass an explicit choice made by a human at a keyboard; an MCP tool call is
    issued by a model, so the default has to be the one that changes nothing. Applying for real is a
    second, explicit call.

    It takes a policy **name**, not a path, and derives the artifact from the run directory — the J2
    precedent: an endpoint that accepts a caller-supplied filesystem path is an arbitrary-file
    reader, and a tool invoked by a model is a worse place for one than an endpoint a human drives.
    """
    from pathlib import Path

    from . import apply as A
    log = log or (lambda m: None)
    if not str(policy_name).strip():
        raise Declined("policy_name is required — the name of a generated service policy; "
                       "list them with scan_result")
    if not str(lb).strip():
        raise Declined("lb is required — the load balancer to apply to")
    if not str(url).strip():
        raise Declined("url is required — the live host the band-aid is validated against")
    # A generated policy name is a slug (`deny-jndi-log4shell-headers`). Anything else is not a
    # policy name, and a name carrying path separators would let the derived artifact path leave the
    # run directory — so an attacker-chosen JSON could be read and pushed to the tenant as a spec.
    # Traversal happens to fail today because the mandatory `service_policy.` prefix makes the first
    # segment a directory that must exist, which is luck rather than a design. Both halves are
    # checked: the name, and that the path it produced is still inside the run's policies dir.
    if not _is_safe_name(policy_name):
        raise Declined(f"{policy_name!r} is not a policy name — expected a generated slug of "
                       "letters, digits, dots, dashes and underscores")
    pol_dir = (Path(out) / "policies").resolve()
    art = pol_dir / f"service_policy.{policy_name}.json"
    if not art.resolve().is_relative_to(pol_dir):
        raise Declined(f"{policy_name!r} resolves outside {out!r}/policies — refusing")
    if not art.is_file():
        raise Declined(f"no generated artifact for policy {policy_name!r} in {out!r} — "
                       "scan_result lists the policies this run produced")
    if refine and not dry_run:
        from .refiner import refine_apply_service_policy
        return refine_apply_service_policy(
            str(art), lb, url, finding_id=finding_id, name=policy_name, keep=keep,
            allow_protected=allow_protected_lb, force=force, allow_overbroad=allow_overbroad,
            out_dir=out, log=log)
    return A.apply_from_scan(str(art), lb, url, name=policy_name, finding_id=finding_id,
                             dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb,
                             force=force, allow_overbroad=allow_overbroad, out_dir=out, log=log)


def _tool_pr(finding_id: str = "", repo: str = "", base: str = "main", path_prefix: str = "",
             dry_run: bool = True, out: str = "out", log=None, **_) -> dict:
    import json as _json
    from pathlib import Path

    from .pr import open_pr
    if not str(finding_id).strip():
        raise Declined("finding_id is required")
    if not str(repo).strip():
        raise Declined("repo is required — the owner/name GitHub slug to open the PR against")
    p = Path(out) / "remediations.json"
    rems = _json.loads(p.read_text()) if p.is_file() else []
    r = next((x for x in rems if x.get("finding_id") == finding_id), None)
    if r is None:
        raise Declined(f"no remediation for {finding_id!r} in {out!r}")
    if r.get("kind") == "dependency_upgrade":
        # H1/H2: the cure is a version bump in someone else's package. `pr.py` declines this too;
        # saying so here means the tool does not look like it merely failed.
        raise Declined(f"{finding_id} is a dependency advisory, not a code finding — its cure is "
                       f"{r.get('summary')!r}, which nobody can open a PR against this repo for")
    return open_pr(r, repo, base=base, path_prefix=path_prefix, dry_run=dry_run, out_dir=out,
                   log=log or (lambda m: None))


def _tool_retire(finding_id: str = "", lb: str | None = None, force: bool = False, dry_run: bool = True,
                 allow_protected_lb: bool = False, out: str = "out", log=None, **_) -> dict:
    from .retire import retire_finding
    if not str(finding_id).strip():
        raise Declined("finding_id is required")
    return retire_finding(out, finding_id, lb=lb, force=force, dry_run=dry_run,
                          allow_protected=allow_protected_lb, log=log or (lambda m: None))


def _tool_reconcile(apply: bool = False, finding_id: str | None = None,
                    allow_protected_lb: bool = False, out: str = "out", log=None, **_) -> dict:
    """Report-only unless `apply` — the same default the CLI has, for the same reason (I1).

    `force_probe` is deliberately NOT exposed. Its guard lives in the module and needs a single
    `--finding`, because replaying every destructive exploit at once is not something to do by
    accident; a model deciding to pass it would be exactly that accident."""
    from .reconcile import reconcile
    return reconcile(out, apply=apply, finding_id=finding_id, trigger="mcp",
                     allow_protected=allow_protected_lb, log=log or (lambda m: None))


def _tool_simulate(policy_name: str | None = None, lb: str = "", url: str = "", logs: str = "",
                   threshold: float | None = None, max_records: int | None = None,
                   out: str = "out", log=None, **_) -> dict:
    """Replay a recorded traffic sample against candidate band-aids and report the would-block set.

    **This is a write tool, and the roadmap listed it as read-only.** G2's simulation creates a
    throwaway `<name>-vpcsim` policy object, attaches it to the load balancer, replays through it and
    deletes it again. That is a real mutation of a real tenant — the fact that it cleans up after
    itself makes it safe, not read-only — so it sits behind the same explicit opt-in as apply. Use
    `simulation_result` to read a previous run's numbers without touching anything."""
    from .simulate import candidates_from_out, simulate_policies, write_result
    from .traffic import load as load_traffic
    log = log or (lambda m: None)
    if not str(lb).strip() or not str(url).strip():
        raise Declined("lb and url are both required — the spare load balancer to replay through")
    if not str(logs).strip():
        raise Declined("logs is required — a HAR or JSONL traffic sample to replay. Reading the "
                       "tenant's own request logs is a CLI-only path (`simulate --from-tenant`), "
                       "because it needs a time window an operator chooses.")
    cands = candidates_from_out(out, policy_name)
    if not cands:
        raise Declined(f"no service_policy artifacts in {out!r} — nothing to simulate")
    records, redacted = load_traffic(logs)
    if not records:
        raise Declined(f"no records ingested from {logs!r}")
    # Resolved through the module, not re-implemented here — this surface used to skip the
    # VPCOPILOT_SIM_THRESHOLD lookup entirely, so an operator's tightened threshold was silently
    # replaced by the default for every simulation an agent ran.
    from .simulate import effective_threshold
    res = simulate_policies(cands, records, lb=lb, url=url, out_dir=out, max_records=max_records,
                            source=f"file:{logs}", redacted=redacted, log=log,
                            threshold=effective_threshold(threshold))
    write_result(out, res)
    return res.model_dump() if hasattr(res, "model_dump") else dict(res)


def _write_tools() -> list[Tool]:
    """The mutating surface, present only when the operator started the server with writes enabled.

    Every one of these calls the SAME module function the CLI and console call, so it inherits the
    guardrails rather than reimplementing them: `guard_lb` for a protected load balancer,
    `PROTECTED_POLICIES` for a protected policy name, `drift.preflight` for operator drift and a
    self-shadowing DENY, `simulate.promotion_gate` for blast radius, rollback-unless-`keep`, and an
    audit record with identity stamped centrally by `audit.record`. K1 moved the blast-radius gate
    out of the console and into the module precisely so this sentence could be true.

    What the server opt-in does NOT do is supply the human. MCP clients are expected to confirm tool
    calls with a user, but that is the client's behaviour and not something this server can enforce
    or verify — which is the whole reason these tools are off by default and the reason `dry_run`
    defaults to True on `apply`, `pr` and `retire`."""
    return [
        Tool("apply", "Apply a band-aid",
             "Attach a generated service policy to a load balancer, validate against the finding's "
             "own exploit and a legitimate request, and roll back unless it passed and keep=true. "
             "DEFAULTS TO dry_run=true: pass dry_run=false to change the tenant. Routes through the "
             "same drift, blast-radius, protected-LB and protected-policy gates as the CLI and "
             "console. Takes a policy NAME; the artifact is read from the run directory.",
             _out_schema({
                 "policy_name": {"type": "string",
                                 "description": "name of a generated service policy (see "
                                                "scan_result)"},
                 "lb": {"type": "string", "description": "load balancer to attach to"},
                 "url": {"type": "string",
                         "description": "live host the band-aid is validated against"},
                 "finding_id": {"type": "string",
                                "description": "finding whose recorded probe validates this policy; "
                                               "defaults to the ledger lookup"},
                 "dry_run": {"type": "boolean", "default": True,
                             "description": "true (the default) changes nothing; false applies for "
                                            "real"},
                 "keep": {"type": "boolean", "default": False,
                          "description": "leave the policy attached when validation passes; the "
                                         "default rolls back even on success"},
                 "refine": {"type": "boolean", "default": True,
                            "description": "refine the policy until it actually blocks the exploit "
                                           "(ignored when dry_run)"},
                 "allow_protected_lb": {"type": "boolean", "default": False,
                                        "description": "permit a load balancer listed in "
                                                       "VPCOPILOT_PROTECTED_LBS"},
                 "force": {"type": "boolean", "default": False,
                           "description": "apply despite the pre-apply drift check"},
                 "allow_overbroad": {"type": "boolean", "default": False,
                                     "description": "apply despite the blast-radius gate; writes a "
                                                    "simulate_override audit record"}},
                 required=["policy_name", "lb", "url"]),
             _tool_apply, access=Access.MUTATES, open_world=True),
        Tool("pr", "Open the cure PR",
             "Open the code-fix pull request for a finding — the cure the band-aid is buying time "
             "for. DEFAULTS TO dry_run=true. Declines for a dependency advisory, whose cure is a "
             "version bump in someone else's package that no PR against this repo can make.",
             _out_schema({
                 "finding_id": {"type": "string", "description": "finding to open the cure PR for"},
                 "repo": {"type": "string", "description": "GitHub slug, owner/name"},
                 "base": {"type": "string", "default": "main",
                          "description": "base branch to open the PR against"},
                 "path_prefix": {"type": "string",
                                 "description": "prefix to prepend to the patched file's path, when "
                                                "the scanned directory is not the repo root"},
                 "dry_run": {"type": "boolean", "default": True,
                             "description": "true (the default) previews the PR without creating "
                                            "anything on GitHub"}},
                 required=["finding_id", "repo"]),
             _tool_pr, access=Access.MUTATES, open_world=True),
        Tool("retire", "Retire a band-aid",
             "Detach a band-aid once its cure has shipped, moving the finding to retired. DEFAULTS "
             "TO dry_run=true. Refuses unless the cure PR is merged, unless force=true.",
             _out_schema({
                 "finding_id": {"type": "string", "description": "finding whose band-aid to retire"},
                 "lb": {"type": "string", "description": "which LB's band-aid, when the finding is live "
                        "on more than one (retire refuses to guess and names them otherwise)"},
                 "force": {"type": "boolean", "default": False,
                           "description": "retire without a merged cure PR"},
                 "dry_run": {"type": "boolean", "default": True,
                             "description": "true (the default) changes nothing"},
                 "allow_protected_lb": {"type": "boolean", "default": False,
                                        "description": "permit a protected load balancer"}},
                 required=["finding_id"]),
             _tool_retire, access=Access.MUTATES, open_world=True),
        Tool("reconcile", "Reconcile live band-aids",
             "Walk every live band-aid: check its cure PR, re-fire its exploit at the ORIGIN, and "
             "act — retire when the cure merged and the exploit is gone, hold and report "
             "fix_ineffective when it merged and the exploit still reproduces, escalate when the "
             "TTL passed with no merged cure. REPORT-ONLY unless apply=true. Every branch that "
             "cannot establish a fact holds the band-aid and says why.",
             _out_schema({
                 "apply": {"type": "boolean", "default": False,
                           "description": "false (the default) reports and changes nothing; true "
                                          "detaches a band-aid whose cure is proven"},
                 "finding_id": {"type": "string",
                                "description": "reconcile a single finding instead of every live "
                                               "patch"},
                 "allow_protected_lb": {"type": "boolean", "default": False,
                                        "description": "permit a protected load balancer"}}),
             _tool_reconcile, access=Access.MUTATES, open_world=True),
        Tool("simulate", "Measure blast radius",
             "Replay a recorded traffic sample against candidate band-aids on a spare load balancer "
             "and report what each WOULD block before anything reaches the gate. This MUTATES the "
             "tenant: it creates a throwaway policy object, attaches it, replays, then deletes it — "
             "cleaning up after itself makes it safe, not read-only. Use simulation_result to read a "
             "previous run's numbers without touching anything.",
             _out_schema({
                 "policy_name": {"type": "string",
                                 "description": "simulate only this candidate; omit for all of the "
                                                "run's service policies"},
                 "lb": {"type": "string",
                        "description": "spare, non-production load balancer to replay through"},
                 "url": {"type": "string", "description": "live host that load balancer fronts"},
                 "logs": {"type": "string",
                          "description": "HAR or JSONL traffic sample to replay; values are redacted "
                                         "at parse time"},
                 "threshold": {"type": "number",
                               "description": "would-block rate above which a policy is marked "
                                              "blocked_promotion; defaults to "
                                              "VPCOPILOT_SIM_THRESHOLD"},
                 "max_records": {"type": "integer",
                                 "description": "cap on records replayed per candidate"}},
                 required=["lb", "url", "logs"]),
             _tool_simulate, access=Access.MUTATES, open_world=True),
    ]


# --------------------------------------------------------------------------- JSON-RPC plumbing

@dataclass
class Server:
    enable_writes: bool = False
    tools: dict[str, Tool] = field(default_factory=dict)
    initialized: bool = False

    def __post_init__(self):
        if not self.tools:
            self.tools = {t.name: t for t in build_tools(enable_writes=self.enable_writes)}


_JSON_TYPES: dict[str, tuple] = {
    "string": (str,), "integer": (int,), "number": (int, float),
    "boolean": (bool,), "array": (list,), "object": (dict,),
}


def validate_args(tool: Tool, args: dict) -> str | None:
    """Check `args` against the tool's own schema. Returns an error message, or None if it passes.

    The spec says a server MUST validate tool inputs, and there is a sharper reason here: every tool
    function takes `**_` so it can be handed a `log` sink uniformly, which means an unrecognised
    argument would be silently swallowed. A client sending `output=` instead of `out=` would then get
    a confident answer about the DEFAULT run directory — a wrong answer that looks like a right one,
    which is the failure this codebase refuses everywhere else. So the schema is authoritative: it is
    both the documentation an agent reads and the gate its arguments pass through, and the two
    therefore cannot disagree.
    """
    props: dict = tool.schema.get("properties", {})
    for name in tool.schema.get("required", []):
        if name not in args:
            return f"missing required argument {name!r} for {tool.name}"
    for name, value in args.items():
        spec = props.get(name)
        if spec is None:
            close = ", ".join(sorted(props))
            return f"unknown argument {name!r} for {tool.name} — accepted arguments: {close}"
        want = spec.get("type")
        allowed = _JSON_TYPES.get(want)
        # bool is a subclass of int in Python; a JSON boolean is not an integer or a number.
        if allowed and (not isinstance(value, allowed)
                        or (want in ("integer", "number") and isinstance(value, bool))):
            return (f"argument {name!r} for {tool.name} must be a {want}, "
                    f"got {type(value).__name__}")
        if spec.get("enum") and value not in spec["enum"]:
            return (f"argument {name!r} for {tool.name} must be one of "
                    f"{', '.join(map(str, spec['enum']))} — got {value!r}")
        if want == "array" and spec.get("items", {}).get("type"):
            it = _JSON_TYPES.get(spec["items"]["type"])
            if it and not all(isinstance(v, it) for v in value):
                return f"every item in {name!r} for {tool.name} must be a {spec['items']['type']}"
    return None


def _result(mid, payload) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": payload}


def _error(mid, code: int, message: str, data=None) -> dict:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


def _tool_result(payload, *, is_error: bool = False) -> dict:
    """A tool result carries the data twice on purpose: `structuredContent` for a client that can
    use it, and the same JSON serialised into a text block, which the spec asks for so a
    text-only client is not left with nothing. `default=str` means one unexpected value degrades to
    a string instead of taking the server down mid-frame."""
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    out: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if not is_error and not isinstance(payload, str):
        out["structuredContent"] = payload if isinstance(payload, dict) else {"result": payload}
    return out


def handle(msg: dict, srv: Server) -> dict | None:
    """One JSON-RPC message in, one response out — or None for a notification, which by definition
    gets no reply. Pure: no streams, so tests drive it directly."""
    mid = msg.get("id")
    method = msg.get("method")
    is_notification = "id" not in msg

    # A notification carries no id and MUST NOT be answered — whatever its method. Checked once,
    # here, rather than per branch: without it `{"method":"initialize"}` with no id was answered with
    # an unsolicited `id: null` frame, and a client that is not expecting a response desynchronises
    # on the next one it reads.
    if is_notification:
        if method == "notifications/initialized":
            srv.initialized = True
        return None

    if method == "initialize":
        # Version negotiation: if the client asked for something else, answer with what we DO
        # support and let it decide, rather than erroring the connection out.
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "title": "Virtual Patch Copilot",
                           "version": __version__},
            "instructions":
                "Virtual Patch Copilot routes vulnerability findings to F5 Distributed Cloud "
                "controls (the band-aid) and to a code fix (the cure). Read a finished run with "
                "scan_result, impact and patches_list; survey dependencies with deps; start new "
                "work with scan_start then poll scan_status. Tools that would change a load "
                "balancer, open a PR or retire a control are absent unless the operator started "
                "this server with writes enabled — the human gate is not something a tool call "
                "can satisfy on its own.",
        })

    if method == "ping":
        return _result(mid, {})

    if method == "tools/list":
        return _result(mid, {"tools": [t.definition() for t in srv.tools.values()]})

    if method == "tools/call":
        params = msg.get("params") or {}
        # JSON-RPC permits positional (array) params, and a list is truthy — so `params.get` would
        # raise straight out of the loop. Likewise a non-string `name` is unhashable and would blow
        # up in the dict lookup below. Both are client-controlled, so both are invalid-params.
        if not isinstance(params, dict):
            return _error(mid, INVALID_PARAMS, "params must be an object")
        name = params.get("name")
        if not isinstance(name, str):
            return _error(mid, INVALID_PARAMS, "params.name must be a string naming a tool")
        args = params.get("arguments") or {}
        tool = srv.tools.get(name)
        if tool is None:
            # An unknown tool is a protocol error, per the spec — not a tool-execution error.
            known = ", ".join(sorted(srv.tools))
            return _error(mid, INVALID_PARAMS, f"Unknown tool: {name}",
                          {"available": sorted(srv.tools), "hint": f"available tools: {known}"})
        if not isinstance(args, dict):
            return _error(mid, INVALID_PARAMS, "arguments must be an object")
        bad = validate_args(tool, args)
        if bad:
            # "Invalid arguments" is a protocol error in the spec, not a tool-execution error: the
            # call never happened, so reporting it as a tool result would make a client typo
            # indistinguishable from a real failure inside a tool that ran.
            return _error(mid, INVALID_PARAMS, bad)
        lines: list[str] = []
        try:
            payload = tool.fn(log=lines.append, **args)
        except Declined as e:
            # The honest decline: a fact could not be established, and saying so is the answer.
            return _result(mid, _tool_result(f"declined: {e}", is_error=True))
        # There is deliberately NO `except TypeError` here. It looks like the natural home for a bad
        # argument, but `validate_args` above has already rejected every unknown name and wrong type,
        # and a test pins that every documented property is a real parameter — so an argument-binding
        # TypeError is unreachable. What a TypeError actually means at this point is a bug INSIDE a
        # tool that ran, and reporting that as "invalid arguments" would send an agent round a loop
        # retrying different arguments against a fault they cannot influence.
        except Exception as e:  # noqa: BLE001 — never let one tool call kill the server
            detail = "".join(traceback.format_exception_only(type(e), e)).strip()
            if lines:
                detail += "\nlog:\n" + "\n".join(lines[-20:])
            return _result(mid, _tool_result(f"{name} failed: {detail}", is_error=True))
        if lines and isinstance(payload, dict):
            payload = {**payload, "log": lines}
        return _result(mid, _tool_result(payload))

    return _error(mid, METHOD_NOT_FOUND, f"Method not found: {method}")


def serve(inp=None, outp=None, *, enable_writes: bool = False, swap_stdout: bool = True) -> None:
    """Read newline-delimited JSON-RPC from `inp`, write responses to `outp`.

    `swap_stdout` is the structural guarantee described in the module docstring: `sys.stdout` is
    pointed at stderr for the duration, and frames go to a private handle. Any `print` beneath us —
    in the pipeline, in an agent, in a library — then lands on stderr, which the spec explicitly
    allows the server to use for logging, instead of corrupting the message stream.
    """
    inp = inp or sys.stdin
    frames = outp or sys.stdout
    # The transport mandates UTF-8; Python opens the real stdio streams with the PROCESS LOCALE, so
    # on a box with a non-UTF-8 locale a client sending a non-ASCII path or advisory summary would
    # get a decode error instead of an answer. Only the real streams are reconfigured — a StringIO
    # from a test has no encoding to set.
    for stream in (inp, frames):
        try:
            stream.reconfigure(encoding="utf-8")     # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass
    srv = Server(enable_writes=enable_writes)
    saved = sys.stdout
    if swap_stdout:
        sys.stdout = sys.stderr
    try:
        for line in inp:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as e:
                _write(frames, _error(None, PARSE_ERROR, f"Parse error: {e}"))
                continue
            if not isinstance(msg, dict):
                _write(frames, _error(None, INVALID_REQUEST, "Request must be a JSON object"))
                continue
            # `handle` is defensive, but the loop does not rely on it being perfect. An unhandled
            # exception here used to propagate out of `serve()` and end the process with NO frame
            # written at all: the client waits forever on a request that will never be answered, and
            # every later request is lost with it. A malformed `params` did exactly that. Dying
            # silently is the worst available failure for a transport, so the loop answers with an
            # internal error and keeps serving — the same reasoning as the per-tool guard, one level
            # up, and it covers bugs not yet written.
            try:
                resp = handle(msg, srv)
            except Exception as e:  # noqa: BLE001
                detail = "".join(traceback.format_exception_only(type(e), e)).strip()
                resp = _error(msg.get("id"), INTERNAL_ERROR, f"internal error: {detail}")
            if resp is not None:
                _write(frames, resp)
    finally:
        if swap_stdout:
            sys.stdout = saved


def _write(stream, payload: dict) -> None:
    """One message, one line. `json.dumps` never emits a raw newline without `indent`, which is why
    none is passed — the spec requires messages to contain no embedded newlines."""
    stream.write(json.dumps(payload, default=str) + "\n")
    stream.flush()
