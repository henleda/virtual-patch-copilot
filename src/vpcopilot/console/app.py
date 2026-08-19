"""Ops console backend (FastAPI). Localhost only.

Read endpoints (results/config/xc-status) are safe. Action endpoints (apply/pr) perform
the same gated, guard-railed mutations as the CLI. The admin panel reads/writes the local
.env so a user can manage XC + model creds without leaving the console."""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
ENV_PATH = Path(os.environ.get("VPCOPILOT_ENV", ".env")).resolve()
OUT = Path(os.environ.get("VPCOPILOT_OUT", "out"))
CONFIG_DIR = Path(os.environ.get("VPCOPILOT_CONFIG_DIR", "config"))
_active_config = os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml")  # switchable live in the UI


def _config_tag(path, model: str) -> str:
    """A short model label for a config file: agents.<tag>.yaml -> <tag>; agents.yaml -> the
    default model's provider (anthropic->claude, openai, ollama->dgx, ...) so out-/benchmark-
    dirs line up (out-claude / out-openai / out-dgx)."""
    parts = Path(path).name.split(".")
    if len(parts) == 3 and parts[0] == "agents":
        return parts[1]
    prov = (model or "").split("/")[0]
    return {"anthropic": "claude", "openai": "openai", "ollama": "dgx", "gemini": "gemini"}.get(prov, prov or "default")


def _model_configs() -> list[dict]:
    from ..config import load_config
    out = []
    for p in sorted(CONFIG_DIR.glob("agents*.yaml")):
        try:
            model = load_config(str(p)).defaults.model
        except Exception:  # noqa: BLE001
            model = "?"
        out.append({"tag": _config_tag(p, model), "config": str(p), "model": model,
                    "active": str(p) == _active_config})
    return out


def _active_tag() -> str:
    for c in _model_configs():
        if c["active"]:
            return c["tag"]
    from ..config import load_config
    try:
        return _config_tag(_active_config, load_config(_active_config).defaults.model)
    except Exception:  # noqa: BLE001
        return "default"

SECRET_KEYS = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XC_API_TOKEN", "GITHUB_TOKEN",
               "VPCOPILOT_PROBE_PASS", "VPCOPILOT_PROBE_TOKEN", "VPCOPILOT_AUDIT_SINK_TOKEN",
               "BIGIP_PASSWORD", "NGINX_SSH_PASSWORD"}
MANAGED_KEYS = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OLLAMA_API_BASE",
    "XC_API_URL", "XC_API_TOKEN", "XC_NAMESPACE", "GITHUB_TOKEN",
    # Validation auth for an auth-protected target — the probe logs in so it can demonstrate the
    # exploit (loaded before every apply via load_dotenv, so a change here takes effect next run).
    "VPCOPILOT_PROBE_USER", "VPCOPILOT_PROBE_PASS", "VPCOPILOT_PROBE_LOGIN_PATH", "VPCOPILOT_PROBE_TOKEN",
    # J3 — off-box audit sink. The URL is NOT secret: it is echoed back so the page can show what
    # is configured, and `audit_sink.redact` keeps the credential-bearing path out of every other
    # surface. The bearer token is secret and lives in SECRET_KEYS above.
    "VPCOPILOT_AUDIT_SINK", "VPCOPILOT_AUDIT_SINK_TOKEN",
    # L2 — the BIG-IP lab appliance. The password is a credential; the URL and user are not, so
    # the page can show what is configured.
    "BIGIP_URL", "BIGIP_USER", "BIGIP_PASSWORD",
    # L2 — the NGINX + App Protect box, reached over SSH. Only the password is secret; the host, port,
    # user, key PATH, reload command and dirs are echoed so the page can show what is configured. This
    # is what the ④ Mitigate "Apply on your own NGINX" panel connects with.
    "NGINX_SSH_HOST", "NGINX_SSH_PORT", "NGINX_SSH_USER", "NGINX_SSH_KEY", "NGINX_SSH_PASSWORD",
    "NGINX_RELOAD_CMD", "NGINX_POLICY_DIR", "NGINX_INCLUDE_DIR", "NGINX_SSH_STRICT",
]

app = FastAPI(title="virtual-patch-copilot console")
load_dotenv(ENV_PATH)
_scan = {"state": "idle", "log": [], "summary": None, "error": None}
# Guards the "is a scan already running?" test-and-set. The check used to read a flag only the
# spawned THREAD set, so two requests arriving close together both passed it and started scans
# into the same out dir, interleaving their artifacts.
_scan_lock = threading.Lock()

LOG_MAX = 20_000  # the log endpoints serve the FULL transcript now — keep a ceiling on what one run pins in memory


def _append(buf: list, msg: str) -> None:
    """Bounded log sink. A scan/apply used to be served as a truncated tail, so an unbounded buffer
    never mattered; now the console streams the whole transcript, so cap it — and say so in-band
    rather than silently dropping the rest."""
    if len(buf) < LOG_MAX:
        buf.append(msg)
    elif len(buf) == LOG_MAX:
        buf.append(f"… log capped at {LOG_MAX} lines — further output suppressed (artifacts are still written to the out dir)")


# ---------------- helpers ----------------
def _read_env() -> dict:
    env = {}
    if ENV_PATH.exists():
        for ln in ENV_PATH.read_text().splitlines():
            s = ln.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def _env_quote(v: str) -> str:
    v = str(v)
    return f'"{v}"' if v and (v != v.strip() or " " in v or "#" in v) else v


def _write_env(updates: dict):
    """B8: line-preserving .env writer — update keys in place, keep comments / blank lines / order,
    quote values that need it, and append genuinely-new keys. Blank updates never clobber."""
    updates = {k: v for k, v in updates.items() if v}
    lines = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    seen, out = set(), []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in updates:
                out.append(f"{k}={_env_quote(updates[k])}")
                seen.add(k)
                continue
        out.append(ln)  # comments, blanks, and untouched keys pass through verbatim
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={_env_quote(v)}")
    ENV_PATH.write_text("\n".join(out) + "\n")


def _rj(name: str, default, *, strict: bool = False):
    p = OUT / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        # Every scan rewrites these files, so a read can land mid-write (partial JSON, or a truncated
        # multibyte sequence). The results page tolerates that — fall back to the default rather than
        # 500 the whole page. Callers that must tell "corrupt index" apart from "genuinely empty"
        # (e.g. /api/emit, which turns it into a 400) pass strict=True to re-raise instead.
        if strict:
            raise
        return default


def _stamped_name(kind: str, ext: str) -> str:
    """`vpcopilot-<kind>-<run dir>-<UTC>.<ext>` — a downloaded artifact has to say which run it came
    from and when, so several of them can sit in one folder (or one ticket) without ambiguity."""
    run = re.sub(r"[^A-Za-z0-9]+", "-", str(OUT)).strip("-") or "run"
    return f"vpcopilot-{kind}-{run}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.{ext}"


# ---------------- read endpoints ----------------
@app.get("/api/results")
def results():
    policies = [f.name for f in sorted((OUT / "policies").glob("*.json"))] if (OUT / "policies").exists() else []
    return {
        "findings": _rj("findings.json", []),
        "triage": _rj("triage.json", []),
        "remediations": _rj("remediations.json", []),
        "summary": _rj("summary.json", {}),
        "policies": policies,
        "policy_index": _rj("policies.json", []),
        "correlations": _rj("correlations.json", []),
    }


@app.get("/api/ledger")
def ledger():
    from ..ledger import load
    return load(str(OUT))


@app.get("/api/audit")
def audit():
    from ..audit import load
    return load(str(OUT))


@app.get("/api/audit-events")
def audit_events():
    """F3: the audit log normalized into one shape per event and joined to the ledger + findings, so
    the Retire step can SHOW the trail — every change made to a load balancer, and the vulnerability
    that justified it — before anyone exports it. Seeing it first is what makes the export
    trustworthy: you can check what leaves the machine."""
    from ..export import build_audit_events
    return {"out": str(OUT), "events": build_audit_events(str(OUT))}


@app.get("/api/simulate")
def simulation():
    """G2: the last blast-radius result for this run — what each candidate band-aid WOULD block,
    measured by replaying a recorded sample through a spare LB. Empty until a simulation runs;
    the Simulate step reads this to render before anything reaches the gate."""
    from ..simulate import load_result
    return {"out": str(OUT), "simulation": load_result(str(OUT))}


@app.get("/api/deps")
def dependencies():
    """H2: the dependency funnel this run produced — every package parsed, every entry that could
    not be pinned, and every advisory found with what became of it. Empty until a scan runs with
    `--manifest`."""
    p = OUT / "dependencies.json"
    if not p.is_file():
        return {"out": str(OUT), "dependencies": None}
    try:
        return {"out": str(OUT), "dependencies": json.loads(p.read_text())}
    except (OSError, json.JSONDecodeError) as e:
        return {"out": str(OUT), "dependencies": None, "error": str(e)}


class DepsReq(BaseModel):
    manifest: list[str] = []
    min_severity: str = "high"
    max_advisories: int = 25
    include_dev: bool = False


@app.post("/api/deps")
def survey_dependencies(body: DepsReq):
    """H2 read-only: what a `--manifest` scan WOULD find, without spending a model call.

    The same module function `vpcopilot deps` calls. Synchronous rather than a background job
    because it is parse + HTTP only — one batch query plus one query per vulnerable package — and
    it needs no model and no credentials, so there is nothing to stream."""
    paths = [m.strip() for m in body.manifest if m.strip()]
    if not paths:
        raise HTTPException(400, "give at least one manifest path")
    if body.min_severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(400, "min_severity must be critical, high, medium or low")
    from ..inputs.deps import survey_report
    log: list[str] = []
    try:
        rep = survey_report(paths, min_severity=body.min_severity,
                            max_advisories=body.max_advisories, include_dev=body.include_dev,
                            log=log.append)
    except Exception as e:  # noqa: BLE001 — a bad path is a 400, not a 500 traceback in the browser
        raise HTTPException(400, str(e)) from e
    return {"dependencies": rep, "log": log}


class SimReq(BaseModel):
    logs: str | None = None            # HAR / JSONL path
    from_tenant: bool = False          # read observed requests from XC access logs
    lb: str = "vpcopilot-lab"          # the spare LB to replay through
    url: str = "https://your-app.example.com"
    source_lb: str | None = None       # whose traffic to read, when from_tenant
    since: str = "1h"
    limit: int = 500
    max_records: int = 200
    threshold: float | None = None
    policy: str | None = None


@app.post("/api/simulate")
def run_simulation(body: SimReq):
    """Run a replay in the background, streaming through the same job contract as apply — the
    console polls /api/action?job=… for the log."""
    import uuid
    load_dotenv(ENV_PATH, override=True)
    job_id = uuid.uuid4().hex[:8]
    _jobs[job_id] = {"state": "running", "log": [], "result": None, "error": None,
                     "control": "simulate", "finding_id": None}
    # OUT is captured HERE, not read inside the worker: POST /api/scan reassigns the global with no
    # lock, so a scan started mid-pass would otherwise repoint a running simulation at another dir.
    threading.Thread(target=_run_simulation, args=(job_id, body, str(OUT)), daemon=True).start()
    return {"job": job_id, "state": "running"}


def _run_simulation(job_id: str, body: SimReq, out: str):
    job = _jobs[job_id]
    log = lambda m: _append(job["log"], m)  # noqa: E731
    try:

        from ..cli import _load_traffic
        from ..simulate import candidates_from_out, simulate_policies, write_result
        cands = candidates_from_out(out, body.policy)
        if not cands:
            raise RuntimeError(f"no service_policy artifacts in {out} — run a scan first")
        records, redacted, src, window = _load_traffic(
            body.logs, body.from_tenant, body.source_lb or body.lb, body.since, body.limit)
        if not records:
            raise RuntimeError("no records ingested — give a traffic file or enable from-tenant")
        log(f"{len(records)} record(s) from {src}")
        from ..simulate import effective_threshold
        thr = effective_threshold(body.threshold)
        res = simulate_policies(cands, records, lb=body.lb, url=body.url, out_dir=out,
                                threshold=thr, max_records=body.max_records, source=src,
                                window=window, redacted=redacted, log=log)
        write_result(out, res)
        job.update(state="done", result=res.model_dump())
    except Exception as e:  # noqa: BLE001
        job.update(state="error", error=str(e))


class ReconcileReq(BaseModel):
    apply: bool = False              # I1: report-only by default — --apply is the human gate
    finding_id: str | None = None
    force_probe: bool = False
    allow_protected_lb: bool = False


@app.get("/api/patches")
def patches():
    """I1: every live band-aid with age, TTL remaining and cure state.

    A pure ledger read — no XC, no GitHub, no exploit fired — so the Retire step can call it on
    every render without cost or side effects."""
    from ..reconcile import list_patches
    return {"out": str(OUT), "patches": list_patches(str(OUT))}


@app.post("/api/reconcile")
def start_reconcile(body: ReconcileReq):
    """I1: one reconcile pass in the background, streaming through the same job contract as apply."""
    import uuid
    load_dotenv(ENV_PATH, override=True)
    job_id = uuid.uuid4().hex[:8]
    _jobs[job_id] = {"state": "running", "log": [], "result": None, "error": None,
                     "control": "reconcile", "finding_id": body.finding_id}
    # OUT is captured HERE, not read inside the worker: POST /api/scan reassigns the global with no
    # lock, so a scan started mid-pass would otherwise repoint a running reconcile at another dir.
    threading.Thread(target=_run_reconcile, args=(job_id, body, str(OUT)), daemon=True).start()
    return {"job": job_id, "state": "running"}


def _run_reconcile(job_id: str, body: ReconcileReq, out: str):
    job = _jobs[job_id]
    log = lambda m: _append(job["log"], m)  # noqa: E731
    try:
        from ..reconcile import reconcile as run
        res = run(out, apply=body.apply, finding_id=body.finding_id,
                  force_probe=body.force_probe, trigger="console",
                  allow_protected=body.allow_protected_lb, log=log)
        job.update(state="done", result=res)
    except Exception as e:  # noqa: BLE001
        job.update(state="error", error=str(e))


@app.get("/api/runs")
def runs():
    """Run dirs on disk that have something to export — backs the Retire step's 'all runs' bundle."""
    from ..export import find_runs
    return {"current": str(OUT), "runs": find_runs(".")}


@app.get("/api/drift")
def drift_ep(lb: str, control: str | None = None, policy: str | None = None,
             finding: str | None = None):
    """I2: what is on the LB now vs what the last run left vs what is about to be pushed.
    Read-only — it never PUTs and never writes a snapshot, so it is safe to poll from the UI."""
    load_dotenv(ENV_PATH, override=True)
    from ..apply import _load_probe
    from ..drift import check
    try:
        exploit = (_load_probe(str(OUT), finding) or {}).get("exploit") if finding else None
        art = OUT / "policies" / f"service_policy.{policy}.json" if policy else None
        spec = json.loads(art.read_text()) if art and art.is_file() else None
        return check(lb, out_dir=str(OUT), control=control, policy_name=policy,
                     exploit=exploit, spec=spec, log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class BackfillReq(BaseModel):
    dry_run: bool = False


@app.post("/api/audit-backfill")
def audit_backfill(body: BackfillReq | None = None):
    """J4: freeze the finding each audit entry belongs to, into `<out>/audit-backfill.json`.

    Operates on THIS run's out dir, never a caller-supplied path — the J2 precedent. POST rather
    than GET because it writes, even though what it writes is derived rather than decided: a GET the
    browser is free to prefetch should not append an audit record."""
    from ..backfill import backfill
    log: list[str] = []
    res = backfill(str(OUT), dry_run=(body.dry_run if body else False), log=log.append)
    return {**res, "log": log}


@app.get("/api/audit-verify")
def audit_verify():
    """J2: check the bundle this run last wrote (`<out>/audit-bundle.zip`) against its own manifest.

    The path comes from server state, never from the request. A verify endpoint that took a
    caller-supplied path would be an arbitrary-file reader, and localhost is not a reason to ship
    one. Verifying a bundle that has already left the machine is the CLI's job — that is where the
    reviewer is."""
    from ..export import verify_bundle
    p = OUT / "audit-bundle.zip"
    if not p.exists():
        return {"bundle": str(p), "exists": False,
                "hint": "run `vpcopilot export` (or the Retire step's download) first"}
    return {"bundle": str(p), "exists": True,
            **verify_bundle(str(p), pubkey=os.environ.get("VPCOPILOT_MINISIGN_PUBKEY"))}


@app.get("/api/audit-export")
def audit_export(scope: str = "run"):
    """F3: download the evidence bundle — `scope=run` for the run the console is reading, `scope=all`
    for every run dir on disk (each in its own folder, under a top-level index). A .zip because the
    evidence is plural: the normalized events, the raw append-only log verbatim, the exact XC configs
    that were pushed, the pre-change LB snapshots, and a manifest that SHA-256s every member."""
    from ..export import bundle_all_bytes, bundle_bytes
    if scope not in ("run", "all"):
        raise HTTPException(400, f"unknown scope '{scope}' (use 'run' or 'all')")
    data = bundle_bytes(str(OUT)) if scope == "run" else bundle_all_bytes(".")
    name = _stamped_name("audit", "zip") if scope == "run" else _stamped_name("audit-all", "zip")
    return Response(content=data, media_type="application/zip",
                    headers={"content-disposition": f'attachment; filename="{name}"'})


AGENT_ROLES = {
    "resolve": "read a security advisory → an HTTP exploitation profile (or decline)",
    "discover": "read source → candidate findings",
    "verify": "adversarially confirm or refute each finding",
    "triage": "route each finding to the strongest XC band-aid (or code-only)",
    "generate": "emit the XC config for each recommended band-aid",
    "remediate": "write the real code fix (opened as a GitHub PR)",
    "probe": "derive an executable exploit to validate the band-aid on any app",
    "refine": "fix a policy that failed live validation (never ship a broken band-aid)",
}


@app.get("/api/agents")
def agents():
    from ..config import load_config
    cfg = load_config(_active_config)
    return {
        "default_model": cfg.defaults.model,
        "agents": [{"name": n, "model": cfg.for_agent(n).model, "role": r} for n, r in AGENT_ROLES.items()],
    }


@app.get("/api/models")
def list_models():
    """Configured model configs (config/agents*.yaml) + which is active — for the live switcher."""
    cfgs = _model_configs()
    # ⑦ Benchmark + the header model switcher are model-evaluation tools (internal demo, stream-1).
    # The everyday product user never sees them: advanced mode is on only when explicitly requested
    # (VPCOPILOT_ADVANCED) or when the operator actually maintains more than one model config.
    advanced = bool(os.environ.get("VPCOPILOT_ADVANCED")) or len(cfgs) > 1
    return {"active": _active_tag(), "out": str(OUT), "configs": cfgs, "advanced": advanced}


class ModelReq(BaseModel):
    tag: str


@app.post("/api/model")
def set_model(body: ModelReq):
    """Switch the active model config live (no relaunch) — CONFIG only. The output dir stays under the
    operator's control (the Output-dir field, which the console follows on scan), and we return a
    suggested `out-<tag>` the UI pre-fills — so you can name a run out-<tag> or out-<tag>-<app> and
    the console reads exactly what you scanned into."""
    global _active_config
    cfgs = {c["tag"]: c for c in _model_configs()}
    if body.tag not in cfgs:
        raise HTTPException(404, f"no config for model '{body.tag}'")
    _active_config = cfgs[body.tag]["config"]
    return {"active": body.tag, "config": _active_config, "suggested_out": f"out-{body.tag}",
            "model": cfgs[body.tag]["model"]}


# Values that are shown, but only in redacted form. Not SECRET_KEYS (which are never echoed at
# all) — the operator needs to see WHICH sink is configured, and a blank field cannot tell them
# that. But a sink URL routinely carries credentials: `https://user:pass@host/…` and the Splunk-HEC
# shape `…/services/collector/<token>` both put a secret in the URL itself. `audit_sink.redact`
# exists for exactly this and every OTHER surface already used it; `/api/config` returned the raw
# string, so the console API handed back the basic-auth password and the HEC token in full.
REDACTED_KEYS = {"VPCOPILOT_AUDIT_SINK"}


def _display_value(key: str, raw: str) -> str:
    if not raw or key not in REDACTED_KEYS:
        return raw
    try:
        from ..audit_sink import redact
        from urllib.parse import urlsplit
        return redact(raw, (urlsplit(raw).scheme or "").lower())
    except Exception:  # noqa: BLE001 — an unparseable sink must not 500 the settings page…
        return "(set — unparseable, hidden)"   # …and must not fall back to showing it raw


@app.get("/api/config")
def get_config():
    """Three states per key, not two: set here (.env), set in the ENVIRONMENT, or genuinely unset.

    This read `.env` only, so a value supplied through the process environment — which is how the
    documented BIG-IP setup works, and how CI and any container run — rendered as "(unset)". The
    Setup page therefore reported `BIGIP_URL (unset)` directly above a panel that was talking to
    the appliance over that very URL: two panels on one screen contradicting each other about
    whether a fact was established.

    It is not cosmetic. An operator who believes a credential is unset sets it, this page writes
    .env, and the process keeps using the environment value that still wins — so the change reads
    as applied and silently is not, on a security-relevant credential.
    """
    env = _read_env()
    out = {}
    for k in MANAGED_KEYS:
        in_file = env.get(k, "")
        in_environ = "" if in_file else os.environ.get(k, "")
        raw = in_file or in_environ
        out[k] = {
            "set": bool(raw),
            "secret": k in SECRET_KEYS,
            "redacted": k in REDACTED_KEYS,
            # Where it came from, so the page can say so rather than implying .env is the only
            # source. "" when unset — an absent source and an unknown one are not the same claim.
            "source": "env-file" if in_file else ("environment" if in_environ else ""),
            "value": ("" if k in SECRET_KEYS else _display_value(k, raw)),
        }
    return out


def _is_redacted_echo(key: str, value: str) -> bool:
    """True if `value` is the ellipsis form this API hands back, not a real setting.

    The settings form shows the redacted sink as a PLACEHOLDER and leaves the input empty, so a
    save cannot echo it. But a guard that lives only in the page is not a guard — the endpoint is
    reachable directly — and writing `https://…@host/…` into .env would silently destroy a working
    audit sink, which is the one component whose failure mode is "no record of anything".
    """
    return key in REDACTED_KEYS and "\u2026" in (value or "")


class ConfigUpdate(BaseModel):
    updates: dict


@app.post("/api/config")
def set_config(body: ConfigUpdate):
    # Drop any value that is just the redacted form echoed back — see `_is_redacted_echo`.
    # Silently ignoring it is right: it means "unchanged", exactly like a blank secret field.
    updates = {k: v for k, v in body.updates.items() if not _is_redacted_echo(k, v)}
    _write_env(updates)
    load_dotenv(ENV_PATH, override=True)
    return get_config()


class EmitReq(BaseModel):
    target: str = "bigip-awaf"
    finding_id: str | None = None
    protocol: str = "http"


@app.post("/api/emit")
def emit_policy(body: EmitReq):
    """L1: emit the run's band-aids for another enforcement point. Read-only with respect to the
    tenant and the appliance — it produces a document and touches nothing.

    Returns every candidate including the ones that DECLINED, because "we did not emit this" and
    "there was nothing to emit" are different answers and only one of them is a gap."""
    from ..emitters import TARGETS, EmitError
    from ..emitters import emit as emit_one
    if body.target not in TARGETS:
        raise HTTPException(400, f"unknown target '{body.target}'")
    try:
        policies = _rj("policies.json", [], strict=True)
        probes = {p.get("finding_id"): p for p in _rj("probes.json", [], strict=True) if isinstance(p, dict)}
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        # Both files are rewritten by every scan and can be caught mid-write. An unreadable index
        # means nothing can be established — a 400 with the reason, not a 500 (the J4 precedent).
        raise HTTPException(400, f"cannot read this run's artifacts: {e}")
    results = []
    for entry in policies:
        fid = entry.get("finding_id")
        if body.finding_id and fid != body.finding_id:
            continue
        control, name = entry.get("control", ""), entry.get("policy_name", "")
        sp = OUT / "policies" / f"{control}.{name}.json"
        try:
            spec = json.loads(sp.read_text()) if sp.exists() else None
        except (json.JSONDecodeError, OSError):
            spec = None    # unused by the declarative targets; xc declines for want of it
        try:
            r = emit_one(target=body.target, control=control, policy_name=name, spec=spec,
                         probe=probes.get(fid), protocol=body.protocol)
        except EmitError as e:
            raise HTTPException(400, str(e))
        results.append({"finding_id": fid, **r.to_dict()})
    return {"target": body.target, "display": TARGETS[body.target].display,
            "emitted": sum(1 for r in results if r["supported"]), "results": results}


@app.get("/api/emit-targets")
def emit_targets():
    """The enforcement points this build can emit for — so the console renders the list from the
    registry rather than hardcoding it, which is what makes 'adding a target touches only the
    emitter module' true on this surface too."""
    from ..emitters import TARGETS
    return {"targets": [{"key": t.key, "display": t.display, "kind": t.kind, "note": t.note}
                        for t in TARGETS.values()]}


@app.get("/api/bigip-lab")
def bigip_lab_status():
    """L2: what is on the lab appliance right now. Read-only — the Setup page polls it.

    The CLI twin is `vpcopilot bigip-lab status`; both call `bigip_lab.status`, so a guard or a
    readout cannot exist on one surface and not the other."""
    load_dotenv(ENV_PATH, override=True)
    from ..bigip_lab import status
    return status()


@app.get("/api/nginx-lab")
def nginx_lab_status():
    """L2: what the operator's NGINX+App-Protect box looks like right now. Read-only — the ④ Mitigate
    panel polls it. The CLI twin is `vpcopilot nginx-lab status`; both call `nginx_lab.status`, so the
    readout cannot drift between the two surfaces."""
    load_dotenv(ENV_PATH, override=True)
    from ..nginx_lab import status
    return status()


class BigIPLabReq(BaseModel):
    action: str                      # create | rm
    tenant: str = "vpcopilot_lab"
    origin: str | None = None
    virtual_address: str | None = None
    virtual_port: int = 80
    app: str = "lab"
    allow_protected: bool = False
    dry_run: bool = True             # the console default is a preview, like the MCP write tools


@app.post("/api/bigip-lab")
def bigip_lab_action(body: BigIPLabReq):
    """Create or remove the lab tenant. Calls the same module functions the CLI calls, so it
    inherits `guard_tenant` — including the unoverridable `/Common` refusal — rather than
    reimplementing it."""
    load_dotenv(ENV_PATH, override=True)
    from ..bigip_lab import LabRefused, create, remove
    lines: list[str] = []
    log = lines.append
    try:
        if body.action == "create":
            if not body.origin or not body.virtual_address:
                raise HTTPException(400, "origin and virtual_address are required for create")
            res = create(body.tenant, body.origin, body.virtual_address, app=body.app,
                         virtual_port=body.virtual_port, allow_protected=body.allow_protected,
                         dry_run=body.dry_run, out_dir=str(OUT), log=log)
        elif body.action == "rm":
            res = remove(body.tenant, allow_protected=body.allow_protected,
                         dry_run=body.dry_run, out_dir=str(OUT), log=log)
        else:
            raise HTTPException(400, f"unknown action '{body.action}' — expected create or rm")
    except HTTPException:
        raise
    except LabRefused as e:
        # A refused guard is a 409, not a 500: the operator asked for something the tool declined,
        # which is an answer rather than a fault (the drift-gate precedent).
        raise HTTPException(409, str(e))
    except RuntimeError as e:
        # The appliance, or the path to it — unreachable, a dropped tunnel, missing credentials, an
        # AS3 rejection. **502**, not 409: 409 says "we declined", and a caller that cannot tell
        # those apart retries the wrong one. A dropped SSM tunnel is the likeliest failure here.
        raise HTTPException(502, str(e))
    return {**res, "log": lines}


@app.get("/api/audit-sink")
def audit_sink_status():
    """J3: what the off-box audit sink is set to, and what this process has managed to deliver.

    Read-only and network-free, because the Setup page polls it — the CLI twin is
    `vpcopilot audit-sink`. The target is reported through `audit_sink.redact`, so a webhook URL
    carrying its credential in the path is never rendered into the page."""
    load_dotenv(ENV_PATH, override=True)
    from ..audit_sink import status
    return status()


class SinkCheckReq(BaseModel):
    send: bool = False


@app.post("/api/audit-sink")
def audit_sink_check(body: SinkCheckReq):
    """Same answer, plus one test event delivered to the collector when `send` is set.

    This is the only endpoint here that reaches the network, and it writes nothing: the test event
    is not an audit record and never touches an `audit.log`."""
    load_dotenv(ENV_PATH, override=True)
    from ..audit_sink import check
    return check(send=body.send)


@app.get("/api/lbs")
def list_lbs():
    """HTTP load balancers in the namespace + their domains, so the console can offer a picker
    instead of a free-typed name (and auto-fill the validate URL from the chosen LB's domain).
    `protected` mirrors the apply-path guard (engine.protected_lbs) so the UI flags exactly what
    enforcement will refuse to mutate without an override."""
    load_dotenv(ENV_PATH, override=True)
    from ..engine import protected_lbs
    from ..xc import XC
    try:
        xc = XC()
        prot = protected_lbs()
        lbs = []
        for it in xc.list_http_loadbalancers().get("items", []):
            name = it.get("name")
            spec = it.get("get_spec") or {}
            lbs.append({"name": name, "domains": spec.get("domains") or [],
                        "protected": name in prot})
        lbs.sort(key=lambda x: (x["protected"], x["name"]))  # usable LBs first
        return {"namespace": xc.ns, "lbs": lbs}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


@app.get("/api/xc-status")
def xc_status(lb: str = "vpcopilot-lab"):
    load_dotenv(ENV_PATH, override=True)
    from ..xc import XC
    try:
        xc = XC()
        pols = [i.get("name") for i in xc.list_service_policies().get("items", [])]
        spec = xc.get_lb(lb).get("spec", {})
        return {"namespace": xc.ns, "policies": pols, "lb": lb,
                "lb_service_policy": {k: v for k, v in spec.items() if "service_polic" in k}}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


@app.get("/api/benchmarks")
def list_benchmarks():
    """Every model-tagged benchmark report on disk (benchmarks/benchmark-*.json), parsed — the
    console renders the side-by-side compare + per-run outcome tables from these."""
    d = Path("benchmarks")
    out = []
    for p in sorted(d.glob("benchmark-*.json")):
        try:
            out.append(json.loads(p.read_text()))
        except Exception:  # noqa: BLE001
            pass  # skip a malformed report rather than failing the whole list
    return {"benchmarks": out}


class BenchReq(BaseModel):
    tag: str
    out: str | None = None      # defaults to the dir the console is reading (OUT)
    target: str = ""


@app.post("/api/bench-model")
def build_benchmark(body: BenchReq):
    """Build benchmark-<tag>.{json,md} from a run: findings + generated policies + LIVE policy
    quality (the apply_timing records the Mitigate step wrote). Same code path as `vpcopilot
    bench-model`; records the active config's per-agent models."""
    from ..bench_model import write
    run = body.out or str(OUT)
    try:
        return write(run, body.tag, target=body.target, config_path=_active_config, dest_dir="benchmarks")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"bench-model failed for {run}: {e}")


@app.get("/api/report")
def report_html(download: bool = False):
    """Build + serve the standalone HTML report (E3) for the current out/ dir. It is REBUILT on every
    request, so whoever opens it always gets the latest run — which is why Review links straight to
    it rather than to a stale file on disk (F2). `download=1` names the file and sends it as an
    attachment (the report is meant to be shared); the default stays inline for the new-tab view."""
    from ..report import write_report
    path = write_report(str(OUT), str(OUT / "report.html"))
    if not download:
        return FileResponse(path, media_type="text/html")
    return FileResponse(path, media_type="text/html", filename=_stamped_name("report", "html"))


@app.get("/api/defaults")
def defaults():
    """Action-settings defaults — env-overridable so the console isn't pinned to one app/demo.
    Set VPCOPILOT_DEFAULT_LB / _URL / _REPO / _BASE / _PREFIX to match whatever you're testing."""
    load_dotenv(ENV_PATH, override=True)
    from ..impact import xc_dashboard_url
    lb = os.environ.get("VPCOPILOT_DEFAULT_LB", "vpcopilot-lab")
    return {
        "lb": lb,
        "url": os.environ.get("VPCOPILOT_DEFAULT_URL", "https://your-app.example.com"),
        "repo": os.environ.get("VPCOPILOT_DEFAULT_REPO", ""),
        "base": os.environ.get("VPCOPILOT_DEFAULT_BASE", "main"),
        "prefix": os.environ.get("VPCOPILOT_DEFAULT_PREFIX", ""),
        "dashboard": xc_dashboard_url(lb) or "",
        "out": str(OUT),  # so a scan lands in the same dir the console reads (per-model runs)
        # default on for normal use; the benchmark console launches with VPCOPILOT_SCAN_REMEDIATE=0
        "draft_code_fixes": os.environ.get("VPCOPILOT_SCAN_REMEDIATE", "1").lower() not in ("0", "false", "no"),
    }


# ---------------- input pickers (data-backed console comboboxes) ----------------
_REPO_MARKERS = ("docker-compose.yml", "docker-compose.yaml", "package.json", "requirements.txt",
                 "pyproject.toml", "pom.xml", "build.gradle", "go.mod", "Gemfile", "Cargo.toml",
                 "services", "openapi-spec", "openapi_specs")


def _repo_markers(d: Path) -> list[str]:
    m = ["git"] if (d / ".git").exists() else []
    return m + [x for x in _REPO_MARKERS if (d / x).exists()]


def _scan_repos() -> list[dict]:
    """Sibling directories that look like scannable app repos, most-relevant first."""
    root = Path.cwd()
    try:
        siblings = sorted(root.parent.iterdir())
    except OSError:
        return []
    repos = []
    for d in siblings:
        if not d.is_dir() or d.name.startswith(".") or d.resolve() == root.resolve():
            continue
        mk = _repo_markers(d)
        if not mk:
            continue
        rec = d.name.lower() in ("crapi", "vampi")  # the bundled vulnerable-app targets
        repos.append({"path": str(d.resolve()), "name": d.name, "markers": mk, "recommended": rec})
    repos.sort(key=lambda r: (not r["recommended"], r["name"].lower()))  # known targets first
    return repos


def _scan_outs() -> list[dict]:
    """Existing run dirs + likely output-dir names (demo/out, per-model out-<tag>, the default)."""
    seen: set[str] = set()
    outs: list[dict] = []

    def add(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        p = Path(name)
        outs.append({"out": name, "exists": p.is_dir(), "has_results": (p / "findings.json").exists()})

    for p in sorted(Path.cwd().glob("out*")):
        if p.is_dir():
            add(p.name)                      # real run dirs (gitignored; appear after scans)
    if (Path.cwd() / "demo" / "out").is_dir():
        add("demo/out")                      # seeded demo run
    for c in _model_configs():
        add(f"out-{c['tag']}")               # suggested per-model dirs — lockstep with the switcher
    add("out")                               # built-in default
    outs.sort(key=lambda o: (not o["has_results"], not o["exists"], o["out"]))
    return outs


@app.get("/api/targets")
def scan_targets():
    """Sibling app repos to scan + existing/likely output dirs, for the Scan step comboboxes.
    Read-only filesystem inspection — no XC, no GitHub."""
    return {"repos": _scan_repos(), "outs": _scan_outs(), "default_out": str(OUT)}


@app.get("/api/repos")
def list_repos():
    """PR-target picker: repos the user can push to, via the gh CLI (the same credential pr.py
    falls back to with `gh auth token`). Empty list if gh is missing/unauthed → the field stays
    free-text; fail-soft so a slow/absent gh never breaks the settings panel."""
    import subprocess
    try:
        raw = subprocess.check_output(
            ["gh", "repo", "list", "--limit", "200", "--json", "nameWithOwner,viewerPermission"],
            text=True, stderr=subprocess.DEVNULL, timeout=15)
        repos = [r for r in json.loads(raw)
                 if r.get("viewerPermission") in ("ADMIN", "MAINTAIN", "WRITE")]  # pushable only
        repos.sort(key=lambda r: r["nameWithOwner"].lower())
        return {"repos": repos}
    except Exception:  # noqa: BLE001 — gh absent/unauthed/slow/errored → free-text fallback
        return {"repos": []}


# ---------------- scan (background) ----------------
class ScanReq(BaseModel):
    # H1 — `str = ""` rather than `str | None`: index.html always sends `repo`, and an empty input
    # yields "". Every existing payload stays valid and nothing can 422.
    repo: str = ""
    cve: str = ""
    spec: str = ""
    # H2 — `list[str] = []` for the same reason `cve` is `str = ""`: index.html can always send the
    # field and an empty picker yields `[]`, so every payload written before H2 stays valid.
    manifest: list[str] = []
    min_severity: str = "high"
    max_advisories: int = 25
    include_dev: bool = False
    out: str = "out"
    min_confidence: float = 0.5
    max_files: int = 200
    max_bytes: int = 60_000
    draft_code_fixes: bool = True


def _run_scan(repo: str, out: str, min_confidence: float = 0.5,
              max_files: int = 200, max_bytes: int = 60_000, draft_code_fixes: bool = True,
              cve: str = "", spec: str = "", manifest: list[str] | None = None,
              min_severity: str = "high", max_advisories: int = 25, include_dev: bool = False):
    # State is claimed by `start_scan` under `_scan_lock` before this thread exists; re-setting it
    # here would reopen the race it closed.
    try:
        from ..pipeline import run_pipeline
        summary = run_pipeline(repo or None, out_dir=out, config_path=_active_config,
                               min_confidence=min_confidence, max_files=max_files,
                               max_bytes=max_bytes, draft_code_fixes=draft_code_fixes,
                               advisory=cve or None, spec_path=spec or None,
                               manifest_paths=list(manifest or []) or None,
                               min_severity=min_severity, max_advisories=max_advisories,
                               include_dev=include_dev,
                               log=lambda m: _append(_scan["log"], m))
        _scan.update(state="done", summary=summary)
    except Exception as e:  # noqa: BLE001
        _scan.update(state="error", error=str(e))


@app.post("/api/scan")
def start_scan(body: ScanReq):
    if _scan["state"] == "running":      # cheap early reject; the authoritative claim is below
        raise HTTPException(409, "a scan is already running")
    load_dotenv(ENV_PATH, override=True)
    # The console reads results from OUT — so point OUT at the dir this scan writes to, or Review /
    # Mitigate would read a different (empty) dir. Makes the Output-dir field authoritative even when
    # it differs from the model-switcher default (e.g. out-claude-vampi).
    manifests = [m.strip() for m in body.manifest if m.strip()]
    if body.cve.strip() and (body.repo.strip() or body.spec.strip() or manifests):
        raise HTTPException(400, "a CVE scan cannot be combined with a repo, a spec or a manifest")
    if not (body.repo.strip() or body.cve.strip() or body.spec.strip() or manifests):
        raise HTTPException(400, "give a repo path, a CVE/GHSA id, an OpenAPI spec, "
                                 "or a dependency manifest")
    if body.min_severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(400, "min_severity must be critical, high, medium or low")
    # Claim the scanner only once the request is known to be VALID, and synchronously — before the
    # worker thread exists. Two halves, both load-bearing:
    #   * synchronous, under a lock: the old check read a flag only `_run_scan` set, so the window
    #     between check and thread start was wide open and two requests both got through, writing
    #     into the same out dir.
    #   * after validation: claiming first meant a request that then 400'd left the scanner marked
    #     running forever — one malformed request and the console can never scan again.
    # On the REQUEST thread, before the worker is spawned — raising inside the pipeline would
    # surface as a job error after this endpoint had already returned 200 "running".
    from ..pipeline import validate_scan_inputs
    try:
        validate_scan_inputs(body.repo or None, body.spec or None, manifests)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    with _scan_lock:
        if _scan["state"] == "running":
            raise HTTPException(409, "a scan is already running")
        _scan.update(state="running", log=[], summary=None, error=None)
    global OUT
    OUT = Path(body.out)
    # kwargs, not a positional tuple: H2/H3 add more inputs here and a positional args tuple is one
    # reordering away from scanning the wrong thing.
    threading.Thread(target=_run_scan, daemon=True,
                     kwargs=dict(repo=body.repo, out=body.out, min_confidence=body.min_confidence,
                                 max_files=body.max_files, max_bytes=body.max_bytes,
                                 draft_code_fixes=body.draft_code_fixes, cve=body.cve,
                                 spec=body.spec, manifest=manifests,
                                 min_severity=body.min_severity,
                                 max_advisories=body.max_advisories,
                                 include_dev=body.include_dev)).start()
    return {"state": "running", "out": str(OUT)}


@app.get("/api/scan")
def scan_status(since: int = 0):
    """F1: scan state + log. The log is the FULL transcript so a long run can be scrolled end-to-end;
    the console passes `since=<lines already rendered>` and appends only the new tail (`log_total`
    is the running length — a smaller value than `since` means a newer scan reset the buffer)."""
    log = _scan["log"]
    return {**_scan, "log": log[max(0, since):], "log_total": len(log)}


# ---------------- impact + ledger loop (C1/C3/C4) ----------------
@app.get("/api/impact")
def impact_ep():
    """Headline numbers for the hero band + Impact tab (vulns, mitigated, MTTM, change-control days)."""
    from ..impact import impact
    return impact(str(OUT))


class RetireReq(BaseModel):
    finding_id: str
    force: bool = False       # retire even if the cure PR isn't merged (demo)
    dry_run: bool = False
    allow_protected_lb: bool = False


@app.post("/api/retire")
def do_retire(body: RetireReq):
    """Close the loop: once the code fix ships, detach the band-aid (found→…→retired). A BIG-IP
    band-aid (control `bigip_awaf`) is detached on the appliance — the tenant/app come from the
    ledger's `mitigation.lb`; every other control is the XC detach as before. One button, both."""
    load_dotenv(ENV_PATH, override=True)
    try:
        from ..ledger import load as _ledger_load
        mit = (_ledger_load(str(OUT)).get(body.finding_id) or {}).get("mitigation") or {}
        if mit.get("control") == "bigip_awaf":
            from ..bigip_apply import retire_bigip
            tenant, _, app = (mit.get("lb") or "").partition("/")
            return retire_bigip(body.finding_id, tenant=tenant or "vpcopilot_lab", app=app or "lab",
                                out_dir=str(OUT), allow_protected=body.allow_protected_lb,
                                log=lambda m: None)
        if mit.get("control") == "nginx_app_protect":
            from ..nginx_apply import _unlb, retire_nginx
            server, location = _unlb(mit.get("lb") or "")
            return retire_nginx(body.finding_id, server=server, location=location,
                                out_dir=str(OUT), allow_protected=body.allow_protected_lb,
                                log=lambda m: None)
        from ..retire import retire_finding
        return retire_finding(str(OUT), body.finding_id, force=body.force, dry_run=body.dry_run,
                              allow_protected=body.allow_protected_lb, log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


# ---------------- action jobs (background apply, live log) — C2 ----------------
class ActionReq(BaseModel):
    control: str                       # service_policy | malicious_user | rate_limit | bot_defense
    finding_id: str | None = None      #   | waf | waf_data_guard | api_schema
    policy_name: str | None = None     # service_policy artifact name
    lb: str = "vpcopilot-lab"
    url: str = "https://your-app.example.com"
    openapi_file: str | None = None
    requests: int = 100
    unit: str = "MINUTE"
    burst: int = 1
    dry_run: bool = False
    keep: bool = False
    refine: bool = True
    refine_attempts: int | None = None
    allow_protected_lb: bool = False
    allow_overbroad: bool = False   # G2: apply anyway when simulation flagged the policy as too broad
    force: bool = False             # I2: apply anyway when the pre-apply drift check objects


_jobs: dict[str, dict] = {}   # job_id -> {state, log, result, error, control, finding_id}


def _dispatch_action(body: ActionReq, log, out: Path):
    """Run the requested control's apply through the SAME functions the CLI uses, but with a real
    log sink so the console can live-stream the refiner (attach → validate → refine → retry).

    `out` is passed in, never read from the module global. `OUT` is reassigned by POST /api/scan,
    and this runs on a worker thread — so an apply already in flight used to write its artifacts
    and its audit record into whatever directory a concurrent scan had just repointed to."""
    from .. import apply as A
    if not (body.lb or "").strip():  # fields no longer pre-fill — a missing LB must fail clearly, not as a swagger 404
        raise HTTPException(400, "select a load balancer in Run settings first")
    c, kw = body.control, dict(finding_id=body.finding_id, dry_run=body.dry_run, keep=body.keep,
                               allow_protected=body.allow_protected_lb, out_dir=str(out), log=log)
    if c == "service_policy":
        # G2 gate: a simulated policy found too broad WARNS and requires an explicit override.
        # Silent when nothing was simulated — G2 adds a check, never a prerequisite.
        # K1 moved the check itself into `simulate.promotion_gate`, called by BOTH apply paths, so
        # the CLI and the MCP server get it too — it used to live only here. The message and the
        # resulting job state are unchanged: `_run_action` catches the raise and reports
        # `state="error"` carrying the "allow overbroad" text, exactly as before.
        art = str(out / "policies" / f"service_policy.{body.policy_name}.json")
        if body.refine and not body.dry_run:
            from ..refiner import refine_apply_service_policy
            return refine_apply_service_policy(art, body.lb, body.url, finding_id=body.finding_id,
                name=body.policy_name, keep=body.keep, allow_protected=body.allow_protected_lb,
                max_refine=body.refine_attempts, config_path=_active_config, force=body.force,
                allow_overbroad=body.allow_overbroad, out_dir=str(out), log=log)
        return A.apply_from_scan(art, body.lb, body.url, name=body.policy_name, dry_run=body.dry_run,
            keep=body.keep, allow_protected=body.allow_protected_lb, force=body.force,
            allow_overbroad=body.allow_overbroad, out_dir=str(out), log=log)
    if c == "malicious_user":
        return A.apply_malicious_user(body.lb, **kw)
    if c == "rate_limit":
        return A.apply_rate_limit(body.lb, requests=body.requests, unit=body.unit, burst=body.burst, **kw)
    if c == "bot_defense":
        return A.apply_bot_defense(body.lb, **kw)
    if c == "waf":
        return A.apply_waf(body.lb, target_url=body.url, **kw)
    if c == "waf_data_guard":
        return A.apply_data_guard(body.lb, **kw)
    if c == "api_schema":
        # Feed the OpenAPI that generate produced for THIS finding (policies/api_schema.<name>.json)
        # so XC enforces the finding's real schema — not the built-in demo default. An explicit
        # uploaded file still wins if provided.
        openapi = None
        if body.openapi_file:
            openapi = json.loads(Path(body.openapi_file).read_text())
        elif body.policy_name:
            art = out / "policies" / f"api_schema.{body.policy_name}.json"
            if art.exists():
                openapi = json.loads(art.read_text())
        return A.apply_api_schema(body.lb, openapi=openapi, target_url=body.url, **kw)
    raise HTTPException(400, f"unknown control '{c}'")


def _run_action(job_id: str, body: ActionReq, out: Path):
    import time
    job = _jobs[job_id]
    t0 = time.perf_counter()
    try:
        res = _dispatch_action(body, lambda m: _append(job["log"], m), out)
        job.update(state="done", result=res)
        if not body.dry_run:  # feed MTTM for the hero + a self-contained record for the model benchmark
            from ..audit import record
            passed = res.get("passed") if res.get("passed") is not None else (res.get("config_enabled") is not False)
            record(str(out), "apply_timing", control=body.control, finding_id=body.finding_id,
                   passed=bool(passed), elapsed_s=round(time.perf_counter() - t0, 1),
                   attempts=res.get("attempts"), before_after=res.get("before_after"),
                   unfixable=res.get("unfixable"), reason=res.get("reason"), kept=res.get("kept"))
    except Exception as e:  # noqa: BLE001
        job.update(state="error", error=str(e))


@app.post("/api/action")
def start_action(body: ActionReq):
    import uuid
    load_dotenv(ENV_PATH, override=True)
    job_id = uuid.uuid4().hex[:8]
    _jobs[job_id] = {"state": "running", "log": [], "result": None, "error": None,
                     "control": body.control, "finding_id": body.finding_id}
    # Keep the last 20 jobs — but never evict one that is still running. Reconcile is the longest
    # job in the app; trimming it mid-pass would 404 the poll and lose the transcript of a run that
    # is still mutating the tenant.
    for old in list(_jobs)[:-20]:
        if _jobs.get(old, {}).get("state") != "running":
            _jobs.pop(old, None)
    # Snapshot the run dir HERE, on the request thread, not inside the worker: `OUT` is a
    # module global that POST /api/scan reassigns, so reading it later binds the apply to
    # whichever directory happened to be current when the thread got round to it.
    threading.Thread(target=_run_action, args=(job_id, body, OUT), daemon=True).start()
    return {"job": job_id, "state": "running"}


@app.get("/api/action")
def action_status(job: str, since: int = 0):
    """F1: same full-transcript + `since` tail contract as /api/scan — the refiner's attach → validate →
    refine → retry narration is the evidence a band-aid works, so none of it should scroll off."""
    j = _jobs.get(job)
    if not j:
        raise HTTPException(404, "no such job")
    log = j["log"]
    return {**j, "log": log[max(0, since):], "log_total": len(log), "job": job}


# ---------------- BIG-IP live-apply (L2) ----------------
class BigipApplyReq(BaseModel):
    finding_id: str
    tenant: str = "vpcopilot_lab"
    app: str = "lab"
    url: str = "https://your-app.example.com"
    dry_run: bool = False
    keep: bool = False
    allow_protected: bool = False


def _run_bigip_apply(job_id: str, body: BigipApplyReq, out):
    job = _jobs[job_id]
    try:
        from ..bigip_apply import apply_bigip
        res = apply_bigip(body.finding_id, tenant=body.tenant, app=body.app, url=body.url,
                          dry_run=body.dry_run, keep=body.keep, allow_protected=body.allow_protected,
                          out_dir=str(out), log=lambda m: _append(job["log"], m))
        job.update(state="done", result=res)
    except Exception as e:  # noqa: BLE001 — surfaced to the operator as the job's error, not a 500
        job.update(state="error", error=str(e))


@app.post("/api/apply-bigip")
def start_bigip_apply(body: BigipApplyReq):
    """Attach a finding's Advanced-WAF band-aid to the operator's own BIG-IP, validated against the
    exploit and rolled back if it does not block. Same job model as /api/action — poll GET /api/action."""
    import uuid
    load_dotenv(ENV_PATH, override=True)
    job_id = uuid.uuid4().hex[:8]
    _jobs[job_id] = {"state": "running", "log": [], "result": None, "error": None,
                     "control": "bigip_awaf", "finding_id": body.finding_id}
    for old in list(_jobs)[:-20]:
        if _jobs.get(old, {}).get("state") != "running":
            _jobs.pop(old, None)
    threading.Thread(target=_run_bigip_apply, args=(job_id, body, OUT), daemon=True).start()
    return {"job": job_id, "state": "running"}


class NginxApplyReq(BaseModel):
    finding_id: str
    server: str = "vpcopilot.lab"
    location: str = "/"
    url: str = "http://your-app.example.com"
    dry_run: bool = False
    keep: bool = False
    allow_protected: bool = False


def _run_nginx_apply(job_id: str, body: NginxApplyReq, out):
    job = _jobs[job_id]
    try:
        from ..nginx_apply import apply_nginx
        res = apply_nginx(body.finding_id, server=body.server, location=body.location, url=body.url,
                          dry_run=body.dry_run, keep=body.keep, allow_protected=body.allow_protected,
                          out_dir=str(out), log=lambda m: _append(job["log"], m))
        job.update(state="done", result=res)
    except Exception as e:  # noqa: BLE001 — surfaced to the operator as the job's error, not a 500
        job.update(state="error", error=str(e))


@app.post("/api/apply-nginx")
def start_nginx_apply(body: NginxApplyReq):
    """Attach a finding's App Protect band-aid to the operator's own NGINX+App-Protect box, validated
    against the exploit and rolled back if it does not block. Same job model as /api/action — poll it
    through GET /api/action."""
    import uuid
    load_dotenv(ENV_PATH, override=True)
    job_id = uuid.uuid4().hex[:8]
    _jobs[job_id] = {"state": "running", "log": [], "result": None, "error": None,
                     "control": "nginx_app_protect", "finding_id": body.finding_id}
    for old in list(_jobs)[:-20]:
        if _jobs.get(old, {}).get("state") != "running":
            _jobs.pop(old, None)
    threading.Thread(target=_run_nginx_apply, args=(job_id, body, OUT), daemon=True).start()
    return {"job": job_id, "state": "running"}


# ---------------- action endpoints (gated) ----------------
class ApplyReq(BaseModel):
    artifact: str
    name: str | None = None
    lb: str = "vpcopilot-lab"
    url: str = "https://your-app.example.com"
    create_only: bool = False
    dry_run: bool = False
    keep: bool = False
    refine: bool = True
    refine_attempts: int | None = None
    allow_protected_lb: bool = False
    force: bool = False
    # K1: this older endpoint is still served even though the UI now posts to /api/action. Moving the
    # G2 gate into the module meant it started enforcing here too — and without this field there was
    # no way to override it, turning a warn-with-audited-override into a machine veto on one surface.
    allow_overbroad: bool = False


@app.post("/api/apply")
def do_apply(body: ApplyReq):
    load_dotenv(ENV_PATH, override=True)
    art = body.artifact if os.path.isabs(body.artifact) else str(OUT / "policies" / body.artifact)
    try:
        if body.refine and not body.dry_run and not body.create_only:
            from ..refiner import refine_apply_service_policy
            return refine_apply_service_policy(art, body.lb, body.url, name=body.name, keep=body.keep,
                                               allow_protected=body.allow_protected_lb,
                                               max_refine=body.refine_attempts, force=body.force,
                                               allow_overbroad=body.allow_overbroad,
                                               out_dir=str(OUT), log=lambda m: None)
        from ..apply import apply_from_scan
        return apply_from_scan(art, body.lb, body.url, name=body.name, create_only=body.create_only,
                               dry_run=body.dry_run, keep=body.keep, force=body.force,
                               allow_protected=body.allow_protected_lb,
                               allow_overbroad=body.allow_overbroad, out_dir=str(OUT),
                               log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class MalUserReq(BaseModel):
    lb: str = "vpcopilot-lab"
    finding_id: str | None = None
    dry_run: bool = True
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-maluser")
def do_apply_maluser(body: MalUserReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_malicious_user
    try:
        return apply_malicious_user(body.lb, dry_run=body.dry_run, keep=body.keep,
                                    allow_protected=body.allow_protected_lb, finding_id=body.finding_id,
                                    out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class RateLimitReq(BaseModel):
    lb: str = "vpcopilot-lab"
    requests: int = 100
    unit: str = "MINUTE"
    burst: int = 1
    finding_id: str | None = None
    dry_run: bool = True
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-ratelimit")
def do_apply_ratelimit(body: RateLimitReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_rate_limit
    try:
        return apply_rate_limit(body.lb, requests=body.requests, unit=body.unit, burst=body.burst,
                                finding_id=body.finding_id, dry_run=body.dry_run, keep=body.keep,
                                allow_protected=body.allow_protected_lb, out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class BotReq(BaseModel):
    lb: str = "vpcopilot-lab"
    finding_id: str | None = None
    dry_run: bool = True
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-bot")
def do_apply_bot(body: BotReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_bot_defense
    try:
        return apply_bot_defense(body.lb, dry_run=body.dry_run, keep=body.keep,
                                 allow_protected=body.allow_protected_lb, finding_id=body.finding_id,
                                 out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class WafReq(BaseModel):
    lb: str = "vpcopilot-lab"
    url: str = "https://your-app.example.com"
    finding_id: str | None = None
    dry_run: bool = False
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-waf")
def do_apply_waf(body: WafReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_waf
    try:
        return apply_waf(body.lb, target_url=body.url, dry_run=body.dry_run, keep=body.keep,
                         allow_protected=body.allow_protected_lb, finding_id=body.finding_id,
                         out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class DataGuardReq(BaseModel):
    lb: str = "vpcopilot-lab"
    finding_id: str | None = None
    dry_run: bool = False
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-dataguard")
def do_apply_dataguard(body: DataGuardReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_data_guard
    try:
        return apply_data_guard(body.lb, dry_run=body.dry_run, keep=body.keep,
                                allow_protected=body.allow_protected_lb, finding_id=body.finding_id,
                                out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class ApiSchemaReq(BaseModel):
    lb: str = "vpcopilot-lab"
    url: str = "https://your-app.example.com"
    openapi_file: str | None = None
    finding_id: str | None = None
    dry_run: bool = False
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-apischema")
def do_apply_apischema(body: ApiSchemaReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_api_schema
    try:
        # An unreadable/invalid OpenAPI file is a 400 with the reason, not a raw 500 traceback.
        openapi = json.loads(Path(body.openapi_file).read_text()) if body.openapi_file else None
        return apply_api_schema(body.lb, openapi=openapi, target_url=body.url, dry_run=body.dry_run,
                                keep=body.keep, allow_protected=body.allow_protected_lb,
                                finding_id=body.finding_id, out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class PrReq(BaseModel):
    finding: str
    repo: str
    base: str = "main"
    path_prefix: str = ""
    dry_run: bool = False


@app.post("/api/pr")
def do_pr(body: PrReq):
    load_dotenv(ENV_PATH, override=True)
    from ..pr import open_pr
    r = next((x for x in _rj("remediations.json", []) if x["finding_id"] == body.finding), None)
    if not r:
        raise HTTPException(404, "remediation not found")
    try:
        return open_pr(r, body.repo, base=body.base, path_prefix=body.path_prefix,
                       dry_run=body.dry_run, out_dir=str(OUT), log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/f5-logo.png")
def f5_logo():
    return FileResponse(STATIC / "f5-logo.png", media_type="image/png")
