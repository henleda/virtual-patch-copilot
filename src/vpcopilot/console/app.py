"""Ops console backend (FastAPI). Localhost only.

Read endpoints (results/config/xc-status) are safe. Action endpoints (apply/pr) perform
the same gated, guard-railed mutations as the CLI. The admin panel reads/writes the local
.env so a user can manage XC + model creds without leaving the console."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
ENV_PATH = Path(os.environ.get("VPCOPILOT_ENV", ".env")).resolve()
OUT = Path(os.environ.get("VPCOPILOT_OUT", "out"))

SECRET_KEYS = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XC_API_TOKEN", "GITHUB_TOKEN"}
MANAGED_KEYS = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OLLAMA_API_BASE",
    "XC_API_URL", "XC_API_TOKEN", "XC_NAMESPACE", "GITHUB_TOKEN",
]

app = FastAPI(title="virtual-patch-copilot console")
load_dotenv(ENV_PATH)
_scan = {"state": "idle", "log": [], "summary": None, "error": None}


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


def _rj(name: str, default):
    p = OUT / name
    return json.loads(p.read_text()) if p.exists() else default


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


AGENT_ROLES = {
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
    cfg = load_config(os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
    return {
        "default_model": cfg.defaults.model,
        "agents": [{"name": n, "model": cfg.for_agent(n).model, "role": r} for n, r in AGENT_ROLES.items()],
    }


@app.get("/api/config")
def get_config():
    env = _read_env()
    return {
        k: {"set": bool(env.get(k)), "secret": k in SECRET_KEYS,
            "value": ("" if k in SECRET_KEYS else env.get(k, ""))}
        for k in MANAGED_KEYS
    }


class ConfigUpdate(BaseModel):
    updates: dict


@app.post("/api/config")
def set_config(body: ConfigUpdate):
    _write_env(body.updates)
    load_dotenv(ENV_PATH, override=True)
    return get_config()


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


@app.get("/api/report")
def report_html():
    """Build + serve the standalone HTML report (E3) for the current out/ dir."""
    from ..report import write_report
    path = write_report(str(OUT), str(OUT / "report.html"))
    return FileResponse(path, media_type="text/html")


@app.get("/api/defaults")
def defaults():
    """Action-settings defaults — env-overridable so the console isn't pinned to one app/demo.
    Set VPCOPILOT_DEFAULT_LB / _URL / _REPO / _BASE / _PREFIX to match whatever you're testing."""
    load_dotenv(ENV_PATH, override=True)
    from ..impact import xc_dashboard_url
    lb = os.environ.get("VPCOPILOT_DEFAULT_LB", "vpcopilot-lab")
    return {
        "lb": lb,
        "url": os.environ.get("VPCOPILOT_DEFAULT_URL", "https://lab.banknimbus.com"),
        "repo": os.environ.get("VPCOPILOT_DEFAULT_REPO", ""),
        "base": os.environ.get("VPCOPILOT_DEFAULT_BASE", "main"),
        "prefix": os.environ.get("VPCOPILOT_DEFAULT_PREFIX", ""),
        "dashboard": xc_dashboard_url(lb) or "",
        "out": str(OUT),  # so a scan lands in the same dir the console reads (per-model runs)
    }


# ---------------- scan (background) ----------------
class ScanReq(BaseModel):
    repo: str
    out: str = "out"
    min_confidence: float = 0.5
    max_files: int = 200
    max_bytes: int = 60_000


def _run_scan(repo: str, out: str, min_confidence: float = 0.5,
              max_files: int = 200, max_bytes: int = 60_000):
    _scan.update(state="running", log=[], summary=None, error=None)
    try:
        from ..pipeline import run_pipeline
        summary = run_pipeline(repo, out_dir=out, min_confidence=min_confidence,
                               max_files=max_files, max_bytes=max_bytes,
                               log=lambda m: _scan["log"].append(m))
        _scan.update(state="done", summary=summary)
    except Exception as e:  # noqa: BLE001
        _scan.update(state="error", error=str(e))


@app.post("/api/scan")
def start_scan(body: ScanReq):
    if _scan["state"] == "running":
        raise HTTPException(409, "a scan is already running")
    load_dotenv(ENV_PATH, override=True)
    threading.Thread(target=_run_scan,
                     args=(body.repo, body.out, body.min_confidence, body.max_files, body.max_bytes),
                     daemon=True).start()
    return {"state": "running"}


@app.get("/api/scan")
def scan_status():
    return {**_scan, "log": _scan["log"][-40:]}


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
    """Close the loop: once the code fix ships, detach the band-aid (found→…→retired)."""
    load_dotenv(ENV_PATH, override=True)
    from ..retire import retire_finding
    try:
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
    url: str = "https://lab.banknimbus.com"
    openapi_file: str | None = None
    requests: int = 100
    unit: str = "MINUTE"
    burst: int = 1
    dry_run: bool = False
    keep: bool = False
    refine: bool = True
    refine_attempts: int | None = None
    allow_protected_lb: bool = False


_jobs: dict[str, dict] = {}   # job_id -> {state, log, result, error, control, finding_id}


def _dispatch_action(body: ActionReq, log):
    """Run the requested control's apply through the SAME functions the CLI uses, but with a real
    log sink so the console can live-stream the refiner (attach → validate → refine → retry)."""
    from .. import apply as A
    c, kw = body.control, dict(finding_id=body.finding_id, dry_run=body.dry_run, keep=body.keep,
                               allow_protected=body.allow_protected_lb, out_dir=str(OUT), log=log)
    if c == "service_policy":
        art = str(OUT / "policies" / f"service_policy.{body.policy_name}.json")
        if body.refine and not body.dry_run:
            from ..refiner import refine_apply_service_policy
            return refine_apply_service_policy(art, body.lb, body.url, finding_id=body.finding_id,
                name=body.policy_name, keep=body.keep, allow_protected=body.allow_protected_lb,
                max_refine=body.refine_attempts, out_dir=str(OUT), log=log)
        return A.apply_from_scan(art, body.lb, body.url, name=body.policy_name, dry_run=body.dry_run,
            keep=body.keep, allow_protected=body.allow_protected_lb, out_dir=str(OUT), log=log)
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
        openapi = json.loads(Path(body.openapi_file).read_text()) if body.openapi_file else None
        return A.apply_api_schema(body.lb, openapi=openapi, target_url=body.url, **kw)
    raise HTTPException(400, f"unknown control '{c}'")


def _run_action(job_id: str, body: ActionReq):
    import time
    job = _jobs[job_id]
    t0 = time.perf_counter()
    try:
        res = _dispatch_action(body, lambda m: job["log"].append(m))
        job.update(state="done", result=res)
        if not body.dry_run:  # feed MTTM for the hero + a self-contained record for the model benchmark
            from ..audit import record
            passed = res.get("passed") if res.get("passed") is not None else (res.get("config_enabled") is not False)
            record(str(OUT), "apply_timing", control=body.control, finding_id=body.finding_id,
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
    for old in list(_jobs)[:-20]:  # keep the last 20 jobs
        _jobs.pop(old, None)
    threading.Thread(target=_run_action, args=(job_id, body), daemon=True).start()
    return {"job": job_id, "state": "running"}


@app.get("/api/action")
def action_status(job: str):
    j = _jobs.get(job)
    if not j:
        raise HTTPException(404, "no such job")
    return {**j, "log": j["log"][-60:], "job": job}


# ---------------- action endpoints (gated) ----------------
class ApplyReq(BaseModel):
    artifact: str
    name: str | None = None
    lb: str = "vpcopilot-lab"
    url: str = "https://lab.banknimbus.com"
    create_only: bool = False
    dry_run: bool = False
    keep: bool = False
    refine: bool = True
    refine_attempts: int | None = None
    allow_protected_lb: bool = False


@app.post("/api/apply")
def do_apply(body: ApplyReq):
    load_dotenv(ENV_PATH, override=True)
    art = body.artifact if os.path.isabs(body.artifact) else str(OUT / "policies" / body.artifact)
    try:
        if body.refine and not body.dry_run and not body.create_only:
            from ..refiner import refine_apply_service_policy
            return refine_apply_service_policy(art, body.lb, body.url, name=body.name, keep=body.keep,
                                               allow_protected=body.allow_protected_lb,
                                               max_refine=body.refine_attempts, out_dir=str(OUT), log=lambda m: None)
        from ..apply import apply_from_scan
        return apply_from_scan(art, body.lb, body.url, name=body.name, create_only=body.create_only,
                               dry_run=body.dry_run, keep=body.keep,
                               allow_protected=body.allow_protected_lb, out_dir=str(OUT),
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
    url: str = "https://lab.banknimbus.com"
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
    url: str = "https://lab.banknimbus.com"
    openapi_file: str | None = None
    finding_id: str | None = None
    dry_run: bool = False
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-apischema")
def do_apply_apischema(body: ApiSchemaReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_api_schema
    openapi = json.loads(Path(body.openapi_file).read_text()) if body.openapi_file else None
    try:
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
