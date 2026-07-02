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


def _write_env(updates: dict):
    env = _read_env()
    for k, v in updates.items():
        if v:  # only set non-empty; blanks don't clobber existing values
            env[k] = v
    ENV_PATH.write_text("\n".join(f"{k}={v}" for k, v in env.items()) + "\n")


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
    }


@app.get("/api/ledger")
def ledger():
    from ..ledger import load
    return load(str(OUT))


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
def xc_status(lb: str = "nimbus-www"):
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


# ---------------- scan (background) ----------------
class ScanReq(BaseModel):
    repo: str
    out: str = "out"


def _run_scan(repo: str, out: str):
    _scan.update(state="running", log=[], summary=None, error=None)
    try:
        from ..pipeline import run_pipeline
        summary = run_pipeline(repo, out_dir=out, log=lambda m: _scan["log"].append(m))
        _scan.update(state="done", summary=summary)
    except Exception as e:  # noqa: BLE001
        _scan.update(state="error", error=str(e))


@app.post("/api/scan")
def start_scan(body: ScanReq):
    if _scan["state"] == "running":
        raise HTTPException(409, "a scan is already running")
    load_dotenv(ENV_PATH, override=True)
    threading.Thread(target=_run_scan, args=(body.repo, body.out), daemon=True).start()
    return {"state": "running"}


@app.get("/api/scan")
def scan_status():
    return {**_scan, "log": _scan["log"][-40:]}


# ---------------- action endpoints (gated) ----------------
class ApplyReq(BaseModel):
    artifact: str
    name: str | None = None
    lb: str = "nimbus-www"
    url: str = "https://www.banknimbus.com"
    create_only: bool = False
    dry_run: bool = False
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply")
def do_apply(body: ApplyReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_from_scan
    art = body.artifact if os.path.isabs(body.artifact) else str(OUT / "policies" / body.artifact)
    try:
        return apply_from_scan(art, body.lb, body.url, name=body.name, create_only=body.create_only,
                               dry_run=body.dry_run, keep=body.keep,
                               allow_protected=body.allow_protected_lb, out_dir=str(OUT),
                               log=lambda m: None)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, str(e))


class MalUserReq(BaseModel):
    lb: str = "nimbus-www"
    dry_run: bool = True
    keep: bool = False
    allow_protected_lb: bool = False


@app.post("/api/apply-maluser")
def do_apply_maluser(body: MalUserReq):
    load_dotenv(ENV_PATH, override=True)
    from ..apply import apply_malicious_user
    try:
        return apply_malicious_user(body.lb, dry_run=body.dry_run, keep=body.keep,
                                    allow_protected=body.allow_protected_lb, out_dir=str(OUT),
                                    log=lambda m: None)
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
