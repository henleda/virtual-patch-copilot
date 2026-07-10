"""C1/C5: the demo's headline numbers — computed once, shared by the console hero band and the
standalone HTML report. The story in one line: 'N exploitable vulns, mitigated live in seconds,
vs. the bank's usual 20–30-day change-control window.'"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import ledger

_LIVE = ("mitigated", "remediated", "retired")  # ledger states with a band-aid in front of the app


def xc_dashboard_url(lb: str | None = None) -> str | None:
    """Deep link to the XC security dashboard so the demo can jump straight from a mitigation to the
    native WAF/API-Security telemetry. Prefers an explicit XC_DASHBOARD_URL; else derives the tenant
    console host from XC_API_URL + XC_NAMESPACE."""
    import re
    explicit = os.environ.get("XC_DASHBOARD_URL")
    if explicit:
        return explicit
    m = re.match(r"(https://[^/]+)", os.environ.get("XC_API_URL", ""))
    ns = os.environ.get("XC_NAMESPACE", "")
    if not m or not ns:
        return None
    return f"{m.group(1)}/web/workspaces/web-app-and-api-protection/namespaces/{ns}/security"


def change_control_days() -> int:
    """The contrast stat — how long a real code fix would take through change control. Env-tunable
    so the number matches the customer telling the story (default 25 = middle of 20–30)."""
    try:
        return max(1, int(os.environ.get("CHANGE_CONTROL_DAYS", "25")))
    except ValueError:
        return 25


def _rj(out_dir: str, name: str, default):
    p = Path(out_dir) / name
    return json.loads(p.read_text()) if p.exists() else default


def _mttm_seconds(out_dir: str) -> float | None:
    """Mean wall-clock seconds to mitigate a finding live, from the audit log's apply durations.
    This is the literal 'in seconds' number behind the hero — real, not asserted."""
    from . import audit
    durs = [a["elapsed_s"] for a in audit.load(out_dir)
            if a.get("action") == "apply_timing" and a.get("passed") is True
            and isinstance(a.get("elapsed_s"), (int, float))]
    return round(sum(durs) / len(durs), 1) if durs else None


def impact(out_dir: str) -> dict:
    """One dict with every headline number the console and report render."""
    summary = _rj(out_dir, "summary.json", {})
    led = ledger.load(out_dir)
    states = [e.get("state") for e in led.values()]
    verified = summary.get("verified", 0)
    counts = {s: states.count(s) for s in ("found", *_LIVE)}
    controls: dict[str, int] = {}
    for e in led.values():
        m = e.get("mitigation")
        if m and e.get("state") != "retired":  # retired = band-aid detached, no longer live
            controls[m["control"]] = controls.get(m["control"], 0) + 1
    days = change_control_days()
    mttm = _mttm_seconds(out_dir)
    mitigated = sum(counts[s] for s in _LIVE)
    return {
        "candidates": summary.get("candidates", 0),
        "vulns": verified,
        "mitigated": mitigated,
        "remediated": counts["remediated"] + counts["retired"],
        "retired": counts["retired"],
        "code_prs": len(summary.get("code_fix_prs", []) or []),
        "change_control_days": days,
        "mttm_seconds": mttm,
        "controls_live": controls,
        "states": counts,
        "speedup": (round(days * 86400 / mttm) if mttm else None),  # how many× faster than change control
    }
