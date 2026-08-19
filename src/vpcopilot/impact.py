"""C1/C5: the demo's headline numbers — computed once, shared by the console hero band and the
standalone HTML report. The story in one line: 'N exploitable vulns, mitigated live in seconds,
vs. the bank's usual 20–30-day change-control window.'"""
from __future__ import annotations

import json
import os
from pathlib import Path

from . import ledger

_LIVE = ("mitigated", "remediated", "retired")  # ledger states with a band-aid in front of the app

# Which enforcement point a live control runs on, so the hero names where the mitigation actually
# landed instead of always claiming XC. The three shared forms (service_policy / waf_data_guard /
# api_schema) are stamped with an appliance-specific control on BIG-IP and NGINX; everything else is XC.
_POINT = {"bigip_awaf": "BIG-IP", "nginx_app_protect": "NGINX"}


def _point_for(control: str) -> str:
    return _POINT.get(control, "XC")


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


def change_control_days() -> int | None:
    """The contrast stat — how long a real code fix would take through change control. Off by default:
    it is a narrative comparison, not a number from the user's scan, so the hero shows it only when the
    operator opts in by setting CHANGE_CONTROL_DAYS (env-tunable so the number matches the story being
    told). Returns None when unset, which the renderers read as 'omit the contrast entirely'."""
    raw = os.environ.get("CHANGE_CONTROL_DAYS")
    if raw is None or raw.strip() == "":
        return None
    try:
        return max(1, int(raw))
    except ValueError:
        return None


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
    # "Mitigated live by XC" must mean a band-aid was actually applied, not merely that the entry
    # reached a late STATE. `ledger._advance` moves found -> remediated directly, and `pr.open_pr`
    # marks remediated for ANY finding it opens a PR for — including one triage routed to
    # code-cure-only, which never touched XC at all. Counting states alone made the hero claim a
    # live mitigation for a finding with `mitigation: null`, while `controls_live` (two lines up,
    # which does require a mitigation) simultaneously reported none. Same requirement, one answer.
    mitigated_entries = [e for e in led.values()
                         if e.get("state") in _LIVE and e.get("mitigation")]
    mitigated = len(mitigated_entries)
    # The enforcement points behind that count, so the hero label names where the band-aids actually
    # landed (XC / BIG-IP / NGINX) rather than always saying "by XC". Derived from the SAME entries the
    # count uses, so the label can never disagree with the number above it.
    points_live = sorted({_point_for(e["mitigation"]["control"]) for e in mitigated_entries})
    return {
        "candidates": summary.get("candidates", 0),
        "vulns": verified,
        "mitigated": mitigated,
        "remediated": counts["remediated"] + counts["retired"],
        "retired": counts["retired"],
        "code_prs": len(summary.get("code_fix_prs", []) or []),
        # H2: upgrades are cures we CANNOT open a PR for. Counted separately so the hero panel
        # never claims a drafted PR that does not exist.
        "dependency_upgrades": len(summary.get("dependency_upgrades", []) or []),
        "change_control_days": days,   # None when CHANGE_CONTROL_DAYS is unset — hero omits the contrast
        "mttm_seconds": mttm,
        "controls_live": controls,
        "points_live": points_live,    # e.g. ["BIG-IP", "XC"] — where the live band-aids actually run
        "states": counts,
        # how many× faster than change control — only meaningful when the operator configured that baseline
        "speedup": (round(days * 86400 / mttm) if (days and mttm) else None),
    }
