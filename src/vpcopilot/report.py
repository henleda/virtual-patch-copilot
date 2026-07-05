"""E3 — standalone, self-contained HTML report of a scan.

Reads the ./out artifacts (findings/triage/remediations/policies/ledger/summary) and writes a
single shareable report.html: no server, no external assets, inline CSS, native <details> for
expansion. `run_pipeline` calls this at the end so every scan drops an HTML dashboard, and
`vpcopilot report` (re)builds it from an existing out dir."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_CSS = """
:root{--ink:#121624;--navy:#1b2a4a;--f5:#e4002b;--grey:#6a7282;--line:#dfe4ee;
 --ok:#167c3a;--amber:#b45a00;--bg:#f6f8fc}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
header{background:var(--navy);color:#fff;padding:18px 28px}
header h1{font-size:18px;margin:0;font-weight:700}header .dot{color:var(--f5)}
header .sub{color:#c7d2e8;font-size:13px;margin-top:4px}
main{padding:24px;max-width:1100px;margin:0 auto}
h2{font-size:15px;margin:26px 0 12px}
.chips{display:flex;gap:10px;flex-wrap:wrap}
.chip{background:#fff;border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:96px}
.chip .n{font-size:22px;font-weight:800;display:block;line-height:1.1}
.chip .l{font-size:11px;color:var(--grey);text-transform:uppercase;letter-spacing:.04em}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fhead .title{font-weight:700}.fhead .id{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--grey)}
.pill{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700}
.sev-critical{background:#fde7ea;color:#a1001b}.sev-high{background:#fde7e0;color:#a1440b}
.sev-medium{background:#fff4d6;color:#7a5a00}.sev-low{background:#e8f0fe;color:#1b4fa1}
.cls{background:var(--bg);border:1px solid var(--line);border-radius:20px;padding:1px 10px;font-size:12px;color:var(--grey)}
.file{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--grey);margin-left:auto}
.bandaids{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.ba{border:1px solid var(--line);border-radius:20px;padding:3px 11px;font-size:12px;font-weight:600;background:#fff}
.ba.rec{background:var(--navy);color:#fff;border-color:var(--navy)}
.ba .cov{opacity:.7;font-weight:500}
.nob{background:#fff4ec;border-color:#f0c9a6;color:var(--amber);font-weight:700}
.cure{margin-left:auto;color:var(--ok);font-weight:700;font-size:12px}
.resid{color:var(--amber);font-size:12px;margin-top:8px}
details{margin-top:10px}details summary{cursor:pointer;color:#1b4fa1;font-size:13px;font-weight:600}
details .body{margin-top:8px;font-size:13px}
details .body p{margin:6px 0}details .body .k{color:var(--grey);font-weight:600}
pre{background:#0f1422;color:#d7e0f2;padding:12px;border-radius:8px;overflow:auto;font-size:12px;white-space:pre-wrap;margin:8px 0 0}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--grey);font-weight:600;background:var(--bg)}
.polgrp{margin:0 0 8px}.polgrp .h{font-weight:700;font-size:13px}.polgrp .items{color:var(--grey);font-size:13px}
.st-found{color:var(--grey)}.st-mitigated{color:var(--amber);font-weight:700}
.st-remediated{color:var(--ok);font-weight:700}.st-retired{color:#1b4fa1;font-weight:700}
footer{color:var(--grey);font-size:12px;padding:20px 28px;text-align:center}
"""


def _load(out: Path, name: str, default):
    p = out / name
    try:
        return json.loads(p.read_text()) if p.exists() else default
    except Exception:  # noqa: BLE001
        return default


def _e(s) -> str:
    return html.escape(str(s), quote=True)


def _chip(n, label) -> str:
    return f'<div class="chip"><span class="n">{_e(n)}</span><span class="l">{_e(label)}</span></div>'


def _finding_card(f: dict, decision: dict | None, rem: dict | None) -> str:
    sev = f.get("severity", "low")
    parts = [
        '<div class="card"><div class="fhead">',
        f'<span class="pill sev-{_e(sev)}">{_e(sev)}</span>',
        f'<span class="title">{_e(f.get("title", ""))}</span>',
        f'<span class="id">{_e(f.get("id", ""))}</span>',
        f'<span class="cls">{_e(f.get("vuln_class", ""))}</span>',
    ]
    loc = f.get("file", "")
    if f.get("line"):
        loc = f"{loc}:{f['line']}"
    if loc:
        parts.append(f'<span class="file">{_e(loc)}</span>')
    parts.append("</div>")  # /fhead

    # band-aids row
    ba = ['<div class="bandaids">']
    if decision and decision.get("no_bandaid"):
        ba.append('<span class="ba nob">no band-aid — code cure only</span>')
    for b in (decision or {}).get("bandaids", []):
        rec = " rec" if b.get("recommended") else ""
        cov = f' <span class="cov">· {_e(b.get("coverage", ""))}</span>'
        ba.append(f'<span class="ba{rec}">{_e(b.get("control", ""))}{cov}</span>')
    if rem:
        ba.append(f'<span class="cure">✓ code fix drafted</span>')
    ba.append("</div>")
    parts.append("".join(ba))

    if decision and decision.get("residual_risk"):
        parts.append(f'<div class="resid">Residual risk: {_e(decision["residual_risk"])}</div>')

    # expandable detail
    body = [f'<p><span class="k">Description:</span> {_e(f.get("description", ""))}</p>']
    if f.get("exploit_sketch"):
        body.append(f'<p><span class="k">Exploit:</span> {_e(f["exploit_sketch"])}</p>')
    if rem and rem.get("pr_title"):
        body.append(f'<p><span class="k">Code cure:</span> {_e(rem["pr_title"])}</p>')
    if f.get("code_snippet"):
        body.append(f'<pre>{_e(f["code_snippet"])}</pre>')
    parts.append(f'<details><summary>Details</summary><div class="body">{"".join(body)}</div></details>')
    parts.append("</div>")  # /card
    return "".join(parts)


def _impact_cell(x: dict) -> str:
    blk, st = x.get("exploit_blocked"), x.get("exploit_status")
    if blk is None:
        return '<span class="cls">—</span>'
    if blk:
        return f'<span class="st-remediated">{_e(st)} blocked</span>'
    return f'<span class="st-mitigated">{_e(st)} allowed</span>'


def _impact_rows(audits: list) -> str:
    label = {"apply_service_policy": "service_policy", "apply_waf": "waf", "apply_api_schema": "api_schema"}
    rows = ""
    for a in audits or []:
        ba = a.get("before_after")
        if not ba:
            continue
        b, af = ba.get("before", {}), ba.get("after", {})
        ctrl = label.get(a.get("action"), a.get("action", ""))
        tgt = a.get("policy") or a.get("app_firewall") or a.get("apidef") or ""
        legit = "ok" if af.get("legit_ok") else "—"
        result = ('<span class="st-remediated">PASS</span>' if a.get("passed")
                  else '<span class="st-mitigated">fail</span>')
        rows += (f'<tr><td>{_e(ctrl)}</td><td class="file">{_e(tgt)}</td>'
                 f'<td>{_impact_cell(b)}</td><td>{_impact_cell(af)}</td>'
                 f'<td>{legit}</td><td>{result}</td><td class="cls">{_e(str(a.get("ts", ""))[:19])}</td></tr>')
    return rows


def build_report(out_dir: str = "out") -> str:
    out = Path(out_dir)
    summary = _load(out, "summary.json", {})
    findings = _load(out, "findings.json", [])
    triage = _load(out, "triage.json", [])
    remediations = _load(out, "remediations.json", [])
    try:
        from .ledger import load as ledger_load
        led = ledger_load(out_dir)
        entries = led.get("entries", led) if isinstance(led, dict) else {}
    except Exception:  # noqa: BLE001
        entries = {}
    try:
        from .audit import load as audit_load
        audits = audit_load(out_dir)
    except Exception:  # noqa: BLE001
        audits = []

    tri = {t.get("finding_id"): t for t in triage}
    rem = {r.get("finding_id"): r for r in remediations}
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("id", "")))

    n_band = sum(1 for f in findings if tri.get(f.get("id"), {}).get("bandaids"))
    chips = "".join([
        _chip(summary.get("candidates", len(findings)), "candidates"),
        _chip(summary.get("verified", len(findings)), "verified"),
        _chip(n_band, "band-aided"),
        _chip(len(summary.get("no_bandaid", [])), "code-cure only"),
        _chip(len(summary.get("policies", [])), "XC policies"),
        _chip(len(summary.get("code_fix_prs", remediations)), "code-fix PRs"),
    ])

    cards = "".join(_finding_card(f, tri.get(f.get("id")), rem.get(f.get("id"))) for f in findings)

    # band-aid policies grouped by control
    pol_html = ""
    by_ctrl: dict[str, list[str]] = {}
    for p in summary.get("policies", []):
        ctrl, _, name = str(p).partition("/")
        by_ctrl.setdefault(ctrl, []).append(name or ctrl)
    for ctrl in sorted(by_ctrl):
        items = ", ".join(_e(n) for n in by_ctrl[ctrl])
        pol_html += f'<div class="polgrp"><span class="h">{_e(ctrl)}</span> <span class="items">{items}</span></div>'

    # ledger
    led_html = ""
    if entries:
        rows = ""
        for fid, e in entries.items():
            if not isinstance(e, dict):
                continue
            st = e.get("state", "found")
            rows += f'<tr><td>{_e(e.get("finding_id", fid))}</td><td class="st-{_e(st)}">{_e(st)}</td>' \
                    f'<td>{_e(e.get("mitigation") or "—")}</td><td>{_e(e.get("cure") or "—")}</td></tr>'
        led_html = ('<h2>Remediation ledger <span class="cls">found → mitigated → remediated → retired</span></h2>'
                    '<table><tr><th>finding</th><th>state</th><th>band-aid</th><th>code cure</th></tr>'
                    f'{rows}</table>')

    impact = _impact_rows(audits)
    impact_html = ('<h2>Band-aid impact <span class="cls">exploit before → after (live validation)</span></h2>'
                   '<table><tr><th>control</th><th>policy</th><th>exploit before</th>'
                   '<th>exploit after</th><th>legit</th><th>result</th><th>when</th></tr>'
                   f'{impact}</table>') if impact else ""

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        from . import __version__ as ver
    except Exception:  # noqa: BLE001
        ver = ""
    target = _e(summary.get("out_dir", out_dir))

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>virtual-patch-copilot · report</title><style>{_CSS}</style></head><body>
<header><h1>virtual-patch<span class="dot">·</span>copilot <span style="font-weight:400">— scan report</span></h1>
<div class="sub">{target} · generated {_e(ts)}</div></header>
<main>
<h2>Run summary</h2><div class="chips">{chips}</div>
<h2>Findings &amp; band-aid coverage</h2>{cards or '<p class="cls">No findings.</p>'}
<h2>Generated XC band-aid policies</h2>{pol_html or '<p class="cls">None.</p>'}
{impact_html}
{led_html}
</main>
<footer>virtual-patch-copilot{(' ' + ver) if ver else ''} · band-aids are temporary — every finding also gets a code-fix PR</footer>
</body></html>"""


def write_report(out_dir: str = "out", output: str | None = None) -> str:
    path = Path(output) if output else Path(out_dir) / "report.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(out_dir))
    return str(path)
