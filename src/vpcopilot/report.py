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
.hero{background:linear-gradient(120deg,#1b2a4a,#25406e);color:#fff;border-radius:12px;
 padding:20px 22px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin:0 0 8px}
.hero .h{text-align:center;min-width:96px}.hero .h.dim{opacity:.72}
.hero .h .n{font-size:28px;font-weight:800;line-height:1.05;display:block}
.hero .h .l{font-size:11px;color:#c7d2e8;margin-top:2px}
.hero .sep{font-size:20px;font-weight:800;color:#7f93bd}.hero .red{color:#ff98a8}
.badge{display:inline-block;background:#e7f5ec;color:var(--ok);border:1px solid #bfe3cc;
 border-radius:20px;padding:0 8px;font-size:11px;font-weight:700}
.bars{display:flex;gap:24px;flex-wrap:wrap}.bars .grp{flex:1;min-width:240px}
.bar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:12px}
.bar .lab{width:96px;color:var(--grey)}.bar .track{flex:1;background:var(--bg);border-radius:6px;height:14px;overflow:hidden;border:1px solid var(--line)}
.bar .fill{height:100%;border-radius:6px}.bar .v{width:24px;text-align:right;font-weight:700}
.models{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.model{background:#fff;border:1px solid var(--line);border-radius:20px;padding:3px 11px;font-size:12px}
.model .a{color:var(--grey)}.model .m{font-family:ui-monospace,Menlo,monospace;color:var(--f5)}
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
    label = {"apply_service_policy": "service_policy", "refine_apply": "service_policy",
             "apply_waf": "waf", "apply_api_schema": "api_schema", "apply_rate_limit": "rate_limit"}
    rows = ""
    for a in audits or []:
        ba, beh = a.get("before_after"), a.get("behavioral")
        ctrl = label.get(a.get("action"), a.get("action", ""))
        when = _e(str(a.get("ts", ""))[:19])
        # C5: surface the self-heal — a policy that only worked after the refine loop retried it
        att = a.get("attempts")
        heal = f' <span class="badge">self-healed ×{_e(att)}</span>' if (att and att > 1) else ""
        result = ('<span class="st-remediated">PASS</span>' if a.get("passed")
                  else '<span class="st-mitigated">fail</span>')
        if ba:  # exploit before/after (service_policy / waf / api_schema)
            b, af = ba.get("before", {}), ba.get("after", {})
            tgt = a.get("policy") or a.get("app_firewall") or a.get("apidef") or ""
            legit = "ok" if af.get("legit_ok") else "—"
            rows += (f'<tr><td>{_e(ctrl)}{heal}</td><td class="file">{_e(tgt)}</td>'
                     f'<td>{_impact_cell(b)}</td><td>{_impact_cell(af)}</td>'
                     f'<td>{legit}</td><td>{result}</td><td class="cls">{when}</td></tr>')
        elif beh:  # behavioral burst (rate_limit) — B3
            lim, sent = beh.get("limited", 0), beh.get("sent", 0)
            after = (f'<span class="st-remediated">{_e(lim)}/{_e(sent)} rate-limited (429)</span>'
                     if lim else '<span class="st-mitigated">not limited</span>')
            rows += (f'<tr><td>{_e(ctrl)}</td><td class="file">{_e(a.get("rate", ""))}</td>'
                     f'<td><span class="st-mitigated">burst {_e(sent)} allowed</span></td><td>{after}</td>'
                     f'<td>—</td><td>{result}</td><td class="cls">{when}</td></tr>')
    return rows


def _metrics_html(m: dict) -> str:
    if not m:
        return ""
    t, v, s = m.get("timing_s", {}), m.get("verify", {}), m.get("synthesize", {})
    chips = "".join([
        _chip(f"{t.get('total', '—')}s", "total time"),
        _chip(f"{t.get('discover', '—')}s", "discover"),
        _chip(f"{t.get('verify', '—')}s", "verify"),
        _chip(f"{t.get('synthesize', '—')}s", "synthesize"),
        _chip(f"{round(v.get('confirm_rate', 0) * 100)}%", "verify confirm-rate"),
        _chip(v.get("avg_confidence", "—"), "avg confidence"),
        _chip(s.get("dupe_bandaids_collapsed", 0), "dupe band-aids collapsed"),
    ])
    detail = (f'<p class="cls">verify: {_e(v.get("candidates", 0))} candidates → '
              f'{_e(v.get("verified", 0))} verified, {_e(v.get("refuted", 0))} refuted, '
              f'{_e(v.get("dropped_low_confidence", 0))} dropped &lt; {_e(v.get("min_confidence", ""))} confidence</p>')
    return f'<h2>Pipeline metrics</h2><div class="chips">{chips}</div>{detail}'


def _hero_html(im: dict) -> str:
    """C5: the same headline the console shows — N exploitable → mitigated live vs change control."""
    if not im.get("vulns"):
        return ""
    mttm = f"{im['mttm_seconds']}s" if im.get("mttm_seconds") is not None else "minutes"
    speed = f" · {im['speedup']:,}× faster" if im.get("speedup") else ""
    h = lambda n, l, dim="": f'<div class="h{dim}"><span class="n">{_e(n)}</span><span class="l">{_e(l)}</span></div>'
    from .impact import xc_dashboard_url
    dash = xc_dashboard_url()
    dash_link = (f'<a href="{_e(dash)}" target="_blank" style="margin-left:auto;color:#fff;font-weight:700;font-size:12px">'
                 'XC security dashboard ↗</a>') if dash else ""
    return ('<div class="hero">'
            + h(im["vulns"], "exploitable vulns")
            + '<span class="sep">→</span>'
            + h(im["mitigated"], "mitigated live by XC")
            + h(mttm, "time to mitigate" + speed)
            + '<span class="sep">vs</span>'
            + f'<div class="h dim"><span class="n red">{_e(im["change_control_days"])} days</span>'
              '<span class="l">normal change control</span></div>'
            + h(im["code_prs"], "code-fix PRs (the cure)")
            + dash_link
            + '</div>')


def _bars_html(findings: list, summary: dict) -> str:
    """C5: severity mix + band-aid coverage by control, as simple CSS bars."""
    sev_c = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev_c[f.get("severity", "low")] = sev_c.get(f.get("severity", "low"), 0) + 1
    ctrl_c: dict[str, int] = {}
    for p in summary.get("policies", []):
        ctrl = str(p).partition("/")[0]
        ctrl_c[ctrl] = ctrl_c.get(ctrl, 0) + 1
    sev_col = {"critical": "#a1001b", "high": "#a1440b", "medium": "#7a5a00", "low": "#1b4fa1"}

    def _grp(title, counts, colfn):
        mx = max(counts.values(), default=0) or 1
        bars = ""
        for k, v in counts.items():
            if not v and title.startswith("Band"):
                continue
            w = round(v / mx * 100)
            bars += (f'<div class="bar"><span class="lab">{_e(k)}</span>'
                     f'<span class="track"><span class="fill" style="width:{w}%;background:{colfn(k)}"></span></span>'
                     f'<span class="v">{_e(v)}</span></div>')
        return f'<div class="grp"><div class="h" style="font-weight:700;font-size:13px;margin-bottom:4px">{title}</div>{bars or "<span class=cls>none</span>"}</div>'

    sev = _grp("Findings by severity", {k: sev_c[k] for k in SEV_ORDER}, lambda k: sev_col.get(k, "#6a7282"))
    ctrl = _grp("Band-aids by XC control", ctrl_c, lambda k: "#1b2a4a")
    return f'<h2>At a glance</h2><div class="bars">{sev}{ctrl}</div>'


def _models_html() -> str:
    """C5: the model-independence proof — which model backs each agent, swappable in config."""
    try:
        from .config import load_config
        import os
        cfg = load_config(os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
        agents = ["discover", "verify", "triage", "generate", "remediate", "probe", "refine"]
        chips = "".join(f'<span class="model"><span class="a">{a}</span> · <span class="m">{_e(cfg.for_agent(a).model)}</span></span>'
                        for a in agents)
    except Exception:  # noqa: BLE001
        return ""
    return ('<h2>Model independence <span class="cls">each agent\'s model is set per-agent in '
            'config/agents.yaml — swap Claude / OpenAI / Gemini / Ollama with no code change</span></h2>'
            f'<div class="models">{chips}</div>')


def build_report(out_dir: str = "out") -> str:
    out = Path(out_dir)
    summary = _load(out, "summary.json", {})
    metrics = _load(out, "metrics.json", {}) or summary.get("metrics", {})
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
    # humanize the target: prefer the live LB the band-aids landed on, else the out dir
    lb = next((e.get("mitigation", {}).get("lb") for e in entries.values()
               if isinstance(e, dict) and e.get("mitigation")), None)
    target = _e(f"target: {lb}" if lb else summary.get("out_dir", out_dir))

    try:
        from .impact import impact as _impact
        im = _impact(out_dir)
    except Exception:  # noqa: BLE001
        im = {}

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>virtual-patch-copilot · report</title><style>{_CSS}</style></head><body>
<header><h1>virtual-patch<span class="dot">·</span>copilot <span style="font-weight:400">— scan report</span></h1>
<div class="sub">{target} · generated {_e(ts)}</div></header>
<main>
{_hero_html(im)}
<h2>Run summary</h2><div class="chips">{chips}</div>
{_bars_html(findings, summary)}
{_models_html()}
{_metrics_html(metrics)}
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
