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
.bar /* `display:block` is load-bearing: `.fill` is a <span>, and an INLINE element ignores both height
   and a percentage width. The width and colour were being computed correctly all along
   (`style="width:33%;background:#a1001b"`) and silently discarded, so C5's severity and control
   bars have never actually drawn a bar — every track rendered empty. Found while adding the J5
   OWASP group, when all three charts were uniformly blank. */
.fill{display:block;height:100%;border-radius:6px}.bar .v{width:24px;text-align:right;font-weight:700}
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
        ba.append('<span class="cure">✓ code fix drafted</span>')
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
    h = lambda n, lbl, dim="": f'<div class="h{dim}"><span class="n">{_e(n)}</span><span class="l">{_e(lbl)}</span></div>'  # noqa: E731
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
            # H2: an advisory's cure is an upgrade in someone else's package — no PR was drafted
            # and none can be. Shown beside the PR count, never folded into it. Omitted entirely
            # when there are none, so a repo-only report is unchanged.
            + (h(im["dependency_upgrades"], "upgrades to ship (no PR)")
               if im.get("dependency_upgrades") else "")
            + dash_link
            + '</div>')


def _weakness_note(ws: dict) -> str:
    """The honesty line under the OWASP chart.

    J5's acceptance requires the mapping to read as *the tool's classification*, not a
    certification claim. It also has to say why some findings carry nothing — several classes have
    no honest mapping (CWE-840 is PROHIBITED by MITRE; Injection left the API Top 10 in 2023), and
    a blank that looks like an oversight is worse than one that explains itself.

    The two reasons are reported separately. `weakness.summary` splits them because only the class
    table can: a declined class is a RESULT, an unstamped finding is a DEFECT, and collapsing them
    into one sentence would state a reason this function cannot know."""
    if not ws["total"]:
        return ""
    bits = [f'{ws["total"] - ws["unclassified"]} of {ws["total"]} findings carry a CWE or an '
            f'OWASP category.']
    if ws.get("declined"):
        bits.append(f'{ws["declined"]} carry neither because no honest mapping exists for their '
                    f'class — considered and declined, not skipped.')
    if ws.get("unstamped"):
        # NOT merged into the line above: their class DOES map, so a blank here means the finding
        # never went through the stamp — it predates J5 or reached the report by a path that
        # bypassed the pipeline. Reporting that as "no honest mapping exists" would be a confident
        # false reason, which is worse than the blank it explains.
        bits.append(f'<strong>{ws["unstamped"]} were never classified</strong> even though their '
                    f'class does map — they predate this feature or bypassed the pipeline.')
    bits.append('This is the copilot\'s classification (or, where marked <code>advisory</code>, '
                'the advisory\'s own), not a certification that any control is satisfied.')
    return ('<p class="sub" style="margin-top:6px;font-size:12px;color:#6a7282">'
            + " ".join(bits) + "</p>")


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

    # J5 — group by OWASP API Top 10 category. The residual bar is every finding WITHOUT a
    # category, which is not the same set as `unclassified` (no CWE *and* no OWASP): an sqli
    # finding carries CWE-89 but no category, because Injection left the API Top 10 in 2023. Using
    # `unclassified` here put those in no bar at all, so the chart quietly summed to less than the
    # total — a chart that undercounts is the exact failure this item exists to avoid. The residual
    # is therefore derived from the total, and asserted below so it cannot drift again.
    from .weakness import summary as _weakness_summary
    ws = _weakness_summary(findings)
    owasp_c = dict(ws["by_owasp"])
    no_cat = ws["total"] - sum(ws["by_owasp"].values())
    if no_cat:
        owasp_c["(no category)"] = no_cat
    assert sum(owasp_c.values()) == ws["total"], "the OWASP chart does not account for every finding"
    owasp = _grp("Findings by OWASP API Top 10", owasp_c,
                 lambda k: "#6a7282" if k.startswith("(") else "#4b57b8")
    return f'<h2>At a glance</h2><div class="bars">{sev}{ctrl}{owasp}</div>{_weakness_note(ws)}'


def _models_html() -> str:
    """C5: the model-independence proof — which model backs each agent, swappable in config."""
    try:
        from .config import load_config
        import os
        cfg = load_config(os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
        agents = ["resolve", "discover", "verify", "triage", "generate", "remediate", "probe", "refine"]
        chips = "".join(f'<span class="model"><span class="a">{a}</span> · <span class="m">{_e(cfg.for_agent(a).model)}</span></span>'
                        for a in agents)
    except Exception:  # noqa: BLE001
        return ""
    return ('<h2>Model independence <span class="cls">each agent\'s model is set per-agent in '
            'config/agents.yaml — swap Claude / OpenAI / Gemini / Ollama with no code change</span></h2>'
            f'<div class="models">{chips}</div>')


def _blast_radius_html(out_dir: str) -> str:
    """G2: what each band-aid would do to recorded traffic, beside the exploit before/after. The
    impact table answers "does it block the attack"; this answers "what else does it block"."""
    try:
        from .simulate import load_result
        sim = load_result(out_dir)
    except Exception:  # noqa: BLE001
        return ""
    pols = (sim or {}).get("policies") or []
    if not pols:
        return ""
    rows = ""
    for p in pols:
        rate = f'{(p.get("block_rate") or 0) * 100:.1f}%'
        verdict = ('<span class="st-mitigated">over threshold</span>' if p.get("blocked_promotion")
                   else ('<span class="cls">error</span>' if p.get("error")
                         else '<span class="st-remediated">within threshold</span>'))
        top = ", ".join(f'{_e(t[0])} ×{_e(t[1])}' for t in (p.get("top_paths") or [])[:3]) or "—"
        rows += (f'<tr><td class="file">{_e(p.get("policy_name"))}</td>'
                 f'<td>{_e(p.get("evaluated"))}</td><td><b>{_e(p.get("would_block"))}</b></td>'
                 f'<td>{rate}</td><td>{verdict}</td><td class="cls">{top}</td></tr>')
    meta = (f'{_e(sim.get("records_replayed"))} of {_e(sim.get("records"))} recorded request(s) '
            f'replayed through {_e(sim.get("lb"))}')
    if sim.get("window"):
        meta += f' · window {_e(sim["window"])}'
    if sim.get("bodies_available") is False:
        meta += ' · no request bodies in this sample'
    return ('<h2>Blast radius <span class="cls">what each band-aid would block in recorded '
            f'traffic — {meta}</span></h2>'
            '<table><tr><th>policy</th><th>evaluated</th><th>would block</th><th>rate</th>'
            f'<th>verdict</th><th>top blocked paths</th></tr>{rows}</table>')


def _dependencies_html(out_dir: str) -> str:
    """H2: the dependency funnel, INCLUDING what was not checked.

    Two counts carry most of the honesty here and both are rendered even when zero: entries whose
    version could not be pinned (never queried, so nothing is known about them) and advisories held
    back by the severity floor or the cap (found and listed, but never sent to an agent). A
    dependency report that showed only the resolved rows would read as a clean bill of health for
    packages it never looked at."""
    dep = _load(Path(out_dir), "dependencies.json", None)
    if not dep:
        return ""
    f = dep.get("funnel") or {}
    s = dep.get("settings") or {}
    chips = "".join(_chip(f.get(k, 0), lbl) for k, lbl in (
        ("packages_parsed", "packages"), ("packages_vulnerable", "vulnerable"),
        ("advisories_distinct", "advisories"), ("exploitable", "exploitable"),
        ("declined", "declined"), ("not_resolved", "not resolved"),
        ("packages_unpinned", "could not pin")))
    rows = ""
    for a in (dep.get("advisories") or [])[:80]:
        fixed = _e(a.get("fixed_version")) or f'<span class="cls">{_e(a.get("fix_note")) or "none published"}</span>'
        rows += (f'<tr><td><span class="pill sev-{_e(a.get("severity"))}">{_e(a.get("severity"))}</span></td>'
                 f'<td class="file">{_e(a.get("package"))}</td><td>{_e(a.get("installed"))}</td>'
                 f'<td class="file">{_e(a.get("advisory_id"))}</td><td>{fixed}</td>'
                 f'<td>{_e(a.get("disposition"))}</td>'
                 f'<td class="cls">{_e(str(a.get("reason") or "")[:140])}</td></tr>')
    extra = ""
    n_un = len(dep.get("unpinned") or [])
    if n_un:
        reasons = ", ".join(sorted({u.get("reason", "") for u in dep["unpinned"]}))
        extra += ('<p class="cls"><b>Not checked.</b> '
                  f'{n_un} manifest entry(ies) could not be pinned to an exact version and were '
                  f'never queried ({_e(reasons)}). Nothing is known about them — this is not a '
                  'statement that they are clean.</p>')
    if f.get("not_resolved"):
        extra += ('<p class="cls"><b>Listed, not resolved.</b> '
                  f'{f["not_resolved"]} advisory(ies) were found but not sent to an agent '
                  f'(--min-severity {_e(s.get("min_severity"))}, --max-advisories '
                  f'{_e(s.get("max_advisories"))}). They are in the table with the reason.</p>')
    # A package the batch flagged as vulnerable but whose advisory fetch then failed used to appear
    # here exactly like one that came back clean: no row, no counter, no warning.
    for u in dep.get("unchecked") or []:
        extra += ('<p class="cls"><b>Could not check.</b> '
                  f'{_e(u.get("ecosystem"))}/{_e(u.get("name"))} {_e(u.get("version"))} — '
                  f'{_e(u.get("error"))}. Its advisories are unknown, not absent.</p>')
    for e in dep.get("errors") or []:
        extra += f'<p class="cls">⚠ {_e(e.get("path"))}: {_e(e.get("error"))}</p>'
    return ('<h2>Dependencies <span class="cls">pinned packages resolved against OSV.dev — '
            'the vulnerability is in code you do not own, so the cure is a version bump</span></h2>'
            f'<div class="chips">{chips}</div>{extra}'
            '<table><tr><th>sev</th><th>package</th><th>installed</th><th>advisory</th>'
            f'<th>fixed in</th><th>disposition</th><th>why</th></tr>{rows}</table>')


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

    # `findings.json` holds every CANDIDATE; `triage.json` holds only the ones the verify agent
    # CONFIRMED. The report rendered all of them in one list, so a candidate verify had REFUTED sat
    # on the page looking exactly like a confirmed one — 25 cards under a hero reading 9, on the
    # artifact whose job is to be trustworthy. Split rather than filter: dropping the refuted ones
    # would hide that the tool considered and rejected them, and "we did not check this" and "we
    # checked and it did not hold" are different answers that must not render the same way either.
    verified = [f for f in findings if f.get("id") in tri]
    refuted = [f for f in findings if f.get("id") not in tri]

    n_band = sum(1 for f in verified if tri.get(f.get("id"), {}).get("bandaids"))
    chips = "".join([
        _chip(summary.get("candidates", len(findings)), "candidates"),
        _chip(summary.get("verified", len(findings)), "verified"),
        _chip(n_band, "band-aided"),
        _chip(len(summary.get("no_bandaid", [])), "code-cure only"),
        _chip(len(summary.get("policies", [])), "XC policies"),
        _chip(len(summary.get("code_fix_prs", remediations)), "code-fix PRs"),
    ] + ([_chip(len(summary.get("dependency_upgrades", [])), "upgrades to ship")]
         if summary.get("dependency_upgrades") else []))

    cards = "".join(_finding_card(f, tri.get(f.get("id")), rem.get(f.get("id"))) for f in verified)
    if refuted:
        # Rendered, but below the fold and unmistakably labelled. The count is stated so the page
        # accounts for every candidate rather than quietly showing a subset.
        rc = "".join(_finding_card(f, None, rem.get(f.get("id"))) for f in refuted)
        cards += (
            '<h2 style="margin-top:26px">Candidates the verify agent did not confirm</h2>'
            f'<p class="sub">{len(refuted)} of {len(findings)} candidates. The discover agent '
            'proposed these; the adversarial verify step could not confirm them, so they carry no '
            'band-aid and are <strong>not</strong> counted anywhere else on this page. They are '
            'shown because "considered and rejected" is a result worth seeing — not because they '
            'are findings.</p>'
            f'<div class="refuted" style="opacity:.72">{rc}</div>')

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
    impact_html += _blast_radius_html(out_dir)

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
{_bars_html(verified, summary)}
{_models_html()}
{_metrics_html(metrics)}
{_dependencies_html(out_dir)}
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
