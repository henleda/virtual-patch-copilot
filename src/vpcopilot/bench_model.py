"""Cross-model benchmark. Capture one run's findings, the policies it generated, and — from the
audit log — whether each applied policy actually WORKED live (blocked the finding's real exploit
while legit traffic passed), then tag it with the model. Runs on Claude / OpenAI / a local
open-source model produce directly comparable benchmark-<tag>.json + .md reports.

Policy quality comes from the `apply_timing` audit records the console writes on every live Mitigate
(finding_id, control, passed, attempts, before/after) — so it reflects real live validation, not a
guess. `scan` and generation come from the run's findings/triage/policies artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path

SEV = ("critical", "high", "medium", "low")
AGENTS = ("discover", "verify", "triage", "generate", "remediate", "probe", "refine")


def _rj(out_dir: str, name: str, default):
    p = Path(out_dir) / name
    try:
        return json.loads(p.read_text()) if p.exists() else default
    except Exception:  # noqa: BLE001
        return default


def _models(config_path: str | None) -> dict:
    try:
        from .config import load_config
        cfg = load_config(config_path or os.environ.get("VPCOPILOT_CONFIG", "config/agents.yaml"))
        return {a: cfg.for_agent(a).model for a in AGENTS}
    except Exception:  # noqa: BLE001
        return {}


def build(out_dir: str, model_tag: str, target: str = "", config_path: str | None = None) -> dict:
    findings = _rj(out_dir, "findings.json", [])
    triage = _rj(out_dir, "triage.json", [])
    policies = _rj(out_dir, "policies.json", [])
    summary = _rj(out_dir, "summary.json", {})
    metrics = _rj(out_dir, "metrics.json", {})
    from . import audit as _audit
    audits = _audit.load(out_dir)

    tri = {d["finding_id"]: d for d in triage}
    fby = {f["id"]: f for f in findings}
    verified = [fby[i] for i in tri if i in fby]

    by_sev = {s: sum(1 for f in verified if f.get("severity") == s) for s in SEV}
    by_cls: dict[str, int] = {}
    for f in verified:
        c = f.get("vuln_class", "other")
        by_cls[c] = by_cls.get(c, 0) + 1

    by_control: dict[str, int] = {}
    for p in policies:
        by_control[p["control"]] = by_control.get(p["control"], 0) + 1
    no_bandaid = [d["finding_id"] for d in triage if d.get("no_bandaid")]

    # policy quality: the LAST live apply_timing per finding (a re-click supersedes an earlier try)
    timings: dict[str, dict] = {}
    for a in audits:
        if a.get("action") == "apply_timing" and a.get("finding_id"):
            timings[a["finding_id"]] = a
    per = []
    for fid, a in timings.items():
        f, ba = fby.get(fid, {}), (a.get("before_after") or {})
        per.append({
            "finding_id": fid, "control": a.get("control"),
            "severity": f.get("severity"), "vuln_class": f.get("vuln_class"),
            "passed": bool(a.get("passed")), "attempts": a.get("attempts") or 1,
            "unfixable": bool(a.get("unfixable")),
            "before_status": (ba.get("before") or {}).get("exploit_status"),
            "after_status": (ba.get("after") or {}).get("exploit_status"),
            "reason": a.get("reason"),
        })
    # Honest per-control outcome. Only per-request positive-security controls block a single fired
    # exploit; behavioral (rate_limit/malicious_user/bot_defense) and response-masking (data_guard)
    # controls are real mitigations but can't be proven by one request — mark those "applied", not
    # "blocked", so the benchmark doesn't overstate single-request efficacy.
    from .controls import CONTROLS

    def _outcome(p):
        if not p["passed"]:
            return "unfixable" if p["unfixable"] else "not_blocked"
        if p["after_status"] == 403:
            return "blocked"
        kind = CONTROLS[p["control"]].validation if p["control"] in CONTROLS else "live"
        return "applied" if kind in ("config", "behavioral") else "blocked"

    for p in per:
        p["outcome"] = _outcome(p)
    per.sort(key=lambda p: (SEV.index(p["severity"]) if p["severity"] in SEV else 9, p["finding_id"]))
    attempted = len(per)
    passed = sum(1 for p in per if p["passed"])
    blocked = sum(1 for p in per if p["outcome"] == "blocked")
    applied = sum(1 for p in per if p["outcome"] == "applied")
    healed = sum(1 for p in per if p["passed"] and (p["attempts"] or 1) > 1)
    atts = [p["attempts"] for p in per if p["attempts"]]
    v = metrics.get("verify") or {}

    return {
        "model_tag": model_tag,
        "target": target or summary.get("out_dir", ""),
        "models": _models(config_path),
        "scan": {
            "candidates": summary.get("candidates", len(findings)),
            "verified": summary.get("verified", len(verified)),
            "by_severity": by_sev, "by_class": by_cls,
            "confirm_rate": v.get("confirm_rate"), "avg_confidence": v.get("avg_confidence"),
            "timing_s": metrics.get("timing_s", {}),
        },
        "policies": {"generated": len(policies), "by_control": by_control, "no_bandaid": no_bandaid,
                     "code_fix_prs": len(summary.get("code_fix_prs", []) or [])},
        "policy_quality": {
            "attempted": attempted, "passed": passed, "failed": attempted - passed,
            "blocked": blocked,               # real single-request exploit block (→403)
            "applied_behavioral": applied,     # passed at config level; not single-request testable
            "block_rate": round(blocked / attempted, 2) if attempted else None,
            "pass_rate": round(passed / attempted, 2) if attempted else None,
            "self_healed": healed,
            "avg_attempts": round(sum(atts) / len(atts), 2) if atts else None,
            "per_finding": per,
        },
    }


def _uniform_model(models: dict) -> str | None:
    vals = set(models.values())
    return next(iter(vals)) if len(vals) == 1 else None


def to_markdown(b: dict) -> str:
    s, pol, pq = b["scan"], b["policies"], b["policy_quality"]
    um = _uniform_model(b.get("models") or {})
    lines = [f"# Benchmark — {b['model_tag']}", ""]
    lines.append(f"**Target:** `{b.get('target') or '—'}`  ")
    lines.append(f"**Model:** {um}" if um else "**Models (per agent):** "
                 + ", ".join(f"{a}={m}" for a, m in (b.get('models') or {}).items()))
    lines += ["", "## Discovery",
              f"- candidates **{s['candidates']}** → verified **{s['verified']}**"
              + (f" (confirm rate {round((s['confirm_rate'] or 0)*100)}%, avg confidence {s['avg_confidence']})"
                 if s.get("confirm_rate") is not None else ""),
              "- by severity: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v),
              "- by class: " + (", ".join(f"{k} {v}" for k, v in s["by_class"].items()) or "—"),
              f"- scan time: {s.get('timing_s', {}).get('total', '—')}s"]
    lines += ["", f"## Policies generated: {pol['generated']}",
              "- by control: " + (", ".join(f"{k} {v}" for k, v in pol["by_control"].items()) or "—"),
              f"- code-only (no band-aid): {', '.join(pol['no_bandaid']) or 'none'}",
              f"- code-fix PRs drafted: {pol['code_fix_prs']}"]
    br = f"{round((pq['block_rate'] or 0)*100)}%" if pq["block_rate"] is not None else "—"
    lines += ["", "## Policy quality (live)",
              f"- attempted **{pq['attempted']}** · **blocked** (real single-request exploit→403) "
              f"**{pq['blocked']}** ({br}) · applied-but-behavioral {pq['applied_behavioral']} · "
              f"failed {pq['failed']} · self-healed {pq['self_healed']} · avg attempts {pq['avg_attempts'] or '—'}",
              "",
              "> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). "
              "_applied-but-behavioral_ = the control was enabled and validated at config level, but is "
              "behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a "
              "single request can't prove a block — it needs a burst / traffic over time.",
              ""]
    if pq["per_finding"]:
        lines += ["| finding | sev | class | control | outcome | before→after | attempts |",
                  "|---|---|---|---|---|---|---|"]
        icon = {"blocked": "✅ blocked", "applied": "🟡 applied (behavioral)",
                "not_blocked": "❌ not blocked", "unfixable": "⚠️ unfixable"}
        for p in pq["per_finding"]:
            ba = (f"{p['before_status']}→{p['after_status']}" if p["before_status"] is not None else "—")
            lines.append(f"| {p['finding_id']} | {p['severity'] or '—'} | {p['vuln_class'] or '—'} | "
                         f"{p['control'] or '—'} | {icon.get(p['outcome'], p['outcome'])} | {ba} | {p['attempts']} |")
    else:
        lines.append("_No live mitigations recorded — run the Mitigate step (dry-run off) to measure efficacy._")
    return "\n".join(lines) + "\n"


def write(out_dir: str, model_tag: str, target: str = "", config_path: str | None = None,
          dest_dir: str = "benchmarks") -> dict:
    b = build(out_dir, model_tag, target=target, config_path=config_path)
    d = Path(dest_dir)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"benchmark-{model_tag}.json").write_text(json.dumps(b, indent=2))
    (d / f"benchmark-{model_tag}.md").write_text(to_markdown(b))
    return b


def compare(paths: list[str]) -> str:
    bs = [json.loads(Path(p).read_text()) for p in paths]
    tags = [b["model_tag"] for b in bs]

    def row(label, fn):
        return "| " + label + " | " + " | ".join(str(fn(b)) for b in bs) + " |"

    out = ["# Model comparison", "",
           "| metric | " + " | ".join(tags) + " |",
           "|---|" + "|".join(["---"] * len(bs)) + "|",
           row("model", lambda b: _uniform_model(b.get("models") or {}) or "mixed"),
           row("candidates", lambda b: b["scan"]["candidates"]),
           row("verified", lambda b: b["scan"]["verified"]),
           row("policies generated", lambda b: b["policies"]["generated"]),
           row("live-validated", lambda b: b["policy_quality"]["attempted"]),
           row("blocked (real exploit)", lambda b: b["policy_quality"].get("blocked", "—")),
           row("block rate", lambda b: (f"{round((b['policy_quality'].get('block_rate') or 0)*100)}%"
                                        if b["policy_quality"].get("block_rate") is not None else "—")),
           row("applied (behavioral)", lambda b: b["policy_quality"].get("applied_behavioral", "—")),
           row("self-healed", lambda b: b["policy_quality"]["self_healed"]),
           row("avg attempts", lambda b: b["policy_quality"]["avg_attempts"] or "—"),
           row("code-fix PRs", lambda b: b["policies"]["code_fix_prs"])]
    return "\n".join(out) + "\n"
