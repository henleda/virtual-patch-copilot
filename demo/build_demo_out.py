"""C6 — build a curated, self-contained out/ so the console and HTML report tell the whole story
OFFLINE (no live XC, no API keys). Walks the ledger through all four states (found → mitigated →
remediated → retired), including one finding taken all the way to retired, across every control
family, with a self-heal on the SQLi service policy.

Usage:  python3 demo/build_demo_out.py            # writes ./demo/out
        VPCOPILOT_OUT=demo/out python3 -m vpcopilot.console   # then open the console against it
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
sys.path.insert(0, str(ROOT.parent / "src"))

from vpcopilot import audit, ledger, runmeta  # noqa: E402
from vpcopilot.config import AGENT_NAMES  # noqa: E402

# --- the curated crAPI-flavoured findings -----------------------------------
FINDINGS = [
    {"id": "crapi-sqli-001", "title": "SQL injection in login", "vuln_class": "sqli", "severity": "critical",
     "file": "services/identity/login.js", "line": 42, "endpoint": "/identity/api/auth/login", "http_method": "POST",
     "description": "The email field is concatenated straight into the auth query.",
     "exploit_sketch": "email=\" OR 1=1 -- lets any password through and dumps the users table.",
     "snippet": "const q = `SELECT * FROM users WHERE email = '${email}'`;  // vulnerable"},
    {"id": "crapi-bola-002", "title": "BOLA on vehicle location", "vuln_class": "broken_object_authz", "severity": "high",
     "file": "services/identity/vehicle.js", "line": 88, "endpoint": "/identity/api/v2/vehicle/{id}/location", "http_method": "GET",
     "description": "Any authenticated user can read another user's vehicle GPS by id.",
     "exploit_sketch": "Swap {id} to another user's vehicle uuid; server returns their live location."},
    {"id": "crapi-mass-003", "title": "Mass assignment on profile", "vuln_class": "mass_assignment", "severity": "high",
     "file": "services/identity/dashboard.js", "line": 61, "endpoint": "/identity/api/v2/user/dashboard", "http_method": "POST",
     "description": "The update handler binds the whole body, so `role` and `credit` are writable.",
     "exploit_sketch": "POST {\"role\":\"admin\",\"available_credit\":9999} — privilege + balance escalation."},
    {"id": "crapi-bruteforce-004", "title": "No rate limit on OTP verify", "vuln_class": "rate_abuse", "severity": "medium",
     "file": "services/identity/otp.js", "line": 30, "endpoint": "/identity/api/auth/v3/check-otp", "http_method": "POST",
     "description": "The 4-digit OTP endpoint has no throttle — brute-forceable in minutes.",
     "exploit_sketch": "Fire all 10k OTPs; no lockout, no delay."},
    {"id": "crapi-tokenleak-006", "title": "JWT + card data in response", "vuln_class": "sensitive_data", "severity": "high",
     "file": "services/workshop/mechanic.js", "line": 120, "endpoint": "/workshop/api/mechanic/receipt", "http_method": "GET",
     "description": "The receipt payload echoes the full PAN and a signed service token.",
     "exploit_sketch": "GET a receipt; response body contains the 16-digit card number in cleartext."},
    {"id": "crapi-userenum-005", "title": "Username enumeration on signup", "vuln_class": "broken_auth", "severity": "medium",
     "file": "services/identity/signup.js", "line": 25, "endpoint": "/identity/api/auth/signup", "http_method": "POST",
     "description": "Distinct errors for taken vs free emails leak which accounts exist.",
     "exploit_sketch": "Diff the 'already registered' vs 'ok' responses to enumerate users."},
]

# control per finding (005 is code-cure-only)
BANDAID = {"crapi-sqli-001": "service_policy", "crapi-bola-002": "api_schema", "crapi-mass-003": "waf",
           "crapi-bruteforce-004": "rate_limit", "crapi-tokenleak-006": "waf_data_guard"}
COV = {"service_policy": "full", "api_schema": "full", "waf": "partial",
       "rate_limit": "full", "waf_data_guard": "partial"}
LB = "crapi-lab"
NS = "crapi-demo"          # the XC namespace the curated run "mutated"
ACTOR, HOST = "security-oncall", "vpcopilot-demo"  # see _curate_identity()

TRIAGE = []
for f in FINDINGS:
    c = BANDAID.get(f["id"])
    TRIAGE.append({"finding_id": f["id"], "no_bandaid": c is None,
                   "bandaids": ([{"control": c, "coverage": COV[c], "recommended": True,
                                  "rationale": f"XC {c} blocks this at the edge while the code fix ships."}] if c else []),
                   "residual_risk": "" if c else "no positive-security band-aid fits; ships as code-only.",
                   "code_cure_required": True})

REMEDIATIONS = [{"finding_id": f["id"], "file": f["file"],
                 "pr_title": f"Fix {f['title'].lower()}", "pr_body": f"Cure for {f['id']}.", "diff": "--- a\n+++ b\n"}
                for f in FINDINGS]

POLICIES = [{"finding_id": fid, "control": c, "policy_name": {"service_policy": "deny-login-sqli",
             "api_schema": "crapi-lab-apidef", "waf": "crapi-lab-waf", "rate_limit": "otp-throttle",
             "waf_data_guard": "mask-pan"}[c]} for fid, c in BANDAID.items()]

SUMMARY = {
    "candidates": 9, "verified": len(FINDINGS),
    "policies": [f"{p['control']}/{p['policy_name']}" for p in POLICIES],
    "no_bandaid": ["crapi-userenum-005"],
    "code_fix_prs": [f["id"] for f in FINDINGS],
    "correlations": [], "out_dir": str(OUT),
}
METRICS = {
    "timing_s": {"discover": 6.4, "verify": 4.1, "synthesize": 8.7, "total": 19.2},
    "verify": {"candidates": 9, "verified": 6, "refuted": 2, "dropped_low_confidence": 1,
               "confirm_rate": 0.67, "avg_confidence": 0.86, "min_confidence": 0.5},
    "synthesize": {"policies": len(POLICIES), "dupe_bandaids_collapsed": 1, "code_fix_prs": len(FINDINGS)},
}


def _blocked(status):  # helper for before/after cells
    return {"exploit_status": status, "exploit_blocked": status in (403,), "legit_ok": True}


def _curate_identity():
    """Rewrite `actor` / `host` / `out_dir` in the generated fixture to curated, portable values.

    `audit.record` stamps the real OS user and hostname, and the writers record an absolute out dir
    — all correct for a real run, all wrong for a dataset committed to a public repo and
    screenshotted into the README. Normalizing here keeps the fiction where it belongs (this curated
    builder) rather than adding a spoofing knob to `runmeta`, which the audit trail depends on being
    honest."""
    ident = {"actor": ACTOR, "host": HOST}
    log = OUT / "audit.log"
    if log.exists():
        # Space the timestamps out. The builder writes the whole trail in one burst, which would
        # show 13 identical clock times — the shape of a fixture, not of a mitigation session.
        from datetime import datetime, timedelta, timezone
        t, out = datetime.now(timezone.utc) - timedelta(minutes=9), []
        for ln in log.read_text().splitlines():
            if not ln.strip():
                continue
            e = json.loads(ln)
            out.append(json.dumps({**e, **ident, "ts": t.isoformat()}))
            t += timedelta(seconds=int(e.get("elapsed_s") or 0) + (45 if e["action"] == "retire" else 4))
        log.write_text("\n".join(out) + "\n")
    for name in ("run.json", "summary.json"):
        p = OUT / name
        if not p.exists():
            continue
        d = json.loads(p.read_text())
        d.update({k: v for k, v in ident.items() if k in d})
        if "out_dir" in d:
            d["out_dir"] = "demo/out"          # portable — no home directory in a shared fixture
        p.write_text(json.dumps(d, indent=2))


def main():
    # Start from a clean slate so the dataset is deterministic — audit.record and the ledger APPEND,
    # so regenerating over an existing out/ would otherwise inflate the action log on every run.
    import shutil
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "policies").mkdir(exist_ok=True)
    # J5 — stamp through the same module the pipeline uses. The curated list is hand-written, so
    # it never passes the pipeline choke point; without this the demo dataset would render as
    # "never classified" while a real run of the same findings classified fine.
    from vpcopilot.weakness import classify
    for _f in FINDINGS:
        _g = classify(_f.get("vuln_class", ""))
        _f["cwe"], _f["owasp"], _f["cwe_source"] = _g["cwe"], _g["owasp"], _g["cwe_source"]
    (OUT / "findings.json").write_text(json.dumps(FINDINGS, indent=2))
    (OUT / "triage.json").write_text(json.dumps(TRIAGE, indent=2))
    (OUT / "remediations.json").write_text(json.dumps(REMEDIATIONS, indent=2))
    (OUT / "policies.json").write_text(json.dumps(POLICIES, indent=2))
    (OUT / "summary.json").write_text(json.dumps(SUMMARY, indent=2))
    (OUT / "metrics.json").write_text(json.dumps(METRICS, indent=2))
    (OUT / "correlations.json").write_text("[]")
    (OUT / "probes.json").write_text("[]")
    for p in POLICIES:
        (OUT / "policies" / f"{p['control']}.{p['policy_name']}.json").write_text(
            json.dumps({"metadata": {"name": p["policy_name"]}, "spec": {"_demo": True}}, indent=2))

    # seed the ledger, then walk it through the four states
    ledger.init_from_scan(str(OUT), FINDINGS, TRIAGE, REMEDIATIONS)
    for fid, c in BANDAID.items():
        ledger.mark_mitigated(str(OUT), fid, control=c, policy_name=dict((p["finding_id"], p["policy_name"]) for p in POLICIES)[fid], lb=LB)
    # PRs merged for three -> remediated; one of them retired
    ledger.mark_remediated(str(OUT), "crapi-sqli-001", pr_url="https://github.com/acme/crapi/pull/311", pr_number=311)
    ledger.mark_remediated(str(OUT), "crapi-bola-002", pr_url="https://github.com/acme/crapi/pull/312", pr_number=312)
    ledger.mark_remediated(str(OUT), "crapi-tokenleak-006", pr_url="https://github.com/acme/crapi/pull/313", pr_number=313)
    ledger.mark_retired(str(OUT), "crapi-sqli-001")  # cure shipped -> band-aid removed

    # F3) run manifest — so the curated dataset also demonstrates provenance + the evidence export
    runmeta.write_manifest(str(OUT), repo="/src/crapi", config_path="config/agents.yaml",
                           models={a: "anthropic/claude-opus-4-8" for a in AGENT_NAMES},
                           caps={"min_confidence": 0.5, "max_files": 200, "max_bytes": 60000,
                                 "draft_code_fixes": True},
                           counts={"candidates": 9, "verified": 6, "policies": 5, "code_fix_prs": 6})

    # audit trail: the SQLi service policy self-heals (attempt 1 fails, attempt 2 blocks). Every
    # LB-mutating record carries the finding that justified it and the namespace it happened in —
    # the same shape a real run writes, so the Retire step's audit trail is fully populated here.
    ba = {"before": _blocked(200), "after": _blocked(403)}
    audit.record(str(OUT), "refine_apply", finding_id="crapi-sqli-001", namespace=NS,
                 control="service_policy", policy="deny-login-sqli", lb=LB,
                 passed=True, attempts=2, before_after=ba)
    audit.record(str(OUT), "apply_timing", control="service_policy", finding_id="crapi-sqli-001",
                 passed=True, elapsed_s=48.0, attempts=2, before_after=ba)
    audit.record(str(OUT), "create_api_definition", finding_id="crapi-bola-002", namespace=NS,
                 name="crapi-lab-apidef", swagger="crapi-lab-swagger")
    audit.record(str(OUT), "apply_api_schema", finding_id="crapi-bola-002", namespace=NS,
                 apidef="crapi-lab-apidef", lb=LB, passed=True, kept=True, before_after=ba)
    audit.record(str(OUT), "apply_timing", control="api_schema", finding_id="crapi-bola-002",
                 passed=True, elapsed_s=33.0, attempts=1, before_after=ba)
    audit.record(str(OUT), "apply_waf", finding_id="crapi-mass-003", namespace=NS,
                 app_firewall="crapi-lab-waf", lb=LB, config_enabled=True, kept=True, before_after=ba)
    audit.record(str(OUT), "apply_timing", control="waf", finding_id="crapi-mass-003",
                 passed=True, elapsed_s=21.0, attempts=1, before_after=ba)
    audit.record(str(OUT), "apply_rate_limit", finding_id="crapi-bruteforce-004", namespace=NS,
                 rate="5/MINUTE", lb=LB, passed=True, kept=True,
                 behavioral={"sent": 30, "limited": 25, "passed": 5, "codes": {"200": 5, "429": 25}})
    audit.record(str(OUT), "apply_timing", control="rate_limit", finding_id="crapi-bruteforce-004",
                 passed=True, elapsed_s=27.0, attempts=1)
    audit.record(str(OUT), "apply_data_guard", finding_id="crapi-tokenleak-006", namespace=NS,
                 app_firewall="crapi-lab-waf", lb=LB, enabled=True, kept=True)
    audit.record(str(OUT), "apply_timing", control="waf_data_guard", finding_id="crapi-tokenleak-006",
                 passed=True, elapsed_s=19.0, attempts=1)
    audit.record(str(OUT), "open_pr", finding_id="crapi-sqli-001", finding="crapi-sqli-001",
                 repo="acme/crapi", url="https://github.com/acme/crapi/pull/311", number=311)
    audit.record(str(OUT), "retire", finding_id="crapi-sqli-001", namespace=NS,
                 control="service_policy", lb=LB, forced=False)
    _curate_identity()

    # G2) a curated blast-radius result, so the offline demo shows the Simulate step doing its job:
    # the SQLi service policy is surgical — it blocks the attack and nothing a customer does.
    # Only service_policy is replayable (the other six are parameterized by the engine, not matched
    # per request), so one policy is the honest picture for this dataset.
    (OUT / "simulation.json").write_text(json.dumps({
        "ts": runmeta.utc_now(), "lb": LB, "source": f"xc:{LB}",
        "records": 500, "records_replayed": 500,
        "window": "2026-07-20T09:00:00Z..2026-07-20T10:00:00Z",
        "redacted": {"authorization": 500, "cookie": 431, "password": 12},
        "bodies_available": True,
        "policies": [{
            "policy_name": "deny-login-sqli", "control": "service_policy",
            "finding_id": "crapi-sqli-001", "evaluated": 500, "would_block": 3,
            "block_rate": 0.006, "threshold": 0.01, "blocked_promotion": False, "reason": "",
            "errored": 0, "enforcement_confirmed": True,
            "samples": [{"method": "POST", "path": "/identity/api/auth/login", "source": "xc",
                         "json_body": None, "user_agent": "python-requests/2.31",
                         "ts": "2026-07-20T09:14:02Z", "status": 200}],
            "top_paths": [["/identity/api/auth/login", 3]],
            "top_user_agents": [["python-requests/2.31", 2], ["sqlmap/1.7", 1]],
        }],
        "caveats": [
            "A would-block count describes THIS sample only — a quiet window makes any policy look "
            "safe. The window and record count are stated above; read them together with the rate.",
            "Replay runs one policy at a time on a spare LB. Two candidates share FIRST_MATCH "
            "ordering, so a batched result would not describe either band-aid alone.",
        ],
    }, indent=2))

    from vpcopilot.report import write_report
    path = write_report(str(OUT))
    print(f"wrote curated demo out/ -> {OUT}")
    print(f"report -> {path}")
    from vpcopilot.impact import impact
    print("impact:", json.dumps(impact(str(OUT)), indent=2))


if __name__ == "__main__":
    main()
