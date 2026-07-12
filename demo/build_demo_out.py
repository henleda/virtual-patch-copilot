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

from vpcopilot import audit, ledger  # noqa: E402

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


def main():
    # Start from a clean slate so the dataset is deterministic — audit.record and the ledger APPEND,
    # so regenerating over an existing out/ would otherwise inflate the action log on every run.
    import shutil
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "policies").mkdir(exist_ok=True)
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

    # audit trail: the SQLi service policy self-heals (attempt 1 fails, attempt 2 blocks)
    audit.record(str(OUT), "refine_apply", control="service_policy", policy="deny-login-sqli", lb=LB,
                 passed=True, attempts=2, before_after={"before": _blocked(200), "after": _blocked(403)})
    audit.record(str(OUT), "apply_timing", control="service_policy", finding_id="crapi-sqli-001", passed=True, elapsed_s=48.0, attempts=2)
    audit.record(str(OUT), "apply_api_schema", apidef="crapi-lab-apidef", lb=LB, passed=True,
                 before_after={"before": _blocked(200), "after": _blocked(403)})
    audit.record(str(OUT), "apply_timing", control="api_schema", finding_id="crapi-bola-002", passed=True, elapsed_s=33.0)
    audit.record(str(OUT), "apply_waf", app_firewall="crapi-lab-waf", lb=LB, passed=True,
                 before_after={"before": _blocked(200), "after": _blocked(403)})
    audit.record(str(OUT), "apply_timing", control="waf", finding_id="crapi-mass-003", passed=True, elapsed_s=21.0)
    audit.record(str(OUT), "apply_rate_limit", rate="5/MINUTE", lb=LB, passed=True,
                 behavioral={"sent": 30, "limited": 25, "passed": 5, "codes": {"200": 5, "429": 25}})
    audit.record(str(OUT), "apply_timing", control="rate_limit", finding_id="crapi-bruteforce-004", passed=True, elapsed_s=27.0)
    audit.record(str(OUT), "apply_data_guard", lb=LB, config_enabled=True)
    audit.record(str(OUT), "apply_timing", control="waf_data_guard", finding_id="crapi-tokenleak-006", passed=True, elapsed_s=19.0)
    audit.record(str(OUT), "retire", finding_id="crapi-sqli-001", control="service_policy", lb=LB, forced=False)

    from vpcopilot.report import write_report
    path = write_report(str(OUT))
    print(f"wrote curated demo out/ -> {OUT}")
    print(f"report -> {path}")
    from vpcopilot.impact import impact
    print("impact:", json.dumps(impact(str(OUT)), indent=2))


if __name__ == "__main__":
    main()
