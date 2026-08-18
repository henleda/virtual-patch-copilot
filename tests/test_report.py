import json
import re
from pathlib import Path

from vpcopilot import report


def _seed(out: Path):
    (out / "summary.json").write_text(json.dumps({
        "candidates": 2, "verified": 2, "policies": ["waf/waf-block-sqli", "service_policy/deny-x"],
        "no_bandaid": ["b-002"], "code_fix_prs": ["a-001", "b-002"], "out_dir": str(out)}))
    (out / "findings.json").write_text(json.dumps([
        {"id": "a-001", "title": "SQLi login", "vuln_class": "sqli", "severity": "critical",
         "file": "api/login.js", "line": 10, "description": "d", "exploit_sketch": "e",
         "code_snippet": "q = 'SELECT * ' + x  // <script>alert(1)</script>"},
        {"id": "b-002", "title": "Info leak", "vuln_class": "sensitive_data", "severity": "low",
         "file": "api/me.js", "line": 0, "description": "d2", "exploit_sketch": "", "code_snippet": ""},
    ]))
    (out / "triage.json").write_text(json.dumps([
        {"finding_id": "a-001", "bandaids": [{"control": "waf", "coverage": "full", "recommended": True,
         "rationale": "r"}], "no_bandaid": False, "residual_risk": "none", "code_cure_required": True},
        {"finding_id": "b-002", "bandaids": [], "no_bandaid": True, "residual_risk": "",
         "code_cure_required": True},
    ]))
    (out / "remediations.json").write_text(json.dumps([
        # `patched_content` is non-empty on purpose: a code_fix with no patch is nothing for
        # `pr.py` to write to a branch, and the report now says so rather than claiming a fix was
        # drafted. An empty stub here made this fixture assert the badge for a plan that had no
        # patch at all.
        {"finding_id": "a-001", "summary": "s", "file": "api/login.js",
         "diff": "--- a/api/login.js\n+++ b/api/login.js\n", "kind": "code_fix",
         "patched_content": "const q = db.prepare('SELECT * FROM users WHERE email = ?');",
         "pr_title": "Fix SQLi in login", "pr_body": "b"}]))


def test_report_renders_and_is_selfcontained(tmp_path):
    _seed(tmp_path)
    html = report.build_report(str(tmp_path))
    assert "SQLi login" in html and "a-001" in html
    assert "no band-aid" in html          # b-002 shown as code-cure-only
    assert "code fix drafted" in html     # a-001 has a remediation
    # no EXTERNAL resource-loading tags => truly shareable (inline data: URIs, e.g. the F5 logo, are fine)
    assert not re.findall(r'<(?:script[^>]*\ssrc|link[^>]*\shref|img[^>]*\ssrc)\s*=\s*["\'](?!data:)', html, re.I)


def test_report_escapes_model_content(tmp_path):
    _seed(tmp_path)
    html = report.build_report(str(tmp_path))
    # the code_snippet's <script> must be escaped, never emitted as a live tag
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_write_report_handles_empty(tmp_path):
    (tmp_path / "summary.json").write_text("{}")
    (tmp_path / "findings.json").write_text("[]")
    p = report.write_report(str(tmp_path))
    assert Path(p).exists() and "<html" in Path(p).read_text()


def test_normalize_unifies_probe_keys():
    from vpcopilot import probe
    assert probe.normalize({"neg_status": 200, "neg_blocked": False, "legit_ok": True}) == \
        {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True}
    assert probe.normalize({"sqli_status": 403, "sqli_blocked": True, "legit_ok": True})["exploit_blocked"] is True
    assert probe.normalize(None)["exploit_status"] is None


def test_report_impact_panel(tmp_path):
    _seed(tmp_path)
    (tmp_path / "audit.log").write_text(json.dumps({
        "ts": "2026-07-05T00:00:00Z", "action": "apply_waf", "app_firewall": "vpcopilot-lab-waf",
        "passed": True, "rolled_back": True,
        "before_after": {"before": {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True},
                         "after": {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True}}}) + "\n")
    html = report.build_report(str(tmp_path))
    assert "Band-aid impact" in html
    assert "200 allowed" in html and "200 blocked" in html
    assert "PASS" in html


def test_report_metrics_panel(tmp_path):
    _seed(tmp_path)
    (tmp_path / "metrics.json").write_text(json.dumps({
        "timing_s": {"discover": 3.1, "verify": 2.4, "synthesize": 5.0, "total": 10.5},
        "verify": {"candidates": 10, "verified": 8, "refuted": 1, "dropped_low_confidence": 1,
                   "confirm_rate": 0.8, "avg_confidence": 0.83, "min_confidence": 0.5},
        "synthesize": {"policies": 6, "dupe_bandaids_collapsed": 2, "code_fix_prs": 8}}))
    html = report.build_report(str(tmp_path))
    assert "Pipeline metrics" in html
    assert "10.5s" in html and "80%" in html                 # total time + confirm-rate
    assert "10 candidates → 8 verified" in html


def test_report_impact_panel_behavioral(tmp_path):
    _seed(tmp_path)
    (tmp_path / "audit.log").write_text(json.dumps({
        "ts": "2026-07-05T00:00:00Z", "action": "apply_rate_limit", "rate": "10/MINUTE",
        "passed": True, "rolled_back": True,
        "behavioral": {"sent": 30, "limited": 20, "passed": 10, "codes": {"200": 10, "429": 20}}}) + "\n")
    html = report.build_report(str(tmp_path))
    assert "Band-aid impact" in html
    assert "rate_limit" in html and "20/30 rate-limited (429)" in html


# ---- BIG-IP Advanced-WAF surface + the before_after shape the report reads ----

def _seed_bigip(out, policies, probes=None):
    _seed(out)
    (out / "policies.json").write_text(json.dumps(policies))
    (out / "probes.json").write_text(json.dumps(probes or []))


def test_bigip_section_names_the_shipped_form_for_an_emittable_finding(tmp_path):
    # waf_data_guard needs no probe — it emits a response-masking form outright
    _seed_bigip(tmp_path, [{"finding_id": "a-001", "control": "waf_data_guard", "policy_name": "mask-pii"}])
    html = report.build_report(str(tmp_path))
    assert "BIG-IP Advanced WAF" in html
    assert "response-masking" in html and "form emitted" in html
    # the footnote names all three shipped forms even though this run exercised one
    assert "value-constraint" in html and "API-contract" in html


def test_bigip_section_splits_no_form_from_no_data_declines(tmp_path):
    # rate_limit: BIG-IP has no Advanced-WAF object for it at all (structural, XC-only).
    # service_policy with an empty probe: the FORM exists, this finding just lacks the recorded pair.
    _seed_bigip(tmp_path, [
        {"finding_id": "a-001", "control": "rate_limit", "policy_name": "rl"},
        {"finding_id": "b-002", "control": "service_policy", "policy_name": "deny-x"}],
        probes=[{"finding_id": "b-002"}])          # present, but carries no exploit/legit pair
    html = report.build_report(str(tmp_path))
    assert "No Advanced-WAF form on BIG-IP" in html
    assert "An Advanced-WAF form exists, but this finding lacked" in html
    # the structural gap (rate_limit) and the data gap (service_policy) are never swapped
    no_form = html.split("No Advanced-WAF form on BIG-IP")[1].split("An Advanced-WAF form exists")[0]
    assert "rate_limit" in no_form and "service_policy" not in no_form


def test_the_nginx_section_renders_from_the_same_generalized_helper(tmp_path):
    """The report shows BOTH bring-your-own surfaces from one code path — a waf_data_guard band-aid
    emits a response-masking form for the nginx-app-protect target too."""
    _seed_bigip(tmp_path, [{"finding_id": "a-001", "control": "waf_data_guard", "policy_name": "mask-pii"}])
    html = report.build_report(str(tmp_path))
    assert "F5 WAF for NGINX (App Protect)" in html      # the NGINX section title
    assert "App Protect form" in html                    # the generalized form_label in the NGINX table
    assert html.count("response-masking") >= 2           # rendered for BIG-IP AND NGINX


def test_report_does_not_crash_on_a_bigip_apply_record_and_labels_it(tmp_path):
    """The regression: a BIG-IP apply records before_after as a dict now (bigip_apply.py), so the
    report's `ba.get('before')` renders the row — labelled as a BIG-IP apply, not a raw action string."""
    from vpcopilot import audit
    _seed(tmp_path)
    audit.record(str(tmp_path), "apply_bigip_awaf", finding_id="a-001", tenant="t", app="lab",
                 policy_name="deny-x", passed=True, kept=True, rolled_back=False,
                 before_after={"before": {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True},
                               "after": {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}})
    html = report.build_report(str(tmp_path))
    assert "Band-aid impact" in html
    assert "BIG-IP Advanced WAF" in html and "deny-x" in html
    assert "200 allowed" in html and "403 blocked" in html


def test_report_tolerates_a_legacy_list_shaped_before_after(tmp_path):
    """Audit logs written before the shape fix carry `before_after` as a [before, after] list.
    Building a report over one must not raise `list.get` — it is normalized on read."""
    _seed(tmp_path)
    (tmp_path / "audit.log").write_text(json.dumps({
        "ts": "2026-08-18T00:00:00Z", "action": "apply_bigip_awaf", "policy_name": "deny-x",
        "passed": True,
        "before_after": [{"exploit_status": 200, "exploit_blocked": False, "legit_ok": True},
                         {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}]}) + "\n")
    html = report.build_report(str(tmp_path))          # must not raise
    assert "200 allowed" in html and "403 blocked" in html


# ---- C5: hero + self-heal + model-independence + bars ----

def test_report_c5_hero_and_selfheal(tmp_path):
    from vpcopilot import audit, ledger
    _seed(tmp_path)  # verified=2, so the hero renders
    ledger.save(str(tmp_path), {"a-001": {"finding_id": "a-001", "state": "mitigated", "severity": "critical",
                                          "title": "SQLi", "mitigation": {"control": "waf", "lb": "crapi-lab"}}})
    audit.record(str(tmp_path), "refine_apply", control="service_policy", policy="deny-x", passed=True, attempts=3,
                 before_after={"before": {"exploit_status": 200, "exploit_blocked": False, "legit_ok": True},
                               "after": {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}})
    audit.record(str(tmp_path), "apply_timing", control="waf", passed=True, elapsed_s=40.0)
    html = report.build_report(str(tmp_path))
    assert 'class="hero"' in html and "normal change control" in html
    assert "self-healed ×3" in html              # the refine loop's retry is visible
    assert "At a glance" in html                 # severity + control bars
    assert "Model independence" in html          # per-agent model chips
    assert "target: crapi-lab" in html           # humanized header from the live LB


def test_report_no_hero_without_vulns(tmp_path):
    (tmp_path / "summary.json").write_text(json.dumps({"candidates": 0, "verified": 0}))
    (tmp_path / "findings.json").write_text("[]")
    html = report.build_report(str(tmp_path))
    assert 'class="hero"' not in html  # nothing to headline
