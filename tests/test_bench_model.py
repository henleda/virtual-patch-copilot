"""Cross-model benchmark harness: findings + policies + LIVE policy quality (from apply_timing),
model-tagged, and comparable across runs."""
import json

from vpcopilot import audit, bench_model, ledger  # noqa: F401


def _seed(out):
    (out / "summary.json").write_text(json.dumps({
        "candidates": 4, "verified": 3, "out_dir": str(out), "code_fix_prs": ["a", "b", "c"]}))
    (out / "findings.json").write_text(json.dumps([
        {"id": "a", "vuln_class": "sqli", "severity": "critical"},
        {"id": "b", "vuln_class": "broken_object_authz", "severity": "high"},
        {"id": "c", "vuln_class": "rate_abuse", "severity": "medium"},
        {"id": "d", "vuln_class": "xss", "severity": "low"}]))  # d = candidate, not verified
    (out / "triage.json").write_text(json.dumps([
        {"finding_id": "a", "no_bandaid": False, "bandaids": [{"control": "service_policy", "recommended": True}]},
        {"finding_id": "b", "no_bandaid": False, "bandaids": [{"control": "api_schema", "recommended": True}]},
        {"finding_id": "c", "no_bandaid": True, "bandaids": []}]))
    (out / "policies.json").write_text(json.dumps([
        {"finding_id": "a", "control": "service_policy", "policy_name": "deny-a"},
        {"finding_id": "b", "control": "api_schema", "policy_name": "schema-b"}]))
    (out / "metrics.json").write_text(json.dumps({
        "timing_s": {"total": 12.3}, "verify": {"confirm_rate": 0.75, "avg_confidence": 0.88}}))
    # live results, as the console writes them on Mitigate
    audit.record(str(out), "apply_timing", control="service_policy", finding_id="a", passed=True, attempts=2,
                 before_after={"before": {"exploit_status": 200}, "after": {"exploit_status": 403}})
    audit.record(str(out), "apply_timing", control="api_schema", finding_id="b", passed=False, attempts=3,
                 before_after={"before": {"exploit_status": 200}, "after": {"exploit_status": 200}}, unfixable=True)
    # a behavioral control (rate_limit) that passed at config level but shows no single-request block
    audit.record(str(out), "apply_timing", control="rate_limit", finding_id="c", passed=True, attempts=1)


def test_build_captures_findings_policies_and_live_quality(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_CONFIG", "config/agents.yaml")
    _seed(tmp_path)
    b = bench_model.build(str(tmp_path), "claude", target="../crapi")
    assert b["model_tag"] == "claude" and b["target"] == "../crapi"
    assert b["scan"]["verified"] == 3 and b["scan"]["by_severity"]["critical"] == 1
    assert b["policies"]["by_control"] == {"service_policy": 1, "api_schema": 1}
    assert b["policies"]["no_bandaid"] == ["c"]
    pq = b["policy_quality"]
    assert pq["attempted"] == 3 and pq["passed"] == 2 and pq["failed"] == 1
    assert pq["blocked"] == 1 and pq["applied_behavioral"] == 1  # a=real block, c=behavioral
    assert pq["self_healed"] == 1  # 'a' passed on attempt 2
    a = next(p for p in pq["per_finding"] if p["finding_id"] == "a")
    assert a["outcome"] == "blocked" and a["after_status"] == 403
    c = next(p for p in pq["per_finding"] if p["finding_id"] == "c")
    assert c["outcome"] == "applied"  # rate_limit passed but no single-request 403
    bfnd = next(p for p in pq["per_finding"] if p["finding_id"] == "b")
    assert bfnd["passed"] is False and bfnd["unfixable"] is True and bfnd["outcome"] == "unfixable"


def test_last_apply_timing_wins(tmp_path):
    _seed(tmp_path)
    audit.record(str(tmp_path), "apply_timing", control="service_policy", finding_id="a", passed=False, attempts=1)
    b = bench_model.build(str(tmp_path), "x")
    a = next(p for p in b["policy_quality"]["per_finding"] if p["finding_id"] == "a")
    assert a["passed"] is False  # the re-click superseded the earlier pass


def test_404_and_401_baselines_flagged(tmp_path):
    # A band-aid whose baseline exploit 404'd (endpoint doesn't exist) or 401'd (needs auth) can't be
    # validated — score it distinctly, not as a failure (even a 401→403 "block" is unvalidatable).
    (tmp_path / "findings.json").write_text(json.dumps([
        {"id": "miss", "vuln_class": "broken_object_authz", "severity": "high"},
        {"id": "auth", "vuln_class": "broken_object_authz", "severity": "high"}]))
    (tmp_path / "triage.json").write_text(json.dumps([{"finding_id": "miss"}, {"finding_id": "auth"}]))
    (tmp_path / "policies.json").write_text(json.dumps([
        {"finding_id": "miss", "control": "service_policy", "policy_name": "m"},
        {"finding_id": "auth", "control": "service_policy", "policy_name": "a"}]))
    audit.record(str(tmp_path), "apply_timing", control="service_policy", finding_id="miss", passed=False,
                 before_after={"before": {"exploit_status": 404}, "after": {"exploit_status": 404}})
    audit.record(str(tmp_path), "apply_timing", control="service_policy", finding_id="auth", passed=True,
                 before_after={"before": {"exploit_status": 401}, "after": {"exploit_status": 403}})
    pq = bench_model.build(str(tmp_path), "x")["policy_quality"]
    assert pq["endpoint_missing"] == 1 and pq["auth_required"] == 1
    assert pq["failed"] == 0  # neither is a genuine band-aid failure
    outc = {p["finding_id"]: p["outcome"] for p in pq["per_finding"]}
    assert outc["miss"] == "endpoint_missing" and outc["auth"] == "auth_required"


def test_markdown_and_write(tmp_path):
    _seed(tmp_path)
    bench_model.write(str(tmp_path), "claude", target="../crapi", dest_dir=str(tmp_path / "bench"))
    md = (tmp_path / "bench" / "benchmark-claude.md").read_text()
    assert "# Benchmark — claude" in md and "Policy quality (live)" in md
    assert "200→403" in md and "✅ blocked" in md and "⚠️ unfixable" in md
    assert (tmp_path / "bench" / "benchmark-claude.json").exists()


def test_compare_side_by_side(tmp_path):
    _seed(tmp_path)
    bench_model.write(str(tmp_path), "claude", dest_dir=str(tmp_path / "bench"))
    # a second, weaker run
    (tmp_path / "summary.json").write_text(json.dumps({"candidates": 4, "verified": 2, "code_fix_prs": ["a"]}))
    bench_model.write(str(tmp_path), "openai", dest_dir=str(tmp_path / "bench"))
    md = bench_model.compare([str(tmp_path / "bench" / "benchmark-claude.json"),
                              str(tmp_path / "bench" / "benchmark-openai.json")])
    assert "| metric | claude | openai |" in md
    assert "block rate" in md and "verified" in md
