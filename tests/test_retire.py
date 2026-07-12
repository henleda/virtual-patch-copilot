from vpcopilot import ledger
from vpcopilot.retire import _detach_control, _pr_ref, retire_finding


def test_mark_retired_advances(tmp_path):
    out = str(tmp_path)
    ledger.mark_mitigated(out, "f-1", control="rate_limit", policy_name="10/MINUTE", lb="lab")
    ledger.mark_retired(out, "f-1")
    assert ledger.load(out)["f-1"]["state"] == "retired"


def test_mark_retired_is_forward_only(tmp_path):
    out = str(tmp_path)
    ledger.mark_mitigated(out, "f-1", control="waf", policy_name="w", lb="lab")
    ledger.mark_retired(out, "f-1")
    ledger.mark_mitigated(out, "f-1", control="waf", policy_name="w", lb="lab")  # can't go backwards
    assert ledger.load(out)["f-1"]["state"] == "retired"


def test_pr_ref_parses_url():
    assert _pr_ref("https://github.com/octocat/hello-world/pull/7") == ("octocat/hello-world", 7)
    assert _pr_ref("not a url") == (None, None)


def test_detach_control_shapes():
    for control, on_key, off_key in [
        ("waf", "app_firewall", "disable_waf"),
        ("rate_limit", "rate_limit", "disable_rate_limit"),
        ("bot_defense", "bot_defense", "disable_bot_defense"),
        ("malicious_user", "enable_malicious_user_detection", "disable_malicious_user_detection"),
        ("api_schema", "api_specification", "disable_api_definition"),
    ]:
        spec = {on_key: {"x": 1}}
        _detach_control(spec, control)
        assert on_key not in spec and off_key in spec
    spec = {"active_service_policies": {"policies": []}}
    _detach_control(spec, "service_policy")
    assert "active_service_policies" not in spec and spec["no_service_policies"] == {}


def test_retire_finding_guards(tmp_path):
    out = str(tmp_path)
    assert retire_finding(out, "missing")["status"] == "no ledger entry"
    ledger.mark_mitigated(out, "f-1", control="rate_limit", policy_name="10/MINUTE", lb="lab")
    assert "skipped" in retire_finding(out, "f-1", force=False)["status"]  # only mitigated, no merged PR
    r = retire_finding(out, "f-1", force=True, dry_run=True)               # force + dry-run: no XC call
    assert r["status"] == "would retire" and r["control"] == "rate_limit"
