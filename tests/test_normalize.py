"""normalize_service_policy_spec fills the XC-required fields a minimal generated spec omits."""
from vpcopilot.apply import normalize_service_policy_spec


def test_fills_required_and_preserves_generated():
    minimal = {"rule_list": {"rules": [{"metadata": {"name": "deny"}, "spec": {
        "action": "DENY",
        "path": {"prefix_values": ["/api/pay"]},
        "http_method": {"methods": ["POST"]},
        "body_matcher": {"regex_values": ["amount[^0-9-]*-[0-9]"]},
    }}]}}
    out = normalize_service_policy_spec(minimal)
    assert out["algo"] == "FIRST_MATCH" and out["any_server"] == {}
    r = out["rule_list"]["rules"][0]["spec"]
    assert r["waf_action"] == {"none": {}}                       # required field filled
    assert r["path"]["prefix_values"] == ["/api/pay"]            # generated value kept
    assert r["http_method"]["methods"] == ["POST"]              # nested-merged
    assert "invert_matcher" in r["http_method"]                 # default sub-key added
    assert r["body_matcher"]["regex_values"] == ["amount[^0-9-]*-[0-9]"]


def test_bare_spec_rules_autonamed():
    out = normalize_service_policy_spec({"rule_list": {"rules": [{"spec": {"action": "ALLOW"}}]}})
    assert out["rule_list"]["rules"][0]["metadata"]["name"]
