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


def test_list_matcher_object_coerced_to_list():
    # A weaker model emits query_params/headers as a single OBJECT; XC wants a list, else it 400s
    # "cannot unmarshal object into []json.RawMessage". Coerce the object into a one-element list.
    spec = {"rule_list": {"rules": [{"spec": {
        "action": "DENY",
        "query_params": {"item": {"regex_values": ["vuln=true"]}},
        "headers": {"name": "X-Debug", "item": {"exact_values": ["1"]}},
    }}]}}
    r = normalize_service_policy_spec(spec)["rule_list"]["rules"][0]["spec"]
    assert r["query_params"] == [{"item": {"regex_values": ["vuln=true"]}}]
    assert isinstance(r["headers"], list) and len(r["headers"]) == 1
    # an empty object collapses to [] (a valid empty list), not [{}]
    empty = {"rule_list": {"rules": [{"spec": {"action": "DENY", "query_params": {}}}]}}
    assert normalize_service_policy_spec(empty)["rule_list"]["rules"][0]["spec"]["query_params"] == []
