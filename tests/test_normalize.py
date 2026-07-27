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


# ---- path widening: a named path value must not inherit the catch-all prefix ----
# Verified live on vpcopilot-lab 2026-07-27: XC ORs the path value lists, so a DENY carrying both
# exact_values ["/x"] and the default prefix_values ["/"] denies EVERY path. 12 of the 31 generated
# rules on disk are exact-only and were being widened this way.

def _deny(path, **extra):
    spec = {"rule_list": {"rules": [{"spec": {"action": "DENY", "http_method": {"methods": ["GET"]},
                                              **({"path": path} if path is not None else {}), **extra}}]}}
    return normalize_service_policy_spec(spec)["rule_list"]["rules"][0]["spec"]["path"]


def test_exact_only_path_does_not_gain_the_catchall_prefix():
    p = _deny({"exact_values": ["/users/v1/_debug"]})
    assert p["exact_values"] == ["/users/v1/_debug"]
    assert p["prefix_values"] == []          # the bug injected ["/"] here -> denied every path


def test_regex_only_path_does_not_gain_the_catchall_prefix():
    assert _deny({"regex_values": ["api/v1/x402/.*"]})["prefix_values"] == []


def test_suffix_only_path_does_not_gain_the_catchall_prefix():
    assert _deny({"suffix_values": ["/admin"]})["prefix_values"] == []


# ---- pins on behaviour that must NOT change ----
def test_explicit_prefix_is_preserved_unchanged():
    p = _deny({"prefix_values": ["/api/pay"]})
    assert p["prefix_values"] == ["/api/pay"] and p["exact_values"] == []


def test_prefix_and_exact_together_are_both_kept():
    p = _deny({"prefix_values": ["/api"], "exact_values": ["/health"]})
    assert p["prefix_values"] == ["/api"] and p["exact_values"] == ["/health"]


def test_rule_with_no_path_still_matches_everything():
    """A rule that names no path at all must still get the catch-all — this is what makes the
    trailing allow-all work when a model omits its path."""
    assert _deny(None)["prefix_values"] == ["/"]


def test_empty_path_object_still_matches_everything():
    assert _deny({})["prefix_values"] == ["/"]


def test_structural_subkeys_are_still_filled_on_a_named_path():
    p = _deny({"exact_values": ["/x"]})
    assert p["transformers"] == [] and p["invert_matcher"] is False
    assert set(p) == {"prefix_values", "exact_values", "regex_values", "suffix_values",
                      "transformers", "invert_matcher"}


def test_other_nested_matchers_are_untouched_by_the_path_rule():
    r = normalize_service_policy_spec({"rule_list": {"rules": [{"spec": {
        "action": "DENY", "path": {"exact_values": ["/x"]},
        "http_method": {"methods": ["POST"]},
        "body_matcher": {"regex_values": ["amount[^0-9-]*-[0-9]"]},
    }}]}})["rule_list"]["rules"][0]["spec"]
    assert r["http_method"]["methods"] == ["POST"] and "invert_matcher" in r["http_method"]
    assert r["body_matcher"]["regex_values"] == ["amount[^0-9-]*-[0-9]"]
    assert r["waf_action"] == {"none": {}}            # unrelated required defaults still filled


def test_catchall_allow_rule_is_unaffected():
    """The trailing allow-all `generate` emits uses prefix_values ["/"] explicitly — it must keep
    matching everything, or legit traffic 403s on XC's default-deny."""
    assert _deny({"prefix_values": ["/"]})["prefix_values"] == ["/"]
