"""Finding-correlation (B1) unit tests — pure, no API."""
from vpcopilot.correlate import coverage_key, endpoint_of


def test_lb_wide_controls_share_one_instance():
    # two WAF findings in different files are covered by a single LB-wide WAF
    assert coverage_key("waf", "login/route.js") == coverage_key("waf", "statements/route.js") == "waf"
    assert coverage_key("malicious_user", "a/x.js") == coverage_key("malicious_user", "b/y.js")


def test_service_policy_is_per_endpoint():
    assert coverage_key("service_policy", "pay/route.js") == "service_policy:pay"
    assert coverage_key("service_policy", "pay/route.js") != coverage_key("service_policy", "login/route.js")


def test_endpoint_of():
    assert endpoint_of("app/src/app/api/pay/route.js") == "pay"
    assert endpoint_of("pay/route.js") == "pay"
