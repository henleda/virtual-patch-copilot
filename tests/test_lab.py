from vpcopilot.lab import _clean_slate, _origin_server


def test_origin_server_ip_vs_dns():
    assert _origin_server("16.59.6.127") == {"public_ip": {"ip": "16.59.6.127"}, "labels": {}}
    assert _origin_server("app.example.com") == {"public_name": {"dns_name": "app.example.com"}, "labels": {}}


def test_clean_slate_disables_all_controls_and_strips_status():
    spec = {"app_firewall": {"x": 1}, "active_service_policies": {"p": []}, "bot_defense": {},
            "rate_limit": {}, "enable_malicious_user_detection": {}, "api_specification": {},
            "api_definition": {}, "data_guard_rules": [{"r": 1}], "host_name": "z", "cert_state": "x",
            "more_option": {"request_headers_to_add": [{"name": "X-Nimbus-Origin"}]}}
    _clean_slate(spec)
    for on, off in [("app_firewall", "disable_waf"), ("bot_defense", "disable_bot_defense"),
                    ("rate_limit", "disable_rate_limit"),
                    ("enable_malicious_user_detection", "disable_malicious_user_detection")]:
        assert on not in spec and spec[off] == {}
    assert "active_service_policies" not in spec and spec["no_service_policies"] == {}
    assert spec["disable_api_definition"] == {} and "api_specification" not in spec
    assert spec["data_guard_rules"] == []
    assert "host_name" not in spec and "cert_state" not in spec
    assert not spec["more_option"].get("request_headers_to_add")
