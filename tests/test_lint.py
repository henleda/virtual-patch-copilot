from vpcopilot.apply import lint_api_schema, lint_generated_spec, lint_service_policy

EXPLOIT = {"method": "POST", "path": "/users/v1/register"}


def _policy(rules):
    return {"rule_list": {"rules": [{"spec": r} for r in rules]}}


def test_lint_good_policy_clean():
    good = _policy([
        {"action": "DENY", "path": {"prefix_values": ["/users/v1/register"]}, "http_method": {"methods": ["POST"]}},
        {"action": "ALLOW", "path": {"prefix_values": ["/"]}}])
    assert lint_service_policy(good, EXPLOIT) == []


def test_lint_catches_allow_before_deny():
    # the crAPI lockUser bug: an ALLOW of the exploit path precedes the DENY (FIRST_MATCH self-defeat)
    bad = _policy([
        {"action": "ALLOW", "path": {"prefix_values": ["/users/v1/register"]}, "http_method": {"methods": ["POST"]}},
        {"action": "DENY", "path": {"prefix_values": ["/users/v1/register"]}, "http_method": {"methods": ["POST"]}},
        {"action": "ALLOW", "path": {"prefix_values": ["/"]}}])
    assert lint_service_policy(bad, EXPLOIT)  # non-empty -> caught


def test_lint_catches_path_mismatch():
    # the VAmPI bug: DENY /users/register but the real exploit is /users/v1/register -> allow-all wins
    bad = _policy([
        {"action": "DENY", "path": {"prefix_values": ["/users/register"]}, "http_method": {"methods": ["POST"]}},
        {"action": "ALLOW", "path": {"prefix_values": ["/"]}}])
    assert lint_service_policy(bad, EXPLOIT)


def test_lint_no_deny():
    assert lint_service_policy(_policy([{"action": "ALLOW", "path": {"prefix_values": ["/"]}}]), EXPLOIT) == ["no DENY rule"]


def test_lint_no_exploit_only_checks_deny_presence():
    good = _policy([{"action": "DENY", "path": {"prefix_values": ["/x"]}}, {"action": "ALLOW", "path": {"prefix_values": ["/"]}}])
    assert lint_service_policy(good, None) == []


# --- A9: api_schema (consumed verbatim by XC) -------------------------------

def test_lint_api_schema_complete_ok():
    good = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "paths": {"/api/pay": {"post": {"responses": {"200": {"description": "ok"}}}}}}
    assert lint_api_schema(good) == []


def test_lint_api_schema_rejects_bare_fragment():
    # a paths-only fragment is what XC put_swagger rejects on upload
    assert lint_api_schema({"paths": {"/api/pay": {}}})  # missing openapi/swagger version
    assert lint_api_schema({"openapi": "3.0.0"})          # no paths to enforce


def test_lint_generated_spec_dispatches_by_control():
    sp = _policy([{"action": "DENY", "path": {"prefix_values": ["/users/v1/register"]}, "http_method": {"methods": ["POST"]}},
                  {"action": "ALLOW", "path": {"prefix_values": ["/"]}}])
    assert lint_generated_spec("service_policy", sp, EXPLOIT) == []
    assert lint_generated_spec("api_schema", {"paths": {}}, None)     # caught
    assert lint_generated_spec("rate_limit", {"anything": 1}, None) == []  # parameterized -> advisory
