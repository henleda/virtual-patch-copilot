from vpcopilot.apply import lint_service_policy

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
