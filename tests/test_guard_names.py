"""The protected-name rails, and the parsing in front of them.

Found by adversarial review. `guard_lb` compared the raw string against the protected set, so a
name that is not *literally* `nimbus-www` sailed past it — and then addressed `nimbus-www` anyway,
because the name is interpolated into the request path and the URL is normalized on the way out.
The BIG-IP side has parsed its tenant names since L2 (`bigip_lab.validate_tenant`, and the test
that `../Common` never reaches the appliance); the XC side never got the same treatment.

These tests assert the guard on the *name*, not on the call, because a guard that only holds for
the spelling the author happened to think of is not a guard.
"""
from __future__ import annotations

import httpx
import pytest

from vpcopilot.engine import guard_lb, validate_xc_name

# Every one of these passed the old guard. `./nimbus-www` is the sharp one: httpx resolves the dot
# segment, so the bytes on the wire address the protected LB exactly.
BYPASSES = ["./nimbus-www", "nimbus-www/", " nimbus-www", "nimbus-www ", "../nimbus-www",
            "nimbus-www%2F", "./././nimbus-www", "nimbus-www/.", "\tnimbus-www"]


@pytest.fixture(autouse=True)
def _protect(monkeypatch):
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


@pytest.mark.parametrize("name", BYPASSES)
def test_no_spelling_of_a_protected_lb_reaches_a_mutation(name):
    with pytest.raises(RuntimeError):
        guard_lb(name, allow_protected=False, dry_run=False)


def test_the_dot_segment_bypass_really_did_address_the_protected_lb():
    """Not a hypothetical. This is why a set-membership test on an unparsed name is worthless:
    the two spellings differ to the guard and are identical on the wire."""
    a = httpx.URL("https://h/api/config/namespaces/default/http_loadbalancers/./nimbus-www").path
    b = httpx.URL("https://h/api/config/namespaces/default/http_loadbalancers/nimbus-www").path
    assert a == b, "if these differ the bypass would not have been exploitable"
    assert a.endswith("/nimbus-www")


def test_an_upper_case_spelling_is_refused_too():
    """XC object names are lowercase by construction, so `NIMBUS-WWW` cannot be a *different*
    object — only a way past a guard that compared exactly. The BIG-IP tenant guard has been
    case-insensitive since L2 for the same reason."""
    with pytest.raises(RuntimeError, match="protected"):
        guard_lb("NIMBUS-WWW", allow_protected=False, dry_run=False)


def test_the_guard_still_lets_the_lab_load_balancers_through():
    """The rail must not become a wall — these are the LBs the demo actually mutates."""
    for ok in ("vpcopilot-lab", "crapi-lab", "vampi-lab", "lab_2", "a1"):
        guard_lb(ok, allow_protected=False, dry_run=False)      # must not raise


def test_a_malformed_name_is_refused_rather_than_trimmed():
    """Refusing to guess: `' nimbus-www'` is not silently normalized to `'nimbus-www'`, because the
    trimmed name may not be the object the operator meant. The error says so."""
    with pytest.raises(RuntimeError, match="whitespace"):
        validate_xc_name(" nimbus-www")
    with pytest.raises(RuntimeError, match="required"):
        validate_xc_name("")
    with pytest.raises(RuntimeError, match="required"):
        validate_xc_name(None)          # not a string at all


def test_the_override_still_works_for_a_well_formed_protected_name():
    """Warn-with-audited-override, not a machine veto: an operator who means it can still proceed.
    But only for a name that parses — an override is not a licence to skip the parsing."""
    guard_lb("nimbus-www", allow_protected=True, dry_run=False)     # must not raise
    with pytest.raises(RuntimeError, match="refusing load balancer name"):
        guard_lb("./nimbus-www", allow_protected=True, dry_run=False)


def test_the_service_policy_delete_path_is_guarded_the_same_way():
    """One defect, two call sites. `vpcopilot xc-rm ./nimbus-bizlogic-policy` deleted the protected
    policy: the check was a bare `in` on a string that then went into the DELETE URL."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    for name in ("nimbus-bizlogic-policy", "./nimbus-bizlogic-policy", "NIMBUS-BIZLOGIC-POLICY"):
        res = CliRunner().invoke(cli.app, ["xc-rm", name])
        assert res.exit_code == 1, f"xc-rm {name!r} was not refused: {res.output[:200]}"
        assert "refusing" in res.output


def test_the_policy_create_path_is_guarded_the_same_way():
    """The third call site — apply.py's create/overwrite. Asserted through the module function so
    a surface that calls it cannot disagree about the answer."""
    from vpcopilot.apply import PROTECTED_POLICIES
    assert PROTECTED_POLICIES, "no protected policies configured — this test would be vacuous"
    protected = sorted(PROTECTED_POLICIES)[0]
    with pytest.raises(RuntimeError):
        validate_xc_name(f"./{protected}", "service policy")


def test_crossing_the_protected_rail_leaves_a_trace(tmp_path):
    """Warn-with-audited-override is this project's stated preference over a machine veto — but the
    *audited* half was missing. The resulting apply record was byte-identical to an ordinary LB
    mutation, so the most sensitive action the tool can take left no evidence a rail was crossed.

    Recorded as its own event rather than a field, so a reader scanning the trail cannot miss it."""
    import json
    guard_lb("nimbus-www", allow_protected=True, dry_run=False, out_dir=str(tmp_path))
    log = tmp_path / "audit.log"
    assert log.exists(), "overriding the protected-LB rail wrote no audit entry at all"
    rec = [json.loads(x) for x in log.read_text().splitlines()]
    assert any(r.get("action") == "protected_lb_override" for r in rec), \
        f"no protected_lb_override event: {[r.get('action') for r in rec]}"
    ev = next(r for r in rec if r.get("action") == "protected_lb_override")
    assert ev.get("lb") == "nimbus-www" and ev.get("protected_set"), \
        "the record must name the LB and the set it was protected by, or it proves nothing"


def test_an_ordinary_apply_does_not_get_a_false_override_record(tmp_path):
    """The inverse, and the reason this is a separate event: if every apply wrote one, the record
    would carry no information. Mutating an unprotected LB must leave no override trace."""
    guard_lb("vpcopilot-lab", allow_protected=True, dry_run=False, out_dir=str(tmp_path))
    log = tmp_path / "audit.log"
    if log.exists():
        import json
        assert not [r for r in (json.loads(x) for x in log.read_text().splitlines())
                    if r.get("action") == "protected_lb_override"], \
            "an unprotected LB produced an override record"


def test_the_console_cannot_skip_the_cure_pr_gate():
    """Surface parity. The console hardcoded `force:true` on every retire, so the "is the cure PR
    actually merged?" gate that the CLI and MCP enforce could not be enforced from the GUI at all —
    the band-aid is the only thing blocking the vulnerability until the fix ships.

    Asserted on the request the page sends, because that is where the bypass lived."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/console/static/index.html").read_text()
    body = re.search(r'jpost\("/api/retire",\s*\{([^}]*)\}', src)
    assert body, "the console no longer posts to /api/retire — update this test"
    assert "force:false" in body.group(1).replace(" ", ""), \
        f"the console still pre-authorises the retire gate: {body.group(1)}"
    # The override must still EXIST — removing the capability is not the fix.
    assert "retireAnyway" in src, "no explicit override path; a veto is not the pattern here"
    assert "WITHOUT a merged cure PR" in src, "the override must say what it is skipping"


def test_retire_refuses_a_protected_lb_by_every_spelling(tmp_path, monkeypatch):
    """retire.py carried a THIRD copy of the protected-LB check with the same bypass. It now
    delegates to the shared guard, so there is one answer rather than three."""
    import json

    from vpcopilot import retire
    for spelling in ("nimbus-www", "./nimbus-www", "NIMBUS-WWW"):
        led = {"f1": {"state": "remediated", "mitigation": {"lb": spelling, "control": "waf"},
                      "cure": {"pr_url": ""}}}
        (tmp_path / "ledger.json").write_text(json.dumps(led))
        with pytest.raises(RuntimeError):
            retire.retire_finding(str(tmp_path), "f1", force=True, allow_protected=False)
