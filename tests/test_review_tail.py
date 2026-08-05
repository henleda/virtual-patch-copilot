"""The last of the 2026-08-04 review findings: honesty of reporting, and one surface-parity gap.

Common thread: a value that means "we could not measure this" rendered as a measurement, or a
lookup that three surfaces remembered to do and the fourth did not.
"""
from __future__ import annotations

import json
import re

import pytest


# ---------------------------------------------------------------- the cure badge


def _card(rem, **finding):
    from vpcopilot.report import _finding_card
    f = {"id": "x", "title": "t", "severity": "critical", "vuln_class": "other",
         "description": "d", **finding}
    html = _finding_card(f, {"no_bandaid": True, "bandaids": []}, rem)
    m = re.search(r'<span class="cure[^"]*">([^<]*)</span>', html)
    return m.group(1) if m else ""


def test_a_dependency_upgrade_is_not_reported_as_a_drafted_code_fix():
    """The badge keyed on the mere PRESENCE of a remediation, so a `dependency_upgrade` claimed
    "✓ code fix drafted" while the hero on the SAME page correctly reported 0 code-fix PRs and 1
    upgrade to ship. There is no file to patch in someone else's package and `pr.py` writes no
    diff for one — the card was describing work that does not exist."""
    got = _card({"kind": "dependency_upgrade", "package": "log4j-core", "fixed_version": "2.17.1"})
    assert "code fix drafted" not in got
    assert "dependency upgrade" in got and "log4j-core" in got and "2.17.1" in got, \
        "the upgrade must name the package and version — that is the actionable part"


def test_a_real_code_fix_still_says_so():
    assert "code fix drafted" in _card({"kind": "code_fix", "patched_content": "x = 1"})


def test_a_plan_with_no_patch_does_not_claim_a_patch():
    """Third outcome. A RemediationPlan with neither a diff nor patched_content is a plan, not a
    drafted fix — `pr.py` has nothing to write to a branch. Saying so beats a tick that is untrue."""
    got = _card({"kind": "code_fix", "patched_content": "", "diff": ""})
    assert "code fix drafted" not in got and "no patch drafted" in got


# ---------------------------------------------------------------- blast radius


def _blast(tmp_path, policy):
    from vpcopilot.report import _blast_radius_html
    (tmp_path / "simulation.json").write_text(json.dumps(
        {"lb": "lab", "records": 12, "records_replayed": 12, "policies": [policy]}))
    return _blast_radius_html(str(tmp_path))


def test_a_replay_where_everything_failed_is_not_reported_within_threshold(tmp_path):
    """`simulate` computes `evaluated`, `errored`, `enforcement_confirmed` and `reason`; the table
    used none of them. A replay in which every request failed in transit (evaluated=0, errored=12,
    reason="nothing measurable") rendered as a green "within threshold" at 0.0% — a block rate that
    means "we measured nothing", presented as "safe to promote"."""
    html = _blast(tmp_path, {"policy_name": "p", "evaluated": 0, "errored": 12, "would_block": 0,
                             "block_rate": 0, "enforcement_confirmed": False,
                             "reason": "nothing measurable"})
    assert "within threshold" not in html, "an unmeasured replay was reported as measured and safe"
    assert "not measured" in html
    assert "0.0%" not in html, "a rate computed from zero samples must not be shown as a rate"
    assert "nothing measurable" in html and "failed in transit" in html, \
        "the caveats the simulation computed must reach the page"


def test_a_healthy_replay_still_reads_within_threshold(tmp_path):
    """The fix must not paint every row amber — a real measurement still reports as one."""
    html = _blast(tmp_path, {"policy_name": "p", "evaluated": 100, "errored": 0, "would_block": 2,
                             "block_rate": 0.02, "enforcement_confirmed": True})
    assert "within threshold" in html and "2.0%" in html


def test_an_unconfirmed_enforcement_is_its_own_verdict(tmp_path):
    """Measured, but the policy was not confirmed to be enforcing during the replay — which is
    neither "safe" nor "over threshold"."""
    html = _blast(tmp_path, {"policy_name": "p", "evaluated": 100, "errored": 0, "would_block": 0,
                             "block_rate": 0.0, "enforcement_confirmed": False})
    assert "unconfirmed" in html and "within threshold" not in html


# ---------------------------------------------------------------- reconcile


def test_a_probe_that_blew_up_in_transport_is_not_reported_as_no_probe(monkeypatch, tmp_path):
    """"This finding has no runnable probe" is a PERMANENT condition an operator can only fix by
    re-scanning. A probe that exists and failed in transport is TRANSIENT — the origin was
    unreachable, TLS failed, the connection dropped — and will very likely work next pass.
    Reporting the second as the first sends someone to fix the wrong thing."""
    import httpx

    from vpcopilot import reconcile
    monkeypatch.setattr(reconcile, "_load_probe",
                        lambda out, fid: {"exploit": {"path": "/x", "method": "POST"}},
                        raising=False)
    monkeypatch.setattr("vpcopilot.apply._load_probe",
                        lambda out, fid: {"exploit": {"path": "/x", "method": "POST"}})
    monkeypatch.setattr("vpcopilot.probe.probe_from_spec",
                        lambda *a, **k: (_ for _ in ()).throw(httpx.ReadError("connection reset")))
    got = reconcile._probe({"finding_id": "f1"}, str(tmp_path), "http://origin", log=lambda m: None)
    assert got.get("probe_error"), "a transport failure returned the same {} as 'no probe recorded'"
    assert "ReadError" in got["probe_error"], "the reason must be carried, not just a flag"


def test_the_two_reasons_are_distinct_hold_codes():
    """Rendered on every surface through the hold code, so they cannot read alike."""
    src = (__import__("pathlib").Path(__file__).resolve().parents[1]
           / "src/vpcopilot/reconcile.py").read_text()
    assert "skipped_probe_error" in src and "skipped_no_probe" in src
    assert "transient failure, not a missing probe" in src


# ---------------------------------------------------------------- the blast-radius threshold


def test_every_surface_honours_the_operators_threshold(monkeypatch):
    """`VPCOPILOT_SIM_THRESHOLD` was a lookup each surface had to REMEMBER. The CLI, console and
    refiner remembered; the MCP server did not — so an operator who tightened the threshold got
    the default silently applied to every simulation an agent ran, and the number they set was the
    number they believed was in force.

    Now a property of the module. Asserted on the source of all four callers, because the defect
    was one caller not calling it."""
    from pathlib import Path

    from vpcopilot.simulate import effective_threshold
    monkeypatch.setenv("VPCOPILOT_SIM_THRESHOLD", "0.05")
    assert effective_threshold() == 0.05
    assert effective_threshold(0.2) == 0.2, "an explicit argument still wins"

    root = Path(__file__).resolve().parents[1] / "src/vpcopilot"
    for mod in ("cli.py", "mcp.py", "refiner.py", "console/app.py"):
        src = (root / mod).read_text()
        assert "effective_threshold(" in src, f"{mod} resolves the threshold its own way"
        assert 'os.environ.get("VPCOPILOT_SIM_THRESHOLD"' not in src, \
            f"{mod} still re-implements the lookup — that is how one surface drifted"


def test_a_malformed_threshold_is_refused_rather_than_defaulted(monkeypatch):
    """Refusing to guess. Silently substituting the default would apply a threshold the operator
    did not choose, on the gate that decides whether a policy is safe to promote — and they would
    never be told."""
    from vpcopilot.simulate import DEFAULT_THRESHOLD, effective_threshold
    monkeypatch.setenv("VPCOPILOT_SIM_THRESHOLD", "1%")
    with pytest.raises(RuntimeError, match="not a number"):
        effective_threshold()
    monkeypatch.setenv("VPCOPILOT_SIM_THRESHOLD", "")
    assert effective_threshold() == DEFAULT_THRESHOLD, "an EMPTY value is unset, not malformed"
