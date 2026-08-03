"""The live harness's own guarantees, tested OFFLINE.

These run in the ordinary suite, deliberately: the harness is what stops the live suite from
reporting a pass it did not earn, so its guarantees cannot themselves be gated behind the credential
they exist to check. A guard that only runs when the thing works is not a guard.
"""
from __future__ import annotations

import pytest

from tests import live


def test_requires_skips_rather_than_returning_a_flag(monkeypatch):
    """The whole point: a helper that returned False would let a test body continue past it and
    report a pass having done nothing — the exact shape of failure this suite exists to eliminate."""
    monkeypatch.delenv("VPCOPILOT_MADE_UP_KEY", raising=False)
    with pytest.raises(BaseException) as e:      # pytest.skip raises Skipped, not Exception
        live.requires("VPCOPILOT_MADE_UP_KEY")
    assert e.typename == "Skipped"
    assert "VPCOPILOT_MADE_UP_KEY" in str(e.value), "a skip must name the missing variable"


def test_requires_treats_an_empty_or_whitespace_value_as_absent(monkeypatch):
    """K2 found that `required: true` on a GitHub action input is not enforced against an empty
    value, and the action scanned nothing while looking clean. Same trap, same answer."""
    for val in ("", "   "):
        monkeypatch.setenv("VPCOPILOT_MADE_UP_KEY", val)
        with pytest.raises(BaseException) as e:
            live.requires("VPCOPILOT_MADE_UP_KEY")
        assert e.typename == "Skipped"


def test_requires_returns_the_values_when_they_are_all_present(monkeypatch):
    monkeypatch.setenv("VPCOPILOT_MADE_UP_KEY", " abc ")
    assert live.requires("VPCOPILOT_MADE_UP_KEY") == {"VPCOPILOT_MADE_UP_KEY": "abc"}


def test_a_live_test_that_observed_nothing_fails_rather_than_passing():
    """The vacuity guard. A live test can pass by doing nothing: the API returns an empty list, the
    `for` body never runs, every assertion inside it is skipped, and the test is green. That is J3's
    fabricated records and K2's zero-file diff in test form."""
    with pytest.raises(AssertionError, match="passed without proving anything"):
        live.check_not_vacuous(live.Evidence())


def test_a_live_test_that_recorded_an_observation_passes():
    ev = live.Evidence()
    ev.record("the API answered with 3 records")
    live.check_not_vacuous(ev)          # must not raise
    assert len(ev) == 1


def test_a_skipped_live_test_is_a_skip_and_never_an_error(evidence):
    """The harness's core promise, and it was broken on its first credential-free run: the vacuity
    check fired on tests that had SKIPPED for a missing credential, turning a clean skip into an
    ERROR. The backlog item requires the opposite in as many words — "a contributor without a
    tenant sees skipped, never failed and never a false pass".

    This test skips, records nothing, and must still report as a skip. If the guard ever regresses,
    this line turns red in the ordinary suite rather than only on someone's laptop."""
    live.requires("VPCOPILOT_A_KEY_THAT_IS_NEVER_SET")
    evidence.record("unreachable — the skip above is the assertion")


def test_the_evidence_fixture_consults_the_call_report_before_asserting():
    """…and the mechanism, so the fix cannot be silently reverted to an unconditional assert."""
    import inspect
    src = inspect.getsource(live.evidence.__wrapped__)
    assert "_vpc_rep_call" in src and "skipped" in src


def test_the_evidence_fixture_actually_applies_the_vacuity_check():
    """The check is only worth having if the fixture runs it — a guard wired to nothing is the I1
    'a surface nothing calls is not a surface' failure, one layer down."""
    import inspect
    assert "check_not_vacuous" in inspect.getsource(live.evidence.__wrapped__)


def test_a_failing_cleanup_fails_the_test_loudly(monkeypatch):
    """A live test that mutates a real tenant and then fails mid-way must not leave the estate
    changed — the next test's baseline depends on it, and so does the operator's demo."""
    def boom():
        raise RuntimeError("detach did not stick")
    with pytest.raises(BaseException) as e:
        live.restoring(boom)
    assert e.typename == "Failed"
    assert "CLEANUP FAILED" in str(e.value) and "left mutated" in str(e.value)


def test_every_live_test_module_is_marked_live():
    """The marker is what keeps these out of CI. A live module that forgot it would hit the network
    from the fast job — and `pytest -m "not live"` would not exclude it."""
    from pathlib import Path
    for p in sorted((Path(__file__).resolve().parent).glob("test_live_*.py")):
        if p.name == Path(__file__).name:
            continue
        src = p.read_text()
        assert "pytestmark = pytest.mark.live" in src or "@pytest.mark.live" in src, \
            f"{p.name} is a live module but carries no live marker"


def test_the_harness_imports_however_pytest_is_invoked():
    """Shipped broken and only CI said so. `python -m pytest` puts the CWD on `sys.path` and bare
    `pytest` does not, so `from tests.live import …` resolved locally as an implicit *namespace*
    package off the CWD and failed in CI with `ModuleNotFoundError: No module named 'tests'`.

    The repo's own documented reproduction command is `python -m pytest`, which does **not**
    reproduce it — CI runs bare `pytest`. `pythonpath` is applied by pytest itself, so it holds for
    both; this asserts the entry is still there, because losing it fails only on the runner."""
    import tomllib
    from pathlib import Path
    cfg = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert "." in cfg["tool"]["pytest"]["ini_options"]["pythonpath"], \
        "the repo root must be on pythonpath or `tests.live` imports only under `python -m pytest`"


def test_the_live_suite_is_excluded_from_the_default_selector():
    """CI runs `-m "not live and not bench"`. If that ever drifts, the fast job starts reaching the
    network and the nightly's promise becomes true by accident rather than by design."""
    from pathlib import Path
    ci = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
    assert 'pytest -m "not live and not bench"' in ci
