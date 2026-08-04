"""Live: `drift.check` against a real load balancer, and the guarantee that it writes nothing.

I2's acceptance says drift runs **read-only**, and gives the reason in as many words: the endpoint
is polled from a browser, so *a version that wrote a snapshot would corrupt the run dir just by
someone opening a page*. The offline tests pin that against `FakeXC`. What only a real tenant can
say is whether it holds when the LB is a real object with the fields XC actually returns — the
comparison walks the live spec, and a spec shape a fake never produces is exactly where an
accidental write would hide.

Read-only throughout: nothing here mutates the tenant, so unlike the spine suite there is no
restore to get wrong. That is also why it is worth having as its own file — the assertions are
about *absence* of writes, and mixing them with mutating tests would make the absence hard to trust.
"""
from __future__ import annotations

import pytest

from tests.live import requires
from vpcopilot import drift

pytestmark = pytest.mark.live


@pytest.fixture
def lb_name():
    """Any LB will do — this suite never writes — but it is still named explicitly rather than
    discovered, so a run cannot quietly start reading a different tenant's object."""
    env = requires("VPCOPILOT_LIVE_LB", "XC_API_URL", "XC_API_TOKEN")
    return env["VPCOPILOT_LIVE_LB"]


@pytest.fixture
def xc(lb_name):
    """Depends on `lb_name` so the credential skip fires before `XC()` is constructed — `XC()`
    raises on a missing var, which would turn a clean skip into an ERROR."""
    from vpcopilot.xc import XC
    return XC()


def test_drift_check_writes_absolutely_nothing(xc, lb_name, evidence, tmp_path):
    """The I2 guarantee, against a real LB. `GET /api/drift` is polled from the browser, so a
    version that wrote a snapshot would corrupt the run dir just by someone opening the page."""
    before = sorted(p.name for p in tmp_path.iterdir())
    assert before == [], "the fixture dir should start empty"

    report = drift.check(lb_name, out_dir=str(tmp_path), xc=xc, log=lambda m: None)

    after = sorted(p.name for p in tmp_path.iterdir())
    assert after == [], (
        f"drift.check WROTE to the run directory: {after}. It is polled from a browser — this would "
        f"corrupt a run dir just by someone opening the page.")
    # Named explicitly, because these are the two files the apply path writes and the ones an
    # accidental `ApplyContext.load()` inside drift would produce.
    assert not (tmp_path / "lb_snapshot.json").exists()
    assert not (tmp_path / "snapshots").exists()
    evidence.record(f"drift.check on {lb_name} wrote nothing; report keys {sorted(report)}")


def test_drift_check_actually_read_the_live_load_balancer(xc, lb_name, evidence):
    """A read-only function that read nothing would also write nothing, and would pass the test
    above perfectly. So assert it came back with the real object — the vacuity guard applied to the
    thing under test rather than to the test."""
    live_spec = xc.get_lb(lb_name).get("spec", {})
    assert live_spec, "the LB returned an empty spec — nothing to compare against"

    report = drift.check(lb_name, out_dir="/nonexistent-run-dir", xc=xc, log=lambda m: None)
    assert isinstance(report, dict) and report, "drift.check returned nothing"
    blob = repr(report)
    # The report must reflect THIS LB, not a generic shape.
    assert lb_name in blob or any(lb_name in str(v) for v in report.values()), \
        f"the drift report does not mention {lb_name}: {sorted(report)}"
    evidence.record(f"drift.check read {lb_name} live ({len(live_spec)} spec keys)")


def test_drift_check_survives_having_no_snapshot_to_compare_against(xc, lb_name, evidence, tmp_path):
    """The first-ever run on a fresh out dir. "No snapshot" is a normal state, not an error — and it
    must not be reported the same way as "no drift", which is the H2 unpinned-vs-clean distinction
    applied to a comparison."""
    report = drift.check(lb_name, out_dir=str(tmp_path), xc=xc, log=lambda m: None)
    assert report, "drift.check returned nothing with no snapshot present"
    assert sorted(p.name for p in tmp_path.iterdir()) == [], "it wrote a snapshot to compare against"
    evidence.record(f"no-snapshot run returned a report rather than erroring: {sorted(report)}")


def test_the_cli_drift_surface_is_read_only_too(lb_name, evidence, tmp_path):
    """One module function, two surfaces — and the read-only property has to hold on both, because
    the console endpoint is the one a browser polls."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    res = CliRunner().invoke(cli.app, ["drift", "--lb", lb_name, "--out", str(tmp_path)])
    assert res.exit_code in (0, 1), f"drift exited {res.exit_code}: {res.output[-400:]}"
    assert sorted(p.name for p in tmp_path.iterdir()) == [], \
        f"the drift CLI wrote to the run directory: {sorted(p.name for p in tmp_path.iterdir())}"
    evidence.record(f"vpcopilot drift --lb {lb_name} exited {res.exit_code} and wrote nothing")
