"""Numbers and blanks that told the operator something untrue.

From the 2026-08-04 deep-dive review. Three separate defects, one shape: a value that reads as an
established fact when it is nothing of the kind. The project's rule is that "we did not check this"
and "this is clean" must never render the same way; these are the places where they did.
"""
from __future__ import annotations

import json
import re

import pytest


# ---------------------------------------------------------------- report: candidates vs verified


@pytest.fixture
def scan_out(tmp_path):
    """A run where verify REFUTED some candidates — the input no fixture in the suite had.
    `tests/test_report.py::_seed` hardcodes candidates == verified, which is why this hid."""
    def f(fid, sev="high"):
        return {"id": fid, "title": f"t-{fid}", "vuln_class": "sqli", "severity": sev,
                "description": "d", "exploit_sketch": "e", "file": "app.py"}
    (tmp_path / "findings.json").write_text(json.dumps([f("keep-1"), f("keep-2"), f("refuted-1"),
                                                        f("refuted-2", "critical")]))
    (tmp_path / "triage.json").write_text(json.dumps(
        [{"finding_id": "keep-1", "bandaids": [{"control": "waf"}]},
         {"finding_id": "keep-2", "bandaids": []}]))
    (tmp_path / "summary.json").write_text(json.dumps({"candidates": 4, "verified": 2}))
    return tmp_path


def test_a_refuted_candidate_does_not_render_as_a_finding(scan_out):
    """`findings.json` holds every CANDIDATE; `triage.json` holds only what verify CONFIRMED. The
    report rendered them in one list, so a candidate the adversarial verify step refused to confirm
    sat on the page looking exactly like a confirmed one — in the repo's own `out/`, 25 cards under
    a hero reading 9."""
    from vpcopilot.report import build_report
    html = build_report(str(scan_out))
    assert "refuted-1" in html, "refuted candidates should still be shown — hiding them is not honesty"
    head = html[:html.index("did not confirm")]
    assert "keep-1" in head and "refuted-1" not in head, \
        "a refuted candidate is rendered among the confirmed findings"
    assert "not</strong> counted anywhere else" in html, \
        "the refuted section must say it is excluded from the counts"


def test_the_charts_count_the_same_set_the_hero_counts(scan_out):
    """A page whose chart and headline disagree is worse than a page with no chart."""
    from vpcopilot.report import build_report
    html = build_report(str(scan_out))
    blk = html[html.index("Findings by severity"):]
    blk = blk[:blk.index("</div></div>")]
    charted = sum(int(n) for n in re.findall(r"<span[^>]*>(\d+)</span>", blk))
    assert charted == 2, f"the severity chart counts {charted}, but only 2 findings were verified"


def test_the_refuted_count_is_stated_not_implied(scan_out):
    """Every candidate must be accounted for somewhere, or the page silently shows a subset."""
    from vpcopilot.report import build_report
    m = re.search(r"(\d+) of (\d+) candidates", build_report(str(scan_out)))
    assert m and (m.group(1), m.group(2)) == ("2", "4")


# ---------------------------------------------------------------- impact: "mitigated live by XC"


def _impact_for(tmp_path, entry):
    from vpcopilot import impact
    (tmp_path / "ledger.json").write_text(json.dumps({"a": entry}))
    (tmp_path / "summary.json").write_text(json.dumps({"candidates": 1, "verified": 1}))
    return impact.impact(str(tmp_path))


def test_a_code_cure_only_finding_is_never_counted_as_mitigated_live(tmp_path):
    """`mitigated` counted STATES alone. `ledger._advance` moves found -> remediated directly and
    `pr.open_pr` marks remediated for ANY finding it opens a PR for — including one triage routed
    to code-cure-only, which never touched XC. The hero then claimed a live XC mitigation for a
    finding with `mitigation: null`, while `controls_live` on the same page reported none."""
    got = _impact_for(tmp_path, {"state": "remediated", "mitigation": None,
                                 "cure": {"pr_url": "https://github.com/x/y/pull/1"}})
    assert got["mitigated"] == 0, "a finding with no band-aid was counted as mitigated live by XC"
    assert not got.get("controls_live"), "the two numbers must agree — that was the whole defect"


def test_a_real_band_aid_is_still_counted(tmp_path):
    """The fix must not swing the other way: a genuine mitigation still counts."""
    assert _impact_for(tmp_path, {"state": "mitigated",
                                  "mitigation": {"control": "waf", "lb": "l"}})["mitigated"] == 1


def test_a_retired_band_aid_was_still_mitigated(tmp_path):
    """Retired means detached, not never-applied — it still happened, it is just no longer live.
    `controls_live` is the number that must drop to zero, and it does."""
    got = _impact_for(tmp_path, {"state": "retired", "mitigation": {"control": "waf", "lb": "l"}})
    assert got["mitigated"] == 1 and not got.get("controls_live")


# ---------------------------------------------------------------- drift: unreadable != clean


class _FakeXC:
    ns = "default"

    def get_lb(self, name):
        return {"spec": {"rate_limit": {"limit": 5}}}


def _drift(tmp_path, snapshot_blob):
    from vpcopilot import drift
    snaps = tmp_path / "snapshots"
    snaps.mkdir(exist_ok=True)
    (snaps / "lb1-20260101T000000.json").write_text(snapshot_blob)
    return drift.check("lb1", out_dir=str(tmp_path), xc=_FakeXC(), log=lambda m: None)


def test_an_unreadable_snapshot_is_not_reported_as_no_drift(tmp_path):
    """The sharpest one in this file, because it gates an apply. Snapshots are written with a plain
    non-atomic `write_text`, so a truncated one is not hypothetical — and `except JSONDecodeError:
    changes = []` made "we could not read what we last left on this LB" render as "no drift" on the
    CLI, the console and the pre-apply gate."""
    clean = _drift(tmp_path, json.dumps({"spec": {"rate_limit": {"limit": 5}}}))
    broken = _drift(tmp_path, '{"spec": {"rate_li')

    assert clean["live_vs_snapshot"]["drifted"] is False
    assert broken["live_vs_snapshot"]["drifted"] is False        # both False — that is the trap
    assert clean["live_vs_snapshot"]["compared"] is True
    assert broken["live_vs_snapshot"]["compared"] is False, \
        "a snapshot that could not be read reports the same as one that compared clean"
    assert broken["live_vs_snapshot"]["unreadable"], "the reason must be carried, not just a flag"


def test_the_operator_is_actually_told_on_every_surface(tmp_path):
    """A flag nobody renders is not a fix. `warnings` is the channel all three surfaces already
    show, so this reaches the CLI, the console and MCP without three separate changes."""
    broken = _drift(tmp_path, '{"spec": {"rate_li')
    warn = " ".join(broken["warnings"])
    assert "could not read the last snapshot" in warn
    assert "NOT 'no drift'" in warn, "the warning must say what it is not, or it reads as cosmetic"
    assert _drift(tmp_path, json.dumps({"spec": {}}))["warnings"] == [], \
        "a readable snapshot must not produce a warning"


def test_an_unreadable_snapshot_does_not_block_the_apply(tmp_path):
    """Warn, do not veto — the G2/I2 precedent. We do not KNOW anything is wrong, so refusing
    would be its own kind of false claim. It says loudly that the question went unanswered."""
    assert _drift(tmp_path, '{"spec": {"rate_li')["ok_to_apply"] is True


def test_no_snapshot_at_all_is_still_a_third_distinct_answer(tmp_path):
    """Three outcomes, not two: absent, compared-clean, unreadable. The first is normal on a first
    run and must not borrow either of the others' rendering."""
    from vpcopilot import drift
    got = drift.check("lb1", out_dir=str(tmp_path), xc=_FakeXC(), log=lambda m: None)
    lvs = got["live_vs_snapshot"]
    assert lvs["snapshot"] is None and lvs["compared"] is False and lvs["unreadable"] == ""
    assert got["warnings"] == [], "a first run has nothing to warn about"
