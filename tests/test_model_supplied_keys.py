"""Model-supplied values that code then trusted as facts.

From the 2026-08-04 deep-dive review, and the same shape as the J5 defect: a field lives on a
pydantic model that is ALSO an agent's `response_model`, so the model can fill it — and downstream
code treats it as something it established itself.

J5 looked like a one-off. It was not: three more instances, all on the identifier that joins one
pipeline stage to the next. A verified vulnerability silently losing its mitigation is the worst
outcome this pipeline has, so these are reconciled in code rather than hoped for in a prompt.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import FakeHarness  # noqa: E402

from vpcopilot import pipeline  # noqa: E402
from vpcopilot.schemas import (  # noqa: E402
    BandaidOption, Control, Coverage, Finding, FindingList, TriageBatch, TriageDecision, Verdict,
)


def _finding(fid, cls="sqli"):
    return Finding(id=fid, title=f"t{fid}", vuln_class=cls, severity="high",
                   description="d", exploit_sketch="e", file="app.py")


def _decision(fid):
    return TriageDecision(
        finding_id=fid, no_bandaid=False, residual_risk="r",
        bandaids=[BandaidOption(control=Control("service_policy"), coverage=Coverage("full"),
                                recommended=True, rationale="x")])


@pytest.fixture
def run(monkeypatch, tmp_path):
    """One source file, so `discover` is called exactly once and finding ids are not
    collision-suffixed — a three-file fixture makes the fake return the same ids repeatedly and
    the suffixing masks what is under test."""
    def go(triage_decisions, findings=("f1", "f2", "f3")):
        # Distinct vuln_class per finding: A6's dedup collapses same-file/same-class/same-line
        # findings into one, which would silently reduce the fixture to a single finding and make
        # every assertion below vacuous.
        classes = ["sqli", "xss", "ssrf", "mass_assignment"]
        fl = FindingList(findings=[_finding(f, classes[i % len(classes)])
                                   for i, f in enumerate(findings)])
        fake = FakeHarness({
            "discover": fl,
            "verify": lambda s, u: Verdict(
                finding_id=re.search(r"\b(f\d+)\b", u).group(1),
                is_real=True, confidence=0.9, rationale="r"),
            "triage": lambda s, u: TriageBatch(decisions=triage_decisions),
        })
        monkeypatch.setattr(pipeline, "Harness", lambda *a, **k: fake)
        repo = tmp_path / "repo"
        repo.mkdir(exist_ok=True)
        (repo / "app.py").write_text("q = 'SELECT ' + u\n")
        out = tmp_path / "out"
        logs: list[str] = []
        summary = pipeline.run_pipeline(str(repo), out_dir=str(out), log=logs.append,
                                        draft_code_fixes=False)
        ledger = json.loads((out / "ledger.json").read_text())
        return summary, ledger, logs
    return go


def test_a_verified_finding_the_triage_agent_omits_is_never_dropped_silently(run):
    """The worst one. `for d in decisions: f = by_id.get(d.finding_id)` iterated the AGENT's list,
    so a finding the agent simply did not mention got no band-aid, no ledger entry and no log
    line. Measured before the fix: three verified findings in, one ledger entry out, nothing said.

    It is now routed to code-cure-only — fail CLOSED, exactly as verify does with an unparseable
    verdict — because a decision that claims no band-aid exists is safe, and silence is not."""
    summary, ledger, logs = run([_decision("f1")])
    assert summary["verified"] == 3
    assert sorted(ledger) == ["f1", "f2", "f3"], \
        f"a verified finding vanished between triage and the ledger: {sorted(ledger)}"
    for fid in ("f2", "f3"):
        assert any(f"NO decision for verified finding '{fid}'" in x for x in logs), \
            f"{fid} was dropped without a word"
    assert ledger["f2"].get("mitigation") is None, "an omitted finding must not claim a band-aid"


def test_an_id_the_triage_agent_invents_does_not_create_a_phantom_ledger_entry(run):
    """The inverse. A renamed id produced a ledger row keyed on an id no finding has, carrying
    `title: null, severity: null, file: null` — a row about nothing, in the audit trail."""
    _, ledger, logs = run([_decision("f1"), _decision("sqli-001")])
    assert "sqli-001" not in ledger, "a model-invented id reached the ledger"
    assert any("not one of the 3 verified findings" in x for x in logs), \
        "the invented id was discarded silently — it must be reported"
    assert all(ledger[k].get("title") for k in ledger), "a ledger entry with no title is a phantom"


def test_a_duplicate_decision_does_not_double_count(run):
    """Two decisions for the same finding used to mean two passes over it."""
    _, ledger, logs = run([_decision("f1"), _decision("f1")])
    assert sorted(ledger) == ["f1", "f2", "f3"]
    assert any("two decisions for 'f1'" in x for x in logs)


def test_the_normal_case_produces_no_warnings(run):
    """The fix must not cry wolf: when the agent returns exactly what it was given, the
    reconciliation is silent. Otherwise every real run would train the operator to ignore it."""
    _, ledger, logs = run([_decision(f) for f in ("f1", "f2", "f3")])
    assert sorted(ledger) == ["f1", "f2", "f3"]
    noisy = [x for x in logs if "triage returned" in x]
    assert not noisy, f"the reconciliation warned on a clean run: {noisy}"


def test_the_generated_policy_index_is_written_by_code_not_by_the_model():
    """`GeneratedArtifact.finding_id` and `.control` are on the generate agent's response_model,
    but the call site already KNOWS both — it asked for that control on that finding. They are the
    policy->finding index every apply / refine / simulate / emit / backfill path keys off, so a
    model that echoed a different id filed the band-aid against the wrong vulnerability.

    Asserted on the source, because the overwrite is the guarantee."""
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/pipeline.py").read_text()
    assert re.search(r"a\.finding_id,\s*a\.control\s*=\s*d\.finding_id,\s*b\.control", src), \
        "the generated artifact's identifiers are still whatever the model returned"


def test_a_source_finding_cannot_be_relabelled_a_dependency_upgrade():
    """`RemediationPlan.kind` and the package/version fields are on the remediate agent's
    response_model. The class docstring says they are "filled from OSV by code, never by a model" —
    and nothing enforced it. A repo-scan cure relabelled `dependency_upgrade` makes `pr.py` skip
    writing the patch and report a model-INVENTED "upgrade <pkg> to <version>", which is a version
    number an operator acts on directly."""
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/pipeline.py").read_text()
    body = src[src.index("def _remediate(f):"):]
    body = body[:body.index("return r") + 8]
    assert 'r.kind = "code_fix"' in body, "the model still decides what kind of cure this is"
    assert "r.package = r.ecosystem = r.vulnerable_range = r.fixed_version" in body, \
        "a model-invented package/version can still reach the operator"
    assert "r.finding_id = f.id" in body, "the cure is still keyed on the model's echo of the id"
