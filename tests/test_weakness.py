"""J5 — CWE / OWASP classification.

The thing under test is mostly what this module *refuses* to say, so most of these tests assert a
blank plus a reason rather than a value.
"""
from __future__ import annotations

import json

import pytest

from vpcopilot import weakness
from vpcopilot.schemas import VulnClass


def test_every_vuln_class_is_accounted_for_either_mapped_or_declined():
    """No class may fall through silently. A class with neither a mapping nor a stated reason would
    produce a blank that looks like an oversight, which is the one outcome this item must avoid."""
    for vc in (v.value for v in VulnClass):
        got = weakness.classify(vc)
        assert got["cwe"] or weakness.CWE_DECLINED.get(vc), f"{vc}: no CWE and no stated reason"
        assert got["owasp"] or weakness.OWASP_DECLINED.get(vc), f"{vc}: no OWASP and no reason"
        if not got["cwe"] or not got["owasp"]:
            assert got["reason"], f"{vc}: declined without a reason"


def test_only_cwes_mitre_allows_for_mapping_are_ever_emitted():
    """Verified at cwe.mitre.org, not assumed. CWE-840 is PROHIBITED ("must not be used to map to
    real-world vulnerabilities" — it is a Category); CWE-200 and CWE-287 are DISCOURAGED (an impact
    and a Class rather than root causes). Emitting one would be a taxonomy error in the artifact
    whose whole job is to be trustworthy."""
    banned = {"CWE-840", "CWE-200", "CWE-287", "CWE-20"}
    emitted = {cwe for cwe, _ in weakness.CLASS_CWE.values()} | {weakness.EVIDENCE_CWE[0]}
    assert not (emitted & banned), f"a PROHIBITED/DISCOURAGED CWE is emitted: {emitted & banned}"


def test_business_logic_maps_to_nothing_at_class_level():
    """The obvious answer (CWE-840) is prohibited, and the class genuinely spans unrelated
    weaknesses — a missing balance check and an unbounded amount are not one CWE."""
    got = weakness.classify("business_logic")
    assert got["cwe"] == "" and got["cwe_source"] == ""
    assert "PROHIBITED" in got["reason"]


@pytest.mark.parametrize("vc", ["sqli", "xss", "command_injection"])
def test_injection_classes_get_no_owasp_api_category(vc):
    """Injection was REMOVED from the API Security Top 10 in 2023 and NOT absorbed into API8 — the
    API8 page never mentions it. Forcing these into a category would be a wrong answer dressed as a
    taxonomy. They still get a CWE, which is the honest half."""
    got = weakness.classify(vc)
    assert got["owasp"] == "" and "REMOVED" in got["reason"]
    assert got["cwe"], "the CWE half is still knowable and must not be dropped too"


# ---------------------------------------------------------------- tier precedence


def test_the_advisory_tier_wins_and_is_never_re_derived():
    """The anti-fabrication rule. `inputs/cve.py` deliberately collapses CWE-77/78/94 into one
    `command_injection` class, so going back the other way would stamp a specific CWE the advisory
    never claimed. Where OSV spoke, we quote it."""
    got = weakness.classify("command_injection", ["CWE-94"])
    assert got["cwe"] == "CWE-94" and got["cwe_source"] == "advisory"
    assert weakness.classify("command_injection")["cwe"] == "CWE-77"      # the class would say this


def test_several_advisory_cwes_are_reported_not_silently_dropped():
    got = weakness.classify("sqli", ["CWE-89", "CWE-564"])
    assert got["cwe"] == "CWE-89" and "2 weaknesses" in got["reason"] and "CWE-564" in got["reason"]


def test_the_evidence_tier_classifies_the_flagship_and_not_its_neighbour():
    """The tier that earns its place: two findings of the SAME class, told apart by the recorded
    requests. A class table cannot do this — that is the whole argument."""
    numeric = {"exploit": {"json_body": {"amount": -100}}, "legit": {"json_body": {"amount": 10}}}
    got = weakness.classify_from_probe("business_logic", numeric)
    assert got and got["cwe"] == "CWE-1284" and got["cwe_source"] == "evidence"
    assert "-100" in got["reason"] and "10" in got["reason"], "the reason must cite the evidence"

    # A business-logic finding that is NOT a quantity flaw stays blank.
    other = {"exploit": {"json_body": {"account": "victim"}},
             "legit": {"json_body": {"account": "mine"}}}
    assert weakness.classify_from_probe("business_logic", other) is None


@pytest.mark.parametrize("vc", ["sqli", "broken_auth", "other"])
def test_the_evidence_tier_only_speaks_for_business_logic(vc):
    numeric = {"exploit": {"json_body": {"amount": -100}}, "legit": {"json_body": {"amount": 10}}}
    assert weakness.classify_from_probe(vc, numeric) is None


def test_stamp_precedence_is_advisory_then_evidence_then_mapped():
    from vpcopilot.schemas import Finding

    def _f(vc):
        return Finding(id="x", title="t", vuln_class=vc, severity="high",
                       description="d", exploit_sketch="e")
    numeric = {"exploit": {"json_body": {"amount": -1}}, "legit": {"json_body": {"amount": 1}}}

    f = _f("business_logic"); weakness.stamp(f, advisory={"cwe_ids": ["CWE-99"]}, probe=numeric)
    assert (f.cwe, f.cwe_source) == ("CWE-99", "advisory"), "advisory must outrank evidence"

    f = _f("business_logic"); weakness.stamp(f, probe=numeric)
    assert (f.cwe, f.cwe_source) == ("CWE-1284", "evidence")

    f = _f("sqli"); weakness.stamp(f, probe=numeric)
    assert (f.cwe, f.cwe_source) == ("CWE-89", "mapped")

    f = _f("other"); weakness.stamp(f)
    assert (f.cwe, f.owasp, f.cwe_source) == ("", "", "")


def test_a_classification_never_breaks_a_scan():
    """Evidence gathering is fail-soft: a taxonomy is not worth failing a completed scan for."""
    from vpcopilot.schemas import Finding
    f = Finding(id="x", title="t", vuln_class="business_logic", severity="high",
                description="d", exploit_sketch="e")
    for bad in ({"exploit": None, "legit": None}, {"exploit": {"json_body": None}}, {}, None):
        weakness.stamp(f, probe=bad)      # must not raise
    assert f.cwe_source in ("", "evidence", "mapped")


# ---------------------------------------------------------------- the fields and their carriers


def test_the_fields_are_optional_so_the_discover_contract_is_unchanged():
    """A REQUIRED field here would be a prompt change to the most recall-critical agent in the
    pipeline — exactly what G4's committed four-provider scorecard measures."""
    from vpcopilot.schemas import Finding
    f = Finding(id="x", title="t", vuln_class="sqli", severity="high",
                description="d", exploit_sketch="e")          # no cwe/owasp supplied
    assert (f.cwe, f.owasp, f.cwe_source) == ("", "", "")


def test_the_recorded_agent_golden_still_validates():
    """The golden omits these fields entirely, as a real LLM response would."""
    from tests.test_schema_golden import GOLDEN

    from vpcopilot.schemas import FindingList
    FindingList.model_validate_json(GOLDEN[FindingList])      # keyed by the model class itself


@pytest.mark.parametrize("field", ["cwe", "owasp", "cwe_source"])
def test_every_carrier_that_would_silently_drop_the_fields_was_updated(field):
    """Four whitelists copy a hand-picked set of finding keys, and each would drop a new field
    without erroring: the ledger entry, the audit CSV columns, the audit-event join, and
    reconcile's denormalization. A field that reaches `findings.json` and nothing else is half a
    feature that looks whole."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "src/vpcopilot"
    for mod in ("ledger.py", "export.py", "reconcile.py"):
        assert field in (root / mod).read_text(), f"{mod} does not carry {field!r}"
    from vpcopilot.export import COLUMNS
    assert field in COLUMNS, f"{field!r} is not an audit.csv column"


def test_the_report_groups_by_owasp_and_says_what_is_unclassified():
    """J5's acceptance asks the report to group by category. `unclassified` is rendered as its own
    bar rather than omitted — a chart showing only the classified findings would overstate the
    coverage."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/report.py").read_text()
    assert "OWASP API Top 10" in src and "(no category)" in src
    assert "certification" in src, "the report must state this is a classification, not a claim"


def test_the_summary_counts_the_unclassified_as_a_first_class_number():
    got = weakness.summary([{"cwe": "CWE-89", "owasp": ""}, {"cwe": "", "owasp": "API1:2023"},
                            {"cwe": "", "owasp": ""}])
    assert got["unclassified"] == 1 and got["total"] == 3
    assert got["by_cwe"] == {"CWE-89": 1} and got["by_owasp"] == {"API1:2023": 1}


def test_it_classifies_a_real_scans_findings():
    """Against the committed fixture rather than a hand-made one, so the class distribution is the
    one a real run produces."""
    from pathlib import Path
    p = Path(__file__).resolve().parents[1] / "demo/out/findings.json"
    findings = json.loads(p.read_text())
    classified = 0
    for f in findings:
        got = weakness.classify(f.get("vuln_class", ""))
        assert got["cwe"] or got["reason"], f"{f['id']}: blank with no reason"
        classified += bool(got["cwe"] or got["owasp"])
    assert classified, "not one finding in the demo dataset could be classified"


def test_the_report_bars_can_actually_render_their_fill():
    """Pre-existing, found while adding the OWASP chart: `.fill` is a <span>, and an INLINE element
    ignores height and a percentage width. The width and colour were computed correctly all along
    (`style="width:33%;background:#a1001b"`) and silently discarded — so C5's severity and
    band-aid-coverage bars had never drawn a bar. Every track rendered empty, in the artifact whose
    job is to communicate at a glance."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/report.py").read_text()
    import re
    m = re.search(r"\.fill\{([^}]*)\}", src)
    assert m, ".fill is not defined in the report CSS at all"
    assert "display:block" in m.group(1), \
        "an inline .fill cannot honour the width the code computes — the bars render empty"


@pytest.mark.parametrize("junk", [[None], [123], "CWE-89", [""], ["   "], ["CWE-89x"], ["cwe"], 42])
def test_a_malformed_advisory_cwe_is_never_quoted_as_a_fact(junk):
    """Found by self-review. `str(c).strip()` accepted `None` (→ the fabricated id "NONE"), `123`
    (→ "123") and — worst — a bare STRING instead of a list, which iterates its characters and
    stamped "C". Each puts a confident wrong CWE into an evidence bundle, which is the one thing
    this module must never do. The advisory tier is the one claiming a FACT, so it validates shape."""
    got = weakness.classify("sqli", junk)
    assert got["cwe_source"] == "mapped", f"junk {junk!r} was quoted as an advisory fact"
    assert got["cwe"] == "CWE-89"        # fell through to the class mapping, which is correct


@pytest.mark.parametrize("ok,expect", [(["CWE-89"], "CWE-89"), (["cwe-22"], "CWE-22"),
                                       (["CWE-89", "junk"], "CWE-89")])
def test_a_well_formed_advisory_cwe_is_still_quoted(ok, expect):
    got = weakness.classify("business_logic", ok)
    assert (got["cwe"], got["cwe_source"]) == (expect, "advisory")


def test_the_module_docstring_states_the_right_number_of_tiers():
    """A docstring that says three while the code has four is the same class of small lie this
    module exists to avoid."""
    assert "Four tiers" in weakness.__doc__
    for tier in ("advisory", "evidence", "mapped"):
        assert f"`{tier}`" in weakness.__doc__


# ---------------------------------------------------------------- found by adversarial review


def test_a_model_supplied_classification_never_survives_the_pipeline():
    """The one that mattered. These three fields live on `Finding`, which IS the response model
    instructor hands the discover agent — so they appear in the wire schema, descriptions and all,
    and a model can fill them. The choke point's `if not cwe_source` guard cannot tell a code-set
    value from a model-set one, so an invented CWE sailed straight through and was persisted to
    findings.json, the ledger, audit.csv and the signed bundle *labelled `advisory`* — a fabricated
    fact in the artifact whose entire job is to be trustworthy.

    Proven with CWE-840, the id MITRE PROHIBITS from mapping, so a pass here cannot be a
    coincidence of the class table agreeing. This is "agents reason, code acts" as an executable
    assertion rather than a sentence in a docstring."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/pipeline.py").read_text()
    # Anchored inside the discover loop, which only ever sees agent output — advisory findings
    # (inputs/cve.py, inputs/deps.py) are stamped at construction and never pass through here.
    loop = src[src.index("for f in res.findings"):src.index("for f in res.findings") + 2500]
    assert re.search(r"f\.cwe\s*=\s*f\.owasp\s*=\s*f\.cwe_source\s*=\s*\"\"", loop), (
        "the discover loop does not discard model-supplied classification fields — a model that "
        "fills them bypasses the choke point and its CWE is persisted as an advisory fact")
    assert loop.index("f.cwe") > loop.index("f.file"), \
        "the discard must sit with the other unconditional overwrites"


def test_the_class_that_spans_three_weaknesses_declines_rather_than_picking_one():
    """`broken_auth` holds missing auth (CWE-306), weak auth (CWE-1390) and response-discrepancy
    enumeration (CWE-204). It mapped to CWE-1390, which made the committed `crapi-userenum-005`
    ("Username enumeration on signup") read as "Weak Authentication" — a confident wrong answer.
    The module's own rule is to map "only where the class maps to exactly one"; `sensitive_data` is
    declined for the identical reason, so mapping this one applied the rule inconsistently."""
    got = weakness.classify("broken_auth")
    assert got["cwe"] == "" and got["cwe_source"] == ""
    assert "CWE-306" in got["reason"] and "CWE-204" in got["reason"], \
        "declining is only honest if it names the siblings it could not choose between"
    assert got["owasp"] == "API2:2023", "the OWASP half is unambiguous and must not be dropped too"
    # An advisory that names one still wins — declining is about what WE may infer, not what OSV said.
    assert weakness.classify("broken_auth", ["CWE-306"])["cwe_source"] == "advisory"


def test_the_owasp_chart_accounts_for_every_single_finding():
    """The bars used `unclassified` (no CWE *and* no OWASP) as the residual, so an sqli finding —
    CWE-89, but deliberately no category since Injection left the API Top 10 in 2023 — appeared in
    no bar at all. On the committed demo dataset the chart summed to 5 of 6 findings. A chart that
    silently undercounts is worse than no chart, because it reads as complete."""
    import re

    from vpcopilot.report import _bars_html
    # Deliberately NO fully-unclassified finding: with one present, `unclassified` and the true
    # residual coincide and the bug hides. Two sqli findings carry a CWE but no category, so the
    # buggy residual is 0 and they vanish from the chart.
    findings = [{"vuln_class": "sqli", "cwe": "CWE-89", "owasp": "", "severity": "high"},
                {"vuln_class": "sqli", "cwe": "CWE-89", "owasp": "", "severity": "high"},
                {"vuln_class": "broken_object_authz", "cwe": "CWE-639", "owasp": "API1:2023",
                 "severity": "high"}]
    html = _bars_html(findings, {"policies": []})
    blk = html[html.index("OWASP API Top 10"):]
    blk = blk[:blk.index("</div></div>")]
    # Counted from the rendered HTML, not from `summary()` and not from the module's own internal
    # assert — the test has to be able to fail when that assert is the thing that regresses.
    charted = sum(int(n) for n in re.findall(r"<span[^>]*>(\d+)</span>", blk))
    assert charted == len(findings), (
        f"the OWASP chart accounts for {charted} of {len(findings)} findings — the ones with a CWE "
        f"but no category are missing from every bar")
    assert "(no category)" in blk


def test_no_honest_mapping_and_never_stamped_do_not_render_the_same_way():
    """The project rule, applied to a taxonomy: "we did not check this" and "this is clean" must
    never render alike. The note claimed every blank was "because no honest mapping exists for
    their class", which is a reason it cannot know — a finding that predates J5, or reaches the
    report via a path that bypasses the pipeline, is blank for a completely different reason."""
    got = weakness.summary([{"cwe": "", "owasp": "", "vuln_class": "business_logic"},
                            {"cwe": "", "owasp": "", "vuln_class": "sqli"}])
    assert got["declined"] == 1 and got["unstamped"] == 1, \
        "business_logic declines by design; a blank sqli means the stamp never ran"
    assert got["declined"] + got["unstamped"] == got["unclassified"]

    from vpcopilot.report import _weakness_note
    note = _weakness_note(got)
    assert "no honest mapping" in note and "never classified" in note
    assert "predate" in note or "bypassed" in note, "the defect case must not borrow the other reason"


def test_the_committed_demo_dataset_is_classified():
    """`demo/build_demo_out.py` hand-writes its findings, so they never pass the pipeline choke
    point. Unstamped, the demo — the thing most people actually look at — rendered every finding as
    "never classified" while a real run of the same findings classified fine."""
    import json
    from pathlib import Path
    findings = json.loads(
        (Path(__file__).resolve().parents[1] / "demo/out/findings.json").read_text())
    assert findings, "the demo dataset is empty"
    for f in findings:
        assert "cwe" in f and "owasp" in f, f"{f['id']}: the demo builder did not stamp it"
    got = weakness.summary(findings)
    assert got["unstamped"] == 0, f"{got['unstamped']} demo findings bypassed the stamp"
    assert got["by_owasp"], "not one demo finding carries an OWASP category"
