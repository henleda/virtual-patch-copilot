"""A4/A6/A7: pure-function coverage for the pipeline's dedup + severity logic — no agents, no XC."""
from vpcopilot import pipeline
from vpcopilot.schemas import Finding


def _f(id, vuln_class="sqli", severity="high", file="app.py", endpoint="", line=1):
    f = Finding(id=id, title=id, vuln_class=vuln_class, severity=severity,
                description="d", exploit_sketch="e", endpoint=endpoint, line=line)
    f.file = file
    return f


def test_dedup_collapses_same_vuln_keeps_highest_severity():
    # two findings, same file+class+endpoint -> one survives, and it's the critical one
    a = _f("f-low", severity="medium", endpoint="/users/v1/register")
    b = _f("f-high", severity="critical", endpoint="/users/v1/register")
    kept = pipeline._dedup_findings([a, b], log=lambda m: None)
    assert [k.id for k in kept] == ["f-high"]


def test_dedup_keeps_distinct_endpoints_and_classes():
    findings = [
        _f("a", vuln_class="sqli", endpoint="/login"),
        _f("b", vuln_class="sqli", endpoint="/statements"),   # different endpoint
        _f("c", vuln_class="broken_object_authz", endpoint="/login"),  # different class, same endpoint
    ]
    kept = pipeline._dedup_findings(findings, log=lambda m: None)
    assert {k.id for k in kept} == {"a", "b", "c"}


def test_dedup_falls_back_to_line_when_no_endpoint():
    same = [_f("x", endpoint="", line=10), _f("y", endpoint="", line=10)]
    diff = [_f("x", endpoint="", line=10), _f("y", endpoint="", line=20)]
    assert len(pipeline._dedup_findings(same, log=lambda m: None)) == 1
    assert len(pipeline._dedup_findings(diff, log=lambda m: None)) == 2


def test_severity_helpers():
    assert pipeline._sev(_f("a", severity="critical")) == "critical"
    assert pipeline._vclass(_f("a", vuln_class="sqli")) == "sqli"
