"""Smoke tests that don't require any model/API: schemas validate and config loads."""
from pathlib import Path

from vpcopilot.config import load_config
from vpcopilot.repo_scan import collect_files
from vpcopilot.schemas import Control, Finding, Severity, TriageDecision, VulnClass


def test_finding_roundtrip():
    f = Finding(
        id="neg-pay-001",
        title="Negative-amount transfer reverses funds",
        vuln_class=VulnClass.business_logic,
        severity=Severity.high,
        file="app/src/app/api/pay/route.js",
        line=22,
        description="No amount>0 guard.",
        exploit_sketch="POST a negative amount to drain the payee.",
    )
    assert Finding.model_validate_json(f.model_dump_json()).id == "neg-pay-001"


def test_triage_defaults_temporary():
    d = TriageDecision(finding_id="neg-pay-001", control=Control.service_policy, rationale="x")
    assert d.temporary is True


def test_config_loads_default():
    cfg = load_config(str(Path(__file__).resolve().parents[1] / "config" / "agents.yaml"))
    assert cfg.for_agent("discover").model


def test_collect_skips_non_code(tmp_path):
    (tmp_path / "a.js").write_text("const x = 1;")
    (tmp_path / "note.md").write_text("# hi")
    files, _ = collect_files(str(tmp_path))
    names = {p.name for p in files}
    assert "a.js" in names and "note.md" not in names
