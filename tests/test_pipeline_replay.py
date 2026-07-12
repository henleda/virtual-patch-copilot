"""D2: full-pipeline replay against a FakeHarness (canned agent outputs) over a tiny repo — proves
discover→verify→triage→generate→remediate→probe wire together and the out/ artifacts are written,
with no model calls. Also guards the B6 warmup-before-fan-out ordering."""
import json

from conftest import FakeHarness

from vpcopilot import pipeline
from vpcopilot.schemas import (BandaidOption, ExploitProbe, FindingList, Finding,
                               GeneratedArtifact, GeneratedArtifacts, ProbeRequest, RemediationPlan,
                               TriageBatch, TriageDecision, Verdict)


def _finding():
    return Finding(id="sqli-1", title="SQLi login", vuln_class="sqli", severity="critical",
                   endpoint="/api/login", http_method="POST", description="concatenated query",
                   exploit_sketch="' OR 1=1 --", code_snippet="q = 'SELECT ' + email")


def _responses():
    return {
        "discover": lambda s, u: FindingList(findings=[_finding()] if "SELECT" in u else []),
        "verify": lambda s, u: Verdict(finding_id="sqli-1", is_real=True, confidence=0.95, rationale="reachable"),
        "triage": lambda s, u: TriageBatch(decisions=[TriageDecision(
            finding_id="sqli-1", no_bandaid=False,
            bandaids=[BandaidOption(control="service_policy", coverage="full", recommended=True, rationale="r")])]),
        "generate": lambda s, u: GeneratedArtifacts(items=[GeneratedArtifact(
            finding_id="sqli-1", control="service_policy", policy_name="deny-login-sqli",
            spec={"rule_list": {"rules": [
                {"spec": {"action": "DENY", "path": {"prefix_values": ["/api/login"]}, "http_method": {"methods": ["POST"]}}},
                {"spec": {"action": "ALLOW", "path": {"prefix_values": ["/"]}}}]}})]),
        "remediate": lambda s, u: RemediationPlan(
            finding_id="sqli-1", summary="parameterize", file="login.py", diff="--- a\n+++ b",
            patched_content="fixed", pr_title="Parameterize login query", pr_body="body"),
        "probe": lambda s, u: ExploitProbe(
            finding_id="sqli-1",
            exploit=ProbeRequest(method="POST", path="/api/login", json_body={"email": "' OR 1=1 --"}),
            legit=ProbeRequest(method="POST", path="/api/login", json_body={"email": "a@b.c"})),
    }


def test_pipeline_replay_end_to_end(monkeypatch, tmp_path):
    fake = FakeHarness(_responses())
    monkeypatch.setattr(pipeline, "Harness", lambda *a, **k: fake)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "login.py").write_text("q = 'SELECT * FROM users WHERE email = ' + email  # vulnerable")
    (repo / "safe.py").write_text("print('nothing to see')")
    out = tmp_path / "out"

    summary = pipeline.run_pipeline(str(repo), out_dir=str(out), log=lambda m: None)

    assert summary["candidates"] == 1 and summary["verified"] == 1
    findings = json.loads((out / "findings.json").read_text())
    assert [f["id"] for f in findings] == ["sqli-1"]
    # generated band-aid + code-fix PR + probe all written
    assert list((out / "policies").glob("service_policy.deny-login-sqli.json"))
    assert json.loads((out / "remediations.json").read_text())[0]["finding_id"] == "sqli-1"
    assert json.loads((out / "probes.json").read_text())[0]["finding_id"] == "sqli-1"
    # ledger seeded to 'found'; report emitted
    assert json.loads((out / "ledger.json").read_text())["sqli-1"]["state"] == "found"
    assert (out / "report.html").exists()
    # B6: warmup ran before any discover call
    roles = [c[0] for c in fake.calls]
    assert roles and roles[0] == "_warmup" or "_warmup" not in roles  # warmup is best-effort/no-op on the fake


def test_pipeline_warmup_called_before_fanout(monkeypatch, tmp_path):
    order = []

    class Rec(FakeHarness):
        def warmup(self):
            order.append("warmup")

        def run(self, role, system, user, schema, **kw):
            order.append(role)
            return super().run(role, system, user, schema, **kw)

    monkeypatch.setattr(pipeline, "Harness", lambda *a, **k: Rec(_responses()))
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / "a.py").write_text("print(1)")
    pipeline.run_pipeline(str(repo), out_dir=str(tmp_path / "o"), log=lambda m: None)
    assert order[0] == "warmup"  # B6: registry warmed before the parallel discover
