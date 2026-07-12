"""D3: unit-test the benchmark scorer (no live scan). D4: a BASELINE-driven gate test (marked
`bench`) that fails if a scored run drops below the floors in BASELINE.md."""
import json
import re
from pathlib import Path

import pytest

from vpcopilot import bench

BASELINE = Path(__file__).resolve().parent.parent / "BASELINE.md"


def _seed(out: Path, findings, triage):
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings))
    (out / "triage.json").write_text(json.dumps(triage))


def _key(tmp_path, expected):
    import yaml
    p = tmp_path / "key.yaml"
    p.write_text(yaml.safe_dump({"expected": expected}))
    return str(p)


# ---- D3: scorer helpers + run_bench(scan=False) ----

def test_scorer_helpers():
    assert bench._tail("/identity/api/v2/user") == "v2/user"
    assert bench._class_ok("sqli", "sqli") and not bench._class_ok("sqli", "xss")
    assert bench._class_ok("broken_auth", "broken_object_authz")  # compatible label
    assert bench._file_ok("services/login.js", "login.js")        # suffix match


def test_run_bench_scores_a_seeded_run(tmp_path):
    out = tmp_path / "out"
    findings = [
        {"id": "a", "file": "login.js", "vuln_class": "sqli"},
        {"id": "b", "file": "me.js", "vuln_class": "broken_object_authz"},
        {"id": "n", "file": "noise.js", "vuln_class": "xss"},  # not in key -> noise
    ]
    triage = [
        {"finding_id": "a", "no_bandaid": False, "bandaids": [{"control": "service_policy", "recommended": True}]},
        {"finding_id": "b", "no_bandaid": False, "bandaids": [{"control": "api_schema", "recommended": True}]},
        {"finding_id": "n", "no_bandaid": False, "bandaids": [{"control": "waf", "recommended": True}]},
    ]
    _seed(out, findings, triage)
    key = _key(tmp_path, [
        {"key": "sqli-login", "file": "login.js", "vuln_class": "sqli", "acceptable_controls": ["service_policy", "waf"]},
        {"key": "bola-me", "file": "me.js", "vuln_class": "broken_object_authz", "acceptable_controls": ["api_schema"]},
    ])
    res = bench.run_bench("unused", key, out_dir=str(out), scan=False, log=lambda m: None)
    s = res["score"]
    assert s["expected"] == 2 and s["found"] == 2
    assert s["discovery_recall"] == 1.0 and s["triage_accuracy"] == 1.0
    assert s["noise"] == 1  # the xss finding


def _baseline_floors():
    txt = BASELINE.read_text()
    rec = float(re.search(r"discovery_recall.*?\*\*([\d.]+)\*\*", txt).group(1))
    tri = float(re.search(r"triage_accuracy.*?\*\*([\d.]+)\*\*", txt).group(1))
    noise = int(re.search(r"noise.*?≤ (\d+)", txt).group(1))
    return rec, tri, noise


def test_baseline_file_is_parseable():
    rec, tri, noise = _baseline_floors()
    assert 0 < rec <= 1 and 0 < tri <= 1 and noise >= 0


@pytest.mark.bench
def test_bench_gate_meets_baseline(tmp_path):
    """The gate mechanism: a scored run must clear BASELINE.md's floors. Runs a deterministic
    fixture here; the nightly job feeds it a real scan of VAmPI/crAPI."""
    rec_floor, tri_floor, noise_ceil = _baseline_floors()
    out = tmp_path / "out"
    findings = [{"id": f"k{i}", "file": f"f{i}.js", "vuln_class": "sqli"} for i in range(5)]
    triage = [{"finding_id": f"k{i}", "no_bandaid": False,
               "bandaids": [{"control": "service_policy", "recommended": True}]} for i in range(5)]
    _seed(out, findings, triage)
    key = _key(tmp_path, [{"key": f"k{i}", "file": f"f{i}.js", "vuln_class": "sqli",
                           "acceptable_controls": ["service_policy"]} for i in range(5)])
    s = bench.run_bench("unused", key, out_dir=str(out), scan=False, log=lambda m: None)["score"]
    assert s["discovery_recall"] >= rec_floor, f"recall {s['discovery_recall']} < {rec_floor}"
    assert s["triage_accuracy"] >= tri_floor, f"triage {s['triage_accuracy']} < {tri_floor}"
    assert s["noise"] <= noise_ceil, f"noise {s['noise']} > {noise_ceil}"
