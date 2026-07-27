"""G4 — the published model scorecard.

`bench.py` scored recall and triage against the answer key. G4 adds the missing half of the old
BACKLOG ask (verify PRECISION — the false-positive filter rate), the discovery-duplicate counter,
and `scorecard.py`, which turns per-config bench results into one committed `benchmarks/RESULTS.md`.

Offline: scores are hand-built dicts, so nothing here scans or calls a model."""
import json

from vpcopilot import scorecard


def _score(**over):
    base = {"expected": 9, "found": 9, "discovery_recall": 1.0, "triage_correct": 9,
            "triage_accuracy": 1.0, "bonus_found": 7, "bonus_total": 8, "noise": 0,
            "verified": 16, "verify_precision": 1.0, "duplicates_dropped": 2,
            "wall_time_s": 41.2}
    base.update(over)
    return base


# ---- verify precision: the residue from the old BACKLOG item ----
def test_precision_counts_key_matches_and_bonus_as_real(tmp_path):
    """Precision is real-over-verified: a finding that matched the key OR a bonus entry is real;
    everything else the verifier let through is noise."""
    from vpcopilot.bench import _precision
    assert _precision(used=9, verified=9) == 1.0
    assert _precision(used=8, verified=16) == 0.5
    assert _precision(used=0, verified=0) == 0.0        # nothing verified -> no claim, not a crash


def test_precision_and_recall_are_different_numbers():
    """Recall asks 'did we find the known vulns'; precision asks 'was what we reported real'.
    A run can ace one and fail the other — which is the whole reason the item exists."""
    from vpcopilot.bench import _precision
    assert _precision(used=9, verified=30) < 0.35       # perfect recall, poor precision


# ---- the scorecard table ----
def test_results_md_has_one_row_per_config():
    md = scorecard.build_results({
        "claude": {"model": "anthropic/claude-opus-4-8", "score": _score()},
        "openai": {"model": "openai/gpt-4.1", "score": _score(found=6, discovery_recall=0.67)},
        "gemini": {"model": "gemini/gemini-3.1-pro-preview", "score": _score(noise=3, verify_precision=0.81)},
        "dgx": {"model": "openai/qwen3-coder:30b-a3b-q8_0", "score": _score(found=5, discovery_recall=0.56)},
    }, target="Nimbus vuln-lab", key="bench/answer_key.yaml")
    rows = [ln for ln in md.splitlines() if ln.startswith("| `")]
    assert len(rows) == 4
    for tag in ("claude", "openai", "gemini", "dgx"):
        assert tag in md
    assert "anthropic/claude-opus-4-8" in md and "qwen3-coder" in md


def test_results_md_reports_every_scored_dimension():
    md = scorecard.build_results({"claude": {"model": "m", "score": _score()}},
                                 target="t", key="k")
    for header in ("recall", "precision", "triage", "bonus", "noise", "wall"):
        assert header in md.lower(), header


def test_results_md_states_the_reproducibility_limit_rather_than_claiming_it():
    """The acceptance asked that a re-run reproduce the score. It cannot: two of the four providers
    accept no seed at all, and none guarantee determinism. Saying so is the honest version."""
    md = scorecard.build_results({"claude": {"model": "m", "score": _score()}}, target="t", key="k")
    low = md.lower()
    assert "seed" in low
    assert any(w in low for w in ("not deterministic", "does not guarantee", "vary", "variance"))


def test_results_md_records_what_produced_it():
    md = scorecard.build_results({"claude": {"model": "m", "score": _score()}},
                                 target="Nimbus vuln-lab", key="bench/answer_key.yaml")
    assert "Nimbus vuln-lab" in md and "bench/answer_key.yaml" in md
    assert "vpcopilot bench" in md          # the command that regenerates it


def test_a_failed_config_is_reported_not_dropped():
    """A config whose run errored must appear with its error — a table that silently omits the
    provider that crashed reads as if it was never tried."""
    md = scorecard.build_results({
        "claude": {"model": "m", "score": _score()},
        "gemini": {"model": "gemini/x", "error": "GeminiException 404: model retired"},
    }, target="t", key="k")
    assert "gemini" in md and "404" in md
    assert len([ln for ln in md.splitlines() if ln.startswith("| `")]) == 2


def test_write_results_lands_in_benchmarks(tmp_path):
    p = scorecard.write_results({"claude": {"model": "m", "score": _score()}},
                                target="t", key="k", dest_dir=str(tmp_path))
    assert p.endswith("RESULTS.md") and "RESULTS.md" in json.dumps(p)
    assert "claude" in open(p).read()


def test_empty_results_is_a_valid_table_not_a_crash():
    md = scorecard.build_results({}, target="t", key="k")
    assert "no configs" in md.lower() or md.strip()


# ---- the sweep ----
def test_every_config_is_scored_and_tagged(monkeypatch, tmp_path):
    cfgs = tmp_path / "config"
    cfgs.mkdir()
    (cfgs / "agents.yaml").write_text("defaults:\n  model: anthropic/claude-opus-4-8\nagents: {}\n")
    (cfgs / "agents.openai.yaml").write_text("defaults:\n  model: openai/gpt-4.1\nagents: {}\n")
    (cfgs / "agents.gemini.yaml").write_text("defaults:\n  model: gemini/g-3.1\nagents: {}\n")
    seen = []
    monkeypatch.setattr(scorecard, "__name__", scorecard.__name__)
    import vpcopilot.bench as bench
    monkeypatch.setattr(bench, "run_bench",
                        lambda repo, key, **kw: seen.append(kw["out_dir"]) or {"score": _score()})
    res = scorecard.run_all_configs("repo", config_dir=str(cfgs), log=lambda m: None)
    # agents.yaml is tagged by its provider, exactly as the console's switcher does
    assert set(res) == {"claude", "openai", "gemini"}
    assert set(seen) == {"out-claude", "out-openai", "out-gemini"}
    assert res["openai"]["model"] == "openai/gpt-4.1"


def test_one_dead_provider_does_not_abort_the_sweep(monkeypatch, tmp_path):
    """A four-way run is expensive; losing the other three because one provider 404s would be the
    worst possible failure mode."""
    cfgs = tmp_path / "config"
    cfgs.mkdir()
    (cfgs / "agents.yaml").write_text("defaults:\n  model: anthropic/claude-opus-4-8\nagents: {}\n")
    (cfgs / "agents.gemini.yaml").write_text("defaults:\n  model: gemini/retired\nagents: {}\n")
    import vpcopilot.bench as bench

    def flaky(repo, key, **kw):
        if "gemini" in kw["out_dir"]:
            raise RuntimeError("GeminiException 404: model no longer available")
        return {"score": _score()}
    monkeypatch.setattr(bench, "run_bench", flaky)
    res = scorecard.run_all_configs("repo", config_dir=str(cfgs), log=lambda m: None)
    assert res["claude"]["score"]["discovery_recall"] == 1.0
    assert "404" in res["gemini"]["error"] and "score" not in res["gemini"]
    assert "404" in scorecard.build_results(res, target="t", key="k")


def test_rescore_does_not_rerun_the_scan(monkeypatch, tmp_path):
    cfgs = tmp_path / "config"
    cfgs.mkdir()
    (cfgs / "agents.yaml").write_text("defaults:\n  model: anthropic/x\nagents: {}\n")
    got = {}
    import vpcopilot.bench as bench
    monkeypatch.setattr(bench, "run_bench",
                        lambda repo, key, **kw: got.update(kw) or {"score": _score()})
    scorecard.run_all_configs("repo", config_dir=str(cfgs), rescore=True, log=lambda m: None)
    assert got["scan"] is False


def test_a_skipped_config_is_omitted_and_declared(monkeypatch, tmp_path):
    """A model unreachable from this machine is not a model that scored badly — it must not get a
    red row, and the table must say it was left out rather than quietly under-reporting coverage."""
    cfgs = tmp_path / "config"
    cfgs.mkdir()
    (cfgs / "agents.yaml").write_text("defaults:\n  model: anthropic/x\nagents: {}\n")
    (cfgs / "agents.dgx.yaml").write_text("defaults:\n  model: openai/local\nagents: {}\n")
    import vpcopilot.bench as bench
    monkeypatch.setattr(bench, "run_bench", lambda repo, key, **kw: {"score": _score()})
    res = scorecard.run_all_configs("repo", config_dir=str(cfgs), skip=("dgx",), log=lambda m: None)
    assert set(res) == {"claude"} and "dgx" not in res
    md = scorecard.build_results(res, target="t", key="k", skipped=("dgx",))
    assert "`dgx`" in md and "unreachable" in md.lower()
    assert not [ln for ln in md.splitlines() if ln.startswith("| `dgx`")]


# ---- policy quality: the column the first real run proved the table needed ----
def test_policy_quality_counts_this_runs_index_not_the_directory(tmp_path):
    """A re-scan into an existing out dir leaves the previous run's artifacts in policies/ — 32
    files for 9 generated policies on the run that surfaced this. Globbing would score a model
    against someone else's leftovers."""
    from vpcopilot.bench import _policy_quality
    out = tmp_path
    (out / "policies").mkdir()
    (out / "policies.json").write_text(json.dumps([
        {"control": "service_policy", "policy_name": "good"}]))
    (out / "policies" / "service_policy.good.json").write_text(json.dumps({"spec": {"rule_list": {
        "rules": [{"spec": {"action": "DENY", "path": {"exact_values": ["/x"]}}}]}}}))
    (out / "policies" / "service_policy.stale-from-a-previous-run.json").write_text("{}")
    assert _policy_quality(out) == (1, 0)


def test_an_empty_spec_counts_as_unusable(tmp_path):
    """Observed live: one model returned `{}` as the spec for three policies. Structured output
    validated — `{}` is a valid dict — while the artifact was useless."""
    from vpcopilot.bench import _policy_quality
    out = tmp_path
    (out / "policies").mkdir()
    (out / "policies.json").write_text(json.dumps([
        {"control": "service_policy", "policy_name": "empty"},
        {"control": "api_schema", "policy_name": "fragment"}]))
    (out / "policies" / "service_policy.empty.json").write_text("{}")
    (out / "policies" / "api_schema.fragment.json").write_text(json.dumps({"paths": {}}))
    assert _policy_quality(out) == (2, 2)


def test_a_missing_artifact_counts_as_unusable(tmp_path):
    from vpcopilot.bench import _policy_quality
    out = tmp_path
    (out / "policies").mkdir()
    (out / "policies.json").write_text(json.dumps([{"control": "service_policy", "policy_name": "gone"}]))
    assert _policy_quality(out) == (1, 1)


def test_no_index_is_zero_not_a_crash(tmp_path):
    from vpcopilot.bench import _policy_quality
    assert _policy_quality(tmp_path) == (0, 0)


def test_the_table_marks_unusable_policies(tmp_path):
    md = scorecard.build_results({
        "good": {"model": "m", "score": _score(policies=9, policies_flagged=0)},
        "bad": {"model": "m", "score": _score(policies=6, policies_flagged=3)},
    }, target="t", key="k")
    assert "9 (0)" in md and "6 (**3**)" in md
    assert "unusable" in md.lower()
