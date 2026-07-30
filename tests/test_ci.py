"""K2 — scan a PR's diff and comment the band-aid. Offline: a real local git repo for the diff, a
faked pipeline, and no GitHub call."""
from __future__ import annotations

import json
import subprocess

import pytest

from vpcopilot import ci


def _git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def repo(tmp_path):
    """A real two-branch repo, so the merge-base logic is exercised rather than mocked."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r.parent, "init", "-q", str(r)) if False else subprocess.run(
        ["git", "init", "-q", str(r)], check=True)
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "t")
    (r / "app.py").write_text("def ok():\n    return 1\n")
    (r / "README.md").write_text("readme\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "branch", "-M", "main")
    _git(r, "checkout", "-q", "-b", "feature")
    (r / "pay.py").write_text("def pay(amount):\n    return amount\n")
    (r / "notes.txt").write_text("not code\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "add pay")
    return r


# ============================================================ the diff
def test_only_the_branchs_own_changed_code_files_are_scanned(repo):
    changed, base, total = ci.changed_files(str(repo), base="main", head="HEAD", log=lambda m: None)
    assert changed == {"pay.py"}                 # notes.txt is not a code extension
    assert base and len(base) == 40


def test_the_diff_is_against_the_merge_base_not_the_tip_of_base(repo):
    """Three dots, not two. With two, every commit that landed on the base branch since the branch
    point reads as a change in this PR — so a busy main makes every PR look like it touched half the
    tree and the review stops being about the diff."""
    _git(repo, "checkout", "-q", "main")
    (repo / "unrelated.py").write_text("# landed on main after the branch point\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unrelated main work")
    _git(repo, "checkout", "-q", "feature")

    changed, _, _total = ci.changed_files(str(repo), base="main", head="HEAD", log=lambda m: None)
    assert changed == {"pay.py"}, "a commit on main leaked into the PR's diff"


def test_a_deleted_file_is_not_offered_for_scanning(repo):
    (repo / "app.py").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "delete app")
    changed, _, _total = ci.changed_files(str(repo), base="main", head="HEAD", log=lambda m: None)
    assert "app.py" not in changed and changed == {"pay.py"}


def test_a_shallow_checkout_declines_with_the_fix_named(tmp_path):
    """actions/checkout fetches one commit by default, which leaves `git merge-base` nothing to find.
    The failure has to name the remedy, because it is the first thing anyone hits in CI."""
    r = tmp_path / "shallow"
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    with pytest.raises(ci.CIError, match="fetch-depth"):
        ci.changed_files(str(r), base="origin/main", head="HEAD", log=lambda m: None)


# ============================================================ scoping the scan
def test_collect_files_restricted_to_a_set_still_applies_every_other_rule(tmp_path):
    """`only` filters the walk rather than replacing it: a changed file that is too large, vendored or
    an unsupported extension is excluded and reported exactly as in a full scan."""
    from vpcopilot.repo_scan import collect_files
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "big.py").write_text("y = 1\n" * 5000)
    (tmp_path / "n.txt").write_text("not code\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "v.py").write_text("vendored\n")

    files, skipped = collect_files(str(tmp_path), max_bytes=100,
                                  only={"a.py", "big.py", "n.txt", "node_modules/v.py"})
    assert [f.name for f in files] == ["a.py"]
    assert ("big.py", "too-large") in skipped          # still reported, not silently dropped


def test_collect_files_without_only_is_unchanged(tmp_path):
    """No regression: the existing call path walks everything."""
    from vpcopilot.repo_scan import collect_files
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 1\n")
    assert {f.name for f in collect_files(str(tmp_path))[0]} == {"a.py", "b.py"}


def test_the_pipeline_passes_only_files_through(monkeypatch, tmp_path):
    from vpcopilot import repo_scan
    seen = {}
    orig = repo_scan.collect_files

    def spy(root, **kw):
        seen.update(kw)
        return orig(root, **kw)
    monkeypatch.setattr("vpcopilot.pipeline.collect_files", spy)
    (tmp_path / "a.py").write_text("x = 1\n")
    from vpcopilot.harness import Harness
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    from vpcopilot.agents import discover
    monkeypatch.setattr(discover, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")))
    from vpcopilot.pipeline import run_pipeline
    try:
        run_pipeline(str(tmp_path), out_dir=str(tmp_path / "o"), only_files={"a.py"},
                     log=lambda m: None)
    except Exception:  # noqa: BLE001 — discovery is stubbed to stop early
        pass
    assert seen.get("only") == {"a.py"}


# ============================================================ the comment
FINDINGS = [
    {"id": "neg-pay-001", "title": "Negative amount accepted", "severity": "critical",
     "file": "pay.py", "line": 2, "description": "No lower bound on amount."},
    {"id": "low-001", "title": "Verbose error", "severity": "low", "file": "pay.py"},
]
TRIAGE = {
    "neg-pay-001": {"finding_id": "neg-pay-001", "no_bandaid": False,
                    "bandaids": [{"control": "service_policy", "recommended": True},
                                 {"control": "api_schema", "recommended": False}]},
    "low-001": {"finding_id": "low-001", "no_bandaid": True, "residual_risk": "cosmetic"},
}
POLICIES = [{"finding_id": "neg-pay-001", "control": "service_policy",
             "policy_name": "deny-negative-pay-amount"}]


def test_the_comment_carries_the_finding_the_control_and_the_policy():
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=3, scanned=1)
    assert ci.MARKER in body
    assert "neg-pay-001" in body and "pay.py" in body
    assert "`service_policy`" in body and "`api_schema` (alt)" in body
    assert "deny-negative-pay-amount" in body
    assert "low-001" not in body                       # below the threshold
    assert "1 lower-severity finding" not in body      # only said when NOTHING is reported


def test_an_unmeasured_blast_radius_says_so_rather_than_implying_safety():
    """The acceptance asked for the simulation result AND for never writing to XC. Measuring blast
    radius means attaching a policy to a load balancer — three tenant writes — so it cannot happen
    here. Neither silence nor "0%" is acceptable: both read as measured-and-safe."""
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1)
    assert "Blast radius: not measured" in body
    assert "cannot make" in body or "deliberately cannot" in body
    assert "vpcopilot simulate" in body                # names how to get the number


def test_a_supplied_simulation_result_is_reported_with_its_verdict():
    sim = {"deny-negative-pay-amount": {"policy_name": "deny-negative-pay-amount", "evaluated": 200,
                                        "would_block": 1, "block_rate": 0.005,
                                        "blocked_promotion": False}}
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim)
    assert "would block **1** of 200" in body and "0.5%" in body
    assert "under the threshold" in body
    assert "not measured" not in body


def test_an_overbroad_simulation_result_is_flagged():
    sim = {"deny-negative-pay-amount": {"policy_name": "deny-negative-pay-amount", "evaluated": 200,
                                        "would_block": 154, "block_rate": 0.77,
                                        "blocked_promotion": True}}
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim)
    assert "over the blast-radius threshold" in body and "77.0%" in body


def test_a_carried_forward_number_is_labelled_as_stale():
    """The G2/K1 `carried_from` marker has to survive into the comment: a number measured by an
    earlier replay must not be presented as this policy's fresh result."""
    sim = {"deny-negative-pay-amount": {"policy_name": "deny-negative-pay-amount", "evaluated": 200,
                                        "would_block": 1, "block_rate": 0.005,
                                        "blocked_promotion": False,
                                        "carried_from": "2026-07-29T10:00:00Z"}}
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim)
    assert "Carried forward" in body and "2026-07-29T10:00:00Z" in body


def test_a_no_bandaid_finding_says_the_code_fix_is_the_only_answer():
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="low", changed=1, scanned=1)
    assert "No band-aid" in body and "cosmetic" in body


def test_findings_held_back_by_the_threshold_are_counted_when_none_are_reported():
    """"We did not report this" must not read as "there was nothing": a clean-looking comment on a PR
    that had two medium findings is the confusion this codebase exists to avoid."""
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="critical", changed=1,
                             scanned=1)
    assert "neg-pay-001" in body                        # critical is at the floor

    only_low = [f for f in FINDINGS if f["severity"] == "low"]
    body2 = ci.render_comment(only_low, TRIAGE, [], min_severity="high", changed=1, scanned=1)
    assert "No findings at or above `high`" in body2
    assert "1 lower-severity finding(s) were found and not reported" in body2


def test_unscanned_changed_files_are_disclosed():
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=50,
                             scanned=40, truncated=10)
    assert "10 changed file(s) were not scanned" in body
    assert "not covered by this review" in body


def test_the_comment_is_deterministic():
    """Rendered by code, not a model: the same inputs must produce the same bytes, or a re-run
    rewrites the comment for no reason and nobody can diff two reviews."""
    a = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=3, scanned=1)
    b = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=3, scanned=1)
    assert a == b


# ============================================================ review orchestration
def _fake_run(out, findings, triage, policies, files=1):
    def run_pipeline(repo_path=None, **kw):
        o = kw["out_dir"]
        from pathlib import Path
        Path(o).mkdir(parents=True, exist_ok=True)
        (Path(o) / "findings.json").write_text(json.dumps(findings))
        (Path(o) / "triage.json").write_text(json.dumps(list(triage.values())))
        (Path(o) / "policies.json").write_text(json.dumps(policies))
        (Path(o) / "metrics.json").write_text(json.dumps({"discovery": {"files": files}}))
        return {"candidates": len(findings), "verified": len(findings)}
    return run_pipeline


def test_a_pr_with_no_scannable_change_scans_nothing_and_posts_nothing(repo, monkeypatch, tmp_path):
    _git(repo, "checkout", "-q", "-b", "docs-only", "main")
    (repo / "DOC.md").write_text("docs\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "docs")
    called = {"ran": False}
    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda *a, **k: called.update(ran=True) or {})
    res = ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), log=lambda m: None)
    assert res["reported"] == 0 and res["posted"] is False
    assert not called["ran"], "the pipeline ran for a diff with no scannable files"
    assert "no scannable files" in res["reason"]


def test_a_pr_with_no_findings_posts_nothing(repo, monkeypatch, tmp_path):
    """Acceptance: "a PR with no new findings posts nothing". A bot that comments "all clear" on
    every PR trains people to stop reading it."""
    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, [], {}, []))
    posted = {"n": 0}
    monkeypatch.setattr(ci, "upsert_comment", lambda *a, **k: posted.update(n=posted["n"] + 1))
    res = ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), post=True,
                    repo_slug="o/n", pr_number=1, log=lambda m: None)
    assert res["reported"] == 0 and posted["n"] == 0
    assert "No findings at or above" in res["comment"]


def test_a_pr_with_a_known_flaw_gets_one_comment(repo, monkeypatch, tmp_path):
    """Acceptance: one comment carrying the policy. One, not one per finding."""
    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, FINDINGS, TRIAGE, POLICIES))
    calls = []
    monkeypatch.setattr(ci, "upsert_comment",
                        lambda slug, num, body, **k: calls.append((slug, num, body)) or
                        {"posted": True, "updated": False})
    res = ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), post=True,
                    repo_slug="o/n", pr_number=7, log=lambda m: None)
    assert res["reported"] == 1 and len(calls) == 1
    assert calls[0][:2] == ("o/n", 7)
    assert "deny-negative-pay-amount" in calls[0][2]


def test_posting_needs_both_the_slug_and_the_number(repo, monkeypatch, tmp_path):
    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, FINDINGS, TRIAGE, POLICIES))
    with pytest.raises(ci.CIError, match="--pr"):
        ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), post=True,
                  repo_slug="o/n", log=lambda m: None)


def test_the_review_never_drafts_code_fixes(repo, monkeypatch, tmp_path):
    """The band-aid and the finding are the deliverable; drafting the cure is the expensive half of a
    scan, for a file the developer is editing by hand right now."""
    from vpcopilot import pipeline
    seen = {}

    def spy(repo_path=None, **kw):
        seen.update(kw)
        return _fake_run(tmp_path, [], {}, [])(repo_path, **kw)
    monkeypatch.setattr(pipeline, "run_pipeline", spy)
    ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), log=lambda m: None)
    assert seen["draft_code_fixes"] is False
    assert seen["only_files"] == {"pay.py"}


def test_a_previous_simulation_on_disk_is_picked_up(repo, monkeypatch, tmp_path):
    from vpcopilot import pipeline
    o = tmp_path / "o"
    o.mkdir()
    (o / "simulation.json").write_text(json.dumps({"policies": [
        {"policy_name": "deny-negative-pay-amount", "evaluated": 200, "would_block": 1,
         "block_rate": 0.005, "blocked_promotion": False}]}))
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, FINDINGS, TRIAGE, POLICIES))
    res = ci.review(str(repo), base="main", out_dir=str(o), log=lambda m: None)
    assert "would block **1** of 200" in res["comment"]


def test_a_corrupt_simulation_file_does_not_become_a_fake_number(repo, monkeypatch, tmp_path):
    from vpcopilot import pipeline
    o = tmp_path / "o"
    o.mkdir()
    (o / "simulation.json").write_text("{ corrupt")
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, FINDINGS, TRIAGE, POLICIES))
    res = ci.review(str(repo), base="main", out_dir=str(o), log=lambda m: None)
    assert "Blast radius: not measured" in res["comment"]


# ============================================================ never writes to XC
def test_the_ci_path_cannot_reach_the_tenant():
    """Structural, not promised: this module imports no tenant client and no apply path, so there is
    no code path from CI to a load balancer. A test that reads the source is the only version of this
    guarantee that survives someone adding a convenient import later."""
    import inspect
    src = inspect.getsource(ci)
    for forbidden in ("from .xc", "import xc", "XC(", "apply_from_scan", "refine_apply",
                      "simulate_policies", "promotion_gate", "retire_finding"):
        assert forbidden not in src, f"ci.py references {forbidden}"


def test_xc_credentials_in_the_environment_are_warned_about(repo, monkeypatch, tmp_path):
    """An XC credential present in CI is one any workflow on the repo can reach, and this path has no
    use for it. Said out loud rather than silently tolerated."""
    from vpcopilot import pipeline
    monkeypatch.setenv("XC_API_TOKEN", "should-not-be-here")
    monkeypatch.setattr(pipeline, "run_pipeline", _fake_run(tmp_path, [], {}, []))
    lines = []
    ci.review(str(repo), base="main", out_dir=str(tmp_path / "o"), log=lines.append)
    assert any("XC credentials are present" in ln for ln in lines)


def test_the_action_passes_no_xc_secrets():
    """The action definition is the other half of the guarantee: no XC input exists to pass one."""
    from pathlib import Path
    y = Path(__file__).resolve().parents[1] / ".github/actions/vpcopilot-scan/action.yml"
    text = y.read_text()
    assert "XC_API_TOKEN" not in text and "XC_API_URL" not in text and "XC_NAMESPACE" not in text
    assert "anthropic-api-key" in text and "github-token" in text


def test_the_action_declares_the_inputs_the_cli_supports():
    from pathlib import Path
    y = (Path(__file__).resolve().parents[1] / ".github/actions/vpcopilot-scan/action.yml").read_text()
    for inp in ("min-severity", "max-files", "fail-on-findings", "simulation-json", "base"):
        assert f"{inp}:" in y, inp
    # the merge-base problem is the first thing anyone hits, so the action deepens the checkout itself
    assert "merge-base" in y and "deepen" in y


# ============================================================ path relativity
def test_a_subdirectory_scan_matches_the_diff_paths(tmp_path):
    """The bug that would have shipped a silent all-clear. `git diff --name-only` answers relative to
    the REPOSITORY ROOT; `collect_files` matches relative to the directory it is given. This project's
    own app fixture lives eight levels down, so compared directly the two never match: zero files
    scanned, no findings, and the PR told it is clean. Catching that needs noticing the absence of an
    error, which is why it is pinned."""
    from vpcopilot.repo_scan import collect_files
    r = tmp_path / "repo"
    sub = r / "app" / "src"
    sub.mkdir(parents=True)
    (sub / "pay.py").write_text("def pay(a):\n    return a\n")
    (r / "top.py").write_text("x = 1\n")

    changed = {"app/src/pay.py", "top.py"}
    inside, outside = ci.rebase_onto(changed, str(sub), str(r))
    assert inside == {"pay.py"}            # rebased onto the scanned dir…
    assert outside == 1                    # …and the rest is counted, not forgotten
    assert [f.name for f in collect_files(str(sub), only=inside)[0]] == ["pay.py"]


def test_a_diff_entirely_outside_the_scanned_directory_says_so(repo, monkeypatch, tmp_path):
    """"Nothing in the directory I scan changed" is a different answer from "nothing is wrong", and
    the reason has to survive into the result."""
    from vpcopilot import pipeline
    ran = {"n": 0}
    monkeypatch.setattr(pipeline, "run_pipeline", lambda *a, **k: ran.update(n=ran["n"] + 1) or {})
    only = repo / "elsewhere"
    only.mkdir()
    res = ci.review(str(only), base="main", out_dir=str(tmp_path / "o"), log=lambda m: None)
    assert res["reported"] == 0 and ran["n"] == 0
    assert res["outside"] == 1 and "outside" in res["reason"]


def test_an_all_clear_discloses_an_unscanned_remainder():
    """An all-clear that hides what it did not scan is the one output this feature must never
    produce."""
    body = ci.render_comment([], {}, [], min_severity="high", changed=50, scanned=40,
                             truncated=10, outside=3)
    assert "No findings at or above" in body
    assert "not scanned" in body and "not a clean bill of health" in body
    assert "outside the scanned directory" in body


def test_the_pr_review_workflow_is_safe_and_self_consistent():
    """`pull_request_target` would run trusted workflow code with secrets against untrusted head
    code — the standard way a repository leaks its secrets. Not worth a review comment. And the
    checkout must be deep, or `git merge-base` has nothing to find."""
    from pathlib import Path

    import yaml
    root = Path(__file__).resolve().parents[1]
    wf = yaml.safe_load((root / ".github/workflows/pr-review.yml").read_text())
    # YAML 1.1 reads a bare `on:` key as the BOOLEAN True, so a workflow's triggers land under
    # `True` rather than `"on"` with pyyaml. Accept either.
    triggers = wf.get("on", wf.get(True))
    # assert on the parsed TRIGGERS, not the raw text — the file names pull_request_target in a
    # comment explaining why it is not used, which is exactly the documentation we want to keep
    assert "pull_request_target" not in triggers
    assert "pull_request" in triggers
    assert wf["permissions"]["pull-requests"] == "write"
    assert wf["permissions"]["contents"] == "read"
    steps = wf["jobs"]["review"]["steps"]
    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0
    # the test gate must not gain a model credential or a comment permission
    ci_yml = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    assert "review" not in ci_yml["jobs"]


def test_docs_ci_states_the_criterion_conflict_rather_than_papering_over_it():
    """The project's rule: where an acceptance criterion is unachievable, say so and explain why."""
    from pathlib import Path
    txt = (Path(__file__).resolve().parents[1] / "docs/CI.md").read_text()
    assert "contradicted itself" in txt
    assert "never writes to XC" in txt and "three writes" in txt
    assert "pull_request_target" in txt          # the fork trade-off is documented, not hidden


def test_the_ci_fixture_stays_out_of_the_benchmark_scan_target():
    """The K2 fixture is a deliberately vulnerable route. Inside
    `bench/fixtures/nimbus-vuln-lab/app/src/app/api` — the directory `bench` scans against
    `answer_key.yaml` — its findings appear in neither `expected` nor `bonus`, and `bench.py` counts
    anything else as NOISE. A test fixture would then silently degrade the precision column of the
    committed scorecard and BASELINE.md. It lives in `bench/fixtures/ci/` instead."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    target = root / "bench/fixtures/nimbus-vuln-lab/app/src/app/api"
    assert (root / "bench/fixtures/ci/refund-route.js").is_file()
    assert not (target / "refund").exists()
    # the README says why, so the next person does not helpfully move it back
    readme = (root / "bench/fixtures/ci/README.md").read_text()
    assert "answer_key.yaml" in readme and "noise" in readme


# ============================================================ review findings, pinned
def test_a_zero_evaluated_simulation_is_no_evidence_not_a_low_rate():
    """Found by adversarial review. G2 treats zero evaluated as NO EVIDENCE, explicitly not as safe —
    every replayed request failed in transit. Rendering "would block 0 of 0 (0.0%) — under the
    threshold" turned a measurement that failed into the most reassuring line in the comment."""
    sim = {"deny-negative-pay-amount": {
        "policy_name": "deny-negative-pay-amount", "evaluated": 0, "would_block": 0,
        "block_rate": 0.0, "blocked_promotion": False,
        "reason": "zero evidence: every replayed request failed in transit"}}
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim)
    assert "no evidence" in body and "nothing was measured" in body
    assert "under the threshold" not in body
    assert "would block **0** of 0" not in body


def test_a_comment_over_githubs_cap_is_truncated_with_the_count_dropped():
    """GitHub rejects an issue-comment body over 65536 characters, and the failure mode is the whole
    comment being lost to an API error — the review silently not happening."""
    many = [{"id": f"f-{i}", "title": f"Finding {i}", "severity": "critical", "file": "a.py",
             "description": "x" * 3000} for i in range(60)]
    triage = {f["id"]: {"finding_id": f["id"],
                        "bandaids": [{"control": "service_policy", "recommended": True}]}
              for f in many}
    pols = [{"finding_id": f["id"], "control": "service_policy", "policy_name": f"p-{i}"}
            for i, f in enumerate(many)]
    body = ci.render_comment(many, triage, pols, min_severity="high", changed=1, scanned=1)
    assert len(body) <= ci.MAX_BODY
    assert "comment was truncated" in body
    assert "of 60 finding(s) are not shown" in body


def test_a_short_comment_is_not_truncated():
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1)
    assert "truncated" not in body


def test_the_marker_is_matched_at_the_start_so_a_quoted_reply_is_not_overwritten():
    """A human quoting the bot produces `> <!-- vpcopilot:pr-review -->`. Matching with `in` would
    find that and overwrite the person's comment with the review."""
    import inspect
    src = inspect.getsource(ci.upsert_comment)
    assert ".startswith(MARKER)" in src
    assert "if MARKER in" not in src
    # and our own comments really do start with it, or the anchor never matches at all
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1)
    assert body.startswith(ci.MARKER)


def test_the_action_normalises_an_origin_prefixed_base():
    """`base: origin/main` is the natural thing to pass — it is the CLI's own default — and blindly
    re-prefixing asks git for `origin/origin/main`, which has no merge base."""
    from pathlib import Path
    y = (Path(__file__).resolve().parents[1]
         / ".github/actions/vpcopilot-scan/action.yml").read_text()
    assert 'BASE_REF="${BASE_REF_RAW#origin/}"' in y


def test_the_action_passes_inputs_through_env_not_shell_interpolation():
    """A `${{ }}` expansion inside `run:` is substituted as TEXT before bash parses the line, which
    is the standard GitHub Actions script-injection vector."""
    import re

    from pathlib import Path

    import yaml
    d = yaml.safe_load((Path(__file__).resolve().parents[1]
                        / ".github/actions/vpcopilot-scan/action.yml").read_text())
    for s in d["runs"]["steps"]:
        for ln in (s.get("run") or "").splitlines():
            if ln.lstrip().startswith("#"):
                continue                     # a comment explaining the hazard is not the hazard
            for m in re.findall(r"\$\{\{\s*[\w.\-]+[^}]*\}\}", ln):
                assert any(k in m for k in ("github.action_path", "github.workspace")), \
                    f"{s.get('name')} interpolates {m} into a shell command"


def test_a_non_ascii_or_spaced_filename_is_not_silently_dropped(tmp_path):
    """Found while verifying the review. Git QUOTES paths by default: a non-ASCII filename comes back
    from `--name-only` as `"caf\\303\\251.py"` — C-style octal escapes inside literal quotes — so its
    suffix reads as `.py"`, no known code extension matches, and the file is dropped from the scan set
    *and* not counted as outside it. It vanishes, and the pull request is told it is clean. `-z`
    output is not quoted at all, which settles spaces and newlines too."""
    from vpcopilot.repo_scan import collect_files
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    _git(r, "config", "user.email", "t@e.com")
    _git(r, "config", "user.name", "t")
    (r / "base.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    _git(r, "branch", "-M", "main")
    _git(r, "checkout", "-q", "-b", "feature")
    for name in ("café.py", "my file.py", "日本語.py"):
        (r / name).write_text("def f():\n    pass\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "odd names")

    changed, _, _total = ci.changed_files(str(r), base="main", log=lambda m: None)
    assert changed == {"café.py", "my file.py", "日本語.py"}
    assert not any('"' in n or "\\3" in n for n in changed)     # nothing arrived quoted
    inside, outside = ci.rebase_onto(changed, str(r), str(r))
    assert outside == 0
    assert {f.name for f in collect_files(str(r), only=inside)[0]} == changed


def test_only_verified_findings_are_reported_never_refuted_candidates(repo, monkeypatch, tmp_path):
    """Found by adversarial review. `findings.json` is the DISCOVER contract — every candidate,
    including the ones `verify` refuted as false positives — and the old filter compared that set
    against itself, so it was a no-op. Triage runs only over the verified set, so a triage decision
    is what "survived verification" looks like on disk. Putting refuted false positives in front of a
    developer with a band-aid attached is the fastest way to teach a team to ignore this bot."""
    from vpcopilot import pipeline
    o = tmp_path / "o"
    candidates = FINDINGS + [{"id": "refuted-001", "title": "Not real", "severity": "critical",
                              "file": "pay.py"}]
    monkeypatch.setattr(pipeline, "run_pipeline",
                        _fake_run(tmp_path, candidates, TRIAGE, POLICIES))
    res = ci.review(str(repo), base="main", out_dir=str(o), log=lambda m: None)
    assert res["candidates"] == 3 and res["refuted"] == 1
    assert {f["id"] for f in res["findings"]} == {"neg-pay-001", "low-001"}
    assert res["reported"] == 1                      # only the critical verified one
    assert "refuted-001" not in res["comment"]
    assert "Not real" not in res["comment"]


def test_truncation_keeps_the_disclosures_it_used_to_delete():
    """The naive truncation cut from the end — which is exactly where "N files were not scanned" and
    "N sit outside the scanned directory" live. The sentences that stop a partial review reading as a
    complete one were the first thing dropped."""
    many = [{"id": f"f-{i}", "title": f"Finding {i}", "severity": "critical", "file": "a.py",
             "description": "x" * 3000} for i in range(60)]
    triage = {f["id"]: {"finding_id": f["id"],
                        "bandaids": [{"control": "service_policy", "recommended": True}]}
              for f in many}
    body = ci.render_comment(many, triage, [], min_severity="high", changed=90, scanned=40,
                             truncated=12, outside=5)
    assert len(body) <= ci.MAX_BODY
    assert "comment was truncated" in body
    assert "12 changed file(s) were not scanned" in body      # survived the cut
    assert "5 changed file(s) sit outside" in body            # survived the cut
    assert body.rstrip().endswith("</sub>")                   # footer intact


def test_an_unconfirmed_enforcement_is_not_reported_as_a_rate():
    """G2's FIRST live defect: attaching a policy and replaying immediately counted an UNENFORCED
    policy as harmless — 0 of 200 blocked, including the exploit. A rate measured before the edge was
    confirmed enforcing measures nothing."""
    sim = {"deny-negative-pay-amount": {
        "policy_name": "deny-negative-pay-amount", "evaluated": 200, "would_block": 0,
        "block_rate": 0.0, "blocked_promotion": False, "enforcement_confirmed": False}}
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim)
    assert "Blast radius: unconfirmed" in body
    assert "under the threshold" not in body
    assert "would block **0** of 200" not in body


def test_a_confirmed_enforcement_still_reports_the_rate():
    """No regression: a confirmed simulation reports its numbers as before. Absent
    `enforcement_confirmed` also reports, so an older simulation.json is not treated as unconfirmed."""
    for extra in ({"enforcement_confirmed": True}, {}):
        sim = {"deny-negative-pay-amount": {
            "policy_name": "deny-negative-pay-amount", "evaluated": 200, "would_block": 1,
            "block_rate": 0.005, "blocked_promotion": False, **extra}}
        body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1,
                                 scanned=1, sim=sim)
        assert "would block **1** of 200" in body, extra
        assert "unconfirmed" not in body, extra


def test_an_unexpected_failure_exits_2_not_1(repo, monkeypatch, tmp_path):
    """Exit 1 means "findings were reported" and the action reads it that way, so a crash exiting 1
    would make a review that never completed look like a completed one with findings — and the
    workflow would publish a comment file that does not exist."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    monkeypatch.setattr("vpcopilot.ci.review",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("model API down")))
    r = CliRunner().invoke(cli.app, ["ci-review", "--repo", str(repo), "--base", "main",
                                     "--out", str(tmp_path / "o")])
    assert r.exit_code == 2, r.output


def test_an_unknown_min_severity_is_rejected_rather_than_defaulted(repo, tmp_path):
    """Unvalidated, it fell through `SEVERITY_RANK.get(..., 1)` to `high` — and the comment then
    stated a threshold the run had not applied."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    r = CliRunner().invoke(cli.app, ["ci-review", "--repo", str(repo), "--base", "main",
                                     "--min-severity", "urgent", "--out", str(tmp_path / "o")])
    assert r.exit_code == 2 and "must be critical, high, medium or low" in r.output


def test_the_action_summary_distinguishes_a_crash_from_a_clean_review():
    """`if: always()` means the summary also runs when the review crashed. Without knowing which, it
    wrote "no findings at or above the threshold" for a diff that was never reviewed."""
    from pathlib import Path
    y = (Path(__file__).resolve().parents[1]
         / ".github/actions/vpcopilot-scan/action.yml").read_text()
    assert "steps.review.outcome" in y
    assert "did not complete" in y and "not a clean bill of health" in y


def test_a_diff_outside_the_scanned_directory_produces_a_comment_that_says_so(repo, monkeypatch,
                                                                             tmp_path):
    """Found by adversarial review — the mirror image of the rebase bug. The early return handed back
    `comment: ""`, so `--comment-out` wrote nothing and the action's step summary fell through to "no
    findings at or above the threshold": a clean bill of health for a diff that was never reviewed.
    Nothing is POSTED (there is nothing to report), but the surface a human reads must say which of
    the two happened."""
    from vpcopilot import pipeline
    monkeypatch.setattr(pipeline, "run_pipeline", lambda *a, **k: {})
    only = repo / "elsewhere"
    only.mkdir()
    res = ci.review(str(only), base="main", out_dir=str(tmp_path / "o"), log=lambda m: None)
    assert res["reported"] == 0 and res["posted"] is False
    assert res["comment"], "an empty comment renders downstream as a clean review"
    assert "Nothing was reviewed" in res["comment"]
    assert "not** a clean bill of health" in res["comment"]
    assert res["comment"].startswith(ci.MARKER)


def test_the_header_denominator_is_the_whole_diff_not_just_the_supported_files():
    """"Scanned 1 of 1" for a diff of eleven files reads as a complete review of the whole change."""
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             diff_total=11)
    assert "of 1 scannable file(s)" in body and "11 changed in total" in body


def test_the_not_scanned_disclosure_names_every_cause_not_just_the_caps():
    """`truncated` counts every file the collector declined for ANY reason — vendored directories and
    unsupported extensions included — so naming only the caps was wrong, and telling the reader to
    raise them was advice that could not work."""
    for kw in ({"truncated": 3}, {"truncated": 3, "min_severity": "critical"}):
        body = ci.render_comment(
            FINDINGS if "min_severity" not in kw else [], TRIAGE, POLICIES,
            min_severity=kw.get("min_severity", "high"), changed=10, scanned=7,
            truncated=kw["truncated"])
        assert "vendored directory" in body and "unsupported file type" in body, kw


def test_a_repo_outside_a_git_worktree_declines_with_a_reason(tmp_path):
    """Previously an unguarded `rev-parse --show-toplevel` propagated a raw CalledProcessError."""
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    with pytest.raises(ci.CIError):
        ci.changed_files(str(outside), base="main", log=lambda m: None)


def test_a_rate_measured_against_bodyless_traffic_is_qualified(tmp_path):
    """Found by adversarial review, and the third instance of the same shape in one review (after
    not-measured, unconfirmed and zero-evaluated). `bodies_available` is false when the sample came
    from XC access logs, which capture no request body — so a `body_matcher` service policy matches
    nothing during replay and scores a perfectly clean 0%. Keeping only the per-policy dicts threw
    away the one field that says the rate is unjudgeable."""
    (tmp_path / "simulation.json").write_text(json.dumps({
        "ts": "2026-07-29T10:00:00Z", "bodies_available": False, "records": 500,
        "caveats": ["Records came from XC access logs, which capture no request body"],
        "policies": [{"policy_name": "deny-negative-pay-amount", "evaluated": 500,
                      "would_block": 0, "block_rate": 0.0, "blocked_promotion": False,
                      "enforcement_confirmed": True}]}))
    sim, meta = ci._blast_radius(str(tmp_path))
    assert meta["bodies_available"] is False and meta["caveats"]
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim, sim_meta=meta)
    assert "no request bodies" in body
    assert "unmeasured, not safe" in body


def test_a_body_carrying_sample_is_not_qualified(tmp_path):
    """No regression: a HAR sample carries bodies, so its rate stands unqualified."""
    (tmp_path / "simulation.json").write_text(json.dumps({
        "bodies_available": True,
        "policies": [{"policy_name": "deny-negative-pay-amount", "evaluated": 200,
                      "would_block": 1, "block_rate": 0.005, "blocked_promotion": False}]}))
    sim, meta = ci._blast_radius(str(tmp_path))
    body = ci.render_comment(FINDINGS, TRIAGE, POLICIES, min_severity="high", changed=1, scanned=1,
                             sim=sim, sim_meta=meta)
    assert "would block **1** of 200" in body and "no request bodies" not in body


def test_an_absent_simulation_returns_two_empty_dicts(tmp_path):
    assert ci._blast_radius(str(tmp_path)) == ({}, {})
