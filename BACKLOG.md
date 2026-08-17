# Backlog — future iterations

Loose ideas, not yet scheduled. Anything with a shape clear enough to plan against moves to
`ROADMAP.md`; anything committed lives in `PLAN.md`. Each item lives in exactly one file.

- ~~**HTML results dashboard.**~~ ✅ **Done** — `report.py` writes a single self-contained
  `<out>/report.html` (inline CSS, no external assets, native `<details>`) at the end of every
  `run_pipeline`; `vpcopilot report` rebuilds it from any existing out dir. It carries the hero,
  at-a-glance severity/coverage bars, model independence, pipeline metrics, findings + band-aid
  coverage, the generated XC policies, the `found → mitigated → remediated → retired` ledger and
  the band-aid impact table. Reachable from ② Review and Setup — **Open HTML report ↗** (rebuilt
  from the current out dir on every request, so it is never stale) and **Download** for a stamped
  `vpcopilot-report-<run>-<UTC>.html`. Not included: the benchmark scorecard — that still lives
  only in the console's ⑦ Benchmark step. Original ask: a standalone, static, shareable export of
  a run for stakeholders. _(Requested 2026-07-01.)_
- ~~**Ops console admin panel (localhost).**~~ ✅ **Done** in the console MVP — the ⚙ Setup page
  reads/writes the local `.env` (XC creds + model API keys), redacting secrets.
- ~~**Benchmark: bonus-vuln handling.**~~ ✅ **Done** as `PLAN.md` **D1** — `bonus:` in
  `bench/answer_key.yaml`; `bench.py` credits `bonus_found` and reports only genuine `noise`.
- ~~**Benchmark: per-stage metrics.**~~ ✅ **Done** as `PLAN.md` **D2** — `run_pipeline` writes
  `metrics.json` with per-stage timing and `verify.{refuted, dropped_low_confidence, confirm_rate,
  avg_confidence}` (the false-positive filter rate), rendered as the report's **Pipeline metrics**
  panel. _Residue:_ `_dedup_findings` logs discovery duplicates but the count never reaches
  `metrics.json` — one counter, tracked in `ROADMAP.md` **G4**.
- ~~**Finding correlation as a first-class step.**~~ ✅ **Done** as `PLAN.md` **B1** —
  `correlate.py` `coverage_key` collapses LB-wide controls and keys `service_policy` per endpoint;
  the pipeline skips a band-aid an earlier finding already covers and writes `correlations.json`.

- **Real live tests behind the `live` marker.** — **STARTED 2026-08-02: the harness and the first
  two suites are in** (`tests/live.py`, `tests/test_live_osv.py`, `tests/test_live_emitter.py`,
  `tests/test_live_harness.py`). `pytest -m live` collected **0 of 959** before this and collects
  **18** now, and **every candidate the entry named is covered**: the safety spine, `drift.check`
  read-only, the OSV client, the MCP handshake — plus L1's emitter proof, which post-dates the
  entry. **The nightly selector still stays `-m bench`**; widening it is a separate, deliberate act
  that needs the four secrets restored, and it should be done by someone who wants the nightly to
  mutate a real tenant every night, not as a side effect of these tests existing.
  - **`drift.check` read-only** — I2's guarantee said the endpoint is polled from a browser, so *a
    version that wrote a snapshot would corrupt the run dir just by someone opening a page*. Now
    asserted against a real LB, on both surfaces, with a companion test proving it actually **read**
    the tenant — a read-only function that read nothing would also write nothing and pass the first
    test perfectly. Verified by mutation: making `check()` write a snapshot fails all four.
  - **The MCP handshake over a REAL subprocess pipe** — K1's `✔ Connected`, which the offline suite
    cannot test: it drives `mcp.serve(StringIO, StringIO)`, and a StringIO has no real stdout to
    corrupt. This spawns the actual CLI and asserts stdout carries only protocol frames, that a
    malformed frame does not kill the connection (K1's sharpest review finding), and that the write
    tools are absent without `--write`.
  - **The safety spine is in** (`tests/test_live_spine.py`, 2026-08-02) — the item's first-listed
    candidate and the claim the whole demo rests on. Against a real XC tenant it proves the PUT
    self-test is genuinely idempotent (XC normalises what you send, so a spec that round-trips
    against a fake may not round-trip here), that the on-disk snapshot matches the live LB (rollback
    restores *from that file*, so a mismatch is a rollback that writes the wrong state back), that
    an apply with rollback returns the LB **byte-identical**, that `safe_rollback` raises rather
    than reporting a silent half-rollback when its verify never passes, and that the protected names
    still correspond to LBs that actually exist — a `VPCOPILOT_PROTECTED_LBS` entry naming nothing
    is a guard protecting nothing, and it looks identical to a working one from offline.
  - **The target is an allowlist, not an argument.** This suite mutates a **shared** estate rather
    than a box built for it, so `VPCOPILOT_LIVE_LB` must be set explicitly and is refused if it
    names a protected LB. A live test that guessed which load balancer to mutate would be the exact
    failure `guard_lb` exists to prevent, committed by the test suite itself.
  - **The headline test shipped VACUOUS in its first draft, and adversarial review caught it** — the
    exact failure mode `tests/live.py` was written to eliminate, committed by the test written to
    prove the safety spine. It asserted `rolled_back is True` and "the LB is byte-identical", and
    **both hold on a run where the control never attached**: `apply.py` sets `rolled = True`
    unconditionally in its `else` branch regardless of the readback, and "unchanged" is trivially
    true when nothing was ever written. **Demonstrated, not argued** — with the attach removed from
    `apply.py`, all three original assertions passed while `config_enabled` was `False`, the one
    fact never checked. Now it asserts the readback (`config_enabled is True`) *and* that the LB
    started clean (`diff.from == "disabled"`), because a lab left enabled by an earlier `--keep`
    demo makes even a working attach a no-op — a hole that opens with no code change at all.
    Verified by mutation: neutering the attach now fails the test.
  - Also fixed there: the evidence line read `res.get("enabled")`, and the return dict has no such
    key (it is `config_enabled`), so every run had been recording the literal `enabled=None` — "we
    did not check this" rendered as data.
  - **The MCP stdout test was vacuous twice before it bit.** First it passed `out_dir` where the
    tool accepts `out`, so `validate_args` rejected the call and it only ever saw an error frame —
    still valid JSON-RPC, still green. Fixed, it then pointed at the repo's ambient `out/`, and
    `ledger` **declines** a nonexistent run dir (a K1 review fix) — a decline is a successful
    `result`, so on a fresh checkout the tool body never ran. It now seeds a run directory it owns
    and asserts the tool actually read it. Verified by mutation: with the stdout swap disabled and a
    stray `print` planted, it fails.
  - **A caution about mutation testing in this repo, learned the hard way.** The venv's editable
    install puts the *real* `src` on `sys.path`, so a mutated copy of the tree is silently **not**
    the code a subprocess imports. Two of my mutation runs "proved" a test had no teeth when the
    mutation had never loaded. `PYTHONPATH=<copy>/src` is required, and the honest check is to
    confirm the mutant is the file being imported before believing the result.
  - **What the harness guarantees**, each pinned by a test in the ordinary offline suite:
    `requires()` **raises** rather than returning a flag, so a body cannot fall through it and
    report a pass having done nothing; an empty or whitespace value counts as absent (K2's
    `required: true` trap); `evidence` fails a test that ran and observed nothing — J3's fabricated
    records and K2's zero-file diff in test form; and `restoring()` fails loudly if cleanup does not
    stick, because a live test that leaves a control attached has changed the estate for the next
    demo.
  - **The harness's own first credential-free run found the bug it exists to prevent.** The vacuity
    check fired on tests that had *skipped* for a missing credential, turning a clean skip into an
    **ERROR** — precisely what this entry forbids ("a contributor without a tenant sees skipped,
    never failed"). Fixed by consulting the call report, and pinned by a test that skips on purpose.
  - **Two live suites, both verified against the real thing.** OSV (no credential but network) re-runs
    H2's four findings — the alias hop to an installable version, CVSS v4 not defaulting to `medium`,
    GHSA/PYSEC duplication, and OSV answering a junk version with a *bigger* set than a real one.
    The emitter suite re-runs L1's proof end to end in ~32 s: emit → attach via AS3 → fire the
    exploit → **assert the balance did not move** → restore → confirm the exploit works again. It is
    idempotent (run twice, both green) and self-cleaning.
  - **Writing the OSV tests corrected two of my own wrong assumptions about the client's return
    shape** (`resolve()` has no `package` key; the upgrade target is `fixed_version`, not `version`)
    — which is the entry's point restated: a proof nobody re-runs is a proof nobody checks.
  - _(Original entry preserved below.)_

- **Real live tests behind the `live` marker.** The marker is declared in `pyproject.toml`
  ("hits a real XC tenant / model / network — excluded from CI (run manually / nightly)") and
  **nothing uses it**: `grep -rn "mark.live" tests/` returns zero hits, so `pytest -m "live or bench"`
  collects exactly one test, and that one scores a synthetic fixture. Every roadmap item so far has
  been proven by hand against the tenant — the G2 canary, I1's origin probe, I2's `example-dev`
  diff, H1/H2's OSV behaviour, K1's MCP client handshake, K2's 76-second PR review — and **not one of
  those proofs is repeatable by anyone but the person who ran it**. That is the gap: the demo's
  central claim is "we ran it for real", and nothing in the repository re-runs it.
  - Shape: a `tests/test_live_*.py` set marked `@pytest.mark.live`, each **restoring what it
    mutates** and skipping cleanly (`pytest.skip`) when its credential is absent, so a contributor
    without a tenant sees "skipped", never "failed" and never a false pass.
  - Candidates, in the order they would pay off: the safety spine end to end on `vpcopilot-lab`
    (create → attach → validate → rollback, asserting the LB returns to its snapshot); `drift.check`
    read-only against a real LB; the OSV client against `api.osv.dev` (alias-following, CVSS v4,
    `upgrade_target_for`) — needs no XC and no model, so it is the cheapest first step; and the MCP
    server's handshake against a real client.
  - **Deliberately NOT simply widening the nightly selector.** Doing that without writing the tests
    reinstates exactly the problem this entry exists to record: a job whose name promises live
    coverage it does not have. When these land, restore the four secrets to the nightly job and widen
    `pytest -m bench` back to `pytest -m "live or bench"`.
  - Note the cost: a nightly that mutates a real tenant needs the lab LBs to be free, and
    `nimbus-www` stays protected. Budget for flakiness that is the tenant's, not the code's.
  _(Requested 2026-07-30, after the nightly job was found to be attesting to coverage it never had.)_

_The four evidence items — sign the bundle, `export --verify`, audit event sink, attribution
backfill — moved to `ROADMAP.md` **J1–J4**._

---

## Deep-dive review, 2026-08-04 — 22 confirmed defects still open

Produced by a fan-out review: 8 reviewers by failure dimension, each finding then handed to an
**independent skeptic told to refute it**, who had to reproduce the failure themselves before it
counted. 37 agents, 29 raised, **27 survived refutation**, 2 killed. Every entry below carries the
command that reproduces it — none is a code-reading opinion.

**Five are already fixed** in `fix-protected-name-rails` (PR #30): the protected-LB rail bypass via
`./nimbus-www`, the same shape in the policy create and delete paths, the third private copy of the
check in `retire.py`, the unaudited `--allow-protected-lb` override, and the console hardcoding
`force:true` past the cure-PR gate.

The rest are below, grouped by theme rather than by severity, because the themes are the point: the
same defect shape recurs across modules, and fixing one instance without sweeping for the others is
how they got here. Ordered within each group by severity.

> Two findings were **refuted** and are deliberately not listed: the probe-derived `evidence` CWE
> tier (judged a documented design decision, not a defect) and one other. Do not re-raise them
> without reading the refutation in the review transcript.

### A. Honesty of reporting — a blank that reads as a clean answer

- [x] **HIGH** `pipeline.py:152` — The spec-vs-code orphan comparison is fed framework route-registration lines, not paths, so `served` is empty and every endpoint the code demonstrably serves is reported as "declared in the spec but served by no route in the code" — while `code_only: []` renders as "no undeclared routes" having checked nothing
  - *Fails when:* The documented invocation `vpcopilot scan ./app --spec ./openapi.yaml` (docs/USAGE.md:96). `openapi.orphans(spec, repo_routes)` documents its input as lines like `"GET POST /users/v1/register"` — the shape `routes._openapi_paths` emits. But pipeline.py:152 hands it `route_ctx.splitlines()`, and for any repo that does not itself contain an OpenAPI/Swagger file, `collect_route_context` returns only 
  - *Repro:* `python /tmp/vpr1/repro.py   (script replays pipeline.py:141 and :152 verbatim against a 3-route Flask app at /tmp/vpr1/app and`
  - *Why the suite misses it:* tests/test_inputs_openapi.py:112-128 exercises `orphans` only with hand-written path-shaped lists (`["POST /api/pay", "GET /api/legacy"]`) — i.e. it invents the input instead of taking it from the real producer, `collect_route_context`. tests/test_routes.py tests `collect_route_context` in isolation
- [x] **HIGH** `drift.py:123` — drift.check() swallows an unparseable snapshot into `changes = []` / `drifted = False`, so "we could not read what we last left on this LB" renders as "no drift" on the CLI, the console and the pre-apply gate
  - *Fails when:* `out/snapshots/<lb>-<ts>.json` is written by `engine.ApplyContext.load()` (engine.py:71) and `drift.save_snapshot` (drift.py:55) with a plain, non-atomic `write_text` — the exact truncation hazard `ledger.save` documents and guards against with `os.replace`. Snapshots are also bundle members (export.py:322). When the newest snapshot for an LB is truncated or otherwise unparseable, `latest_snapshot
  - *Repro:* `python /tmp/vpr2/repro.py   (case A: readable snapshot, real drift rate_limit 100->5; case B: same LB, newest snapshot truncat`
  - *Why the suite misses it:* tests/test_drift.py covers no-snapshot (`test_no_snapshot_yet_is_not_drift`), identical-snapshot, changed-snapshot and newest-snapshot-wins, but never writes a snapshot that fails to parse — so the one `except` in the function has no test. `grep -n snapshot tests/test_drift.py` shows every snapshot 
- [x] **HIGH** `report.py:439` — report.html renders every CANDIDATE finding, not the verified ones — the severity and OWASP charts count 25 findings on a page whose hero says 9, and a verify-REFUTED finding renders identically to a real one with no band-aid
  - *Fails when:* pipeline.py writes findings.json from `findings` (all candidates) and triage.json from `verified` only — in the repo's own out/ that is 25 vs 9. build_report loads findings.json at report.py:409, sorts it at :426 and never intersects it with triage. `cards` (:439) therefore emits 25 cards, and `_bars_html(findings, summary)` (:496) charts all 25. A refuted finding gets `<div class="bandaids"></div
  - *Repro:* `python -c "
import json,re,sys; sys.path.insert(0,'src')
from vpcopilot import report
O='out'; s=json.load(open(O+'/summary.js`
  - *Why the suite misses it:* tests/test_report.py::_seed hardcodes candidates == verified == 2 and gives every finding a triage entry, so findings.json and triage.json are always the same set in every report test. No fixture anywhere in the suite has a candidate that verify refuted, which is the only input that separates the tw
- [x] **HIGH** `impact.py:68` — impact()'s `mitigated` counts any ledger entry in state remediated/retired even when it has no mitigation — opening a PR for a `no_bandaid` finding makes both the console hero and report.html claim it was "mitigated live by XC"
  - *Fails when:* `mitigated = sum(counts[s] for s in _LIVE)` where `_LIVE = ("mitigated", "remediated", "retired")` counts states only. `controls_live` two lines above (impact.py:62-65) correctly requires `e.get("mitigation")`; `mitigated` does not. `ledger._advance` moves found -> remediated directly, and `pr.open_pr` (pr.py:81) calls `mark_remediated` for ANY finding it opens a PR for — including one triage rout
  - *Repro:* `python -c "
import json,sys,tempfile; sys.path.insert(0,'src')
from vpcopilot import ledger, impact, report
d=tempfile.mkdtemp`
  - *Why the suite misses it:* Every ledger fixture in tests/test_impact.py gives the remediated/retired entries a `mitigation` block (`_seed` line 12-13, `test_controls_live_excludes_retired` line 50). The suite has no entry that reached `remediated` without first being `mitigated`, so `mitigated` and `controls_live` always agre
- [x] **MEDIUM** `cli.py:70` — The scan input-path existence check exists only on MCP: `vpcopilot scan /does/not/exist` and POST /api/scan both run the pipeline to completion and write a clean-bill-of-health summary.json for a directory that was never read
  - *Fails when:* mcp.py:290-294 checks every repo/spec/manifest path before starting the job, citing run_pipeline's own docstring: "a scan of nothing would write a summary saying nothing was found, which is not the same answer". cli.py:66-75 and console/app.py:847-854 validate the CVE-exclusivity rule and min_severity but never check that the paths exist, and `run_pipeline` (pipeline.py:80-88) validates only that 
  - *Repro:* `python /tmp/probe_surfaces_scan.py   # calls scan_start / the typer CLI / POST /api/scan with repo=/does/not/exist/at/all;  an`
  - *Why the suite misses it:* tests/test_mcp.py:801 is the only test that asserts "does not exist" anywhere in the suite, and it drives the MCP frame path exclusively. The CLI scan tests and the console scan tests (test_inputs_openapi.py:168, test_inputs_manifest.py:955) assert the *accepting* half of the input rules — that a sp
- [x] **MEDIUM** `cli.py:1017` — `_require_run_dir` — "a run directory that does not exist is not an empty one" — is enforced only in mcp.py: the CLI prints a green "no live band-aids" and the console returns all-zero impact for a run directory that isn't there
  - *Fails when:* mcp.py:128-137 declines `patches_list`, `ledger` and `impact` for a missing `out`, with the docstring "A typo'd `out` would have produced the most reassuring possible answer." That exact answer is what the other two surfaces give: `vpcopilot patches-list --out <typo>` prints `no live band-aids` in green and exits 0 (cli.py:1016-1018), and the console — whose OUT global is set straight from the Sca
  - *Repro:* `python -m vpcopilot.cli patches-list --out /nonexistent-run-dir; echo "exit=$?"   # then the MCP contrast: .venv/bin/python -c`
  - *Why the suite misses it:* The guard lives in mcp.py rather than in reconcile.list_patches / ledger.load / impact.impact, so the only test that can see it is tests/test_mcp.py:790 — the sole "no run directory" assertion in the suite, driven through MCP frames. tests/test_console_reconcile.py and the CLI tests always build a r
- [x] **MEDIUM** `reconcile.py:494` — reconcile reports a probe that blew up in transport as "this finding has no runnable probe" — a permanent, unfixable condition — indistinguishable from a finding that genuinely has no probe recorded
  - *Fails when:* `_probe` (reconcile.py:300-304) catches every exception from `probe_from_spec` — DNS failure, connect timeout, TLS error, a transient 5xx at the origin — and returns `{}`, the same value it returns when `probes.json` has no entry for the finding. The caller at reconcile.py:494 tests `not probe or probe.get("exploit_status") is None` and holds with "cure merged, but this finding has no runnable pro
  - *Repro:* `python /tmp/vpr3/repro_reconcile.py   (two run dirs, both cure=merged and origin healthy; A has no probes.json, B has a valid `
  - *Why the suite misses it:* tests/test_reconcile.py substitutes the whole of `_probe` via `_fake_probe(monkeypatch, result)` (line 55-56), so the `except Exception -> return {}` arm inside `_probe` is never executed by the suite. `skipped_no_probe` is only ever tested by omitting probes.json, i.e. the branch that is genuinely 
- [x] **MEDIUM** `report.py:336` — report.py's blast-radius table drops `reason`, `errored`, `enforcement_confirmed`, `carried_from` and the whole `caveats` list — a replay where every request failed in transit renders as a green "within threshold" 0.0%
  - *Fails when:* `simulate._score` (simulate.py:155-157) sets `reason = "nothing measured — every replayed request failed in transit, so this is zero evidence, not a clean result"` when `evaluated == 0`, and leaves `blocked_promotion=False`, `block_rate=0.0`, `error=""`. `_blast_radius_html`'s verdict expression (report.py:332-334) only branches on `blocked_promotion` and `error`, so it falls through to `<span cla
  - *Repro:* `python -c "
import json,re,sys,tempfile; sys.path.insert(0,'src')
from vpcopilot.schemas import PolicySimulation, SimulationRe`
  - *Why the suite misses it:* tests/test_simulate.py exercises `_score`/`write_result` at the model level and asserts on the dict; tests/test_console_simulate.py exercises the /api/simulate JSON. Nothing asserts on the HTML `_blast_radius_html` produces, so no test ever compares what report.py renders against what the PolicySimu
- [x] **MEDIUM** `report.py:119` — A `dependency_upgrade` remediation makes the finding card claim "✓ code fix drafted", contradicting the hero on the same page which correctly reports 0 code-fix PRs and 1 upgrade to ship
  - *Fails when:* `_finding_card` builds `rem` from remediations.json without looking at `kind` (report.py:119-120: `if rem: ba.append('✓ code fix drafted')`). pipeline._write_out splits the two kinds correctly into summary['code_fix_prs'] and summary['dependency_upgrades'], and both the hero and the run-summary chips honour that split. But remediations.json holds both kinds, so for an advisory finding (--cve / --m
  - *Repro:* `python -c "
import json,re,sys,tempfile,pathlib; sys.path.insert(0,'src')
from vpcopilot import report
d=pathlib.Path(tempfile`
  - *Why the suite misses it:* tests/test_report.py's only remediation fixture (line 25-27) omits `kind` entirely, so it defaults to `code_fix` and the badge is correct. The H2 tests cover the summary split and pr.py's advisory branch but never render report.html for an out dir containing a dependency_upgrade remediation.

### B. Model-supplied values trusted as code-set facts

- [x] **HIGH** `pipeline.py:437` — Triage decisions are keyed on the model-supplied `TriageDecision.finding_id`, so a verified finding the triage agent omits or renames silently gets no band-aid, no ledger entry and no log line
  - *Fails when:* `TriageBatch`/`TriageDecision` is the triage agent's instructor response_model, so `finding_id` is a free string the model writes. pipeline.py:437 does `f = by_id.get(d.finding_id); if not f: continue` — an id that matches nothing is dropped with no log — and there is no reciprocal check that every verified finding got a decision. ledger.init_from_scan (ledger.py:72) then builds the ENTIRE ledger 
  - *Repro:* `python /tmp/scratch/rep`
  - *Why the suite misses it:* tests/test_pipeline_replay.py's FakeHarness always returns decisions whose finding_id matches the finding exactly, and test_ledger.py seeds decisions from the same ids it seeds findings from. No test feeds the pipeline a decision list that is shorter than the verified list or carries an id that is n
- [x] **HIGH** `pipeline.py:416` — `GeneratedArtifact.finding_id` and `.control` come from the generate agent and are written verbatim into policies.json — the policy->finding index every apply/refine/simulate/emit/backfill path resolves through
  - *Fails when:* generate.run is called with an explicit finding and an explicit control ('CONTROL TO GENERATE: service_policy'), but the returned artifacts are appended unchanged (pipeline.py:416-429) and _write_out:570 writes `{finding_id: a.finding_id, control: a.control.value, ...}` as policies.json. Consequences, all reproduced: (1) ledger.find_finding_for_policy returns the model's id, so applying that polic
  - *Repro:* `python /tmp/scratch/rep`
  - *Why the suite misses it:* Every fixture that exercises generate (tests/test_pipeline_replay.py:27-31 and the mcp/ci fixtures) returns a GeneratedArtifact whose finding_id and control already equal the ones the pipeline asked for, so the fields are never observed being trusted. tests/test_correlate.py tests coverage_key in is
- [x] **MEDIUM** `schemas.py:157` — `RemediationPlan.kind` / `package` / `fixed_version` are on the remediate agent's response_model, so a repo-scan cure can be relabelled a dependency upgrade and pr.py reports a model-invented package version as the fix
  - *Fails when:* pipeline.py:492 appends `remediate.run(...)` results unchanged. A model that decides the cure is an upgrade sets kind='dependency_upgrade' and fills package/ecosystem/fixed_version from memory — no OSV lookup happens anywhere on a repo scan. Then: summary['code_fix_prs'] and metrics.synthesize.code_fix_prs drop to 0 while a complete patched file sits in remediations.json, the report hero renders '
  - *Repro:* `python /tmp/scratch/rep`
  - *Why the suite misses it:* Every dependency_upgrade in the suite is built by inputs/cve.py or inputs/deps.py, where code fills the fields from OSV; every repo-path remediation fixture leaves kind at its 'code_fix' default. The tests therefore only ever see the two consistent combinations and never the model-labelled one, so t

### C. Concurrency and shared state

- [x] **HIGH** `console/app.py:989` — console `_run_action` reads the global `OUT` inside the worker thread, so an in-flight apply's `apply_timing` audit record lands in whatever run dir a concurrent `POST /api/scan` has since repointed the console at — the run that owns the LB change loses its MTTM measurement and an unrelated run gains one
  - *Fails when:* Operator starts an apply against out-A from the Mitigate step (`POST /api/action`, dry_run=false). The control is pushed to the load balancer. While the job is still running, a scan is started into out-B (`POST /api/scan`), which does `global OUT; OUT = Path(body.out)` at app.py:856. `_run_action` then evaluates `record(str(OUT), "apply_timing", ...)` at app.py:989 — reading the global, not a capt
  - *Repro:* `python /tmp/vpc_repro/t_out_race.py   # starts /api/action against out-A with apply_malicious_user stubbed to block, then POST`
  - *Why the suite misses it:* Every console test monkeypatches `A.OUT` to a single tmp_path and never changes it while a job is in flight, so no test ever exercises two run dirs in one process. `tests/test_impact.py` writes `apply_timing` records directly into the dir it then reads, so the join is never tested across a reassignm
- [x] **HIGH** `runmeta.py:118` — `runmeta.write_manifest` mints `run_id` in an unguarded read-modify-write — `_MINT_LOCK` only guards `run_id()`, so a scan finishing while any thread records an audit entry produces entries whose run_id does not exist in run.json
  - *Fails when:* `run_id()` takes `_MINT_LOCK` (line 89) for its load→mint→save. `write_manifest` does the identical load (line 117) → `setdefault("run_id", uuid4())` (line 118) → `_save` (line 122) with NO lock, and the window between them contains `actor()` (getpass) and `host()` (gethostname) syscalls. Interleaving on a run dir that has no run.json yet: the audit thread loads {}, mints rid1 under the lock, save
  - *Repro:* `python /tmp/vpc_repro/t_runmeta_manifest.py   # 200 trials, 2 threads, NO injected sleeps: one thread calls runmeta.write_mani`
  - *Why the suite misses it:* `tests/test_audit_provenance.py` exercises the concurrency guard only through `runmeta.run_id`/`audit.record` (the path that IS locked). No test ever calls `write_manifest` concurrently with anything, so the second, unlocked mint of the same field is untested.
- [x] **MEDIUM** `console/app.py:841` — console `POST /api/scan`'s "a scan is already running" guard is an unlocked check-then-act on state the endpoint never sets, so two concurrent scans both start into the same out dir — the interleaving MCP explicitly declines
  - *Fails when:* `start_scan` checks `_scan["state"] == "running"` (app.py:841) but never sets it; `state="running"` is set by `_run_scan` (app.py:823) once the daemon thread is scheduled. Two requests that arrive before that — a double-clicked Start button, two browser tabs, a retried POST — both read the stale state, both pass the guard and both spawn a pipeline into the same out dir. Both pipelines then write f
  - *Repro:* `python /tmp/vpc_repro/t_double_scan_rate.py   # 20 trials, 2 threads barrier-synced on POST /api/scan with run_pipeline stubbe`
  - *Why the suite misses it:* The 409 guard is tested only sequentially (post, then post again), where the worker thread has already been scheduled and the guard does hold — my sequential control case returned 409 correctly. No console test issues two requests concurrently.
- [x] **MEDIUM** `backfill.py:230` — `backfill.py` writes its sidecar through a fixed temp filename with no pid or thread id, so concurrent `POST /api/audit-backfill` requests collide on it and all but one 500 with FileNotFoundError from `os.replace`
  - *Fails when:* `backfill()` writes `<out>/audit-backfill.json.tmp` and then `os.replace`s it onto the sidecar. The name is constant, so every concurrent caller shares one temp path. FastAPI runs the sync `audit_backfill` endpoint in the anyio threadpool, so two Retire-step clicks (or two tabs polling) run it on different threads in the same process: T1 replaces the shared tmp onto the sidecar, T2's `os.replace` 
  - *Repro:* `python /tmp/vpc_repro/t_backfill_console_500.py   # 8 barrier-synced POST /api/audit-backfill against a 400-entry run dir, Tes`
  - *Why the suite misses it:* `tests/test_backfill.py` only ever calls `backfill()` sequentially against a tmp_path, and the no-op check makes a second sequential call write nothing at all — so the write path is never entered twice at once.

### D. Secrets

- [x] **HIGH** `traffic.py:74` — Traffic ingest never redacts the QUERY STRING, so `?api_key=…` / `?access_token=…` ships verbatim inside simulation.json — in the signed evidence bundle, the console API and MCP — while the `redacted` counter affirmatively reports the sample as clean
  - *Fails when:* An operator feeds a recorded sample to `vpcopilot simulate --logs sample.har` (or `--from-tenant`, since XC access logs put the query in `req_path`). Any request whose URL carries a credential in the query string — `GET /api/export?api_key=xoxb-…`, a signed-URL `?access_token=…`, `?sig=…` — is parsed by `_split` → `parse_qs` and stored on `RequestRecord.query` with no redaction: `REDACT_HEADERS` c
  - *Repro:* `python /tmp/vpc_leak_query2.py`
  - *Why the suite misses it:* tests/test_traffic.py has exactly two redaction tests — `test_secret_looking_body_fields_are_redacted_not_dropped` (JSON body) and `test_extra_redact_patterns_are_configurable` (headers). The only query-string assertions (test_traffic.py:39, :53) are `r.query == {'ref': ['abc','def']}` and `{'id': [
- [x] **MEDIUM** `audit_sink.py:157` — An audit-sink URL that `urlsplit` rejects has its full raw value — basic-auth password and Splunk-HEC-style path token included — echoed in `reason`/`last_error` to stderr, the CLI panel and `GET /api/audit-sink`, defeating the `redacted` field that was added for exactly this
  - *Fails when:* `VPCOPILOT_AUDIT_SINK` is a credential-bearing URL (basic auth in userinfo, or a HEC/Slack token in the path — `redact()`'s own docstring says so and is built to show only the origin). If the value is one `urlsplit` raises on, `configure()` correctly sets `redacted: "(unparseable)"` but sets `reason` to `f"...({e})"`, and CPython's `_checknetloc` ValueError embeds the ENTIRE netloc — userinfo and 
  - *Repro:* `python /tmp/vpc_leak_sink.py`
  - *Why the suite misses it:* tests/test_audit_sink.py:86-104 parametrises this exact NFKC case (`"https://ho℀st/x"`) but its fixtures carry no credential, and its only redaction assertion is `assert raw not in audit_sink.status()["target"]` — it checks `target` and never `reason` or `last_error`. `test_a_webhook_url_never_rende

### E. Surface parity

- [x] **HIGH** `mcp.py:640` — MCP `simulate` ignores VPCOPILOT_SIM_THRESHOLD — the operator's tightened blast-radius threshold is silently replaced by the hardcoded 0.01, and the wrong verdict is persisted to simulation.json where promotion_gate reads it on all three surfaces
  - *Fails when:* `simulate_policies` hardcodes `threshold: float = DEFAULT_THRESHOLD` (0.01, simulate.py:182) and never reads the environment; cli.py:822 and console/app.py:279-280 each resolve `VPCOPILOT_SIM_THRESHOLD` themselves and pass it. mcp.py:640 does `kw = {} if threshold is None else {"threshold": threshold}` — so when a caller omits `threshold` (the documented path) the env var is dropped, even though t
  - *Repro:* `VPCOPILOT_SIM_THRESHOLD=0.001 python /tmp/probe_threshold.py   # records the threshold simulate_policies is actually handed by`
  - *Why the suite misses it:* tests/test_simulate.py:76 (`test_threshold_is_configurable`) passes `threshold=` explicitly to `simulate_policies`, which is the one call shape that cannot expose this. Nothing in tests/test_mcp.py sets VPCOPILOT_SIM_THRESHOLD or inspects the threshold `_tool_simulate` forwards — grepping tests/test

### F. Tests that cannot fail

- [x] **HIGH** `tests/test_bigip_lab.py:293` — `test_the_client_never_lets_the_password_reach_an_error_string` asserts the password is absent from a mocked body that never contained it — BigIP._redact can be deleted entirely and the whole suite stays green
  - *Fails when:* The test builds `httpx.Response(500, text="boom")`, so `"s3cr3t-pw" not in str(e.value)` holds whether or not `_redact` does anything — `BigIPError` is constructed from `f"{method} {path} -> {r.status_code}: {r.text[:400]}"`, and none of `method`, `path`, `500` or `boom` can ever contain the password. Replace `src/vpcopilot/bigip.py:68` with `return s`, and both that test and all 1009 offline test
  - *Repro:* `zsh /tmp/scratch/repro2_bigip.sh   # rsyncs to /tmp/vpc-repro2, rewrites bigi`
  - *Why the suite misses it:* The mock transport returns a fixed body (`"boom"`) that is not derived from the credential under test, so the negative assertion is trivially true. A redaction test must plant the secret in the payload being redacted; this one plants it only in the client constructor.
- [x] **MEDIUM** `tests/test_inputs_cve.py:323` — `test_the_resolve_agent_is_registered_everywhere_it_has_to_be` checks report.py with a whole-file substring search that unrelated dependency-report text already satisfies
  - *Fails when:* The assertion is `assert "resolve" in Path("src/vpcopilot/report.py").read_text()`. report.py contains `"resolve"` in six unrelated places in `_dependencies_html` (`("not_resolved", "not resolved")`, `"Listed, not resolved."`, `"resolved against OSV.dev"`, ...), so the check is satisfied no matter what `_models_html` contains. Delete `"resolve"` from the hardcoded list at src/vpcopilot/report.py:3
  - *Repro:* `zsh /tmp/scratch/repro4_report.sh   # rsyncs to /tmp/vpc-repro4, drops "resol`
  - *Why the suite misses it:* report.py's agent list is a module-local literal inside `_models_html`, not an importable constant, so the test reached for a text search instead of a membership test. The search is over the whole file, and the H2 dependency section independently contains the same word. No other test renders the mod

### Ungrouped

- [x] **MEDIUM** `engine.py:115` — `test_safe_rollback_restores_and_verifies` never proves the "verifies" half — the `verify` callable can be dropped and rollback will report success on an LB that was not restored
