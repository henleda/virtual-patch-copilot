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
  **10** now. Still open: `drift.check` read-only and the MCP handshake — and **the nightly selector
  stays `-m bench`** until those land, per the note below.
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
  been proven by hand against the tenant — the G2 canary, I1's origin probe, I2's `banknimbus-dev`
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
