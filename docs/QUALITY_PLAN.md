# Quality & Demo Deep-Dive — burn-down tracker

Synthesized from 5 parallel code audits (UI, demo/report, agents, testing, orchestration).
Execute in phase order; check items off as they land. Effort: S/M/L. Source audit in parens.

## Phase 0 — P0 safety/correctness bugs (do first)
- [x] **P0-1** `retire.pr_is_merged` calls `_resolve_token()` with no arg → `TypeError` on the real
  retire-after-merge flow. Fix `_resolve_token(None)` / give a default; add a test. (S, Orch)
- [x] **P0-2** Refine path bypasses the `PROTECTED_POLICIES` guard — `--from-scan --refine` can
  clobber a protected object. Move the guard to the XC write boundary; add a test. (S, Orch)
- [x] **P0-3** Ledger mixes findings across apps (`init_from_scan` never scopes to the target) →
  cross-run leakage. Scope/tag the ledger per run/target. (S, UI/Orch)

## Phase 1 — A. Correctness & agent quality (the root-cause fixes)
- [ ] **A1** Endpoint-aware pipeline: add `endpoint`/`http_method` to `Finding`; discover traces the
  effective route (mounts/blueprints/App-Router). (M, Agents)
- [ ] **A2** Reorder probe → before generate; pass the concrete exploit into generate so the policy
  matches the request it will be validated against. (S, Agents)
- [ ] **A3** Deterministic policy linter (DENY-before-allow-all; DENY path/method matches the
  exploit) — catch bugs before any live round-trip. (M, Agents)
- [ ] **A4** Fix id-collision silent drop (pipeline-authoritative unique ids, keep model id as a
  label). (S, Agents)
- [ ] **A5** Decouple remediation from triage (iterate cures over `verified`, not `decisions`). (S, Agents)
- [ ] **A6** Finding dedup pass (kills the double-PR) keyed on (file, vuln_class, endpoint). (M, Agents)
- [ ] **A7** Confidence calibration: anchored definition + severity-weighted gate; reconcile
  `is_real`/`confidence`. (S–M, Agents)
- [ ] **A8** Verify hardening: credit only mitigations seen executing; lower (not refute) confidence
  when a sink/mitigation is in unseen code; optional cross-file context. (S–M, Agents)
- [ ] **A9** Constrain generated specs: typed `ServicePolicySpec` (or per-control examples +
  deterministic validators); reconcile generate output with what apply actually consumes. (M, Agents)

## Phase 2 — C. Demoability (make the proof self-evident)
- [ ] **C1** Hero band: "N vulns exploitable → mitigated live in seconds, vs. 20–30-day change
  control" (report + console; `CHANGE_CONTROL_DAYS` config). (S, Demo)
- [ ] **C2** Live-stream apply/refine in the console (background thread + poll, like scan); render
  `before_after` (200→403) + `self-healed in N attempts` badge; feed the real refiner log. (M, UI+Demo)
- [ ] **C3** Kill raw-JSON summary → clean metric chips; add an **Impact** tab off `/api/audit`;
  add a control-family coverage view; expandable finding inspection (exploit/snippet/policy). (M, UI)
- [ ] **C4** Close the ledger loop in the UI: Retire button + `/api/retire`; scope to current run;
  severity + title + 4-state progress track; auto-refresh after apply/PR. (M, UI+Demo)
- [ ] **C5** Report polish: promote the impact table under the hero; add `refine_apply` self-heal
  row; model lockup + model-independence chip; humanized target/title; severity + per-control bars. (M, Demo)
- [ ] **C6** Demo assets: curated demo `out/` (ledger walked to all 4 states incl. one→retired);
  `docs/DEMO.md` 5-min runbook; README rewrite; screenshots/GIF; XC-dashboard deep links. (M, Demo)

## Phase 3 — B. Architecture (the keystone — robustness + extensibility + testability)
- [ ] **B1** `Control` plugin protocol + one `SafeApply` engine — collapse the 7 `apply_*` +
  standalone refiner into one spine (snapshot→self-test→prepare→attach→validate→keep/rollback),
  mirroring `retire._detach_control`. Uniform result envelope. (L, Orch)
- [ ] **B2** Generic refine loop over the engine → extends to waf/api_schema/rate_limit (spec-refine
  vs param-refine vs no-op→unfixable). (L, Orch)
- [ ] **B3** Safe rollback (retry + verify GET==snapshot + loud audit + `RollbackError`) + orphan
  cleanup (unwind created objects) + upsert (no delete-then-create gap). (M, Orch)
- [ ] **B4** One `CONTROLS` registry (derive LB_WIDE, CLI, console, dispatch, retire from it);
  `poll_until(deadline)` helper; DI (`xc`/prober/clock); `ApplyContext` (kills the log-NameError
  class). (M, Orch+Test)
- [ ] **B5** Fail-closed validation: no silent Nimbus-probe fallback on a real app; sharpen
  `_blocked` to XC's specific block signal; assert legit success status. (M, Orch)
- [ ] **B6** Per-item error isolation in discover/verify (sentinels, continue); explicit
  `h.warmup()`; per-LLM-call timeout. (M, Orch)
- [ ] **B7** Ledger atomic/locked writes + rollback-aware state (mitigated never lies) + stale
  reconciliation; per-LB timestamped snapshots. (M, Orch)
- [ ] **B8** Polish: dry-run shouldn't silently fire the real exploit (`--probe/--no-probe`);
  redact secrets in XCError; robust `.env` writer. (S, Orch)

## Phase 4 — D. Durability (lock quality in)
- [ ] **D1** `FakeXC` + `FakeHarness` in `tests/conftest.py`; test the engine for all controls
  (attach/rollback/keep/self-test-abort/oneof invariants). (M, Test)
- [ ] **D2** Full-pipeline replay (recorded `out/` fixtures) + instructor thread-safety regression
  guard. (M, Test)
- [ ] **D3** `xc.py` via `httpx.MockTransport`; bench-scorer unit test; `_blocked` table test;
  refiner `unfixable`/`over_block`; retire/pr/lab mutation paths; schema golden-replay. (M, Test)
- [ ] **D4** CI (`.github/workflows`, ruff + `pytest -m "not live and not bench"`, py3.10–3.12,
  coverage floor) + markers + nightly live-smoke + bench-gate (fails below `BASELINE.md`). (M, Test)
