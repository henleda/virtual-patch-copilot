# Build plan — remaining functionality

Living burn-down tracker. **Done today:** the core loop — admin → scan → verify → triage →
generate → **apply band-aid** (`service_policy` create+attach+exploit-validate+rollback;
`malicious_user` LB-enable+config-validate+rollback) → **open code-fix PR** — model-
independent, with a localhost console and a 9/9 benchmark. This file tracks what's left.

Effort: **S** ≈ <1 session · **M** ≈ 1–2 · **L** ≈ multi. Priority: **P0** foundational ·
**P1** high-value · **P2** later/bigger. Check items off as we land them.

## Phase A — Complete the apply toolbox
Every control `generate` can emit should also be `apply`-able + validated, behind a dispatcher.
- [x] **A0** Unified apply dispatcher — **DONE:** `apply_control(control, lb, **kw)` routes
  malicious_user / rate_limit / bot_defense to their handlers. (M, P1)
- [x] **A1** `bot_defense` apply — **DONE:** `apply_bot_defense` flips `disable_bot_defense`→
  `bot_defense` with a valid default flag-only policy (add-on IS present on the tenant), config
  validation + rollback + guardrails. **Live round-trip validated on nimbus-www** (default
  policy accepted by XC: enable→readback→rollback). CLI `apply-bot`. (S, P1)
- [x] **A2** `rate_limit` apply — **DONE:** `apply_rate_limit` enables LB rate limiting
  (requests/unit/burst), config-validate + rollback; **live round-trip validated on
  nimbus-www**. CLI `apply-ratelimit`. (M, P1)
- [ ] **A3** `waf` / `waf_data_guard` apply — enable App Firewall blocking on the LB and/or add
  `data_guard_rules`; validate by firing injection (→403) / response-mask check. (M, P2)
- [ ] **A4** `api_schema` apply — create an API Definition (OpenAPI) object + enable enforcement
  on the LB; validate with a schema-violating request. (L, P2)

## Phase B — Detection & triage quality
- [x] **B1** Finding-correlation step — **DONE:** `correlate.py` `coverage_key` (LB-wide
  controls collapse to one instance; `service_policy` keyed per endpoint); pipeline skips
  generating a band-aid an earlier finding already covers, writes `correlations.json` + a
  summary line. Live: 4 redundant band-aids deduped. (M, P1)
- [x] **B2** Verify confidence threshold — **DONE:** `--min-confidence` (default 0.5) drops
  verified findings below it (logged, no silent cap); wired through scan/bench/console +
  `run_pipeline`. (S, P1)
- [ ] **B3** Behavioral validation (optional) — drive abusive traffic and confirm
  malicious-user/bot/rate actually flag+mitigate, vs config-only. (L, P2)

## Phase C — Cure side & ledger
- [x] **C1** Remediation ledger — **DONE:** `ledger.py` persists per-finding
  `found→mitigated→remediated→retired` (forward-only) in `ledger.json`; pipeline seeds
  `found` (+ a `policies.json` policy→finding index), `apply` marks `mitigated`, `pr` marks
  `remediated`. `vpcopilot ledger` CLI + `/api/ledger` console endpoint. Tests added. (M, P0)
- [ ] **C2** Auto-retire band-aid on cure-merge — poll PR state; when the fix merges, offer/auto
  detach the temporary policy. (M, P2)
- [x] **C3** PR tracking — **DONE:** "Open all code-fix PRs" batch button; PR links surfaced
  inline (dashboard actions) and in the Ledger tab (from the ledger `cure`). (S, P1)

## Phase D — Benchmark & model-independence
- [ ] **D1** Bonus-vuln scoring — `bonus:` section in the answer key; credit extra real findings
  vs noise. (S, P1)
- [ ] **D2** Per-stage metrics — verify precision/recall, discovery dupes, timing. (M, P2)
- [x] **D3** Multi-provider proof run — **DONE (see MODELS.md):** config-only swap ran the
  full pipeline on `gpt-4o` (Claude 9/9, gpt-4o ~8/9 real, triage 100% on both). Surfaced +
  fixed the "trust intentional/demo comments" reviewer weakness for all models. (S, P0)

## Phase E — Console polish
- [x] **E1** Per-finding action buttons — **DONE:** dashboard rows have inline **Apply
  {control}** (routes service_policy→/api/apply, malicious_user/rate_limit/bot_defense→their
  endpoints) + **Open PR**, driven by an action-settings bar; per-row result inline. (M, P1)
- [x] **E2** Ledger view — **DONE:** Ledger tab renders `/api/ledger`
  (found→mitigated→remediated→retired) with mitigation control + cure PR links. (S, P1)
- [ ] **E3** Standalone shareable HTML export — single self-contained file. (M, P2)
- [ ] **E4** Richer before/after panel — allowed-vs-blocked counts / XC events summary. (M, P2)

## Phase F — Productization & hardening
- [ ] **F1** Packaging — static files ship in the wheel; `vpcopilot` entrypoint on PATH; `--version`. (S, P1)
- [ ] **F2** Test coverage with fakes — mock harness/XC/GitHub; unit-test the normalizer, triage
  matching, apply flows, and guardrails. (M, P0)
- [ ] **F3** Pipeline concurrency — parallelize discover/verify (threads/async) for large repos;
  cap + log. (M, P1)
- [ ] **F4** Audit log — append-only record of every applied/rolled-back change (what/when/result). (S, P1)
- [ ] **F5** Customer docs — setup, provider config, safety/guardrails, worked example. (M, P1)

## Recommended burn-down order
1. **C1** ledger + **F2** tests — foundations everything else leans on.
2. **D3** multi-provider proof — cheap, and it substantiates the headline claim.
3. **A0 → A1 → A2** — finish the easy apply toolbox behind the dispatcher.
4. **B2 → B1** — triage quality (confidence gate, correlation).
5. **C3 → E1 → E2** — cure tracking + console UX.
6. **D1, F1, F4, F5** — eval polish + hardening + docs.
7. **A3, A4, B3, C2, D2, E3, E4** — bigger / optional.

_(BACKLOG.md holds looser "someday" ideas; this file is the committed plan.)_
