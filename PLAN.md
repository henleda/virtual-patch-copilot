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
- [x] **A3** `waf` / `waf_data_guard` apply — **DONE:** `apply_waf` creates a Blocking app_firewall
  (cloned from a template), attaches it via a fully-qualified ref (name+namespace+**tenant**, popping
  the `disable_waf` oneof), fires a SQLi and confirms the block (XC serves a 200 `Request Rejected`
  page — the prober matches on the body), then rolls back. `apply_data_guard` ensures the WAF is on
  (Data Guard requires it) then adds masking `data_guard_rules`; config-readback validated. Both
  live-validated on `vpcopilot-lab`. (M, P2)
- [x] **A4** `api_schema` apply — **DONE:** `apply_api_schema` uploads an OpenAPI to the XC object
  store (`put_swagger`, PUT to the stored-objects/swagger endpoint), creates an `api_definition`
  referencing it, then attaches `api_specification.validation_all_spec_endpoints` with
  `validation_mode_active` + `request_validation_properties:[PROPERTY_HTTP_BODY]` +
  `enforcement_block` + `fall_through_mode_allow`. Validated live on `vpcopilot-lab`: a `-1` payment
  (OpenAPI `amount: exclusiveMinimum 0`) returns 403 as a schema violation while `+1` passes; then
  rolls back. The schema-preferred positive-security band-aid. (L, P2)

## Phase B — Detection & triage quality
- [x] **B1** Finding-correlation step — **DONE:** `correlate.py` `coverage_key` (LB-wide
  controls collapse to one instance; `service_policy` keyed per endpoint); pipeline skips
  generating a band-aid an earlier finding already covers, writes `correlations.json` + a
  summary line. Live: 4 redundant band-aids deduped. (M, P1)
- [x] **B2** Verify confidence threshold — **DONE:** `--min-confidence` (default 0.5) drops
  verified findings below it (logged, no silent cap); wired through scan/bench/console +
  `run_pipeline`. (S, P1)
- [x] **B3** Behavioral validation — **DONE:** `apply-ratelimit --behavioral` enables the limit,
  then `probe_rate_limit` drives a burst above it and confirms the excess is rate-limited (429),
  proving mitigation vs config-only. Live-validated on `vpcopilot-lab`: 10/MINUTE + a 30-burst →
  10 pass / 20 × 429. Surfaced in the report's **Band-aid impact** panel. (malicious-user/bot stay
  config-level — behavioral proof there needs sustained abuse + telemetry over minutes, tier-
  dependent; noted honestly.) (L, P2)

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
- [x] **D1** Bonus-vuln scoring — **DONE:** `bonus:` section in `answer_key.yaml`; scorer
  credits real extra findings (`bonus_found`) and reports only genuine `noise`. (S, P1)
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
- [x] **E3** Standalone shareable HTML export — **DONE:** `report.py` reads the out/ artifacts and
  writes a single self-contained `report.html` (inline CSS, native `<details>`, no server/external
  assets; model content HTML-escaped): run-summary chips, per-finding cards (severity, class,
  band-aid chips, code-cure badge, expandable exploit/snippet), grouped XC policies, and the ledger.
  Every scan auto-writes `out/report.html`; `vpcopilot report [--open]` + a console **Open HTML
  report** button (`/api/report`) rebuild it. 3 tests. (M, P2)
- [x] **E4** Richer before/after panel — **DONE:** the exploit-validated applies (service_policy,
  waf, api_schema) fire a baseline exploit BEFORE mutating and return a `before_after`
  {before/after → exploit_status, exploit_blocked, legit_ok} (normalized across probes via
  `probe.normalize`), persisted to the audit log. The HTML report renders a **Band-aid impact**
  table (exploit `200 allowed → 403 blocked`, legit ok, PASS). Live-validated. (M, P2)
- [x] **E5** Workflow tab — **DONE:** visual agent pipeline (discover→verify→triage→generate→
  remediate) with each agent's configured model (from `/api/agents`) + roles, the deterministic
  spine (correlate / human gate / apply / PR), and last-run counts. (S, P1)

## Phase F — Productization & hardening
- [x] **F1** Packaging — **DONE:** `--version`; wheel `force-include` ships the console HTML;
  `vpcopilot` console-script entrypoint. (S, P1)
- [x] **F2** Test coverage — **DONE:** unit tests for the service-policy normalizer, the
  protected-LB + protected-policy guardrails (fake XC env, no network), the ledger, correlate,
  audit, and schemas. 16 tests. (M, P0)
- [x] **F3** Pipeline concurrency — **DONE:** discover + verify run in a `ThreadPoolExecutor`
  (`--concurrency`, default 8); the first discover call runs solo to warm instructor's
  (non-thread-safe) mode registry, then the rest parallelize. Validated live. (M, P1)
- [x] **F4** Audit log — **DONE:** `audit.py` appends every mutating action
  (create/attach/enable/rollback/PR) to `<out>/audit.log` (UTC ts + details); `vpcopilot audit`
  CLI + `/api/audit`. (S, P1)
- [x] **F5** Customer docs — **DONE:** `docs/USAGE.md` (install, config/model-independence, all
  commands, console, safety model + guardrails, worked Nimbus example). (M, P1)

## Recommended burn-down order
1. **C1** ledger + **F2** tests — foundations everything else leans on.
2. **D3** multi-provider proof — cheap, and it substantiates the headline claim.
3. **A0 → A1 → A2** — finish the easy apply toolbox behind the dispatcher.
4. **B2 → B1** — triage quality (confidence gate, correlation).
5. **C3 → E1 → E2** — cure tracking + console UX.
6. **D1, F1, F4, F5** — eval polish + hardening + docs.
7. **A3, A4, B3, C2, D2, E3, E4** — bigger / optional.

_(BACKLOG.md holds looser "someday" ideas; this file is the committed plan.)_
