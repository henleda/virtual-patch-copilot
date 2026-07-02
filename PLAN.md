# Build plan — remaining functionality

Living burn-down tracker. **Done today:** the core loop — admin → scan → verify → triage →
generate → **apply band-aid** (`service_policy` create+attach+exploit-validate+rollback;
`malicious_user` LB-enable+config-validate+rollback) → **open code-fix PR** — model-
independent, with a localhost console and a 9/9 benchmark. This file tracks what's left.

Effort: **S** ≈ <1 session · **M** ≈ 1–2 · **L** ≈ multi. Priority: **P0** foundational ·
**P1** high-value · **P2** later/bigger. Check items off as we land them.

## Phase A — Complete the apply toolbox
Every control `generate` can emit should also be `apply`-able + validated, behind a dispatcher.
- [ ] **A0** Unified apply dispatcher `apply(control, …)` + per-control validator; refactor the
  two existing paths under it. (M, P1)
- [ ] **A1** `bot_defense` apply — flip LB `disable_bot_defense`→enable; config-readback. (S, P1)
- [ ] **A2** `rate_limit` apply — enable LB rate limiting + threshold/window from the generated
  config; config-validate (optional burst-probe for 429). (M, P1)
- [ ] **A3** `waf` / `waf_data_guard` apply — enable App Firewall blocking on the LB and/or add
  `data_guard_rules`; validate by firing injection (→403) / response-mask check. (M, P2)
- [ ] **A4** `api_schema` apply — create an API Definition (OpenAPI) object + enable enforcement
  on the LB; validate with a schema-violating request. (L, P2)

## Phase B — Detection & triage quality
- [ ] **B1** Finding-correlation step — dedupe/link band-aids that cover multiple findings
  ("A's band-aid covers B"); reflect in output + ledger. (M, P1)
- [ ] **B2** Verify confidence threshold — drop/flag findings below a configurable confidence
  (we saw 0.60 kept). (S, P1)
- [ ] **B3** Behavioral validation (optional) — drive abusive traffic and confirm
  malicious-user/bot/rate actually flag+mitigate, vs config-only. (L, P2)

## Phase C — Cure side & ledger
- [ ] **C1** Remediation ledger — persist per-finding state `found→mitigated→remediated→retired`
  (`ledger.json`); update on apply/PR. (M, P0)
- [ ] **C2** Auto-retire band-aid on cure-merge — poll PR state; when the fix merges, offer/auto
  detach the temporary policy. (M, P2)
- [ ] **C3** PR tracking — batch-open from console; show PR status/links in the dashboard. (S, P1)

## Phase D — Benchmark & model-independence
- [ ] **D1** Bonus-vuln scoring — `bonus:` section in the answer key; credit extra real findings
  vs noise. (S, P1)
- [ ] **D2** Per-stage metrics — verify precision/recall, discovery dupes, timing. (M, P2)
- [ ] **D3** Multi-provider proof run — run the benchmark on a non-Claude model
  (OpenAI/Gemini/Ollama) to substantiate model-independence; record scores. (S, P0)

## Phase E — Console polish
- [ ] **E1** Per-finding action buttons in the dashboard (inline apply/PR, not separate tabs). (M, P1)
- [ ] **E2** Ledger view in the console (depends C1). (S, P1)
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
