# Roadmap — beyond the committed plan

`PLAN.md` burns down the committed build. Everything in phases A through F is landed. This
file picks up at **G** and holds the next wave: work with a clear enough shape to plan
against, not yet scheduled. `BACKLOG.md` stays the home for looser ideas.

Same conventions as `PLAN.md`. Effort: **S** ≈ <1 session · **M** ≈ 1–2 · **L** ≈ multi.
Priority: **P0** foundational · **P1** high-value · **P2** later/bigger. Check items off as
they land.

Paths, module names, CLI commands and config keys below were reconciled against the source tree
on 2026-07-27. Items carrying **Reconciled:** notes had a stated surface that did not match the
real layout — the note records what changed and why, so the original intent is not lost.

## How to use this file

Work one item at a time. Before writing code:

1. Read the item, its dependencies, and the invariants below.
2. Write a plan naming files to add or change, the test written first, and any new config
   keys or CLI commands.
3. Implement, then check the box and add a one-line **DONE:** note in the same commit, the
   way `PLAN.md` items read.

Items marked **decision needed** are blocked on a call from the maintainer. Do not start
those without an answer recorded in the item.

## Invariants

Carried forward from `DESIGN.md`. Every item holds to these.

- **Agents reason, code acts.** New capability puts judgment in an agent returning a typed
  artifact and side effects in the deterministic spine.
- **Model independence.** No provider hardcoding. Model choice resolves through
  `config/agents.yaml` and the LiteLLM plus instructor harness.
- **Band-aid, cure always.** Anything producing a mitigation also produces or updates the
  code cure and the ledger state.
- **Human gate before any write.** New write paths route through the same gate and
  guardrails as `apply` and `pr`.
- **One module function, two surfaces.** CLI and console call the same function. Adding a
  command means adding the console endpoint alongside it.
- **Evidence is fail-soft and read-only.** Anything gathering evidence never fails the run
  it observes and never mutates what it records.
- **Tests run offline against fakes.** No network in `tests/`.
- **No regressions.** An item never removes or narrows a capability that already works. Where it
  changes something shared — `scan`'s required positional `repo`, `normalize_service_policy_spec`,
  the console step numbering, an artifact schema — the existing call path keeps working and a test
  pins the old behaviour before the new one is added.

---

## Phase G — Blast radius before the LB is touched

The safety spine proves a band-aid blocks the exploit and passes one legit request. It does
not answer what a policy would do to the other several million requests a day. That gap is
the last unproven claim in the pitch, and the reason security teams sit in monitor mode.

Live validation on the LB stays. This runs before it, not instead of it.

- [ ] **G1** Offline policy evaluator. (M + M, P2) **DEFERRED 2026-07-27 — see the decision below.**
  A pure function taking a generated control spec and a request record, returning
  allow or deny plus the matching rule. Covers the predicate types `generate` emits for
  `service_policy` and `api_schema`. Request records come from `traffic.py` (see G2).
  - Acceptance: every predicate reachable from `generate` has an implementation and a test;
    a predicate carrying a NON-DEFAULT value with no implementation raises a named error rather
    than silently allowing (keys left at their `_RULE_DEFAULTS` value are ignored — every
    normalized rule carries all 25); 100k
    records evaluate against **one policy** in under 10 seconds; a conformance suite pins
    behavior to the documented XC semantics already encoded in the `generate` prompt
    (FIRST_MATCH, specific DENY then catch-all ALLOW, path-regex starts alphanumeric,
    `body_matcher` for JSON).
  - Surfaces: `src/vpcopilot/evaluate.py`, `tests/test_evaluate.py`.
  - **Reconciled:** split into two independently shippable halves, each **M**, not one **L**.
    **G1a `service_policy`** — the *observed* predicate surface is seven, measured across the 31
    generated rules on disk: `action`, `path.prefix_values` (19) / `path.exact_values` (12),
    `http_method.methods`, `body_matcher.regex_values` (7), `query_params[].{key,item}` (5),
    `headers[].{name,item}` (1), `any_client`. Treat that as the v1 implementation target, **not
    a closed set** — `path.regex_values` is reachable from the prompt (`generate.py:60`) but
    unobserved, and `_RULE_DEFAULTS` enumerates 18 further matchers a model could legally emit.
    **G1b `api_schema`** — a JSON-Schema subset; the two artifacts on disk use `type`, `required`,
    `additionalProperties:false`, `format` and `minLength`/`maxLength`, while the numeric bounds
    (`exclusiveMinimum`/`maximum`) appear only in the prompt example — plus XC's
    `fall_through_mode_allow` semantics. The uncertain half; droppable without losing G1a.
  - **Must evaluate the NORMALIZED spec.** `apply.py` never sends what `generate` emits.
    The divergence is the **nested matcher merge** (`apply.py:93-95`), not the top-level defaults:
    12 of the 31 rules on disk set only `path.exact_values`, and the merge injects
    `prefix_values: ["/"]` beside it. Normalization also coerces a single `query_params`/`headers`
    object into a list (`apply.py:99-101`). Both are invisible to an evaluator reading the raw
    artifact — the same class of defect `lint_service_policy` shipped with until `artifact_spec()`
    (`apply.py:106-113`) was added to unwrap `{metadata, spec}`.

- [x] **G2** Shadow simulation report. (M, P1) — **DONE:** `simulate.py` + `traffic.py` replay a
  recorded sample against each candidate on a spare LB and report the would-block set;
  `vpcopilot simulate` / `GET`+`POST /api/simulate` / a ③ Simulate console step / a **Blast radius**
  panel in the HTML report / `simulation.json` in the evidence bundle. Live on `vpcopilot-lab`:
  the negative-amount policy blocked **1 of 200** recorded requests — the exploit — and **none** of
  the 60 legitimate transfers (0.5%, under threshold); a deliberately overbroad `/api` DENY blocked
  **154 of 200** (77%) and tripped it. 34 tests.
  Replay a traffic sample against candidate policies and report the would-block set before
  anything reaches the gate.
  - Per policy: requests evaluated, would-block count and rate, a sample of blocked
    requests, top blocked paths and user agents. A configurable threshold marking a policy
    `blocked_promotion` with the reason recorded.
  - Acceptance: the Nimbus negative-amount policy blocks the exploit and zero recorded
    legitimate transfers ✅; a deliberately overbroad policy trips the threshold ✅ and **warns
    at the gate with an audited override** rather than being unpromotable (decision of
    2026-07-27 — a machine veto would invert "a human approves"); the result renders in the HTML
    report next to the band-aid impact table ✅; **ingest** runs with no XC credentials, but the
    would-block numbers need the tenant ✅ (rewritten from "simulation runs with no XC
    credentials present", which only held for the deferred offline evaluator).
  - **Record sources (decided 2026-07-27): both.** `traffic.py` ingests a file (HAR or JSONL)
    **and** reads XC request logs directly, which needs a new read-only method on `xc.py`
    alongside the existing config-API calls. File ingest works with no tenant; the log read needs
    credentials and is the path that makes `simulate` usable without an export step first.
  - Surfaces: `src/vpcopilot/simulate.py`, `src/vpcopilot/traffic.py`, a request-log read in
    `src/vpcopilot/xc.py`,
    `vpcopilot simulate [--logs <path> | --from-tenant --lb <name> --since <window>]`,
    `GET /api/simulate` + `POST /api/simulate`,
    a Simulate step in the console between ② Review and ④ Mitigate.
  - **Reconciled:** there is no "Apply" step — the console steps are Scan · Review · Mitigate ·
    Cure · Retire · Benchmark. Inserting Simulate renumbers Mitigate through Benchmark, and
    registration touches four places in `console/static/index.html` (`STEPS`, the `<section>`,
    the `show()` branch, the deep-link allowlist). **Corrected during build:** Simulate *is* in
    `ACTION_STEPS` after all — it needs the LB and validate-URL fields from Run settings to know
    which spare LB to replay through. It stays read-only with respect to the run's artifacts.
  - **Deliverable shipped:** `bench/fixtures/traffic/nimbus-sample.jsonl` — 200 records, one
    negative-amount transfer among 60 legitimate ones and 139 reads.
  - **Three defects only the live run could find**, each now pinned by a test:
    (1) attaching and replaying immediately counted an *unenforced* policy as harmless — 0/200
    blocked, including the exploit; a canary built from the finding's own probe now confirms
    enforcement before anything is counted, and an unconfirmed run says so instead of reading as
    safe. (2) one transient TLS error aborted a whole policy's simulation; failures are now
    per-request, excluded from the rate rather than guessed either way. (3) attaching by name
    assumed the policy object already existed — a fresh candidate has none, and referencing a
    missing policy broke the LB config outright (every request failed in transit, not just the
    matched ones); simulation now creates a throwaway `<name>-vpcsim` object and deletes it, so it
    never rides on, or mutates, the operator's own policies.
  - **Criterion rewritten** (G1 deferred, so replay runs on the tenant): *without XC credentials
    `vpcopilot simulate` parses and reports the record set and exits cleanly, evaluating nothing;
    it never errors for want of a tenant.* The would-block numbers require a monitor-mode LB.
  - **Threshold behaviour (decided 2026-07-27): warn + explicit override, not a hard block.**
    Exceeding the threshold marks the policy and surfaces the rate on the Mitigate row; applying
    anyway requires `--allow-overbroad` (or a console confirm) and writes a `simulate_override`
    audit record carrying `finding_id`, `namespace`, rate, threshold and actor. A machine veto
    would invert `DESIGN.md`'s "the model proposes, code disposes, **a human approves**".
  - **Traffic data (decided 2026-07-27): redact on ingest, and the redacted sample ships in the
    evidence bundle.** `traffic.py` strips `Authorization` / `Cookie` / `Set-Cookie` and
    configurable header and JSON-field patterns at parse time, so raw values never reach disk.
    Because the redacted sample is distributed, redaction is a correctness requirement, not a
    convenience: it needs its own test file, a redaction count in `simulation.json`, and a
    `caveats` line in `export.build_manifest` stating what was stripped and what was not.

- [x] **G3** Simulation feeds the refiner. (S, P2) — **DONE:** the refine loop now accepts a
  candidate only when it blocks the exploit **and** stays under the blast-radius threshold. An
  over-broad candidate is fed back as the `over_block` diagnosis the refine agent already
  understands, with the top blocked paths attached so it knows *what* it over-blocked.
  - Acceptance: a refinement pass increasing would-block rate past the threshold gets
    rejected and the refiner tries again or gives up honestly, matching existing behavior ✅
  - **Measured where it is already attached.** The refiner has just confirmed the candidate is
    enforcing, so `simulate.measure_attached` replays through that LB rather than paying a second
    attach and propagation wait elsewhere — slower-but-correct per the decision of 2026-07-27, but
    only one round trip per attempt rather than two.
  - `_score` is shared by `simulate_policies` and `measure_attached`, so the standalone run and the
    refiner cannot drift on what "too broad" means.
  - **Sample comes from `VPCOPILOT_SIM_LOGS`** (or an explicit `records=`). With neither, the second
    gate is skipped and the loop behaves exactly as before — pinned by a test that fails if anything
    is replayed without a sample. An unreadable sample logs a warning and refines without the gate.

- [x] **G4** Published model scorecard. (M, P1) — **DONE:** `vpcopilot bench <repo> --all-configs
  [--skip <tag>]` sweeps every `config/agents*.yaml` and writes `benchmarks/RESULTS.md`. First real
  run (Nimbus fixture, 2026-07-27, dgx skipped — the local box was unreachable): claude recall 1.00
  / triage 0.89, openai 0.89 / 1.00, gemini 0.67 / 1.00, precision 1.00 and zero noise on all three.
  `D3` proved a config-only swap on `gpt-4o`. Turn that into a committed table across four
  providers including a local Ollama model, regenerated by command.
  - Acceptance: `vpcopilot bench <repo> --all-configs` writes `benchmarks/RESULTS.md` with one
    row per `config/agents*.yaml`, scoring discovery, verify precision and recall, triage
    accuracy, bonus finds, noise, and wall time; re-running with the same seed and model
    reproduces the score; `MODELS.md` links the table rather than restating numbers.
  - **The run surfaced a column the acceptance did not ask for, and the table needed.** Gemini
    scored precision 1.00 and triage 1.00 while emitting `{}` as the spec for **3 of its 6**
    policies — structured output validated, the artifact was useless. Recall, precision and triage
    all say the routing was right; none of them notice. `policies (unusable)` counts what
    `lint_generated_spec` rejects, reusing machinery the pipeline already runs. Without it the
    table would have flattered a model that routed correctly and then emitted nothing.
  - **A second latent bug it surfaced:** a re-scan into an existing out dir leaves the previous
    run's artifacts in `policies/` — 32 files for 9 generated policies — so the count is taken from
    the run's own `policies.json` index rather than the directory.
  - **BUILT 2026-07-27.** `scorecard.py` + `vpcopilot bench <repo> --all-configs`
    sweep every `config/agents*.yaml` into `out-<tag>` and write `benchmarks/RESULTS.md`; a config
    that fails gets a row carrying its error rather than vanishing from the table (one dead
    provider must not cost the other three runs). `bench.py` now scores **verify precision** — the
    false-positive filter rate, the real residue of the old `BACKLOG.md` item — and
    `metrics.json` carries `discovery.duplicates_dropped`, the other half of it. `MODELS.md` links
    the table instead of restating numbers. 12 tests.
    **The box stays unchecked until a real four-way run produces `benchmarks/RESULTS.md`** — that
    spends live Gemini and OpenAI quota and is the maintainer's call to start.
  - **Reproducibility: the acceptance criterion is not achievable as written.** "Re-running with
    the same seed and model reproduces the score" cannot hold here — Anthropic accepts no seed at
    all and none of the four guarantee determinism. Rather than fake it, `RESULTS.md` states the
    run date and says scores vary between runs, and tells the reader to re-run before reading
    anything into a small difference.
  - **Fourth provider (decided 2026-07-27): Gemini.** `config/agents.gemini.yaml` is committed and
    the console's model switcher already picks it up (`_config_tag` maps `gemini`). The four are
    Claude (`agents.yaml`), OpenAI (`agents.openai.yaml`), Gemini, and the local Ollama model
    (`agents.dgx.yaml`) — which satisfies "four providers including a local Ollama model".
    **Smoke-tested 2026-07-27** against a live key: pinned to `gemini/gemini-3.1-pro-preview`
    after `gemini-2.5-pro` and `gemini-3-pro-preview` both 404'd as retired-for-new-keys. Discover
    on the real Nimbus fixture returned a correct `business_logic` finding on `/api/pay`
    (Gemini 1, Claude 2 on the same file), and structured output validated on every call.
    **Reproducibility caveat for the scorecard:** every current Gemini *pro* model is
    preview-tagged, so the pin will eventually retire. Prefer re-pinning and re-running over
    switching to the `gemini-pro-latest` alias — a benchmark whose model silently changes makes
    the committed table a lie. `mode: json` remains the escape hatch if structured output churns.
  - **Token cost is NOT a hard requirement (decided 2026-07-27).** There is no counter anywhere in
    `harness.py`, so it would be new plumbing through every agent call for a column nobody gated on.
    Add it opportunistically if LiteLLM's usage data proves easy to thread; drop it otherwise.
  - **Reconciled:** output goes to `benchmarks/` (generated artifacts), not `bench/` (inputs:
    `answer_key.yaml`, `fixtures/`, `BASELINE.md`). `bench` takes a required positional `repo`,
    which `--all-configs` keeps. Effort raised to **M**: three of the four configs already exist
    (`agents.yaml` Claude, `agents.openai.yaml`, `agents.dgx.yaml` local Ollama) and
    `benchmarks/compare-vampi-three-way.md` is already committed — but **token cost has no
    plumbing anywhere** (no counter in `harness.py`) and models are not seeded today, so
    reproducibility-by-seed is new work, not a report format.
  - **Reconciled note:** verify precision and recall largely landed in `PLAN.md` **D2** —
    `metrics.json` carries `verify.{refuted, dropped_low_confidence, confirm_rate,
    avg_confidence}` — but those are volume/confidence stats, not precision or recall. Recall
    already exists as `bench.discovery_recall` (`bench.py:107`) scored against
    `bench/answer_key.yaml`; **precision is genuinely new work** (derivable from `noise`,
    `bench.py:103,112`). The other residue from that `BACKLOG.md` item is one counter:
    `_dedup_findings` logs discovery duplicates but never writes the count to `metrics.json`.

### Decision needed on G1

`DESIGN.md` records validation target as **live LB with snapshot and rollback (confirmed)**.
An offline evaluator adds a second, weaker source of truth, and a divergence between the
evaluator and real XC enforcement would be worse than no evaluator. Three options:

1. **Build it.** Highest value, and the conformance suite is the mitigation. Accept the
   maintenance cost of tracking XC semantics in two places.
2. **Skip it, simulate on the tenant.** Attach the candidate policy to a non-production LB
   in monitor mode, replay the sample through it, read the counters. Real semantics, no
   second implementation, but it needs a spare LB and a tenant round trip per candidate.
3. **Defer G1, ship G2 against option 2.** Simulation lands sooner and the evaluator becomes
   an optimization later.

**DECIDED 2026-07-27 — option 3.** A spare non-production LB can be created on demand, so the
tenant round-trip is not blocked. **G2 ships against monitor-mode replay; G1 is deferred to P2**
and becomes a speed optimization, to be reconsidered only with the labeled request/verdict corpus
G2 produces. If G1 is revived, scope it to G1a (`service_policy`) and keep G1b out.

**Why** — two reasons from the code. First, the
evaluator's real cost is not the predicate list but tracking `normalize_service_policy_spec` —
`apply.py` never sends what `generate` emits, and the matcher defaults it nested-merges in decide
the verdict on exactly the rules most likely to differ
(measurably: the nested matcher merge at `apply.py:93-95` widens 12 of the 31 rules on disk from
exact-path to also carrying `prefix_values: ["/"]`). Second, `api_schema` is enforced by XC's own
OpenAPI validator on a spec uploaded verbatim, so predicting it offline means reimplementing that
validator plus `fall_through_mode_allow`.
Divergence is asymmetric: *evaluator blocks, XC allows* silently discards a working band-aid;
*evaluator allows, XC blocks* ships the outage this feature exists to prevent. A conformance
suite pins the evaluator to **our documentation of XC**, not to XC — the ground truth that would
catch a misreading is a real LB, which is what option 2 builds. Shipping G2 first also produces
the labeled request/verdict corpus that makes a later G1 verifiable rather than self-consistent.

**Resolved, and fixed, 2026-07-27.** Reconciling G1 surfaced that normalization widened 12 of the
31 DENY rules on disk from an exact path to also carrying `prefix_values: ["/"]`. Tested on
`vpcopilot-lab`: **XC ORs the value lists**, so those band-aids denied every path — the exact-path
probe and two unrelated paths all returned 403, against a 307/405 baseline. The safety spine caught
it every time (the legit probe was blocked too, so validation failed and rolled back), so the cost
was effectiveness, not an outage: an exact-path band-aid could never pass on the first attempt.
Fixed in `normalize_service_policy_spec` — the nested merge no longer contributes the catch-all to
a rule that named a path itself. Worth re-reading historic self-heal counts with that in mind.

This is also the first concrete argument for G2: a policy that over-blocks *everything* is exactly
what a would-block replay surfaces in one pass, and it took a hand-built tenant probe to find.

---

## Phase H — Widen what the pipeline accepts

Input today is a source repo. The vulnerabilities most customers lose sleep over sit in
dependencies they do not own, where the code cure is a version bump someone else has to
ship. That is the case virtual patching exists for, and the pipeline cannot see it.

- [x] **H1** CVE and advisory input path. (M, P1) — **DONE:** `vpcopilot scan --cve CVE-2024-23334`.
  `inputs/osv.py` fetches the advisory, the new `resolve` agent derives its HTTP exploitation
  profile (or declines), and the result enters triage and generate unchanged. Verified live against
  api.osv.dev and a real model.
  - **Acceptance, as met (all four checked live):** CVE-2024-23334 (aiohttp path traversal) →
    **both** a `waf` and a `service_policy` band-aid; GHSA-8r6j-v8pm-fqw3 (fsevents supply-chain) →
    `no_bandaid` with the residual risk naming why a load balancer cannot see it; the cure reads
    `upgrade aiohttp to 3.9.2` with `patched_content` empty; the ledger seeds `found` with severity,
    band-aids and `has_cure` exactly as a repo finding does.
  - **What querying OSV for real changed.** Three behaviours are not visible from the schema and
    each silently degrades the answer: (a) asking for a **CVE id usually returns the GIT-range
    record** — no package, and `fixed` values that are commit SHAs; the installable `PyPI/aiohttp
    3.9.2` only exists on the `GHSA-5h86-8mv2-jq9f` alias, so the client follows aliases (2 of 4
    advisories tested needed the hop); (b) a commit SHA is never offered as an upgrade target —
    "upgrade to 24a6d649…" is not a recommendation; (c) `summary` is frequently empty and OS-level
    CVEs have no package at all, only a CPE, with the human versions hidden in
    `database_specific.extracted_events`.
  - **Declining is the load-bearing behaviour.** An agent that invents a plausible path for every
    CVE would make this input path worse than useless — confident band-aids that block nothing
    while a real vulnerability hides behind a green check. So `network_observable=false` is a
    first-class answer with a required, min-length `reason`, the agent is forbidden from choosing a
    control or guessing a version, and its paths are cleared in code if it declines and lists them
    anyway. The `no_bandaid` routing is **deterministic**, not delegated to triage.
  - **The fixed version is never model-generated.** `remediate` is not called on this path at all;
    `inputs/cve.py` builds the `RemediationPlan` from OSV. Drafting a patch against vendor code is
    structurally impossible rather than merely discouraged.
  - **Decisions:** `inputs/` **is** a package (H1/H2/H3 are three siblings of one shape and share
    the OSV client — the same criterion that justifies `agents/`), with a one-directional rule that
    nothing under it imports `pipeline`. `VulnClass` is **not** widened — a CWE→class table covers
    the common cases and `other` plus a concrete `exploit_sketch` is honest; widening ripples into
    every agent prompt and golden. No sentinel in `file`.
  - **Identity, not a fake path.** New optional `Finding.source` (`osv:CVE-…`) carries what `file`
    carries for a code finding. Two real bugs it fixes: `coverage_key` returned the plausible-
    looking `service_policy:` for every file-less finding, so all but the first were logged
    "already covered" and got **no band-aid at all**; and the dedup key `("", class, "L0")` merged
    distinct advisories of the same class. Both take a defaulted `identity` fallback, so the repo
    path is structurally unreachable and byte-identical.
  - **Registration is four places, not the three the roadmap said** — `config.AGENT_NAMES`,
    `console.AGENT_ROLES`, `report.py`, and **`bench_model.AGENTS`**, plus a `resolve:` block in
    all four `config/agents*.yaml` (an unlisted agent silently falls back to the default model and
    `run.json` records that as fact).
  - **Fixed en route (pre-existing `pr.py` bugs):** the no-patch check sat *above* the dry-run
    branch, so `--dry-run` raised identically to a live run and could preview nothing; and an empty
    `file` would have reached `repo.get_contents("")` as a directory listing rather than erroring.
  - **Deliberate consequence:** an advisory finding has no cure PR, so `reconcile` holds its
    band-aid and escalates at TTL. Someone still has to ship the upgrade — documented, not a
    surprise.

- [x] **H2** Dependency manifest input. (M, P2) — **DONE:** `vpcopilot scan --manifest <path>`
  (repeatable, additive like `--spec`) and the read-only `vpcopilot deps <path>…`.
  `inputs/manifest.py` parses `requirements.txt` / `package-lock.json` (v1/v2/v3) / `pom.xml`;
  `inputs/deps.py` resolves them against OSV and hands H1's stages one candidate per
  (advisory, package). `GET`+`POST /api/deps`, a manifest field and a **Preview (no model calls)**
  button on ① Scan, a **Dependencies** panel in the HTML report, `dependencies.json` in the evidence
  bundle. Verified live end to end against api.osv.dev and a real model. 81 tests.
  - **Acceptance, as met:** a manifest run lists affected packages ✅ and resolved advisories ✅
    (`dependencies.json`, complete regardless of what the agent stage reached) and produces one
    band-aid per exploitable advisory ✅; correlation collapses overlapping band-aids ✅ — and does
    it **across inputs**, which is the part that turned out to matter (see below).
  - **The Reconciled note below was already satisfied before this item started.** H1 added the
    `identity` fallback to `coverage_key` and the `f.file or f.source or f.id` dedup key, for the
    same reason. Nothing in `correlate.py` or `_dedup_findings` needed changing. (Both line
    citations had also drifted: the `coverage_key` call is `pipeline.py:352`, not `:226`.)
  - **Batch was the wrong tool for the obvious job, and the right tool for a different one.**
    `POST /v1/querybatch` returns advisory **ids only** — never the bodies. Fetching each id would
    be one request per *advisory* (70 for `aiohttp 3.9.1` alone) where `/v1/query` returns every
    full record for a coordinate in one round trip. So batch answers *which* packages are worth
    asking about (400 coordinates in 3.4s, ids identical to `/v1/query`, nothing truncated) and the
    bodies come from per-package queries for the hits: 16 requests for a 100-package manifest with
    15 vulnerable, against 100. One invalid ecosystem also fails the **whole** batch with HTTP 400,
    so entries are validated before sending and a failed batch degrades to per-package queries
    rather than to "no advisories".
  - **Four defects the live API found, three of them in code H1 already shipped:**
    - **CVSS v4 is now the majority and was being read as `medium`.** `severity_from_cvss` matched
      `CVSS:3.[01]` only. Live, `aiohttp 3.9.1` returns 43 v4 scores against 32 v3, and **38 of its
      70 records publish a v4 vector and nothing else** — every one of which fell through to the
      `medium` default whatever it said, including `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H`, an
      unauthenticated remote DoS. One CVE at a time that is a cosmetic mislabel; H2 *filters* on this
      value, so it decided what got resolved at all. Fixed by mapping v4's `VC/VI/VA` onto the v3
      names so **one** bucketing rule serves both and they cannot drift; `AT` defaults to `N`, so
      every v3 verdict is byte-identical (pinned by the existing parametrized test, unchanged).
    - **`upgrade_target` recommends another package's version.** It takes the first `affected` row
      carrying a version, whatever package it names — which is right for H1's question ("what does
      this advisory fix", shown beside the package) and wrong for H2's ("what should I install").
      Reproduced live: a manifest pinning `org.ops4j.pax.logging:pax-logging-log4j2 1.10.0` is told
      by Log4Shell to upgrade to **2.15.0**, which is `log4j-core`'s fix and not a version
      pax-logging has ever published; its own is `1.10.8`. Same shape on `GHSA-p6mc-m468-83gw`,
      where `lodash.pick` is affected with **no fix published at all** and would be sent to
      `lodash`'s 4.17.19. `upgrade_target_for()` filters to the installed package and takes the
      smallest published fix **strictly greater than the installed version**; `upgrade_target` is
      untouched, so H1 is unaffected.
    - **Which maintenance branch you are told about was decided by document order.** Selection
      ignored the installed version entirely. Log4Shell publishes `2.13.0→2.15.0`, `2.0-beta9→2.3.1`
      and `2.4→2.12.2` for one package; the live record happens to list the right one first, so
      `2.14.1` got the correct answer **by luck**. Nothing in the OSV schema promises that order and
      the failure it permits is recommending `2.3.1` to someone running `2.14.1` — a downgrade,
      presented as the fix. Pinned by a test that reorders the blocks. This also needed a version
      comparator: `packaging` is PEP 440 only and raises on Maven's `2.0-beta9`, and a string sort
      puts `1.10.0` below `1.9.2`.
    - **70 OSV records are 35 advisories.** OSV publishes a GHSA *and* a PYSEC entry for most Python
      advisories, cross-linked by `aliases`. Collapsing them is correctness, not thrift — the
      duplicate carries a different id, so nothing downstream would have recognised it as one, and
      it would have cost two model calls and two band-aids per hole. `related` is deliberately not
      followed: it links advisories that are *about* each other, not identical ones.
  - **A defect only the live run could find, and the one worth reading.** The first end-to-end run
    left **Log4Shell with no band-aid at all** while reporting it as covered. Triage recommended one
    control for it — the LB-wide `waf` — which an aiohttp header-injection advisory had already
    claimed, so the loop ended having generated nothing, and the WAF that actually shipped
    (`waf-block-header-injection-nullbyte-crlf`) addressed nothing about JNDI. Two fixes, both
    pinned: a finding whose *every* recommended band-aid was collapsed now falls through to its
    non-recommended alternatives rather than ending bare (Log4Shell gets
    `deny-log4j-jndi-lookup`), and an LB-wide correlation record now states that the attached policy
    was generated and validated against the **owning** finding's exploit, not this one's. **This is
    a deliberate behaviour change to a shared path** (B1 correlation, which repo scans use too): it
    only widens — the alternatives are reached solely when the recommended tier produced nothing, so
    a run where they succeed is byte-identical. Pinned in both directions.
  - **The scale problem is the design.** A manifest is an unbounded input, so listing and resolving
    are separated: `dependencies.json` carries every package parsed, every entry that could not be
    pinned, and every advisory found, whatever the agent stage reached; only the agent stage is
    bounded, by `--min-severity` (default `high`) and `--max-advisories` (default 25, `0` = off).
    Everything held back is listed **with the reason it was held back** — "we did not check this"
    and "this is clean" must never render the same way, in the CLI, the console, the report or the
    bundle caveats.
  - **The cap is shared across packages, not consumed in sort order.** The first live run made this
    obvious: `aiohttp 3.9.1` alone carries 35 advisories and a flat `(severity, package, id)`
    ordering handed it 23 of 25 slots, so every other package competed with one dependency's back
    catalogue and anything later in the alphabet was capped out by advisories no worse than its own.
    Dealt round-robin, the same 25 slots cover **7 vulnerable packages instead of 3**.
  - **Refusing to pin a version is the load-bearing behaviour, and OSV is why.** A version string it
    cannot parse does **not** error: `aiohttp` at `not-a-version`, `1.0.0-SNAPSHOT` and
    `${project.version}` each returned **81 advisories** live, against 70 for the real `3.9.1` and
    87 for no version at all. So an unresolved `${...}` or an unpinned `flask>=2.0` produces a
    bigger, wrong answer that every downstream stage treats as fact. Every entry the parsers cannot
    pin goes to `unpinned` with a machine-readable reason and is never sent.
  - **`vpcopilot deps` is the read-only surface**, reaching the same verdict about *which*
    advisories a scan would spend a model call on without spending one — no model, no credentials,
    no tenant. Both it and `POST /api/deps` call `deps.survey_report`, so the preview and the scan
    cannot disagree about scope.
  - **The artifact is `dependencies.json`, deliberately NOT `manifest.json`.** `export.verify_bundle`
    locates each run inside an archive by every member whose name ends `manifest.json`, so an
    out-dir artifact by that name would be read as a second evidence manifest and break verification
    of the bundle it ships in. Pinned by a test.
  - **Found by adversarial review, before shipping** (28 raised across five failure dimensions, 2
    refuted, 8 confirmed and fixed, plus 4 found while verifying the reviewers' claims). Every one
    is the same shape — *something never actually checked rendering as clean* — which is the single
    thing this input path exists to prevent:
    - **The alternates fallback re-inflicted the exact bug it was written to fix, on a different
      finding.** It ran interleaved with the recommended tier and generated **every** alternative,
      so a non-recommended alternate could claim an LB-wide slot *before* a later finding that
      actually recommended that control was reached. Reproduced: `loser`'s unrecommended
      `rate_limit` took the slot, `brute` — which recommended `rate_limit` — got **no band-aid at
      all** and was recorded as covered by a policy built from `loser`'s exploit, and `loser` got
      three controls triage never recommended. This contradicted the "only widens / byte-identical"
      guarantee stated below. Now a **deferred second pass**: every recommended claim is registered
      first, and the fallback takes only the **first** alternative that generates. Verified live —
      Log4Shell still gets `deny-jndi-log4shell-headers` after a *code* finding claims the WAF, and
      `otp-brute-001` gets one alternative where it used to get three.
    - **`code_fix_prs` counted dependency upgrades as drafted PRs.** A `--manifest` run reported
      `code_fix_prs: 6` and the report's impact hero rendered "6 — code-fix PRs (the cure)" when
      zero were drafted and none *can* be. Split on `kind`, the discriminator `pr.py` already
      decides by; `dependency_upgrades` is its own count and hero stat. A repo scan is unchanged
      (every remediation is `code_fix`). Pre-existing in H1 at N=1; H2 made it N-per-manifest.
    - **A `package.json` parsed to zero packages, zero skipped and no error** — byte-identical to a
      clean lockfile. `detect_kind` routes any JSON carrying `dependencies` to the npm parser, and
      a package.json has one, but of name → *range string* where a v1 lock has name → `{version}`;
      every entry failed the isinstance check and was dropped. It is now refused with an actionable
      error, because a package.json has no installed versions to check at all.
    - **`dependencies.json` was never cleared**, so a later scan of the same out dir *without* a
      manifest republished the previous run's dependency data through the report, `GET /api/deps`
      and the evidence bundle. It is the only conditionally-written member; the rest are always
      rewritten. (G4 shipped this same class of bug with leftover `policies/` artifacts.)
    - **One 429 during the batch fallback ended the whole scan** — including the repo half of a
      `scan ./repo --manifest` run. The per-package retry loop was unguarded, so the fallback that
      exists so a batch failure never loses a chunk became the thing that lost everything. Each
      coordinate is now guarded and a failed one is reported **unchecked**, never clean.
    - **A package whose advisory fetch failed rendered exactly like a clean one** — it stayed in
      `vulnerable` but contributed no row, no counter and no warning. New `unchecked` list and
      `packages_unchecked` counter, surfaced in `dependencies.json`, the CLI, the console and the
      report.
    - **The console preview dropped parse errors entirely**, so an unreadable manifest showed an
      all-zero funnel and an empty table — indistinguishable from a clean one. The CLI had printed
      them in red all along, so the guard lived on only one surface.
    - **A cleared "Max advisories" box meant NO cap in the console** (`parseInt("")||0` → 0 → off)
      where the CLI defaults to 25 — a two-surfaces divergence failing in the expensive direction.
    - **npm workspace source trees were queried as registry packages.** v2/v3 `packages` keys are
      paths; only `node_modules/…` are installs. First-party code was sent to OSV under a name that
      can collide with a public package, and an entry with no `name` went under its directory path,
      which is not a legal npm name — both counted as checked-and-clean.
    - Plus: a v1 lock entry with no `version` vanished from both halves of the answer where the
      v2/v3 branch refuses it explicitly; an unresolved `${...}` in a pom's **groupId/artifactId**
      reached OSV inside the coordinate name (only the *version* was guarded); and a short `200`
      from `querybatch` left the unanswered tail absent from the result, which the caller reads as
      "no advisories".
    - **Refuted, and worth recording:** `POST /api/deps` taking a caller-supplied path is *not* a
      new arbitrary-file reader. The console already accepts caller paths in `POST /api/scan`
      (`repo`, `spec`, `manifest`), `/api/apply` and `/api/apply-apischema`, binds `127.0.0.1`, and
      ships no CORS middleware; the identical capability is the documented CLI contract. J2's
      refusal of a caller-supplied path applied to a bundle **derivable from server state**, where
      accepting one adds capability for zero function. A manifest has no server-state equivalent.
  - **Decisions:** `--manifest` is **additive** (H3's precedent) rather than exclusive like `--cve`,
    because a manifest lives in the repo you are already scanning and the cross-input correlation is
    the point — verified live: Log4Shell's WAF slot was claimed by a *code* finding
    (`sqli-login-001`) in a `repo+manifest` run. Dev/test-scoped dependencies are **listed but not
    resolved** without `--include-dev`: a build-time package is not in the request path. One
    candidate per (advisory, package) — two packages hit by one advisory are two upgrades to ship —
    but the resolve agent runs once per *advisory*, so they cost one model call and cannot receive
    two different verdicts.
  - **Reconciled (superseded — see above):** B1 cannot be inherited as-is. `correlate.coverage_key`
    (`correlate.py:19-23`) keys request-scoped controls on `endpoint_of(file)`, which parses a *repo
    path*, and is called with `f.file` (`pipeline.py:226`). An advisory finding has no repo file.
    `coverage_key` needs a non-file identity (fall back to `Finding.endpoint` or the package
    coordinate) and `pipeline.py:40`'s dedup key needs the same treatment.

- [x] **H3** OpenAPI as a discovery input. (M, P2) — **DONE:** `vpcopilot scan --spec <path>`,
  alone or alongside a repo. `inputs/openapi.py` does a deterministic structural pass (unbounded
  numbers/strings/arrays, operations with no `security`, `additionalProperties` left open, `$ref`
  followed with a cycle bound) and the spec is then handed to the **existing `discover` agent** as
  one more file — no fourth agent, so spec findings verify, triage and generate exactly like code
  findings. Verified live end to end.
  - **Acceptance, as met:** a spec declaring `amount` with no lower bound produced
    `neg-amount-001` → `service_policy` + **`api_schema`**; spec/code drift is reported as
    `undocumented_or_orphaned`; findings flow into the same triage table.
  - **Split by what needs judgement.** The structural pass is code, so recall does not depend on
    which model is configured; the agent only decides which facts *matter* (an unbounded `page` is
    nothing, an unbounded `amount` on a transfer is a hole). The orphan comparison is pure code —
    it is a diff of two documents.
  - **Two real bugs the first live run surfaced.** (a) A spec is ONE file declaring MANY endpoints,
    so `endpoint_of("pay-api.yaml")` returned the same string for every finding and all six
    collapsed onto one `service_policy` coverage key, with five logged "already covered" and given
    no band-aid. Spec findings now carry `source` and leave `file` empty, and the coverage identity
    prefers `endpoint` — three endpoints, three keys, and only the two genuinely on
    `/api/v1/transfer` collapse. (b) The `undocumented_or_orphaned` finding was being sent through
    `verify`, which reads the offending source; with no source to read it refuted the finding at
    0.10 confidence. It is appended after verify instead — a comparison of two documents is not a
    claim about code.
  - **`--spec` is additive**, unlike `--cve`: alone it scans the contract, with a repo it also
    reports the drift (which needs both). `run.json` records `input_kind` as
    `repo` / `spec` / `repo+spec` / `advisory`.
  - Fixture: `bench/fixtures/specs/pay-api.yaml`.

---

## Phase I — Keep the band-aid temporary without being asked

`C2` retires a band-aid when someone runs `vpcopilot retire` and the cure PR has merged.
Nothing notices a band-aid nobody retired. The claim that virtual patches are temporary
holds only while a human keeps checking.

- [x] **I1** Patch expiry and reconcile loop. (L, P1) — **DONE:** `reconcile.py`. Every applied
  control gets a TTL at `ledger.mark_mitigated`, the one chokepoint all eight apply paths already
  call, so no apply site changed. `vpcopilot reconcile` walks the live band-aids and takes one of
  three branches per finding; `vpcopilot patches-list` is the cheap read. Console: `POST
  /api/reconcile` (background job, same log contract as apply) + `GET /api/patches`, surfaced as a
  patch-expiry table and two buttons in step ⑥ Retire. Three new audit actions, category
  `reconcile`. Verified live against the tenant and against real GitHub.
  - **The probe fires at ORIGIN, and that question decided the item.** With the band-aid live,
    firing at the LB proves only that the band-aid works. Measuring the tenant settled which of the
    three candidate designs was real: `crapi-lab` and `vampi-lab` origins answer directly (200),
    while `vpcopilot-lab`'s sits behind a BIG-IP that returns `403 Direct origin access denied`.
    So an operator-declared origin URL works — and "cannot probe" is a routine state, not an edge
    case. Detach → fire → re-attach was rejected: it turns an unattended pass into a mutating one,
    six of seven controls are LB-wide so detaching for one finding drops protection for all the
    others on that LB, and `ApplyContext.load()` writes a snapshot per call, so a nightly pass
    would repoint `drift.latest_snapshot` and I2 would start reporting reconcile as operator drift.
  - **Acceptance, as met:** `patches-list` shows age, TTL remaining and PR state; reconcile is
    idempotent and cron-safe (`O_EXCL` pass lock that exits rather than piling up and breaks itself
    when stale; a pass that changes nothing writes nothing; escalate-once-then-on-change); an
    escalation leaves the control in place (`kept: true`) and writes an audit record; step ⑥
    surfaces TTL and escalation state.
  - **Decisions (2026-07-29):** escalation delivers an audit record + exit 2 **and** an optional
    `VPCOPILOT_ESCALATION_WEBHOOK`; reconcile is **report-only unless `--apply`** — authoring the
    crontab is the human gate, exercised once; `init_from_scan` no longer prunes an entry whose
    band-aid is still live.
  - **Deliberate behaviour change:** `ledger.init_from_scan` used to delete every entry absent from
    the current triage, including one whose control was still attached — orphaning a live band-aid
    where reconcile could never find it. It now keeps entries with a live mitigation. Cross-target
    mixing (the P0-3 invariant) is still prevented, because a finding from another app has no
    mitigation of ours.
  - **Refusing to guess is a first-class outcome.** No origin, unreachable origin, failing legit
    request, probe that cannot authenticate, no recorded probe, unreadable cure PR — each holds the
    band-aid and says why. The dangerous failure is the mirror image: a connection error reading as
    "the exploit did not succeed", reading as "fixed", detaching a control protecting a still-
    vulnerable app.
  - **No new state.** `STATES` stays four long and `_advance` is untouched: `fix_ineffective` and
    `escalated` are facts about time and evidence, not lifecycle positions — a finding past its TTL
    is still `mitigated`. Four other modules order these states by index. TTL and reconcile state
    are top-level keys, deliberately not nested in `mitigation`, which `report.py` stringifies
    straight into the committed demo fixture.
  - **Found by adversarial review, before shipping** (33 findings raised, 18 refuted, 15 confirmed
    and fixed; the first two were reproduced live against the tenant):
    - **A band-aid could vouch for its own removal.** Both HTTP paths follow redirects and nothing
      checked which host answered, so a probe that reached the LB — via a canonical-host redirect
      or a mistyped origin — was blocked by the very control under test, and that read as "the app
      is fixed". Now `probe.blocked_by_edge()` separates an F5 edge verdict from the app's own, and
      that case is `skipped_not_at_origin`. **Verified live**: a real DENY policy attached to
      `crapi-lab`, reconcile pointed at the public URL, probe returned `blocked=True, legit_ok=True`
      — the exact retire conditions — and the guard held it. Tenant restored afterwards.
    - **Retiring one finding could strip another's protection.** Six of seven controls are LB-wide,
      so detaching finding A's WAF removes finding B's too — and Data Guard dies with the WAF it
      hangs off, a pair that ships in the demo dataset. `_control_present` cannot see this: it
      answers "is a control of this kind attached", not "is this mine and does anyone else need
      it". Now `skipped_shared_control`, plus `skipped_not_our_policy` when the attached policy
      name is not the one this finding applied.
    - A transient `ok` (probe cooling down) overwrote a standing `fix_ineffective`, turning a
      known-broken fix green on the dashboard and in cron.
    - `last_probe_at` was stamped for probes that never fired — a missing probes.json or a wrong
      login path silenced the real probe for 24h. Observed live.
    - One finding's exception ended the whole pass, so findings after it were never checked.
    - `--force-probe`'s guard lived only in the CLI, leaving the console able to mass-replay every
      destructive exploit; it now lives in the module, where both surfaces get it.
    - Reconcile's probe was stored as `before_after`, which `report.py`'s Band-aid impact table
      renders and marks `fail` without a `passed` key — a successful auto-retire showed as a
      failure. It is `origin_probe` now.
    - Plus: a vacuous origin gate for probes with no `legit` leg, `init_from_scan` writing the
      ledger outside `_LOCK`, denormalized finding fields not reaching the export columns they were
      added for, `trigger=cron` documented but unreachable, and the console refreshing only the
      ledger after a pass.
  - **Fixed en route (I2 defect):** `drift._control_present` reported EVERY control as attached on
    an LB whose spec omitted the key, because each `detach_control` also *writes* an explicit
    disable marker, so "detaching changed the spec" was true even when the control was never there.
    Now derived from what detach **removed**. Pinned by a 17-case table over all seven controls.

- [x] **I2** Drift and conflict detection. (M, P1) — **DONE:** `drift.py` compares live LB vs last
  snapshot vs proposed, read-only throughout. `drift.preflight()` is the pre-apply gate, called by
  **both** apply paths — `apply.apply_from_scan` and `refiner.refine_apply_service_policy` (the
  latter is the default for `--from-scan` and the console's Mitigate button, so gating only the
  former would have gated nothing anyone uses). Surfaces: `vpcopilot drift --lb <name>` (exit 1 on
  conflict), `GET /api/drift`, `--force` / console **apply anyway**. Six new audit actions, all
  category `gate`. Verified live against `banknimbus-dev`.
  - **Acceptance, as met:**
    - `no_change` — met. Reports and writes nothing: no LB PUT, no `snapshots/`, no
      `lb_snapshot.json`, and no stray policy object, because the gate runs before the XC *create*,
      not just before `ApplyContext.load()`.
    - field-level diff of a hand edit — met. Verified against a real 2026-07-24 snapshot of
      `banknimbus-dev`: 12 dotted-path changes, correctly attributed.
    - drift runs read-only — met, and pinned by tests on both the CLI and the endpoint (the
      endpoint is polled from the browser; a version that wrote a snapshot would corrupt the run
      dir just by someone opening a page).
    - **"an earlier ALLOW rule shadowing the new DENY blocks apply as a conflict" — the criterion
      as written was wrong, and running it live is what proved it.** It assumes the new policy is
      appended after the attached ones. Both attach paths do the opposite — they replace the oneof
      with exactly one policy (`apply.py`, `refiner.py`: `active_service_policies = {"policies":
      [{ns, name}]}`) — so this tool never leaves two service policies attached and there is no
      earlier policy to be shadowed by. The first live run produced a confident false positive on
      `banknimbus-dev`. Replaced by the two real behaviours underneath it:
      - **shadowing, in its only true scope** — an ALLOW *inside the policy being applied* that
        matches the exploit before its DENY. This **refuses** (`--force` overrides), and reuses
        `lint_service_policy` rather than re-deriving FIRST_MATCH so the two can never disagree.
        On the refine path it degrades to a warning: reordering rules is what the refine loop
        exists to do, and refusing there would break the default flow to protect it from a problem
        it already fixes.
      - **displacement** — that same wholesale replacement silently *detaches* whatever was
        attached, which is a live loss of protection nothing was reporting. Warned and audited
        (`policy_displaced`, carrying whether the displaced policy is what currently blocks this
        exploit), never refused: replacing the previous band-aid is the normal flow and refusing
        would break every second apply. Follows the G2 precedent — warn with an audited override,
        not a machine veto.
  - **Deliberate partial:** `no_change` is determined for `service_policy` only. There the proposed
    end state is exact (that policy name in `active_service_policies`), so "unchanged" is a fact.
    For the six LB-wide toggles, presence is detectable by inverting `detach_control` but presence
    is **not** parameter equality — a `rate_limit` already on at 100/MINUTE would read as unchanged
    while you push 5/MINUTE. Silently skipping a real change is worse than re-applying an identical
    one, so those report `already_attached` with a note and are never auto-skipped.
  - **No regressions:** an LB already carrying a foreign policy still mitigates (warn + proceed);
    dry runs are never gated; `create_only` is never gated; behaviour with no snapshot and no
    conflict is byte-identical to before. Each pinned by a test.

---

## Phase J — Evidence a reviewer outside the building trusts

The export is internally consistent: `manifest.json` SHA-256s every member. Nothing
*cryptographically* binds the bundle to who produced it — the manifest records `generated_by` /
`generated_on` (`export.py:165`), but as unauthenticated strings — and nothing outside the machine
sees the trail. J1–J4 are the open `BACKLOG.md` evidence entries, scheduled; **J5 is new**.

- [x] **J1** Sign the evidence bundle. (S, P1) — **DONE:** `sign.py` shells out to `minisign` and
  drops `manifest.json.minisig` beside the manifest in every bundle (each run's manifest in an
  `--all` bundle). No new dependency, so `export.py` stays stdlib-only. Optional at every level: no
  key, no binary, an unreadable key or a failing signer each log one line and export unsigned.
  A detached signature beside the manifest, making a bundle attributable after it leaves the
  machine. **DECIDED 2026-07-27: minisign.** One small dependency, one keypair, a detached
  `manifest.json.minisig`, and verification is a single command a reviewer runs without this
  toolchain. GPG drags in keyring assumptions that fail badly in CI; sigstore (OIDC flow, bundle
  format) is the more defensible answer but is **not S** — raise it as its own item if wanted.
  The signature attests **who exported this bundle**, not that the audit log it contains is
  truthful; `docs/USAGE.md` has to say exactly that.
  - Acceptance: signing is optional and its absence never fails an export ✅; the signature
    covers the manifest digest ✅ (it signs the exact manifest bytes that ship, and the manifest
    SHA-256s every member, so coverage is transitive); `docs/USAGE.md` states plainly what the
    signature does and does not attest ✅.
  - **No passphrase handling, by design.** The key must be unencrypted (`minisign -G -W`). A signing
    passphrase is a credential this tool has no business holding; requiring a key managed by
    whatever already manages your secrets is the honest trade, and it is documented rather than
    discovered at the prompt.
  - **Round-trip verified against minisign 0.12**, not just a stub: keygen → export → verify
    ("Signature and comment signature verified"); a tampered manifest fails; a tampered *member*
    is caught by the manifest's own SHA-256 while the signature stays valid — the chain is what
    makes that digest trustworthy; a wrong public key fails on key-id mismatch.
  - **The real run found a leak a stub could not.** The signed trusted comment embedded the
    exporter's absolute filesystem path. It now carries the tool version and `run_id` — the join
    key that already identifies the run — and a test pins that no local path appears in it.
  - **The signature is not self-verifying from inside the bundle.** The reviewer needs the public
    key out of band — a key shipped alongside the thing it signs proves nothing. Stated in the
    manifest's own `caveats`, so it travels with the bundle.

- [x] **J2** `vpcopilot export --verify`. (S, P1) — **DONE:** `export.verify_bundle` re-reads a
  bundle and checks it against its own manifest; `vpcopilot export --verify <zip> [--pubkey <key>]`
  exits non-zero on any problem, so it drops into CI. Verified end to end against a real signed
  bundle: clean → OK, tampered member → `MISMATCH audit.log`, smuggled file → `UNLISTED`, no key →
  `present-unverified` and still OK.
  Re-read a bundle, recompute every member digest against the manifest, check the signature
  when present, print pass or fail per member.
  - Acceptance: a tampered member reports by name ✅; a bundle with no signature verifies its
    digests and says the signature is absent rather than failing ✅; stdlib only ✅ (the digest half
    is pure stdlib — the same check `docs/AUDIT.md` documents by hand; only the optional signature
    check shells out to `minisign`, adding no dependency).
  - **Four member verdicts, not two.** `ok` / `mismatch` / `missing` / `unlisted`. A file **added**
    to a bundle is exactly as suspicious as one altered, and a check over only the listed members
    would wave it through.
  - **`present-unverified` is a third signature state and NOT a failure.** Without a public key the
    signature genuinely cannot be checked, and one shipped inside the bundle proves nothing. A
    reviewer without the key must still be able to check digests; reporting "I cannot check this"
    the same way as "this is forged" would destroy the distinction that matters most.
  - **Console surface is deliberately narrow.** `GET /api/audit-verify` checks
    `<out>/audit-bundle.zip` only — a path derived from server state, never from the request. An
    endpoint taking a caller-supplied path would be an arbitrary-file reader, and localhost is not
    a reason to ship one; verifying a bundle that has already left the machine is the CLI's job,
    because that is where the reviewer is.
  - **Reconciled:** does **not** depend on J1. Digest verification works on any bundle today —
    `manifest.json` already SHA-256s every member and `docs/AUDIT.md` ships a runnable
    verification snippet. Signature checking is added when J1 lands.

- [ ] **J3** Audit event sink. (M, P2)
  An optional sink on `audit.record` sending each entry to syslog, an HTTP webhook, or
  stdout JSON, putting the trail somewhere other than the box making the change.
  - Acceptance: fail-soft, a dead collector never fails an apply and logs one warning;
    configured in `.env` and the ⚙ Setup page; the local `audit.log` stays authoritative.
  - **Reconciled:** there is no Admin tab — credential and `.env` editing lives on the ⚙ Setup
    page (`GET`/`POST /api/config`).

- [ ] **J4** Attribution backfill. (S, P2)
  `vpcopilot audit-backfill` fills only what is provably derivable, policy name to finding
  via `policies.json`, marks the rest `unknown`, and records the backfill itself.
  - Acceptance: no entry gets an invented actor or run_id; the backfill writes its own audit
    record; a second run is a no-op.
  - **Reconciled:** `audit` is a flat `@app.command()` with no typer sub-app, so `audit backfill`
    as two words is not addable as written — `audit-backfill` matches the existing kebab
    convention (`bench-model`, `apply-maluser`, `xc-rm`, `lab-create`). Smaller than it looks:
    `export.build_audit_events` **already** recovers a finding from the `policies.json` index for
    legacy entries and already leaves blanks rather than inventing. J4 persists what the exporter
    derives at read time. **It cannot rewrite `audit.log`**: the log is append-only
    (`audit.py:26`) and `record()` strips caller-supplied identity (`_STAMPED`, `audit.py:17,21`),
    enforced by `test_identity_cannot_be_overridden_by_a_caller`. The backfill must write a
    sidecar (e.g. `<out>/audit-backfill.json`) that `export.build_audit_events` consults beside
    its existing `by_policy` lookup. Note a second copy of that lookup already exists —
    `ledger.find_finding_for_policy` (`ledger.py:108`) — consolidate on one rather than adding a
    third. Needs a `POST /api/audit-backfill` twin per the two-surfaces invariant.

- [ ] **J5** Weakness and framework mapping. (M, P2)
  Stamp each finding with a CWE ID and an OWASP API or Web Top 10 category at triage, and
  carry them through the ledger, report, and export.
  - **Decide where the field lives first:** `findings.json` is a dump of the *discover* contract
    (`Finding`, `schemas.py:47-61`, written at `pipeline.py:301`); triage's output is
    `TriageDecision` in `triage.json`. Either add optional `cwe`/`owasp` to `Finding` and have the
    pipeline back-fill them from the triage result before `_write_out`, or put them on
    `TriageDecision` and reword the acceptance to name `triage.json`.
  - Acceptance: every finding in `findings.json` carries a CWE; the HTML report groups by
    category; `audit.csv` includes the columns; the mapping is stated as the agent's
    classification, not a certification claim, matching the honesty of the existing caveats
    list.
  - Note: regulated buyers ask for the compensating-control story in these terms. The claim
    stays "here is the evidence a reviewer needs," not "this satisfies a control."

---

## Phase K — Reach developers without the console

- [x] **K1** MCP server mode. (M, P1) — **DONE:** `vpcopilot mcp [--write]`. `mcp.py` is a
  hand-rolled Model Context Protocol server over stdio — **no new dependency** — exposing ten
  read/scan tools always and five mutating ones only when writes are explicitly enabled.
  **Verified against a real MCP client**: registered with Claude Code, `✔ Connected`, tools
  enumerated, and driven end to end over a real subprocess pipe against the live H2 run data and
  live OSV. 53 tests.
  - **Acceptance, as met:** apply/pr/retire/reconcile (and `simulate`) are **absent** from
    `tools/list` unless enabled ✅ — absent rather than present-and-refusing, because a tool an agent
    can see is a tool it will try; every write tool calls the same module function the CLI and
    console call ✅, so it inherits `guard_lb`, `PROTECTED_POLICIES`, `drift.preflight`, the G2
    blast-radius gate, rollback-unless-`keep` and a centrally-stamped audit record rather than
    reimplementing any of them; every argument of every tool carries a description ✅, pinned by a
    test that walks the schemas rather than by review.
  - **The acceptance criterion could not be met as written, and fixing that is the largest change
    here.** "The same gate and guardrails as the CLI and console" presumes the two agree. They did
    not: `simulate.promotion_block` — the G2 blast-radius gate — had exactly **one** production
    caller, `console/app.py`, so `vpcopilot apply --from-scan` would attach an over-broad policy the
    console refuses with a 409, and the `--allow-overbroad` flag **this file described at line 143
    did not exist**. Same shape as I1's `--force-probe`, whose guard lived only in the CLI and left
    the console able to mass-replay every destructive exploit. So the check moved into
    `simulate.promotion_gate`, called by **both** `apply.apply_from_scan` and
    `refiner.refine_apply_service_policy` (the latter is the default for `--from-scan` and the
    console's Mitigate button, so gating only the former would have gated nothing anyone uses), and
    the CLI gained the flag. **This is a deliberate behaviour change to a shared write path**: a CLI
    apply now refuses an over-broad policy unless `--allow-overbroad`, and writes the
    `simulate_override` audit record it previously never wrote. Still warn-with-audited-override, not
    a machine veto (the G2/I2 precedent). Pinned in both directions, including that a policy with no
    simulation applies exactly as before.
  - **`simulate` is not read-only, and the item listed it as such.** G2's simulation creates a
    throwaway `<name>-vpcsim` policy object, **attaches it to the load balancer**, replays through it
    and deletes it. Cleaning up after itself makes it safe, not read-only, so it sits behind the same
    opt-in as `apply`; `simulation_result` is the ungated way to read a previous run's numbers. The
    three-tier taxonomy this forced — `READ` / `WRITES_OUT` (a scan, additive, tenant untouched) /
    `MUTATES` — drives the MCP annotations from one `Access` value per tool, so `readOnlyHint` and
    `destructiveHint` cannot drift from the truth.
  - **stdout belongs to the protocol, and this codebase is the worst possible tenant for that.** The
    spec forbids writing anything to stdout that is not an MCP message, and `run_pipeline`,
    `survey_report` and `drift.check` all default `log=print`, with `rprint` used throughout the CLI.
    Passing `log=` at every call site is a convention, and a convention is what the next call site
    forgets — so `serve()` reassigns `sys.stdout` to stderr for its lifetime and writes frames to a
    private handle, which makes a stray `print` **anywhere beneath it** structurally incapable of
    corrupting the stream. Verified empirically that `rich` follows the swap (it resolves
    `sys.stdout` at write time rather than binding it at import), and pinned by a test that prints
    from inside a tool.
  - **A scan is start-then-poll, not one blocking call.** A scan takes minutes and an MCP call is
    request/response, so `scan_start` returns a job id and `scan_status` tails the log with a `since`
    cursor — the same shape the console already uses, with none of its FastAPI coupling. The log sink
    is a list, so progress is returned to the caller rather than written anywhere.
  - **Decisions.** *Stdlib, not the official SDK* (which is available, at 2.0.0): the surface K1 needs
    is `initialize` / `tools/list` / `tools/call` / `ping`, hand-rolling it keeps `vpcopilot mcp`
    working with no extra install unlike `console`, it is testable offline by feeding frames to
    `handle()`, and it avoids pinning a major-version API that churns under a committed demo. The
    interop risk is real but bounded, and it was retired by testing against a real client rather than
    by argument. *Opt-in is `--write` or `VPCOPILOT_MCP_WRITE=1`*, not a key in `agents.yaml` —
    `config.py` is an agent-model registry and a feature flag does not belong in it; authoring the
    client config is the human action, exercised once, which is the argument I1 made about the
    crontab. *`apply`/`pr`/`retire` default to `dry_run=True`*, inverting every module default,
    because the CLI and console each pass a choice a human made at a keyboard and an MCP call is
    issued by a model. *`force_probe` is not exposed at all* — its guard needs a single `--finding`
    because replaying every destructive exploit at once is not something to do by accident, and a
    model deciding to pass it is exactly that accident. *`apply` takes a policy **name**, not a
    path*, derived against the run directory (the J2 precedent), validated as a slug and checked to
    resolve inside `<out>/policies`; traversal already failed because the mandatory `service_policy.`
    prefix makes the first segment a directory that must exist, which is luck rather than design.
  - **What the opt-in cannot do is supply the human.** MCP clients are expected to confirm tool calls
    with a user, but that is client behaviour this server can neither enforce nor verify — stated in
    `docs/USAGE.md` rather than implied, and the reason the write tools are off by default.
  - **Fixed en route (pre-existing):** `apply_from_scan(create_only=True)` returned before
    `apply_service_policy`, the only caller of `guard_lb`, so it wrote a policy object into the tenant
    with neither the protected-LB check nor the drift preflight. It attaches nothing, so no traffic
    changed — but a persistent write against a protected target should not be the one path that skips
    the guard. `guard_lb` is now unconditional at the top of `apply_from_scan`; it is a pure check, so
    the other paths are unchanged.
  - **Found by adversarial review, before shipping** (18 raised across five failure dimensions; 12
    verified, of which 3 were confirmed outright and 9 were refuted **because they had already been
    fixed mid-review** — the skeptics were reading the patched tree, as happened in H2 — plus 6 lower
    -severity ones triaged afterwards). The two that mattered:
    - **A malformed `tools/call` killed the server outright, with zero frames written.** JSON-RPC
      permits positional (array) `params`, and a list is truthy, so `params.get(...)` raised straight
      out of `serve()`'s loop; a non-string tool name did the same through an unhashable dict lookup.
      The client waits forever on a request that will never be answered and every later request is
      lost with it. Dying silently is the worst available failure for a transport. Both inputs are now
      invalid-params, and — the structural half — the loop wraps `handle()` and answers `-32603`
      rather than ending, so a bug not yet written cannot kill the connection either.
    - **A narrower replay erased an earlier policy's blast-radius flag.** `simulate --policy B`
      filters the candidates and `write_result` overwrote `simulation.json` wholesale, so a policy A
      an earlier run had flagged lost `blocked_promotion` — and the gate above went quiet for it. An
      operator who simulated everything, saw A flagged, then re-simulated only B would find A
      applying with no warning: a guard erased as a side effect of measuring something else, which is
      I1's "a band-aid could vouch for its own removal" in a new place. Entries this run did not
      measure are now carried forward stamped `carried_from`, so the gate keeps firing and nothing
      passes an old number off as fresh. Pre-existing in G2; the gate move is what made it load-bearing.
    - **A regression this change introduced, caught here:** the legacy `POST /api/apply` — still
      served though the UI no longer calls it — began enforcing the moved gate while `ApplyReq`
      carried no `allow_overbroad`, turning warn-with-audited-override into an unoverridable machine
      veto on that one surface. All four call sites of the two gated functions now expose the flag.
    - Plus: a `tools/call` `TypeError` was reported as *invalid arguments*, which would send an agent
      round a loop retrying arguments against a fault inside a tool (there is now deliberately no
      `except TypeError`, because `validate_args` makes an argument-binding error unreachable and a
      test pins that every documented property is a real parameter); `scan_status` read the log twice
      and could advance its cursor past what it returned, losing lines a client could never re-request
      (proven at 565 of 20000 polls); a corrupt `findings.json` rendered as `[]` — the H2 confusion,
      reproduced in new code — so an unreadable member is now `null` and named in `unreadable`;
      `impact`/`ledger`/`patches_list` answered a **nonexistent** run directory with confident zeros;
      `scan_start` accepted a path that does not exist, which `run_pipeline`'s own docstring calls
      "the failure mode not to extend"; two scans into one run directory interleaved their artifacts;
      a notification whose method was a request method was answered with an unsolicited `id: null`;
      stdin was decoded with the process locale rather than the mandated UTF-8; and the `drift` tool's
      description promised a shadowing check that does not run without `policy`.
  - **Reconciled, and confirmed accurate:** `triage` and `generate` have **no module function to
    share** — both take a live `Harness` plus pydantic models with no CLI or console twin — so v1
    exposes them only as stages inside `scan_start` rather than inventing twins for them. `vpcopilot
    mcp` matches the flat command set; there is no `serve` verb.
  - Note: pairs with the vendor's own Distributed Cloud MCP server effort. Keep them independent.
    This one exposes the pipeline, not the tenant — `mcp.py` never imports `xc`, pinned by a test.

- [ ] **K2** GitHub Action. (M, P2) Depends on G2.
  Scan the diff on a pull request and comment each new finding above a severity threshold
  with the proposed band-aid and its would-block count.
  - Acceptance: a PR introducing a known flaw gets one comment carrying the policy and the
    simulation result; a PR with no new findings posts nothing; runs in under three minutes
    on the Nimbus repo; never writes to XC from CI.
  - Surfaces: `.github/actions/vpcopilot-scan/`, `docs/CI.md` (every file in `docs/` is
    uppercase).

---

## Phase L — One finding, every enforcement point

- [ ] **L1** Emitter abstraction and non-XC backends. (L, P2) **Decision needed.**
  Refactor `generate` output behind an emitter interface and add NGINX App Protect,
  BIG-IP ASM, and ModSecurity backends. Generation only, no apply.
  - Acceptance: the Nimbus negative-amount finding emits a working rule on all four
    backends; a control with no equivalent reports `unsupported` with the reason rather than
    emitting a broken rule; adding a backend touches nothing outside the emitter package;
    `controls.py` keeps the XC registry unchanged.
  - Surfaces: none stated. `src/vpcopilot/emitters/` would be a **third** sanctioned package
    alongside `agents/` and `console/` — everything else is flat under `src/vpcopilot/`. Settle
    that with the `inputs/` question in H1, or use a flat `emitters.py` with a registry keyed the
    way `controls.py` is.
  - Decision: the triage toolbox in `DESIGN.md` is XC-shaped by design, and the seven
    controls map to XC objects. Three questions before starting. Does one finding covering
    BIG-IP and NGINX strengthen the hybrid-fabric story enough to carry the abstraction
    cost. Does ModSecurity output belong here as the contributor hook, or does it dilute the
    XC proof. Does the emitter refactor wait until the pipeline stops changing shape.

---

## Deliberately out of scope

- Replacing a SAST or DAST product. This routes findings to controls and closes the loop.
- Autonomous application with no human decision.
- A hosted or multi-tenant service.
- Full XC policy language coverage in any offline evaluator.
- Applying to non-XC enforcement points. `L1` generates, it does not deploy.
