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

- [x] **J3** Audit event sink. (M, P2) — **DONE:** `audit_sink.py`, hooked inside `audit.record`
  itself, so all 30 call sites and all three surfaces inherit it with no call-site change.
  `VPCOPILOT_AUDIT_SINK` picks the transport by scheme — `https://…` (POST), `syslog://host:514`
  (RFC 3164 datagram), `syslog:///var/run/syslog` (unix datagram), `stdout`, or `off` — plus
  `VPCOPILOT_AUDIT_SINK_TOKEN`. Both keys are on the ⚙ Setup page; `vpcopilot audit-sink [--send]`
  and `GET`+`POST /api/audit-sink` are the check. No new dependency (httpx is already a base dep;
  syslog is a raw socket). Verified live end to end. 68 tests; suite 785 → 854, coverage 79% → 80%.
  - **Acceptance, as met:** a dead collector never fails an apply ✅ — verified live, a real
    `audit-backfill` against a black-holed sink exited **0**, wrote its sidecar and its audit entry,
    and emitted exactly **one** warning; configured in `.env` and the ⚙ Setup page ✅ — verified by
    POSTing `/api/config` in a running console and watching it take effect with **no restart**; the
    local `audit.log` stays authoritative ✅ — the line is serialized **once** and handed to both
    destinations, so the shipped copy is byte-identical to the line on disk (verified live), and a
    failed local write delivers nothing.
  - **"Logs one warning" is a design constraint, not a log line.** A hung collector at a 5 s timeout
    times the several entries one apply writes is a stall the criterion does not name but plainly
    forbids. So a failure starts a 60 s cooldown: one timeout and one warning per outage, not per
    entry. The warning goes to **stderr**, never stdout — `audit.record` takes no log callable and
    adding one would land it in `**detail` and be serialized into the entry, and a warning that
    relied on K1's stdout swap would corrupt the protocol stream anywhere the swap is not in force.
  - **Refusing to guess, applied to a transport.** An unparseable sink value is reported `unusable`
    with the reason on every surface — it is *not* silently equivalent to having no sink. That is the
    H2 `unpinned`-vs-clean distinction, and it is the whole feature: a run succeeds either way, so
    without it a misconfigured sink is invisible.
  - **`off` is a value, not an empty box.** `console._write_env` drops falsy updates and the UI skips
    empty inputs, so clearing the field cannot unset a key — without an explicit `off`, a sink
    switched on from the Setup page could never be switched off from it.
  - **The syslog size limit is asked of the kernel, never hardcoded — and it is not theoretical.**
    Measured: a macOS `/var/run/syslog` unix socket has `SO_SNDBUF` **2048** and refuses more with
    `EMSGSIZE`; UDP walls near 9216; a Linux `/dev/log` is far larger. A realistic `drift_detected`
    carrying a 60-field diff measured **5,481 bytes** — 2.7× the macOS limit — so the entries that
    overflow are exactly the ones worth shipping. The full entry is sent and *only* a kernel refusal
    triggers a reduced envelope. Verified against a real kernel: a **16,139-byte** entry was refused
    on UDP and a **363-byte** valid-JSON envelope arrived carrying the action, `finding_id`, the true
    byte count and a pointer to the local log, while the on-disk entry kept all 120 changes. A
    dropped record or a truncated fragment would both have read as nothing happening.
  - **Decisions.** *Hooked inside `audit.record`*, the one chokepoint, so the MCP write tools inherit
    it with no tool-list change (pinned by a test). *No new `record()` parameter of any kind* —
    `**detail` swallows unknown kwargs and `json.dumps` has no `default=`, so a stray `log=` would be
    serialized into the entry or raise after the LB was already mutated. *The sink never writes an
    audit record of its own*: it lives inside `record`, so that would recurse, and an
    entry-count-changing side effect is the bug J4's no-op check exists to prevent — delivery status
    is reported by `audit-sink` and the Setup card instead. *The entry goes verbatim, with no
    envelope and no `out_dir`* — a filesystem path is not something to put on the wire (the J1 leak
    precedent) and `run_id` is already the join key. *One sink, not a list.* *Timeout hardcoded at
    5 s*, matching the house style of literal timeouts, but shorter than `reconcile.notify`'s 10 s
    because this one sits on the critical path of an apply rather than at the end of a pass.
  - **Deliberately no MCP tool.** The sink itself is inherited by every MCP write tool, which is the
    point; the *check* is operator configuration, and sending a test event to an external collector
    on a model's initiative is what K1's opt-in exists to prevent.
  - **Found by self-review before the reviewers reported, each pinned by a test.** Two were real
    leaks or dead ends rather than style:
    - **A password in the sink URL would have been printed on every surface.** `urlsplit` puts
      userinfo in `netloc`, and the redactor was rebuilding the origin from `netloc` — so
      `https://svc:hunter2@collector/x` rendered the password on the CLI panel, the Setup page and
      the API response. Rebuilt from `hostname`/`port`, with userinfo collapsed to `…@`.
    - **An IPv6 collector could never be reached.** The socket family was hardcoded `AF_INET`, so
      `syslog://[fe80::1]:514` was configured and delivered nothing, for ever — the exact
      "configured but silently dead" failure the item exists to surface. Resolved via `getaddrinfo`.
    - **`check(send=True)` erased the evidence it was called to diagnose.** It called `reset_state()`
      to escape the cooldown, wiping a long-lived console's record of earlier failures: an operator
      clicking the button to investigate deleted the symptom. Replaced by an explicit `force` that
      bypasses only the cooldown; a test event that lands also re-arms a suppressed sink.
    - Plus: the one-warning latch was a check-then-set across the console's per-apply threads (now
      check-and-set under a lock); the oversize envelope could itself overflow, since it borrows
      unbounded strings from the entry (now bounded); and whitespace in a hostname could split the
      syslog header so a receiver read part of it as the tag.
  - **Found by adversarial review, before shipping** (35 raised across six failure dimensions; 4
    confirmed after independent skeptics tried to refute each, and every one was the same shape the
    item exists to prevent — *not delivering, rendering as delivering*):
    - **The one input that produced silence was the one this module exists to make loud.**
      `urlsplit` *raises* on some malformed values — a dropped bracket in an IPv6 host
      (`https://[2001:db8::1/x`), a netloc failing NFKC validation — and unguarded that propagated
      out of `status()` into a **CLI traceback and a console 500**, while `emit`'s catch-all
      swallowed it with **no warning and no `last_error`**. Reproduced on all three surfaces. Made
      reachable by this item's own IPv6 support, which is what invites that typo. Now returns the
      ordinary invalid shape every surface already renders.
    - **A 3xx counted as a successful delivery.** The client does not follow redirects, so the body
      was never re-sent — a moved ingest path or a proxy bouncing to an SSO page would swallow the
      entire audit stream while every surface read `delivered N/N`. Reproduced against a real 302
      server: `sent`, `delivered 1`, exit 0, and the redirect target never contacted. **Refused
      rather than followed**, deliberately: the request carries the bearer token, and chasing a
      `Location` to an unconfigured host is how a credential travels.
    - **`sent` over UDP meant "handed to the kernel".** A datagram to a port with nothing bound
      succeeds at the send call, so `audit-sink --send` against a dead collector printed `sent` and
      exited 0. Now `sent, unconfirmed` on both surfaces, saying what was established and what was
      not — the J2 `present-unverified` precedent, where reporting "I cannot check this" as "this
      worked" was the one thing that would destroy the distinction that matters.
    - **The test suite shipped fabricated audit records to a real collector.** With
      `VPCOPILOT_AUDIT_SINK` exported, one full run sent **267 datagrams** of invented
      `apply_waf` / `retire` / `rollback_failed` entries — indistinguishable, at the collector, from
      records of real changes to a load balancer. The doc had said "unset it before running the
      suite", which is a guard that depends on remembering; `tests/conftest.py` now clears it in an
      autouse fixture. Verified with a counter: 1 deliberate record registers, the full suite adds
      **zero**.
  - **Two pre-existing races in `runmeta`, found because J3's concurrency test reproduced them, and
    both fixed here.** They are called out rather than slipped in — neither is caused by this change,
    but the first is a raise inside `audit.record`, which no audit-integrity item should ship past:
    - **`_save`'s temp file was named by PID only**, so two threads writing a fresh out dir shared it
      and the loser of the `os.replace` got `FileNotFoundError` **out of `audit.record`** — a change
      already made to a load balancer that could not be recorded. Reproduced **12 times out of 12**
      with 8 threads and *no sink configured at all*. The console starts every apply on its own
      daemon thread with no job lock. Now namespaced by pid **and** thread id.
    - **`run_id` minting was an unguarded read-modify-write**, so those same eight concurrent first
      writes produced **eight different run_ids** — seven audit entries carrying a join key
      `run.json` does not contain, which is the export's whole attribution path. Now thread-atomic;
      single-threaded behaviour is byte-identical, and the remaining cross-*process* case is stated
      rather than pretended away.
  - **Fixed en route (pre-existing console defect, found while validating the Setup card):**
    `class="bad"` marks a failure in the H2 dependency preview — a manifest that would not parse, a
    package OSV could not be asked about — and **`.bad` was defined nowhere in the CSS**, so all of it
    rendered as ordinary body text. A warning styled like content is precisely the defect that
    preview exists to prevent. Defined, which repairs the three pre-existing call sites as well as
    J3's own; pinned by a test that fails if any failure-marking class is used but undefined.
  - **What a sink does not do, stated rather than left to be discovered** (the J1/J4 precedent, and
    `docs/AUDIT.md`'s honest-limits list is amended rather than left contradicting the feature): it
    does **not** make the log tamper-evident. A delivered copy raises the cost of editing the local
    file afterwards; a *missing* one proves nothing, because the transport is allowed to fail. It is
    best-effort by construction, and where the two disagree they disagree about delivery.
  - **Could not be confirmed on this box, and says so rather than claiming it:** that an entry
    reaches a real syslog *daemon's* store. macOS discards `local0.info` by default — `/etc/asl.conf`
    routes only auth facilities and `/etc/syslog.conf` forwards only `install.*` — and the control
    proves it is the box, not the frame: `/usr/bin/logger -p local0.info` also produces zero hits.
    What *was* verified is the wire format, against a strict RFC 3164 parser: `<134>` (local0.info),
    space-padded day, hostname, `vpcopilot[pid]`, and a JSON payload that survives framing intact.
  - **Reconciled:** there is no Admin tab — credential and `.env` editing lives on the ⚙ Setup
    page (`GET`/`POST /api/config`), which renders `MANAGED_KEYS` generically, so the two new keys
    needed no HTML change to appear.

- [x] **J4** Attribution backfill. (S, P2) — **DONE:** `vpcopilot audit-backfill` +
  `POST /api/audit-backfill`. `backfill.py` freezes the finding each audit entry belongs to into
  `<out>/audit-backfill.json`, which `export.build_audit_events` reads beside the log and the
  evidence bundle ships. Verified against the two real audit logs on disk. 21 tests.
  - **Acceptance, as met:** no entry gets an invented actor or run_id ✅ — guaranteed by having
    nowhere to put one: the sidecar carries attribution and nothing else, pinned by a test on its
    keys; the backfill writes its own audit record ✅ (`audit_backfill`, with identity stamped
    centrally like every other action); a second run is a no-op ✅ — nothing written, nothing
    recorded.
  - **The reconciled note undersold why this matters, and running it on real data showed it.** It
    framed J4 as persisting what the exporter already derives at read time. But `policies.json` is
    rewritten by **every** scan, so the derivation does not merely decay — it can go *wrong*. Two
    outcomes, and the second is the one worth building for:
    - Re-scan into the same out dir and the mapping is gone; the exporter silently stops attributing
      those entries.
    - If the later scan generates a policy with the **same name** for a **different** finding, the
      live lookup still succeeds and attributes the old entry to the **wrong** finding — a confident
      wrong answer in the artifact whose entire job is to be trustworthy. That is why the frozen
      answer **wins over** the live lookup rather than merely filling gaps in it.
    Both reproduced against the real `out-claude` log, whose four `refine_apply` entries record a
    policy but no finding: attribution survived a wiped index, and a planted name collision failed to
    move them.
  - **`unknown` is sticky, deliberately.** An entry the backfill looked at and could not resolve stays
    unresolved, so a later `policies.json` cannot supply an answer the backfill already declined to
    give. "We looked and could not establish this" and "we have not looked" are different facts —
    the same distinction H2 draws between an unpinned dependency and a clean one.
  - **The no-op is load-bearing, not tidiness.** The command appends its own `audit_backfill` entry,
    so without the check every run would see one more entry than the last, decide something had
    changed, and append again: a log that grows by a line every time anyone asks whether it needs
    backfilling. (The I1 precedent — a reconcile pass that changes nothing writes nothing.)
  - **Keyed by index, verified by `(ts, action)`.** The index is stable only because the log is
    append-only; if it is ever rebuilt or truncated the index still resolves — to a *different*
    entry. Mismatched rows are dropped and counted rather than moved onto the wrong record, and the
    count is surfaced, because a non-zero one means the log was rewritten and that is itself worth
    knowing.
  - **Verified against the real logs, and the no-op case is the interesting one.** `demo/out` is
    already fully attributed — every entry carries its `finding_id` — so the backfill resolved
    nothing and wrote nothing, which is the correct answer and the one a synthetic fixture would not
    have exercised. `out-claude` had four genuinely unattributed `refine_apply` entries; all four
    resolved, and a repeat run left `audit.log` byte-identical.
  - **Found by adversarial review, before shipping** — and the first one nearly shipped a feature
    that destroyed its own purpose.
    - **A second run wiped the attribution it had just frozen.** `derive` recomputed every row from
      the CURRENT `policies.json`, which is precisely what the sidecar is a defence against: run the
      command, re-scan, run it again, and every resolved row collapsed to `unknown` — permanently,
      because `unknown` is sticky. The second use of the feature undid the first. **Two reviewers
      found it independently**, which is the signal worth noting. The sidecar is now monotonic: a row
      already on disk is carried forward verbatim and never recomputed, exactly like the append-only
      log it annotates. Forcing a fresh derivation means deleting the sidecar — an explicit act, not
      a side effect of running a command twice.
    - **The sidecar was written non-atomically.** `write_text` truncates first, so a crash mid-write
      left a half-written evidence file — and `load` swallows the resulting `JSONDecodeError`, so the
      failure mode was losing every frozen attribution without a word. Written to a temp file and
      `os.replace`d now. The skeptic verifying it went further and **found a weakness in the test
      that was supposed to cover this**: `test_a_corrupt_sidecar_is_ignored_rather_than_fatal`
      pinned "does not crash" but not "does not mis-attribute", because its fixture left the live
      index agreeing with the frozen answer. With a re-scan that reused a policy name, a torn
      sidecar fell through and produced a confidently wrong attribution — reproduced at 372 wrong
      exports across 1,887 concurrent reads. So *absent* and *unreadable* are now different answers:
      no sidecar means nobody froze anything and the live index is the best available guess, while a
      sidecar that exists and will not parse means the live index is by definition not the one those
      entries belong to, and the cell is left blank.
    - **The bundle's caveats said nothing about it.** A derived sidecar that can supply a
      `finding_id` is exactly what the manifest's caveat list exists to disclose; it now says what
      the sidecar is, that it carries no identity, and that where it and the log disagree the log is
      the evidence.
    - **A corrupt `policies.json` tracebacked out of the CLI and 500'd the console.** Keeping the
      raise for the apply paths (above) is right; propagating it out of a read-mostly evidence
      command is not. An unreadable index means nothing can be established, which is a decline with a
      reason.
    - **Rich silently ate the `[dry-run]` marker.** `rprint(f"[dim]{m}[/dim]")` reads `[dry-run]` as
      a markup tag and drops it — so the one word telling an operator that nothing was written was
      the one word that vanished. Escaped at this command's log sink. The same pattern exists in
      other commands whose messages contain brackets; only the one whose output actually does was
      changed here rather than sweeping the CLI.
    - **The two removed copies disagreed about duplicate policy names** — the exporter's inline dict
      was last-wins, `find_finding_for_policy` first-wins — so consolidation could not preserve both.
      First-wins is the deliberate unification: it matches the apply path, the safety-critical
      consumer. Pinned, with the caveat that `policies.json` should never contain duplicates anyway.
  - **Found while verifying the reviewers: consolidating the lookup silently changed three
    behaviours.** Compared against the previous implementation across nine inputs, `policy_index`
    had altered duplicate-name precedence (last-wins instead of first), filtered falsy `finding_id`s
    to `None`, and swallowed a corrupt `policies.json` that used to raise. All three reach four
    apply-path callers, where the corrupt-file case is the sharp one: returning `None` instead of
    raising means applying a band-aid with weaker probe validation and no explanation. The old
    semantics are restored exactly and pinned by a parametrized comparison; the exporter keeps its
    own tolerance at its call site, and the backfill does its own `or None`. A consolidation that
    quietly changes behaviour is worse than the duplication it removes.
  - **The limit is stated rather than left to be discovered** (the J1 precedent). A forged sidecar
    can move `finding_id` and the columns joined *through* it — `title`, `vuln_class`, `severity`,
    `ledger_state`, `pr_url` — and nothing else: everything the log stamped is unreachable. That adds
    no trust assumption the export did not already make, because `findings.json` and `ledger.json`
    already drive those same joins and are the same kind of file in the same directory. Verified end
    to end: the sidecar is digested in the bundle manifest, a clean bundle verifies at 47 members,
    and a forged one is caught as `MISMATCH audit-backfill.json`.
  - **Reconciled, and confirmed accurate:** `audit` is a flat `@app.command()` with no typer sub-app,
    so `audit-backfill` matches the kebab convention. `export.build_audit_events` already left blanks
    rather than inventing. The log cannot be rewritten (`audit.py` `_STAMPED`, enforced by
    `test_identity_cannot_be_overridden_by_a_caller`), hence the sidecar. The duplicate lookup was
    real — `ledger.find_finding_for_policy` and an inline copy in the exporter — and J4 would have
    been the third; both now go through `ledger.policy_index`, the one implementation.

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

- [x] **K2** GitHub Action. (M, P2) — **DONE:** `.github/actions/vpcopilot-scan/` (a composite
  action), `.github/workflows/pr-review.yml`, `src/vpcopilot/ci.py`, `vpcopilot ci-review`, and
  `docs/CI.md`. Scans a pull request's diff against the **merge base** and leaves one comment
  carrying, per finding above a threshold, the F5 XC control triage routed it to and the generated
  policy name. Verified live against the Nimbus fixture. 40 tests.
  - **Acceptance, as met:** a PR introducing a known flaw gets **one** comment carrying the policy ✅
    (live: a deliberately vulnerable `/api/refund` route → three findings, four policies across
    `service_policy`, `waf`, `malicious_user` and `rate_limit`); a PR with no findings above the
    threshold posts **nothing** ✅ — silence is the correct output, because a bot that says "all
    clear" on every PR trains people to stop reading it; **75–77 s** on the Nimbus repo against a
    three-minute budget ✅; never writes to XC ✅, structurally (below).
  - **The acceptance criterion contradicted itself, and this is the resolution.** It asked for one
    comment carrying the policy *and the simulation result* while also requiring *never writes to XC
    from CI*. Both cannot hold: G2's blast-radius measurement creates a throwaway policy object,
    **attaches it to a load balancer**, replays recorded traffic through it and deletes it — three
    tenant writes — and there is no offline evaluator to fall back on, because G1 was deliberately
    deferred. So a would-block count is **not computed in CI**. The comment reports blast radius only
    from a `simulation.json` produced by a real tenant run (committed, or passed via the
    `simulation-json` input), and otherwise says in as many words that no measurement was made and
    what it would take. Neither silence nor `0%` would do: both read as *measured and safe*. Same
    precedent as G2's own rewritten criterion, G4's reproducibility, and I2's conflict criterion.
  - **The defect that would have shipped a silent all-clear.** `git diff --name-only` answers relative
    to the **repository root**; `collect_files` matches relative to the directory it is given; and this
    project's own app fixture lives eight levels down. Compared directly the two never match — zero
    files scanned, no findings, and the pull request told it is clean. Catching it requires noticing
    the *absence* of an error, which is the hardest kind of bug to see in a review. `rebase_onto()`
    translates the paths and returns a count of changed files that fall outside the scanned directory,
    which the comment discloses.
  - **Never writes to XC, by construction rather than by care.** `ci.py` imports no `xc`, no `apply`,
    no `refiner`, no `simulate` and no `promotion_gate`, so there is no code path from CI to a load
    balancer — pinned by a test that reads the module's own source, which is the only version of that
    guarantee that survives someone adding a convenient import later. The action declares no XC
    inputs, so there is nothing to pass one through, and `ci-review` says so out loud if it finds an
    XC credential in its environment, because it has no use for one.
  - **Every boundary is disclosed rather than left to be assumed** — the theme of H2 and H3, applied
    to a comment a developer reads in ten seconds: changed files outside the scanned directory, files
    over the size cap or beyond `--max-files`, findings held back by the threshold (counted when
    nothing is reported, so "we did not report this" never reads as "there was nothing"), deleted
    files, and the absent blast radius. The all-clear branch carries the unscanned remainder too.
  - **Decisions.** *Additive plumbing, not a new scan path*: `collect_files(..., only=)` and
    `run_pipeline(..., only_files=)` filter the existing walk, so a changed file that is vendored,
    unsupported or oversized is still excluded and reported exactly as in a full scan, and the
    existing call path is untouched. *No cure drafting* — the developer is editing the file by hand
    right now; the band-aid and the finding are what CI can add, and drafting is the expensive half.
    *One comment, updated in place*, anchored on a hidden marker, because a branch pushed ten times
    should not produce ten comments. *`fail-on-findings` defaults to false* — the comment is the
    deliverable, and a red check on a finding the team has decided to accept is how a useful bot gets
    switched off. *`pull_request`, never `pull_request_target`*: the latter runs trusted workflow code
    with secrets against untrusted head code, which is the standard way a repository leaks its
    secrets. The consequence — fork PRs get no review — is documented, not discovered.
  - **Found by adversarial review, before shipping** (21 raised across four failure dimensions; 12
    verified — 2 confirmed and 10 refuted, again mostly because they had already been fixed while the
    review ran — plus 9 lower-severity ones triaged after). Almost every real finding was one shape:
    **a failure rendering as an all-clear.**
    - **Refuted candidates were being reported as findings.** `findings.json` is the *discover*
      contract — every candidate, including the ones `verify` refuted as false positives — and the
      filter compared that set against itself, so it was a no-op. Triage runs only over the verified
      set, so a triage decision is what "survived verification" looks like on disk. Putting refuted
      false positives in front of a developer with a band-aid attached is the fastest way to teach a
      team to ignore the bot.
    - **A diff with nothing scannable produced an *empty* comment**, so `--comment-out` wrote no file
      and the action's step summary fell through to "no findings at or above the threshold" — a clean
      bill of health for a diff that was never analysed. This was reachable by default: the shipped
      workflow triggers on any `**/*.py` change while scanning one fixture directory. Now a comment
      that says *nothing was reviewed*, and says it is not a clean bill of health. Still posts nothing
      to the PR, because there is nothing to report.
    - **Truncating an oversized comment deleted exactly the disclosures.** GitHub caps a body at
      65,536 characters; cutting from the end removed the "N files were not scanned" and "N sit
      outside the scanned directory" lines — the sentences that stop a partial review reading as a
      complete one. The finding list is cut instead and the disclosures always survive.
    - **A crash exited 1, which the action reads as "findings reported".** So a review that never
      completed looked like a completed one, and the workflow went on to publish a comment file that
      did not exist. Unexpected failures now exit 2, and the summary distinguishes a crash from a
      clean review by consulting the step outcome.
    - **Three more ways a meaningless blast-radius number read as safe**, each carried through from
      G2 rather than flattened into a rate: a simulation that could not confirm the edge was
      *enforcing* the policy (G2's own first live defect — an unenforced policy blocked 0 of 200 and
      looked harmless); one that evaluated *zero* requests because they all failed in transit; and one
      replayed against XC access logs, which carry **no request bodies**, so a `body_matcher` policy
      matches nothing and scores a perfect 0% that `simulate` itself had declared unjudgeable.
    - Plus: git **quotes** non-ASCII paths (`"caf\303\251.py"`), so its suffix read as `.py"`, no
      extension matched, and the file was neither scanned nor counted as outside — it vanished, and
      the PR was told it was clean (`-z` output is unquoted); a caller passing the natural
      `base: origin/main` got `origin/origin/main` and no merge base; every action input reached bash
      through a `${{ }}` text substitution rather than the environment; `--min-severity` was
      unvalidated and fell through to `high` while the comment stated the value the caller asked for;
      the header's "scanned N of M" used the post-filter count as its denominator, so a fourteen-file
      diff read as "1 of 1"; and the "not scanned" line named only the caps when the count also
      includes vendored directories and unsupported file types.
  - **Two defects only CI could find, and both are worth reading.** The suite passed locally and the
    PR went red immediately.
    - **The moved G2 gate needed tenant credentials to refuse.** `refine_apply_service_policy` and
      `apply_from_scan` both constructed `XC()` before reaching the gate, and `XC.__init__` raises when
      `XC_API_URL`/`XC_API_TOKEN` are unset — so on a runner without credentials "this policy is too
      broad" came back as "XC_API_URL not set". The test passed locally *only because the developer's
      `.env` happened to have them*: a test that quietly depended on developer-local state, which is
      precisely what "tests run offline against fakes" exists to prevent. Every refusal that needs no
      tenant now precedes `XC()`, which is also better behaviour — an over-broad policy should be
      refused whether or not a tenant is reachable. Reproducing CI locally is one `env -u` away and is
      now part of the check.
    - **A comment inside the action broke the action.** The runner parses Actions expression syntax
      anywhere in a `run:` block — **comments included** — so a comment that spelled out an empty
      expression while explaining the script-injection hazard failed the whole action to load with
      "An expression was expected". Neither local check could see it: `pyyaml` parses YAML rather than
      Actions templates, and the test that scanned for interpolations skipped comment lines, which is
      exactly where the offending text was. The test no longer skips them, because the runner does not.
  - **Found while fixing those:** the repository has **no secrets configured**, so
    `secrets.ANTHROPIC_API_KEY` is the empty string — and `required: true` on an action input is not
    enforced against an empty value. The action would have scanned nothing and produced a review that
    read as clean, which was also a review finding left open. It now fails loudly on an empty key and
    names the cause, and the workflow skips with a stated "this is not a clean bill of health" summary
    rather than going permanently red for something no PR author can fix. The `paths` filter was also
    scoped to the directory the action actually scans — it fired on any `**/*.py` change and then
    scanned zero files, spending a credential and a runner to review nothing.
  - **The fixture lives in `bench/fixtures/ci/`, not in the Nimbus app, and that is not tidiness.**
    `bench` scans `bench/fixtures/nimbus-vuln-lab/app/src/app/api` against `answer_key.yaml`, and a
    new vulnerable route there produces findings listed in neither `expected` nor `bonus` — which
    `bench.py` scores as **noise**. Committing the fixture inside the scan target would have silently
    degraded the precision column of G4's committed scorecard and `BASELINE.md`: a benchmark
    regression caused by a test fixture. Pinned by a test, and the reason is in the fixture's README
    so the next person does not helpfully move it back.
  - Surfaces: `.github/actions/vpcopilot-scan/`, `docs/CI.md` (every file in `docs/` is
    uppercase).

---

## Phase L — One finding, every enforcement point

- [ ] **L1** F5 declarative WAF policy emitter. (M, P2) **Rescoped 2026-07-30 — see below.**
  One emitter behind an emitter interface, producing a **declarative WAF policy** that both
  **BIG-IP Advanced WAF** and **F5 WAF for NGINX (App Protect)** consume, so one finding covers the
  XC control it already generates *and* the enforcement points a customer already owns.
  - Acceptance:
    - The negative-amount finding emits a declarative policy that, **loaded onto a real BIG-IP with
      Advanced WAF, blocks the recorded exploit and passes the recorded legit request** — the same
      two-request proof `apply.py` already makes against XC, via the same
      `probe.probe_from_spec(target_url, …)`, which is already target-agnostic.
    - The same policy object, with only its `template.name` swapped, validates against the NGINX
      App Protect schema.
    - A control with no declarative equivalent reports `unsupported` **with a named reason**, and
      emits nothing.
    - The XC path is byte-identical; `controls.py` keeps the XC registry unchanged.
    - Adding a target touches only the emitter module and its tests.
  - **The three questions that blocked this are answered.** (1) *Is the hybrid-fabric story worth
    the abstraction cost?* — **yes** (maintainer, 2026-07-30). (2) *Does ModSecurity belong?* —
    **no, dropped**; it could express only 3 of 7 controls and would have been the least-proven code
    in the repo. (3) *Wait for the pipeline to settle?* — **no, and the git history says why**: over
    the project's whole 31-day history, 22 commits touched `pipeline.py` and **exactly one** also
    changed the emitter's input surface — 6c6e6ac, the commit that *defined* the seven-control
    toolbox, on day two. Since 2026-07-01: **0 breaking, 4 additive, 16 zero-impact.** The
    `generate.run(...)` call site has been byte-identical for 19 days and 11 pipeline commits,
    through G2/H1/H2/H3/K1/K2/J4. `pipeline.py` absorbed 828 insertions in that window;
    `agents/generate.py` absorbed 143, two of which were prompt text. H2 alone added 3,150 lines
    repo-wide and changed the emitter contract by **zero characters**. Pipeline churn is not emitter
    churn: the emitter binds to `Finding` + the `Control` enum + two probe dicts, and `Control` has
    changed once, ever.
  - **Collapsed from two backends to one emitter, and this is the finding that shaped the item.**
    BIG-IP Advanced WAF and NGINX App Protect are the same schema family: both emit
    `{"policy": {…}}` plus an optional `modifications` array, both draft-07, both use the same
    kebab-case sections, 41 of NAP's 50 top-level policy properties are shared verbatim, and the
    **`parameters` entity matches on 47 of 48 fields with identical prose descriptions**. F5 ships a
    first-party converter (`/opt/app_protect/bin/convert-policy`) and its own Policy Supervisor
    models XC + AWAF + NAP as three emit targets from one source policy — the architecture this item
    was going to invent. The divergences are four parameterizable items; only `template.name`
    touches the flagship. **Stated limit:** F5 publishes no sentence declaring them one schema, no
    shared version, no cross-referenced `$id`. Build on "same family, NAP is close to a strict
    subset", not on "officially one schema".
  - **The emitted policy is MORE faithful than the XC original, which is the story worth telling.**
    XC expresses the negative-amount rule as `body_matcher.regex_values:
    ["amount[^0-9-]*-[0-9]"]` — a regex approximating "a minus sign near the word amount". The
    declarative WAF policy expresses the constraint itself: `dataType: "integer"`,
    `checkMinValue: true`, `minimumValue: 0`. Verified verbatim against the v17.1 schema. So this is
    not "we can also emit for BIG-IP"; it is "one finding, and the emitted rule is sometimes better
    than the one we started from".
  - **Three traps the schema research found, each of which would have shipped a policy that blocks
    nothing.** Every one is the G2 canary's failure mode — a band-aid that looks applied and is not.
    - **`dataType: "integer"` does not reject `-500`.** F5 defines integer as "whole numbers only";
      the sign rejection comes entirely from `minimumValue`.
    - **The constraint only ALARMS unless the violation is armed.** `VIOL_PARAMETER_NUMERIC_VALUE`
      must be set `block: true` in `policy.blocking-settings.violations`.
    - **`parameterLocation` has no `json` value** (`[any, cookie, form-data, header, path, query]`).
      A JSON body value is reached only via a `json-profile` with
      `handleJsonValuesAsParameters: true`, attached through `urls[].urlContentProfiles`; the
      extracted values then flow through the ordinary parameter engine.
    Also killed: `isNumericValueEnforced`, `allowNegative`, `integerValue`, `decimalValue` — none
    exist. The spellings are `exclusiveMin`/`minimumValue`, not JSON-Schema's
    `exclusiveMinimum`/`minimum`.
  - **Decisions.** *Flat `emitters.py`*, registry keyed like `controls.py` — H1's precedent is that a
    package is earned when siblings share machinery, and one emitter with a target profile does not
    earn one. *XC becomes an emitter too*, so the abstraction is proven by the backend that already
    works and "adding a target touches nothing else" is testable on day one. *A new return type* —
    `GeneratedArtifacts.items` carries `min_length=1`, so `unsupported` cannot be expressed as an
    empty list. *AS3 to drive the appliance*, not iControl REST: `GET /declare` is
    `ApplyContext.load()`'s snapshot, `action: dry-run` is `self_test()`, one POST is the attach,
    task polling is `poll_until`, and a tenant-scoped `DELETE` gives the same hard blast-radius
    boundary XC's namespace gives — everything lands in `/vpcopilot_lab/` and cannot reach
    `/Common`. iControl needs 4–6 calls where AS3 needs one, with partial-failure states between and
    no dry-run.
  - **Open, and a first-run check on the appliance rather than a blocker:** how ASM names a
    parameter extracted from JSON for **nested** keys — flat key or JSON-pointer path. Top-level
    `amount` is unambiguous; nothing in F5's docs states the rule for nested objects.
  - **Corrected:** an earlier note here assumed NGINX App Protect was free to run locally. It is
    not — NAP v5's compose trio pulls from `private-registry.nginx.com`, which needs a client cert
    and key from an active subscription or trial. That removed the reason to sequence NGINX first.
  - Surfaces: `src/vpcopilot/emitters.py` (flat), `vpcopilot emit --target <name>`, and the
    console twin per the two-surfaces invariant.
  - Depends on **L2** for its live validation.

- [ ] **L2** BIG-IP lab and a copilot-owned test application. (M, P2)
  The appliance and origin L1 validates against. Separate item because it is infrastructure, and
  because L1's emitter is useful (as golden-file output) before the lab exists.
  - **A copilot-owned BIG-IP, not the Nimbus one.** `nimbus-demo-bigip` (us-east-2,
    `i-0a0938f1fe2531a29`) carries a PAYG **GOOD** licence — LTM and iRules only, no ASM, per F5's
    own Marketplace listing — so it could validate at most the iRule half of the emitter. It is also
    another demo's front door. Stand up a separate instance on an **Advanced WAF with LTM** SKU
    ($1.52/hr software + EC2; cost is not the deciding factor per the maintainer). Note ASM is not
    provisioned in the base AMI — Declarative Onboarding must set `asm: nominal`, which restarts
    daemons; budget ~10–15 min to a ready box, and 8 GiB is the memory floor for LTM+AWAF.
  - **`vpcopilot bigip-lab create|rm`**, extending `lab.py`'s existing shape: idempotent by
    existence, clean-slate, deterministic names from one base, and — the two gaps the XC version
    has — an explicit inverse and an audit record. Guard by AS3 tenant the way `guard_lb` guards a
    load balancer: a `VPCOPILOT_PROTECTED_BIGIP_TENANTS` env var and one choke point.
  - **The test application: a small copilot-owned banking API, and the reason is not cosmetic.**
    The flagship finding is a *numeric business-logic* flaw, and it has nowhere to run today:
    `bench/fixtures/nimbus-vuln-lab` is **source only** (no `package.json`, no compose — scannable,
    not runnable), and **crAPI, which IS running and IS the copilot's demo dataset, has no numeric
    flaw at all** — its six findings are SQLi, BOLA, mass assignment, rate abuse, sensitive data and
    broken auth. So the single strongest L1 result, the constraint that beats XC's regex, cannot be
    demonstrated against any app the copilot currently owns.
    - Deliberately **small**: a handful of endpoints chosen to exercise the emitter's control
      coverage, one container, its own name and branding. **Not a Nimbus look-alike** — looking like
      Nimbus Bank is exactly what would confuse the two demos the maintainer has just separated.
    - It does **not** replace `bench/fixtures/nimbus-vuln-lab`. `answer_key.yaml` and
      `bench/BASELINE.md` are calibrated against that snapshot, and re-pointing them would
      invalidate the committed scorecard. Scan benchmark and emitter lab stay separate fixtures.
  - **First concrete decoupling fix, and it is cheaper than any of the above.** `lab.py:48` defaults
    to `pool_template="nimbus-bigip-pool"`, `lb_template="nimbus-www"` — the copilot builds its
    "own" clean-slate XC lab by cloning the protected customer LB and stripping it, so `nimbus-www`
    is simultaneously the default protected object and the default source template. Parameterise
    both out.

---

## Deliberately out of scope

- Replacing a SAST or DAST product. This routes findings to controls and closes the loop.
- Autonomous application with no human decision.
- A hosted or multi-tenant service.
- Full XC policy language coverage in any offline evaluator.
- Applying to non-XC enforcement points **in production**. `L1` generates; `L2` loads the result
  onto a lab appliance only, to prove the emitted policy actually blocks. There is no gated apply
  path to a customer's BIG-IP or NGINX.
