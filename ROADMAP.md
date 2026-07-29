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

- [ ] **H1** CVE and advisory input path. (M, P1)
  Accept a CVE ID or GHSA identifier instead of a repo. An agent resolves the advisory into
  an exploitation profile of affected paths, parameters, headers, and request shapes, and
  that profile enters the existing triage and generate stages unchanged.
  - Acceptance: a known path-traversal CVE in a web framework produces a `waf` or
    `service_policy` band-aid; an advisory with no network-observable exploitation pattern
    routes to `no_bandaid` with residual risk stated; `remediate` recommends the fixed
    version rather than drafting a patch to vendor code; the ledger seeds `found` the same
    way a repo finding does.
  - Surfaces: `src/vpcopilot/inputs/cve.py`, a `resolve` agent in `agents/`,
    `vpcopilot scan --cve CVE-YYYY-NNNNN`.
  - **Advisory source (decided 2026-07-27): OSV.dev primary, GHSA for enrichment.** OSV needs no
    auth, spans ecosystems on one schema, and returns affected ranges **and the fixed version** —
    which is exactly what the acceptance needs for "recommend the fixed version rather than
    drafting a patch to vendor code". It also keeps H1 runnable with no credentials, matching
    `scan`'s "safe to run anywhere". GHSA (reusing the existing `GITHUB_TOKEN`) only for advisory
    prose an agent reasons over; NVD is rejected — slow, rate-limited, imprecise version data.
    Note what OSV does **not** give: the network-observable exploitation pattern (paths, params,
    request shapes). Deriving that is the agent's job, and it is what makes the `no_bandaid`
    branch of the acceptance meaningful.
  - **Reconciled:** `src/vpcopilot/inputs/` does not exist — every module is flat under
    `src/vpcopilot/` except `agents/` and `console/`. Creating a package is a new convention;
    decide it deliberately or use `src/vpcopilot/input_cve.py`. A new `resolve` agent must also
    be added to `config.AGENT_NAMES`, or it will be absent from `run.json` provenance, the
    console's agent list, and the report's model chips. **The agent name is duplicated in three
    places** — `config.AGENT_NAMES` (`config.py:16`, feeds `run.json` only), `AGENT_ROLES`
    (`console/app.py:198`, drives `GET /api/agents`) and a hardcoded list in `report.py:251`
    (drives the report's model chips) — all three need the same change.
  - **Also touches an existing signature:** `scan`'s `repo` is a required positional
    (`cli.py:36`) flowing into `run_pipeline(repo_path)` which does `Path(repo_path)`
    (`pipeline.py:49-61`). `--cve` means making `repo` optional with mutual exclusion, an
    alternate `run_pipeline` entry that does not walk a filesystem root, and the same optionality
    on `ScanReq` / `POST /api/scan`. `RemediationPlan` (`schemas.py:122-131`) also *requires*
    `file`, `diff` and `patched_content`, so "recommend the fixed version" needs either an
    advisory-shaped remediation artifact or optional fields plus a `pr.py` branch that skips
    `update_file`.

- [ ] **H2** Dependency manifest input. (M, P2) Depends on H1.
  Parse `requirements.txt`, `package-lock.json`, and `pom.xml`, resolve advisories, and run
  H1 per exploitable advisory.
  - Acceptance: a manifest run lists affected packages, resolved advisories, and one
    band-aid per exploitable advisory; correlation collapses overlapping band-aids the way
    `B1` already does for repo findings.
  - **Reconciled:** B1 cannot be inherited as-is. `correlate.coverage_key` (`correlate.py:19-23`)
    keys request-scoped controls on `endpoint_of(file)`, which parses a *repo path*, and is called
    with `f.file` (`pipeline.py:226`). An advisory finding has no repo file. `coverage_key` needs a
    non-file identity (fall back to `Finding.endpoint` or the package coordinate) and
    `pipeline.py:40`'s dedup key needs the same treatment.

- [ ] **H3** OpenAPI as a discovery input. (M, P2)
  `A4` applies a schema the operator supplies. This is the other direction: read a spec and
  find the flaws in it, including endpoints absent from the code and code paths absent from
  the spec.
  - Acceptance: a spec declaring `amount` with no lower bound gets reported as a finding and
    routes to `api_schema`; endpoints in the spec with no code match report as
    `undocumented_or_orphaned`; findings flow into the same triage table.
  - Surfaces: `src/vpcopilot/inputs/openapi.py`, `vpcopilot scan --spec <path>`.
  - **Reconciled:** same `inputs/` package question as H1 — settle it there first. `--spec`
    changes the same required `repo` positional H1 does; do both in one change.

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

- [ ] **K1** MCP server mode. (M, P1) Depends on G2 and I1.
  Expose the read-only surface as MCP tools so an agent session gets a band-aid proposal
  inline: `scan`, `triage`, `generate`, `simulate`, `patches list`.
  - Acceptance: apply, pr, retire, and reconcile are absent from the tool list unless
    explicitly enabled in config; **enabling them does not bypass the human gate** — a write
    tool still routes through the same gate and guardrails as the CLI and console; tool schemas
    document every argument; the server calls the same module functions as the CLI and console.
  - **Reconciled:** `simulate` needs G2 and `patches list` needs I1; the item declared no
    dependencies.
  - Surfaces: `src/vpcopilot/mcp.py`, `vpcopilot mcp`.
  - Note: pairs with the vendor's own Distributed Cloud MCP server effort. Keep them independent.
    This one exposes the pipeline, not the tenant.
  - **Reconciled:** there is no `serve` command — `console` (`cli.py:499`) is the only launcher, so
    a second verb would be a new convention; `vpcopilot mcp` matches the flat command set. Two of
    the five listed tools have **no module function to share**: `triage` and `generate` exist only
    as agent entry points taking a live `Harness` plus pydantic models (`agents/triage.py:57`,
    `agents/generate.py:94`), with no CLI or console twin. Either scope v1 to surfaces that exist,
    or add a sub-item creating those twins first. The dependency is also transitive — G2 is itself
    gated on the undecided G1.

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
