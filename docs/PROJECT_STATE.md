# Project state — a running handoff

A living snapshot so a fresh session (or a new machine) picks up where we left off. Public repo —
kept free of tenant/credential specifics; real values live in `.env` (gitignored).

_Last updated: 2026-07-26._

## What this is
An agentic AppSec copilot: scan an app → find + verify vulns → triage each to an F5 Distributed
Cloud (XC) band-aid control → apply it live behind a human gate → validate against the finding's
real exploit (self-heal until it blocks, or honestly "unfixable") → open the code-fix PR (the cure)
→ retire the band-aid when the cure ships. Model-independent (per-agent config, LiteLLM + instructor).

## Status
- **Quality plan fully burned down** — `docs/QUALITY_PLAN.md` Phases 0–4 all ✅ (P0 fixes, agent
  correctness, demoability, the SafeApply engine + control registry, durability/tests/CI).
- **185 tests** (offline against fakes), 73% coverage, ruff clean, CI
  (`.github/workflows/ci.yml`, py3.10–3.12, coverage floor 65%, `live`/`bench` markers),
  **v0.1.0** released, repo public (Apache-2.0).
- **Cross-model benchmark harness** built and in use (see below).
- **Local open-source model wired** — `config/agents.dgx.yaml` runs every agent on a local
  Ollama/vLLM server (structured output validated live). The third leg of the benchmark; see below.
- **The console is now a full benchmark-driving surface** — model dropdown, data-backed pickers
  (load balancer, scan target, output dir, PR repo), **Mitigate ALL**, and a **⑦ Benchmark**
  build+compare step. The whole three-way runs without leaving the UI.
- **Audit capture + evidence export (F3) landed** — the answer to "why was this LB changed, by
  whom, in which tenant?". Every LB/object-mutating record now carries `finding_id` + `namespace`
  (7 `apply_*`, 3 `create_*`, 5 `refine_apply` sites, `rollback_failed`); `apply_waf` /
  `apply_data_guard` also record `kept`. `audit.record` stamps `run_id`/`actor`/`host`/
  `tool_version` on **every** entry. New `runmeta.py` (`<out>/run.json` — run id + repo commit +
  models + caps + counts) and `export.py` (normalized events → `audit.csv`/`audit-events.json` +
  the raw artifacts + a SHA-256'd `manifest.json`, stdlib-only). Surfaces: `vpcopilot export
  [--all]`, `GET /api/audit-events` · `/api/audit-export?scope=run|all` · `/api/runs`, and an
  **Audit trail** card on ⑥ Retire that shows the trail before you export it. New env var
  **`VPCOPILOT_ACTOR`** (defaults to the OS user).
- **Console log windows are complete and scrollable** — `/api/scan` and `/api/action` now return
  the FULL transcript plus `log_total` and take `?since=<n>` for the new tail only (they used to
  serve the last 40 / 60 lines, so the rest never existed client-side). `.logbox` caps the box at
  46vh instead of letting it push the page down; the poll appends a **text node** (never
  `innerHTML` — pipeline output is untrusted) so scroll position and selection survive, sticking to
  the bottom only if you were already there (`↓ follow` chip + line counter otherwise). Bounded
  sink `_append` / `LOG_MAX = 20_000` says in-band when it caps.
- **The HTML report is reachable from ② Review** — **Open HTML report ↗** + **Download**
  (`/api/report?download=1` → `vpcopilot-report-<run dir>-<UTC>.html`). It was always rebuilt from
  the current out dir on every request; only the affordance was missing (Setup-only).

## Architecture worth knowing (before changing anything)
- `engine.py` + `controls.py` — one **SafeApply spine** (snapshot → self-test → attach → validate →
  keep or **verified rollback**) and a **registry** of the 7 XC controls (attach/detach inverse,
  validation kind, refine strategy). Add a control in the registry, not a bespoke function.
- **Safety spine + guardrails** everywhere: protected LBs (`VPCOPILOT_PROTECTED_LBS`) and `nimbus-*`
  policies refuse mutation without an explicit override; every apply rolls back on failure.
- **Refiner** (`refiner.py`) — validate → refine → retry until a policy actually blocks the exploit,
  or gives up honestly ("code fix required").
- **Model-independence** — `config/agents*.yaml` (one per model). Per agent: `model` plus optional
  `mode` (instructor structured-output — `tools`|`json`|`md_json`), `api_base`/`api_key`
  (a **per-config** OpenAI-compatible endpoint — how the local model reaches Ollama's `/v1` without
  a global `OPENAI_API_BASE` hijacking the real OpenAI config), and `temperature`/`timeout`/
  `max_retries`. A **live model switcher** in the console header swaps the active config with no
  relaunch; the Output-dir field is authoritative and the console reads whatever dir you scan into.
- **Run identity joins processes, not memory** — `runmeta.run_id(out_dir)` mints an id on first use
  and persists it in `<out>/run.json`; every audit entry carries it. So a console scan and a
  `vpcopilot apply` an hour later in a *separate process* against the same out dir belong to the
  same run, and an exported bundle explains its own provenance (repo + commit/branch/dirty, config
  path, per-agent models, caps, counts, actor/host/tool_version) without needing this machine.
  `write_manifest` never clobbers an existing `run_id` — a re-scan keeps the identity the entries
  on disk already join to. Provenance is **fail-soft**: it warns and moves on, never failing a
  completed scan.
- **Write heterogeneous, normalize at export** — `audit.log` stays append-only and per-action (a
  WAF's `config_enabled` is not a service policy's `passed`); `export.build_audit_events` does the
  flattening at read time into one row per event (`export.COLUMNS`), coalescing the outcome keys,
  mapping legacy `finding` → `finding_id`, recovering a finding from the `policies.json` index, and
  joining ledger + findings for title/class/severity/state. Add a field to a record freely — the
  normalizer, not the writer, owns the reviewer's shape. It keeps **every** entry on purpose
  (report.py's impact table filters to entries with `before_after` or `behavioral` and would drop
  `retire`, `open_pr`, `create_*` and config-only applies). Identity is stamped inside `audit.record`, so
  add a new mutating path and it is attributable for free — and a caller cannot override it.
- **Benchmark harness** — `bench_model.py` + `vpcopilot bench-model` / `bench-compare`, **also in
  the console's ⑦ Benchmark step** (`POST /api/bench-model` build + `GET /api/benchmarks` compare
  table — same `benchmarks/*.json` as the CLI). Reads a run's findings/policies + the audit log's
  `apply_timing` records → findings, policies-by-control, and **live policy quality** (blocked /
  applied-behavioral / failed / self-healed).

## The cross-model benchmark
Goal: run the **same** test on Claude, OpenAI, and a local open-source model, and compare discovery
+ policy generation + *live* policy quality. Configs: `config/agents.yaml` (Claude, default),
`config/agents.openai.yaml` (gpt-4.1), `config/agents.dgx.yaml` (local Qwen3-Coder 30B via Ollama's
`/v1`, `json` mode). Runs committed under `benchmarks/`.

**Matched VAmPI three-way (min-conf 0.5, all findings mitigated, code-fixes off) — the headline:**

| | dgx (qwen3-coder 30B) | claude (opus-4-8) | openai (gpt-4.1) |
|---|---|---|---|
| candidates → verified | 13 → 5 (38%) | 14 → **12** (86%) | 6 → 5 (83%) |
| ✅ blocked / 🟡 applied | 1 / 3 | **4** / 5 | 1 / 3 |
| 🚫 endpoint-missing / 🔒 needs-auth / ❌ failed | 1 / 1 / **0** | 0 / 0 / **0** | 0 / 0 / **0** |
| self-healed | 0 | 2 | 0 |

**Claude wins decisively** (2.4× verified, 4× real blocks, nothing unvalidatable). The models differ
most at *discovery*: gpt-4.1 is conservative (found only 6 candidates); Qwen3-Coder finds plenty but
refutes hard (38%) and is weakest downstream — its 🚫/🔒 are the visible gaps. **No model "failed" a
mitigation.** Full write-up: `benchmarks/compare-vampi-three-way.md`.

_Earlier crAPI 2-way (Claude vs gpt-4.1, min-conf mismatch 0.5 vs 0.7): Claude 92→40 verified /
13→9 blocked; gpt-4.1 69→64 / 9→5. gpt-4.1 barely refutes (93% confirm → more false positives) and
its first-try policies were less precise. See `benchmarks/compare-claude-openai.md`._

## Harness honesty (why `failed = 0` in the three-way)
Scoring separates *the band-aid didn't work* from *the finding/probe couldn't be validated*:
- **Endpoints grounded** in the app's OpenAPI spec / route registrations (`routes.py`) — a weak model
  looks a path up instead of hallucinating it (Qwen3-Coder: `/register` → `/users/v1/register`). If
  no route context is found, the scan warns that endpoints are inferred.
- **🚫 endpoint-missing** (baseline exploit 404 — endpoint doesn't exist) and **🔒 needs-auth**
  (baseline 401 — needs a token the probe lacks) score distinctly, NOT as failures.
- **WAF is config-validated ("applied"), not per-request** — a WAF's block of a single crafted request
  is signature/payload-dependent (verified live: a blocking WAF let `' OR '1'='1` through, path+query).
- **service_policy self-heals XC rejections** — a bad spec (`query_params` as an object / missing
  `key`) is coerced in `normalize_service_policy_spec` or refined at apply time instead of crashing.

Only **per-request positive-security** controls (`service_policy`, `api_schema`) can prove a
*single-request* block (→403); `waf` / `rate_limit` / `bot_defense` / `malicious_user` /
`waf_data_guard` are config/behavioral and score **"applied"**.

## How to run a benchmark (the workflow)
Now fully UI-drivable (headless CLI still works — add `--no-code-fixes` to `vpcopilot scan`):
1. `VPCOPILOT_SCAN_REMEDIATE=0 vpcopilot console` (code-fix drafting off — biggest token cost, not
   part of the benchmark; it's also the default state of the "draft code fixes" checkbox).
2. Pick the model in the header dropdown (it suggests `out-<tag>`); set the **Output dir** to
   `out-<model>-<app>` — the Output-dir combobox offers the per-model suggestions.
3. **① Scan** (Target repo + Output dir are comboboxes — pick the app) → **② Review**.
4. **Run settings**: pick the app's **load balancer** (the picker lists the namespace's LBs and
   **auto-fills the validate URL** from its domain), **dry-run OFF**, **keep OFF** (validate then
   roll back — LB stays clean, quality still recorded) → **④ Mitigate ALL** (one click; applies
   every band-aid sequentially).
5. **⑦ Benchmark** → tag the run (e.g. `dgx-vampi`) → **Build benchmark** → the compare table
   updates across all runs. (CLI equivalents: `bench-model --tag … --out … --config …`, then
   `bench-compare benchmarks/*.json`.)

## Gotchas (don't relearn these)
- **Match settings across models** for a fair compare: same min-confidence and the same tier of
  findings mitigated. Pick one min-confidence and stick to it.
- **Name runs `out-<model>-<app>`** so the model × app matrix stays separate; the console reads the
  dir you scan into.
- **Don't run live applies from two machines** against the same LB at once (scanning is safe).
- crAPI is big (~69 findings) — fine for discovery comparison, impractical to fully mitigate.
  **VAmPI (~13 findings) is the better target for a matched, fully-mitigated 3-way comparison.**
- **Local model (`agents.dgx.yaml`)** uses `json` mode (tools/md_json also validated clean); give
  the local scan a low `--concurrency` (one GPU serving one model) and a generous `timeout`. Reach
  the box however (Tailscale/tunnel) so `localhost:11434/v1` resolves; the config's dummy `api_key`
  keeps those calls off the real `OPENAI_API_KEY`.
- **Target dirs are the OSS apps' real names** (`crAPI` capitalized, `vampi` lowercase) — the target
  picker returns case-correct absolute paths, so pick from it rather than typing.
- **PR-repo picker needs `gh`** authenticated (`gh auth login`); without it that field just stays
  free-text (nothing breaks).
- **Dry runs are not recorded** — by design (nothing changed, so there is nothing to answer for).
  The Retire step's audit table and the evidence bundle stay **empty until the first LIVE Mitigate**;
  a dry-run demo will look like nothing happened.
- **`apply_timing` only exists for console-driven live applies** — the console writes it after a
  non-dry action job. A CLI-driven run has none, which is also why `bench-model` needs the console's
  Mitigate step for live policy quality.
- **Audit logs written by older builds lack `finding_id` / `namespace` / `actor`** — the export
  leaves those cells **blank rather than inferred** (the one exception: a finding recovered from the
  `policies.json` index by policy name). There is no backfill; historic runs stay as they were
  written.
- **The console reads ONE run dir at a time** (`OUT`, set by the Output-dir field on scan) — so
  "Export evidence bundle (.zip)" covers *that* dir only. Use **All runs** (`scope=all` /
  `vpcopilot export --all`) for everything on disk; `GET /api/runs` lists what it would find.

## Open threads / next
- ✅ **Matched VAmPI three-way — DONE** (dgx/claude/openai at min-conf 0.5, all findings mitigated).
  Results above + `benchmarks/compare-vampi-three-way.md`; reports at `benchmark-{dgx,claude,openai}-vampi.*`.
- **Bigger local model** to close the discovery/classification gap: try `gpt-oss-120b` (reasoning,
  ~63GB, fits one DGX Spark) on the DGX before adding a second Spark — a config-only swap +
  structured-output probe, then re-run the VAmPI benchmark for a 4-way.
- **api_schema on the tenant** intermittently 429s on OAS-validation entitlement (infra, not model) —
  worth confirming the F5 tenant's API-protection quota if you want api_schema to validate reliably.
- Optional: re-run OpenAI on crAPI at min-confidence 0.5 for strict parity with the Claude baseline.
- Nice-to-have: `/api/repos` shells to `gh` at console start — could lazy-load it.
- **Audit/export, still open:** no backfill of historic `audit.log` files (pre-F3 entries export
  with blank `finding_id`/`namespace`/`actor` — a one-shot rewrite would be a judgement call about
  inventing attribution, so it hasn't been done). The export is scoped to **run dirs on the local
  filesystem** (`find_runs` = `out*/` + `demo/out` under the given root) — no object store, no
  cross-machine collation, and no signing of the bundle beyond the per-member SHA-256s. It is
  evidence for a human reviewer, not a compliance certification.

## Running on a fresh machine
`README` quickstart + `docs/TRY_IT.md`. In short: clone repo → `pip install -e ".[deploy,console,dev]"`
(in a venv) → recreate `.env` (model key(s) + `XC_API_URL`/`XC_API_TOKEN`/`XC_NAMESPACE`, plus the
`VPCOPILOT_DEFAULT_*`) → clone the target apps (crAPI/VAmPI) next to the repo → verify with
`vpcopilot xc-status --lb <your-lb>`. The copilot needs the model APIs, the XC API token, and
(optionally) GitHub — nothing else. For the **local model**, reach the Ollama box (Tailscale/tunnel)
so `localhost:11434/v1` resolves — `config/agents.dgx.yaml` handles the rest. For the PR-repo
picker, `gh auth login`.
