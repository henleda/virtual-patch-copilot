# Project state — a running handoff

A living snapshot so a fresh session (or a new machine) picks up where we left off. Public repo —
kept free of tenant/credential specifics; real values live in `.env` (gitignored).

_Last updated: 2026-07-14._

## What this is
An agentic AppSec copilot: scan an app → find + verify vulns → triage each to an F5 Distributed
Cloud (XC) band-aid control → apply it live behind a human gate → validate against the finding's
real exploit (self-heal until it blocks, or honestly "unfixable") → open the code-fix PR (the cure)
→ retire the band-aid when the cure ships. Model-independent (per-agent config, LiteLLM + instructor).

## Status
- **Quality plan fully burned down** — `docs/QUALITY_PLAN.md` Phases 0–4 all ✅ (P0 fixes, agent
  correctness, demoability, the SafeApply engine + control registry, durability/tests/CI).
- **118 tests** (offline against fakes), ruff clean, CI (`.github/workflows/ci.yml`, py3.10–3.12,
  coverage floor, `live`/`bench` markers), **v0.1.0** released, repo public (Apache-2.0).
- **Cross-model benchmark harness** built and in use (see below).
- **Local open-source model wired** — `config/agents.dgx.yaml` runs every agent on a local
  Ollama/vLLM server (structured output validated live). The third leg of the benchmark; see below.
- **The console is now a full benchmark-driving surface** — model dropdown, data-backed pickers
  (load balancer, scan target, output dir, PR repo), **Mitigate ALL**, and a **⑥ Benchmark**
  build+compare step. The whole three-way runs without leaving the UI.

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
- **Benchmark harness** — `bench_model.py` + `vpcopilot bench-model` / `bench-compare`, **also in
  the console's ⑥ Benchmark step** (`POST /api/bench-model` build + `GET /api/benchmarks` compare
  table — same `benchmarks/*.json` as the CLI). Reads a run's findings/policies + the audit log's
  `apply_timing` records → findings, policies-by-control, and **live policy quality** (blocked /
  applied-behavioral / failed / self-healed).

## The cross-model benchmark (in progress)
Goal: run the **same** test on Claude, OpenAI, and a local open-source model, and compare
discovery + policy generation + *live* policy quality. Configs: `config/agents.yaml` (Claude,
default), `config/agents.openai.yaml` (gpt-4.1), `config/agents.dgx.yaml` (local Qwen3-Coder 30B
via Ollama's `/v1`, `json` mode). Runs committed under `benchmarks/`.

Results so far (target: crAPI, code-fixes off):

| | Claude (opus-4-8) | OpenAI (gpt-4.1) |
|---|---|---|
| candidates → verified | 92 → 40 (43% confirm) | 69 → 64 (**93% confirm**) |
| policies generated | 15 | 14 |
| mitigated → blocked | 13 → 9 (**69%**) | 9 → 5 (56%) |
| self-heal / avg attempts | 0 / 1.0 | 1 / 1.44 |

**Two findings that matter:**
1. **gpt-4.1 barely refutes** — 93% confirm at 0.96 confidence (vs Claude 43% / 0.82), even on the
   stricter threshold it used. Adversarial verify only helps if the model will say "no"; gpt-4.1
   over-confirms (more likely false positives).
2. **gpt-4.1's policies were less precise on the first try** — needed the refine loop (a 3-attempt
   self-heal) and had 3 outright failures, vs Claude's 9/9 first-try blocks. The safety spine
   (refine, honest "unfixable") mattered *more* with the weaker-on-this-task model.

Also learned: only **per-request positive-security** controls (`service_policy`, sometimes
`api_schema`) block a *single* fired exploit. `rate_limit` / `bot_defense` / `malicious_user`
(behavioral) and `waf_data_guard` (response masking) are real mitigations but validate at config
level — the benchmark scores them **"applied"**, not **"blocked"**.

_Caveats on the current compare: OpenAI ran at min-confidence 0.7 vs Claude's 0.5, and a different
number of findings was mitigated each run. Same target/harness otherwise._

## How to run a benchmark (the workflow)
Now fully UI-drivable (headless CLI still works — add `--no-code-fixes` to `vpcopilot scan`):
1. `VPCOPILOT_SCAN_REMEDIATE=0 vpcopilot console` (code-fix drafting off — biggest token cost, not
   part of the benchmark; it's also the default state of the "draft code fixes" checkbox).
2. Pick the model in the header dropdown (it suggests `out-<tag>`); set the **Output dir** to
   `out-<model>-<app>` — the Output-dir combobox offers the per-model suggestions.
3. **① Scan** (Target repo + Output dir are comboboxes — pick the app) → **② Review**.
4. **Run settings**: pick the app's **load balancer** (the picker lists the namespace's LBs and
   **auto-fills the validate URL** from its domain), **dry-run OFF**, **keep OFF** (validate then
   roll back — LB stays clean, quality still recorded) → **③ Mitigate ALL** (one click; applies
   every band-aid sequentially).
5. **⑥ Benchmark** → tag the run (e.g. `dgx-vampi`) → **Build benchmark** → the compare table
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

## Open threads / next
- **Run the matched VAmPI three-way** (the big open item — now fully console-drivable): Claude +
  OpenAI + the local model on VAmPI at the *same* min-confidence (0.5), **Mitigate ALL** each, into
  `out-<model>-vampi`, then the ⑥ Benchmark compare. `config/agents.dgx.yaml` is wired and its
  structured output is validated live; it just needs the run.
- Optional: re-run OpenAI on crAPI at min-confidence 0.5 for strict parity with the Claude baseline.
- Nice-to-have: `/api/repos` shells to `gh` at console start — could lazy-load it; and tighten the
  target-repo marker list in `_scan_repos` if the sibling-repo suggestions feel noisy.

## Running on a fresh machine
`README` quickstart + `docs/TRY_IT.md`. In short: clone repo → `pip install -e ".[deploy,console,dev]"`
(in a venv) → recreate `.env` (model key(s) + `XC_API_URL`/`XC_API_TOKEN`/`XC_NAMESPACE`, plus the
`VPCOPILOT_DEFAULT_*`) → clone the target apps (crAPI/VAmPI) next to the repo → verify with
`vpcopilot xc-status --lb <your-lb>`. The copilot needs the model APIs, the XC API token, and
(optionally) GitHub — nothing else. For the **local model**, reach the Ollama box (Tailscale/tunnel)
so `localhost:11434/v1` resolves — `config/agents.dgx.yaml` handles the rest. For the PR-repo
picker, `gh auth login`.
