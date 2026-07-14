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

## Architecture worth knowing (before changing anything)
- `engine.py` + `controls.py` — one **SafeApply spine** (snapshot → self-test → attach → validate →
  keep or **verified rollback**) and a **registry** of the 7 XC controls (attach/detach inverse,
  validation kind, refine strategy). Add a control in the registry, not a bespoke function.
- **Safety spine + guardrails** everywhere: protected LBs (`VPCOPILOT_PROTECTED_LBS`) and `nimbus-*`
  policies refuse mutation without an explicit override; every apply rolls back on failure.
- **Refiner** (`refiner.py`) — validate → refine → retry until a policy actually blocks the exploit,
  or gives up honestly ("code fix required").
- **Model-independence** — `config/agents*.yaml` (one per model). A **live model switcher** in the
  console header swaps the active config with no relaunch (config-only; the Output-dir field is
  authoritative and the console reads whatever dir you scan into).
- **Benchmark harness** — `bench_model.py` + `vpcopilot bench-model` / `bench-compare`. Reads a run's
  findings/policies + the audit log's `apply_timing` records → findings, policies-by-control, and
  **live policy quality** (blocked / applied-behavioral / failed / self-healed).

## The cross-model benchmark (in progress)
Goal: run the **same** test on Claude, OpenAI, and a local open-source model, and compare
discovery + policy generation + *live* policy quality. Configs: `config/agents.yaml` (Claude,
default), `config/agents.openai.yaml` (gpt-4.1). Runs committed under `benchmarks/`.

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
1. `VPCOPILOT_SCAN_REMEDIATE=0 vpcopilot console` (code-fix drafting off — it's the biggest token
   cost and not part of the benchmark).
2. Pick the model in the header dropdown. Set the **Output dir** to `out-<model>-<app>`
   (e.g. `out-claude-vampi`) — the console reads exactly that dir.
3. **① Scan** the target repo → **② Review** → **Run settings: dry-run OFF** → **③ Mitigate** the
   findings (keep OFF = validate then roll back, so the LB stays clean and quality is still recorded).
4. `vpcopilot bench-model --tag <model>-<app> --out out-<model>-<app> --config config/agents.<model>.yaml`
5. `vpcopilot bench-compare benchmarks/*.json`

## Gotchas (don't relearn these)
- **Match settings across models** for a fair compare: same min-confidence and the same tier of
  findings mitigated. Pick one min-confidence and stick to it.
- **Name runs `out-<model>-<app>`** so the model × app matrix stays separate; the console reads the
  dir you scan into.
- **Don't run live applies from two machines** against the same LB at once (scanning is safe).
- crAPI is big (~69 findings) — fine for discovery comparison, impractical to fully mitigate.
  **VAmPI (~13 findings) is the better target for a matched, fully-mitigated 3-way comparison.**

## Open threads / next
- **Local open-source model run** (e.g. Ollama on a reachable host): add `config/agents.dgx.yaml`
  (`OLLAMA_API_BASE=http://<host>:11434`, `ollama/<model>` per agent, higher timeout — local
  inference is slower), pick it from the dropdown, scan into `out-<model>-vampi`. Validate a
  one-call structured-output probe first — some local models need instructor's JSON mode.
- **Matched VAmPI sweep**: re-run Claude + OpenAI + the local model on VAmPI at the *same*
  min-confidence, mitigate *all* 13, then `bench-compare` for a clean three-way.
- Optional: re-run OpenAI on crAPI at min-confidence 0.5 for strict parity with the Claude baseline.

## Running on a fresh machine
`README` quickstart + `docs/TRY_IT.md`. In short: clone repo → `pip install -e ".[deploy,console,dev]"`
(in a venv) → recreate `.env` (model key(s) + `XC_API_URL`/`XC_API_TOKEN`/`XC_NAMESPACE`, plus the
`VPCOPILOT_DEFAULT_*`) → clone the target apps (crAPI/VAmPI) next to the repo → verify with
`vpcopilot xc-status --lb <your-lb>`. The copilot needs the model APIs, the XC API token, and
(optionally) GitHub — nothing else.
