# Model comparison — VAmPI three-way

Same code, same target (VAmPI), same harness, **min-confidence 0.5**, code-fixes off. Each model ran
the full pipeline (discover → verify → triage → generate) and every band-aid was mitigated live
behind F5 XC (validate-then-rollback). Configs: `config/agents.yaml` (Claude, default),
`config/agents.openai.yaml` (gpt-4.1), `config/agents.dgx.yaml` (local Qwen3-Coder 30B via Ollama).

| metric | dgx (qwen3-coder 30B) | claude (opus-4-8) | openai (gpt-4.1) |
|---|---|---|---|
| candidates → verified | 13 → **5** (38% confirm) | 14 → **12** (86%) | 6 → **5** (83%) |
| policies generated | 4 | 6 | 5 |
| live-validated | 6 | 9 | 4 |
| ✅ blocked (real exploit) | 1 | **4** | 1 |
| 🟡 applied (config/behavioral) | 3 | 5 | 3 |
| 🚫 endpoint-missing | 1 | 0 | 0 |
| 🔒 needs-auth | 1 | 0 | 0 |
| ❌ **failed** | **0** | **0** | **0** |
| self-healed | 0 | 2 | 0 |

## What the run showed
- **Claude leads decisively** — 12 verified (2.4× the others), **4** real single-request blocks (4×),
  5 applied, 2 self-heals, and nothing left unvalidatable.
- **The models differ most at _discovery_, not mitigation.** gpt-4.1 is conservative (only 6
  candidates found — it confirms what it finds but surfaces far fewer issues). Qwen3-Coder 30B finds
  plenty (13) but refutes hard (38% confirm) and is weakest downstream.
- **No model "failed" a mitigation.** Every generated band-aid either blocked, applied as
  config-level defense-in-depth, or was honestly flagged unvalidatable — not a phantom failure.

## Scoring honesty (why `failed = 0`)
The harness distinguishes _the band-aid didn't work_ from _the finding/probe couldn't be validated_:
- **🚫 endpoint-missing** — baseline exploit 404'd; the finding's endpoint doesn't exist (a discovery
  hallucination). Surfaced only on dgx (`/api/users/*`).
- **🔒 needs-auth** — baseline exploit 401'd; it needs a token the unauthenticated probe doesn't have
  (BOLA behind auth). The band-aid may be correct but can't be demonstrated this way.
- **WAF = "applied", not pass/fail** — a WAF's block of a single crafted request is
  signature/accuracy/payload-dependent (verified live: a blocking WAF let `' OR '1'='1` through, path
  and query), so it's scored as config-level defense-in-depth, not a per-request block.
- **Endpoints are grounded** in the app's OpenAPI spec / route registrations, so a weak model looks a
  path up instead of inferring it — Qwen3-Coder's endpoints went from `/register` to
  `/users/v1/register` once grounded.

## Caveats
- api_schema validation depends on the XC tenant's OAS-validation entitlement (a 429 there is infra,
  not the model).
- The local model ran on a single DGX Spark; a reasoning model (e.g. `gpt-oss-120b`) or more active
  parameters would likely close the discovery/classification gap.
