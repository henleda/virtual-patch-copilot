# Design

## Goal
An agent pipeline that scans an application repo → finds vulnerabilities → triages each
to the right control → generates the fix → (human-gated) deploys to F5 Distributed Cloud
→ self-validates → rolls back on failure. **Model-independent**, with virtual patches
treated as **temporary** and tracked toward a real code fix shipped as a **GitHub PR**.

It automates exactly the manual loop proven in the Nimbus demo: read code → find the
negative-amount transfer flaw → decide "service policy" → write the spec → deploy to XC
→ attach to the LB → validate (exploit blocked, legit ok) → keep detach as undo.

`virtual-patch-copilot` is the **product**; Nimbus is the first dogfood example.

## Mandatory requirements (locked)
1. **Its own repo** — `henleda/virtual-patch-copilot`.
2. **Band-aids, not cures** — service-policy / malicious-user mitigations are temporary;
   every application-logic finding also gets a **code-level fix as a GitHub PR**. The
   pipeline tracks each finding `found → mitigated → remediated → policy retired`.
3. **Model-independent** — customers swap the underlying model (Claude / OpenAI / Gemini /
   Ollama / ...) without touching agent code.

## Architecture: agents reason, code acts
The single most important choice: **agents emit typed artifacts; a deterministic spine
performs all side-effects** (XC API, GitHub). This makes the system both model-independent
(no reliance on uneven cross-provider tool-calling) and safe (the model proposes, code
disposes, a human approves).

```
repo ─▶ discover ─▶ verify ─▶ triage ─┬▶ generate ─▶ [GATE] ─▶ deploy+attach ─▶ validate ─▶ (rollback?)
                                       └▶ remediate ─▶ [GATE] ─▶ open GitHub PR
```

### Agents (`src/vpcopilot/agents/`)
- **discover** — read source, return high-signal `Finding`s (business logic, BOLA/IDOR,
  injection, auth, sensitive data). Per-file today; batched/prioritized later.
- **verify** — adversarial: tries to *refute* each finding. Kills false positives before
  they propagate. Keeps only `is_real`.
- **triage** — routes each finding to one `Control`:
  `service_policy` · `malicious_user` · `both` · `waf` · `code_fix_only`.
- **generate** — emits the XC config object(s). Its prompt carries the demo-proven rules
  (FIRST_MATCH; specific DENY then catch-all ALLOW because XC default-denies; path-regex
  must start alphanumeric; `body_matcher` for JSON bodies; etc.).
- **remediate** — writes the real code fix as a unified diff + PR title/body (the cure).

### The triage rubric (where the value lives)
| Vuln pattern | Control |
|---|---|
| Input/invariant violations (negative amount, missing `amount>0`, type/range/schema, client-set fields) | **service_policy** (per-request, positive security) |
| Behavioral abuse (credential stuffing, BOLA/IDOR *enumeration*, scraping, velocity) | **malicious_user** (per-user, behavioral) |
| Constrain the request *and* catch the actor | **both** |
| Injection (SQLi/XSS/cmd) | **waf** — the AI WAF handles it; don't write a policy |
| Deep logic only the app can enforce (auth context, balance math) | **code_fix_only** |

## Model independence (`config.py` + `harness.py`)
You don't build a harness per provider — you build **one** harness over a transport
abstraction and handle differences with config.
- **Transport:** LiteLLM — one interface to Anthropic/OpenAI/Gemini/Bedrock/Azure/vLLM/
  **Ollama**. Provider auth via env. "Swap the model" = edit a string.
- **Structured output:** `instructor` + Pydantic (JSON Schema + validate-and-repair).
  Every agent returns a typed object the same way on every model, including weak/local
  models with no native JSON mode.
- **Per-agent model registry:** `config/agents.yaml` assigns a model per agent. Use a
  frontier model for triage/verify, a cheap or on-prem Ollama model for mechanical steps
  (cost + data-residency control).
- **Honest capability tiers:** a tiny local model won't triage like a frontier model.
  Guidance, not a silent failure — keep judgment agents strong.

## Safety spine (the credibility)
- **Human approval gate** between generate and any write (review findings, triage,
  proposed policies, PRs).
- **Snapshot + one-click undo** of the LB's policy set before any attach.
- **Self-validation + auto-rollback:** after applying, fire the exploit + a legit request;
  if the exploit isn't blocked or legit traffic breaks → auto-revert and flag. Validation
  target is the **live LB** (more demo-dramatic; the snapshot/rollback makes it safe).
- **Secrets:** scoped XC token + provider keys in env / secret store, never in git.

## XC integration (`xc/`, next increment)
- **Service policy:** create object + attach/detach on the LB + snapshot the prior set.
- **Malicious user:** first-class, fully automatable in XC (F5 publishes Terraform +
  pipeline examples that build detection/mitigation and fire validation traffic; the
  console maps to the same API objects). For Nimbus this is the natural third beat —
  repeated injection from the load generators raises the attackers' risk scores, XC flags
  them on the Malicious Users tab and auto-mitigates: "the platform learns the attacker,"
  layered on the WAF and the service policy.

## Remediation = GitHub PRs (`req #2`)
`remediate` produces the diff + PR copy; the deploy increment opens a PR via the GitHub
API. Each PR notes it permanently remediates an issue currently held closed by a temporary
XC virtual patch (retire the policy on merge). A **ledger** tracks finding state so
band-aids don't silently become permanent.

## Repo layout
```
src/vpcopilot/
  schemas.py        typed agent I/O (the cross-model contract)
  config.py         per-agent model registry
  harness.py        LiteLLM + instructor (model independence)
  repo_scan.py      collect candidate source files
  agents/           discover, verify, triage, generate, remediate
  pipeline.py       deterministic orchestration (read-only today)
  cli.py            `vpcopilot scan`
config/agents.yaml  model-per-agent
tests/              schema/config smoke tests (no API needed)
```

## Roadmap
1. **Brain (done):** discover → verify → triage → generate → remediate, read-only. ✅
2. **XC client + deploy/apply:** create policy, snapshot, attach, validate on live LB,
   auto-rollback. Behind the human gate.
3. **Malicious-user branch:** detection/mitigation config + validation traffic.
4. **GitHub PRs:** open code-fix PRs from `remediate` output.
5. **Ops console:** review → approve → apply → undo, with a live before/after panel and
   the remediation ledger.

## Open decisions
- Remediation output starts as **GitHub PRs** (confirmed).
- Validation target: **live LB** with snapshot/rollback (confirmed).
- Language: **Python** (confirmed).
