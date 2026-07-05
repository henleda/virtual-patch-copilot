# Using virtual-patch-copilot

Find application vulnerabilities, triage each to the right F5 Distributed Cloud control (or
to code), deploy the **band-aid** (with validation + rollback), and open the **code-fix PR** —
model-independent, behind a human gate. See `DESIGN.md` for architecture, `PLAN.md` for status.

## 1. Install
```sh
pip install -e ".[deploy,console,dev]"     # deploy=GitHub PRs, console=web UI, dev=tests
```
Requires Python ≥ 3.10. `vpcopilot --version` to check. If the `vpcopilot` script isn't on your
PATH, use `python3 -m vpcopilot.cli …` everywhere below.

## 2. Configure
Copy the env template and fill in what you use:
```sh
cp .env.example .env
```
| Key | For |
|---|---|
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GEMINI_API_KEY` / `OLLAMA_API_BASE` | the model(s) you run |
| `XC_API_URL`, `XC_API_TOKEN`, `XC_NAMESPACE` | deploying band-aids to F5 XC |
| `GITHUB_TOKEN` *(or `gh auth login`)* | opening code-fix PRs |

**Model-independence:** every agent's model is chosen per-agent in `config/agents.yaml`
(LiteLLM naming). Swap Claude / OpenAI / Gemini / Ollama — globally or per agent — with no
code change. Use a strong model for `discover`/`verify`/`triage`, a cheaper/local one for
mechanical steps. Proven cross-provider — see `MODELS.md`.

## 3. Scan (read-only, safe anywhere)
```sh
vpcopilot scan /path/to/app-repo --out out [--min-confidence 0.5]
```
Runs `discover → verify → triage → generate → remediate` and writes to `out/`:
`findings.json`, `triage.json`, `policies/*.json` (XC specs), `remediations/*.patch|.pr.md`
(code fixes), `correlations.json`, `ledger.json`, `summary.json`. No XC/GitHub writes.

## 4. Apply a band-aid (mutates XC — gated + reversible)
```sh
vpcopilot apply --from-scan out/policies/<artifact>.json --lb <lb> --url <host> --dry-run   # preview
vpcopilot apply --from-scan out/policies/<artifact>.json --lb <lb> --url <host> --keep       # keep on success
vpcopilot apply-maluser   --lb <lb>            # enable Malicious-User detection
vpcopilot apply-ratelimit --lb <lb> --requests 100 --unit MINUTE
vpcopilot apply-ratelimit --requests 10 --behavioral   # B3: drive a burst + confirm the excess is 429'd
vpcopilot apply-bot       --lb <lb> --live     # Bot Defense (needs the add-on)
```
Every apply: **snapshot → idempotent PUT self-test → create/attach or enable → validate →
rollback** (service-policy validates by firing the exploit + a legit request; behavioral
controls validate by config readback). Default is **rollback after validation**; `--keep`
leaves it live.

## 5. Open the code-fix PR (the cure)
```sh
vpcopilot pr --repo owner/name --base <branch> --path-prefix <repo-relative-dir> [--finding <id>] [--dry-run]
```
Uses the full corrected file from `remediate` (no fragile diff apply). Token from
`GITHUB_TOKEN` or `gh auth token`.

## 6. Track & audit
```sh
vpcopilot ledger    # found -> mitigated -> remediated -> retired (per finding)
vpcopilot audit     # append-only log of every applied / rolled-back change
vpcopilot report --open   # standalone shareable HTML dashboard of the results
vpcopilot retire --finding <id>   # C2: when the cure PR merges, detach the band-aid + mark retired
vpcopilot retire --all            # retire every mitigated finding whose cure PR merged (--force to skip the check)
```
Every scan also drops a self-contained `out/report.html` (no server, no external assets);
the console's Dashboard has an **Open HTML report** button too.

## 7. Ops console (localhost)
```sh
vpcopilot console         # http://127.0.0.1:8787
```
Tabs: **Dashboard** (findings + inline Apply/PR with an action-settings bar), **Workflow**
(the agent pipeline + each agent's model), **Ledger**, **Run scan**, **Admin** (reads/writes
`.env`), **XC status**. The action bar's **dry-run** is on by default.

## Safety model
- **Human gate:** apply/PR run only when *you* trigger them (CLI or console).
- **Guardrails:** `PROTECTED_POLICIES` (the `nimbus-*` demo policies) can't be created/deleted;
  protected LBs (`VPCOPILOT_PROTECTED_LBS`, default `nimbus-www`) can't be mutated without
  `--allow-protected-lb`.
- **Reversible:** every apply snapshots the LB and rolls back on validation failure (or by
  default). Every change is written to the audit log.
- **Band-aids are temporary:** every finding also gets a code-fix PR; the ledger tracks each
  finding to `retired` (band-aid removed once the cure merges).

## Worked example (Nimbus)
```sh
vpcopilot scan  ./nimbus/app/src/app/api --out out
vpcopilot apply --from-scan out/policies/service_policy.deny-negative-pay-amount.json --dry-run
vpcopilot pr    --repo henleda/nimbus-demo --base vuln-lab --path-prefix app/src/app/api --finding neg-pay-001 --dry-run
vpcopilot ledger
```
Apply/validate default to the **isolated test LB `vpcopilot-lab`** (`https://lab.banknimbus.com`),
so agent-run demos never touch the live `nimbus-www` security-demo path. Drop `--dry-run` to go
live on the test LB. `nimbus-www` is protected — mutating it requires `--allow-protected-lb`.
