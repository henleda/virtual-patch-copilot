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
| `VPCOPILOT_ACTOR` *(optional)* | who changes are attributed to in the audit log — defaults to the OS user |

**`VPCOPILOT_ACTOR`** is what the audit trail records as the person who made a change. On your own
machine the OS user is right. In CI, or on a shared jump host, set it so the record names the
engineer who asked for the change rather than the service account it happens to run as.

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

**Self-healing policies (`--refine`, default on).** If a service-policy apply doesn't actually
block the exploit (or over-blocks legit traffic), the copilot diagnoses why, asks the `refine`
agent to correct the spec (using the exact exploit + legit requests), and retries — up to
`--refine-attempts` (default `$VPCOPILOT_REFINE_ATTEMPTS` or 3). It only reports success once it's
*watched* the exploit get blocked; otherwise the finding stays `found` with an honest "code fix
required". The working refined spec is written back to the artifact. `--no-refine` for single-shot.
Configurable in the console's action bar (**refine** + **attempts**).

## 5. Open the code-fix PR (the cure)
```sh
vpcopilot pr --repo owner/name --base <branch> --path-prefix <repo-relative-dir> [--finding <id>] [--dry-run]
```
Uses the full corrected file from `remediate` (no fragile diff apply). Token from
`GITHUB_TOKEN` or `gh auth token`.

## 6. Track & audit
```sh
vpcopilot simulate --out out --logs traffic.har          # what each band-aid WOULD block
vpcopilot simulate --out out --from-tenant --source-lb <lb> --since 6h
vpcopilot ledger    # found -> mitigated -> remediated -> retired (per finding)
vpcopilot audit     # append-only log of every applied / rolled-back change
vpcopilot export [--out DIR] [--output PATH]   # evidence bundle (.zip) for one run
vpcopilot export --all [--root DIR]            # every run dir on disk, each in its own folder
vpcopilot report --open   # standalone shareable HTML dashboard of the results
vpcopilot retire --finding <id>   # C2: when the cure PR merges, detach the band-aid + mark retired
vpcopilot retire --all            # retire every mitigated finding whose cure PR merged (--force to skip the check)
```
**Refine with a blast-radius gate.** Set `VPCOPILOT_SIM_LOGS` to a traffic sample and the
refiner stops at the first policy that blocks the exploit *and* stays under the threshold, instead
of the first that merely blocks it — a refinement that widened the rule too far is fed back as
`over_block` and retried. With the variable unset the refine loop behaves exactly as before.

`export` writes `<out>/audit-bundle.zip` (`--all` → `<root>/audit-bundle-all.zip` with a top-level
`index.json`). Inside: `manifest.json` (bundle identity, the run manifest, a SHA-256 per member, and
an explicit `caveats` list), `audit.csv` + `audit-events.json` (one normalized row per change, joined
to the finding that justified it), the raw `audit.log` verbatim, `run.json`, the ledger and scan
artifacts, `policies/*` (the exact XC configs pushed), `snapshots/*` (pre-change LB state), and
`report.html`. It is the same bundle the console's ⑥ Retire step downloads, and it is read-only —
nothing here touches XC or GitHub.

Dry runs are not in it: nothing changed, so nothing is logged. The bundle is evidence for a human
reviewer, not a compliance certification. Full reference: **[AUDIT.md](AUDIT.md)**.

Every scan also drops a self-contained `out/report.html` (no server, no external assets). In the
console it's on **② Review** and **⚙ Setup** — **Open HTML report ↗** for a new tab, **Download**
for a timestamped copy. Both rebuild it from the current run dir on every open, so you always get
the latest run.

## 7. Ops console (localhost)
```sh
vpcopilot console         # http://127.0.0.1:8787
```
A six-step stepper that follows the lifecycle, plus a **⚙ Setup** page. A persistent hero band
(exploitable vulns → mitigated live in seconds, vs. change-control days) sits above every step, the
header carries a live model switcher, and each step is deep-linkable (`#mitigate`, `#retire`, …).

| Step | What |
|---|---|
| **① Scan** | point at a repo and run the pipeline — read-only, no XC/GitHub writes. Auto-advances to Review when it finishes |
| **② Review** | verified findings + the recommended band-aid; click a row for exploit / code / generated policy. **Open HTML report ↗** + **Download** |
| **③ Simulate** | replay a recorded sample against each candidate through a **spare** LB and report what it would block; over-threshold policies warn at the gate |
| **④ Mitigate** | apply each band-aid (or **Mitigate ALL**, one at a time, continuing past failures) and watch `before → after` stream, with a *self-healed in N attempts* badge |
| **⑤ Cure** | open the code-fix PR per finding, or all of them |
| **⑥ Retire** | the four-state ledger track, plus the **Audit trail** table and **Export evidence bundle (.zip)** / **All runs** |
| **⑦ Benchmark** | build a model-tagged report from this run, then compare models side by side per target app |
| **⚙ Setup** | credentials (writes `.env`), XC status, the per-agent model wiring, and the report buttons |

**Run settings** — the collapsible bar shown on the action steps (**Mitigate / Cure / Retire**):
LB · validate URL · PR repo · base · path prefix, plus **dry-run** (on by default), **refine** +
attempts, **keep live**, and **allow protected LB**. Its summary line spells out the mode you're
about to run in — `dry-run · rollback · LB=… · refine×3`.

**Log windows.** ① Scan and ④ Mitigate's per-finding job log hold the *whole* transcript in a
scrollable box, not the last N lines. The endpoints serve the full log and the page appends only the
new tail, so scroll position and text selection survive each poll — you can read back through a long
run while it's still going. Both stick to the bottom only while you're already at the bottom; on
① Scan, scrolling up also reveals a **↓ follow** chip and a line count (the Mitigate job log has
neither — it's a small box inside a table row).

**Audit trail (⑥ Retire).** One row per change made to a load balancer — when (UTC) · action ·
justified by (the finding, its id and severity) · control (+ the XC object) · load balancer
(+ namespace) · outcome (with a self-heal ×N badge and the `200 allowed → 403 blocked` proof) · by
(actor). Filter it, expand `▸` for the raw JSON, then **Export evidence bundle (.zip)** for this run
or **All runs** — the same bundle `vpcopilot export` writes (§6). The trail is shown *before* it can
be exported, so you can check what leaves the machine. Dry runs are absent by design.

The LB / validate URL / PR repo fields are **pickers**, not pre-filled defaults — load balancers come
from your XC namespace (with their domains), scan targets from sibling directories, PR repos from
`gh` — so the console is never pinned to one app. `/api/defaults` still reads the
`VPCOPILOT_DEFAULT_*` env vars, and `VPCOPILOT_DEFAULT_LB` is what the hero's
**XC security dashboard ↗** link points at:
```sh
VPCOPILOT_DEFAULT_LB=vampi-lab
VPCOPILOT_DEFAULT_URL=https://vampi.banknimbus.com
VPCOPILOT_DEFAULT_REPO=owner/repo        # a repo you can push code-fix PRs to
VPCOPILOT_DEFAULT_BASE=main
VPCOPILOT_DEFAULT_PREFIX=                 # usually empty
```

## Safety model
- **Human gate:** apply/PR run only when *you* trigger them (CLI or console).
- **Guardrails:** `PROTECTED_POLICIES` (the `nimbus-*` demo policies) can't be created/deleted;
  protected LBs (`VPCOPILOT_PROTECTED_LBS`, default `nimbus-www`) can't be mutated without
  `--allow-protected-lb`.
- **Reversible:** every apply snapshots the LB and rolls back on validation failure (or by
  default). Every change is written to the append-only audit log — the finding that justified it,
  the control and the XC object, the load balancer and its namespace, whether it was kept or rolled
  back, and who ran it (`VPCOPILOT_ACTOR`, else the OS user) on which host, under which run id.
  Dry runs are not recorded: nothing changed, so there is nothing to answer for.
- **Band-aids are temporary:** every finding also gets a code-fix PR; the ledger tracks each
  finding to `retired` (band-aid removed once the cure merges).

## Worked example (Nimbus)
```sh
vpcopilot scan  ./nimbus/app/src/app/api --out out
vpcopilot apply --from-scan out/policies/service_policy.deny-negative-pay-amount.json --dry-run
vpcopilot pr    --repo <owner>/nimbus-demo --base vuln-lab --path-prefix app/src/app/api --finding neg-pay-001 --dry-run
vpcopilot ledger
```
Apply/validate default to the **isolated test LB `vpcopilot-lab`** (`https://lab.banknimbus.com`),
so agent-run demos never touch the live `nimbus-www` security-demo path. Drop `--dry-run` to go
live on the test LB. `nimbus-www` is protected — mutating it requires `--allow-protected-lb`.
