# DEMO — the whole product, from the console

Everything here is driven from the **ops console** in a browser. No terminal is needed once the
server is up. CLI equivalents are given where you might want them, but the demo is the GUI.

The one-line story to keep in mind:

> A frontier model finds exploitable vulns. The code fix needs 20–30 days of change control. The
> copilot puts an **F5 band-aid in front of the app in minutes** — exploit blocked, legit traffic
> untouched — and opens the **code-fix PR (the cure)** in the same pass. When the cure ships, it
> **retires** the band-aid. Every step is gated, validated, reversible and recorded.

There are three demos, in increasing order of what they need. **Pick one and finish it** — they
tell the same story at different levels of proof, and running half of each is worse than running
one whole.

| | needs | proves | wall clock |
|---|---|---|---|
| **A — Offline** | nothing | the whole arc, from a curated dataset | 5 min |
| **B — Live on F5 XC** | XC tenant + a model key | a real exploit blocked at a real edge | 12 min |
| **C — Declarative WAF** | B, plus a BIG-IP | the same policy, emitted for someone else's WAF | +6 min |

---

## The console at a glance

```
1 Scan → 2 Review → 3 Simulate → 4 Mitigate → 5 Cure → 6 Retire → 7 Benchmark        ⚙ Setup
```

The seven numbered steps are the arc, left to right. **⚙ Setup** holds credentials, the XC and
BIG-IP status panels, the audit sink and the per-agent model table. A **Run settings** bar
(`dry-run · rollback · LB · refine×3`) appears on the four steps that can change something —
Simulate, Mitigate, Cure, Retire — and never on the ones that cannot.

The **hero band** across the top is the headline: exploitable vulns → mitigated live → time to
mitigate, against your change-control window.

---

## Demo A — offline (no cloud, no keys)

```bash
pip install -e ".[console]"
python3 demo/build_demo_out.py             # writes a curated demo/out (crAPI-flavoured)
VPCOPILOT_OUT=demo/out vpcopilot console   # http://127.0.0.1:8787
```

Nine candidates, six verified — the whole arc already in the data. Walk the steps left to right.

### ② Review — what was found, and what was not

The chip row is the funnel: **candidates: 9 → verified: 6 → band-aids: 5 → code-fix PRs: 6**.

The gap between 9 and 6 is the point. An adversarial verify step refuted three candidates — an
`eval()` sink that is not reachable, a "hardcoded password" that is a test fixture, a missing rate
limit that already exists upstream — and they are **not** silently dropped. In the HTML report they
render below the fold in their own section, labelled *"Candidates the verify agent did not
confirm"*, excluded from every count and every chart on the page.

Say this out loud: *the tool argues with itself, and shows you the argument.*

Click any finding row to expand the exploit, the vulnerable code, the generated policy and the
code cure.

Each row carries its **CWE and OWASP API category**, with the tier spelled out — `CWE-89 · mapped`
versus `CWE-22 · advisory`. That distinction is the honesty: `advisory` means the OSV record named
the weakness and we are quoting it; `mapped` means the copilot classified it. Two findings carry
**no CWE at all**, and that is the correct answer — `CWE-840` is *prohibited* by MITRE for mapping
to real vulnerabilities, and username enumeration is not "weak authentication". A blank you can
explain beats a guess.

### ② Review → **Open HTML report ↗**

The shareable artifact, rebuilt from the run directory every time you open it, so it is never
stale. **Download** takes a stamped copy.

Point at three things:

1. **Findings by OWASP API Top 10** — and the `(no category)` bar. Injection was *removed* from the
   2023 API list, so `sqli` carries a CWE and no category. The chart accounts for every finding
   rather than quietly charting a subset.
2. **The blast-radius table** — a verdict per policy, with a caveats column. A replay that could
   not be measured says *not measured*, not a green 0.0%.
3. **Self-healed ×2** on the SQLi policy — the first generated policy did not block; the refiner
   diagnosed it and retried until the exploit actually returned 403.

### ③ Simulate — the blast radius, before anything is applied

The step people do not expect, and the one that lands with security teams. The safety spine proves
a band-aid blocks *the finding's exploit* and passes *one* legit request. It says nothing about the
other million requests a day, and that gap is why controls sit in monitor mode.

Simulate replays a recorded traffic sample against each candidate policy through a **spare** load
balancer and reports what each one *would* block. Nothing is applied; the spare LB is snapshotted
and restored.

### ⑥ Retire — the ledger and the audit trail

The four-state track: `found → mitigated → remediated → retired`. `crapi-sqli-001` is walked all
the way — its cure PR merged, so the band-aid was detached.

Below it, **every change ever made to a load balancer**, one row each: when (UTC) · action ·
justified by (finding + severity) · control · load balancer + namespace · outcome (with the
`200 allowed → 403 blocked` proof) · by whom. Expand `▸` for the raw JSON.

**Export evidence bundle (.zip)** — the normalized `audit.csv`, the raw `audit.log`, the exact
configs pushed, the pre-change LB snapshots, and a manifest that SHA-256s every member. **All
runs** does the same across every run directory on disk.

Two things worth saying while it downloads:

- Dry runs are deliberately **absent** from the trail. Nothing changed, so there is nothing to
  answer for.
- Overriding a protected load balancer writes its **own** audit event, so crossing a rail is
  visible to anyone scanning the trail rather than buried in a field of an ordinary record.

### ⑦ Benchmark *(advanced mode)*

Compare models per agent — an evaluation view shown only in **advanced mode** (`VPCOPILOT_ADVANCED`,
or more than one `config/agents*.yaml`), so the everyday user never meets it. The point is that
*nothing here is Anthropic-specific* — every agent's model is set in `config/agents.yaml`, and ⚙
Setup shows the current assignment for all eight.

---

## Demo B — live on F5 Distributed Cloud

**⚙ Setup** first. Fill in `XC_API_URL`, `XC_API_TOKEN`, `XC_NAMESPACE` and a model key, then
**Save to .env**. A value already supplied through the environment shows as **(set in
environment)** — saving `.env` will not override it until the console restarts, and the page says
so rather than letting you believe a change took effect.

Then `vpcopilot console`, and pick a lab load balancer in **Run settings**.

### ① Scan — four kinds of input

The step takes any of these, and the last three are the ones people have not seen before:

| Field | What it does |
|---|---|
| **Target repo** | source scan — discover → verify → triage → generate → remediate |
| **…or a security advisory** | a CVE / GHSA / PYSEC id, resolved against OSV. No repo, no credentials |
| **…or an OpenAPI spec** | scans the *contract*. With a repo, also cross-checks the spec against the code |
| **…or dependency manifests** | every pinned package resolved against OSV — `requirements.txt`, `package-lock.json`, `pom.xml` |

**Preview (no model calls)** surveys the dependencies without spending a token — a good answer when
someone asks what a run costs.

The run log is the whole transcript and stays where you scroll it; a **↓ follow** chip appears if
you scroll up mid-scan.

### ④ Mitigate — the moment that sells it

**Run settings**: `dry-run` OFF, `keep live` ON. Then **Mitigate ▶** on a finding.

The row streams: attach → validate → *(refine → retry)* → **before 200 through → after 403
BLOCKED · legit ok**. It never reports success unless the live exploit is actually blocked, and
never reports a block without also confirming a legitimate request still passes.

Seven control families are available — `service_policy`, `waf`, `waf_data_guard`, `api_schema`,
`rate_limit`, `malicious_user`, `bot_defense` — and triage picks per finding. Some findings get
**no band-aid at all**: plaintext password storage is a data-at-rest problem the edge never sees,
and the tool says "code cure only" rather than inventing a control for it.

Then **XC security dashboard ↗** in the hero band, to show the block landing in F5's own telemetry.

### ⑤ Cure → ⑥ Retire

**Open PR** drafts the real fix against your repo. When it merges, **Reconcile & retire proven
fixes** re-fires the exploit at the app's **origin** — around the band-aid, so a blocked request
cannot be mistaken for a fixed bug — and only then detaches the control.

If the cure has not merged, the console **refuses and tells you why**, with an explicit *retire
anyway* button. That is the pattern throughout: warn, explain, let a human override, record the
override.

---

## Demo C — the declarative WAF (not just F5 XC)

The objection you will hear is *"we are not an F5 shop"*. This answers it.

### ② Review → **Emit**

Pick a target and emit the same finding's policy as a declarative WAF policy for:

- `xc` — F5 Distributed Cloud
- `bigip-awaf` — BIG-IP Advanced WAF, as an AS3 declaration
- `nginx-app-protect` — NGINX App Protect

Same finding, same evidence, three vendors' syntax. Where a target genuinely cannot express a
control, it is listed as **unsupported** rather than emitted as something approximate.

### ⚙ Setup → BIG-IP lab

With an appliance configured, the panel shows the AS3 version, the tenants it can see, and the
protected ones. `/Common` is refused outright — not overridable, not even on a dry run, because
previewing the deletion of the appliance's own configuration is previewing an outage.

The emitted policy is validated against the vendor's own published schema and — in the reference
lab — pushed to a real BIG-IP, where the exploit is fired and the account balance is checked
afterwards. The assertion is the **balance**, not the status code: BIG-IP's blocking page returns
HTTP 200, so a status-code assertion would pass on a policy that blocked nothing.

---

## The safety rails, if someone asks

All of these hold on **all three surfaces** — CLI, console and the MCP server:

- **Protected load balancers** refuse mutation unless explicitly overridden, and the name is parsed
  before the check, so `./nimbus-www` is refused too.
- **Every apply snapshots first** and rolls back on failure — and the rollback is *verified*, not
  assumed. A control plane that accepts the restore and applies nothing raises loudly.
- **The blast-radius gate** blocks promotion of a policy that would block too much real traffic,
  and honours the threshold you set rather than silently substituting a default.
- **Secrets never reach an artifact.** Headers, bodies *and query strings* are redacted before a
  request sample is written, and the redaction is counted, so a sample cannot report itself clean.
- **Refusing to guess.** "We could not check this" and "this is clean" never render alike, anywhere.
  An unreadable snapshot is not "no drift". A scan of a path that does not exist is refused, not
  answered with an empty report.

## For an agent audience: MCP

`vpcopilot mcp` serves the pipeline over stdio as 15 tools — `scan_start`, `scan_status`,
`scan_result`, `impact`, `patches_list`, `deps`, `drift`, `simulate`, `ledger`, `reconcile`,
`verify_bundle` and more. Tools that would change a load balancer, open a PR or retire a control
are **absent** unless the operator started the server with writes enabled. The human gate is not
something a tool call can satisfy on its own.

---

## Talking points

- **Band-aids, not cures.** Every mitigated finding also gets a code-fix PR. The band-aid buys the
  20–30 days; the PR is the fix. The ledger tracks both to `retired`.
- **Self-healing.** The copilot validates its own policy against the finding's real exploit and
  refines until it works, so it never ships a band-aid that does not block.
- **Model-independent.** Eight agents, each with its own model in `config/agents.yaml` — Claude,
  OpenAI, Gemini or local Ollama, with no code change.
- **Reversible and gated.** Snapshot → self-test → attach → validate → keep or roll back. A human
  approves every live change.
- **Auditable.** Every live change carries the finding that justified it, the LB and namespace it
  touched, whether it stuck, and who ran it — exportable with a SHA-256 manifest
  ([AUDIT.md](AUDIT.md)). Evidence for a human reviewer, **not** a compliance certification.

## When something declines mid-demo

Do not treat it as a failure — it is the product working, and in front of a security audience it is
the most credible thing that can happen. Read the reason aloud.

| You see | Say |
|---|---|
| a finding with **no band-aid** | "the edge cannot see this one — it gets a code fix, and it says so" |
| a finding with **no CWE** | "MITRE prohibits the obvious mapping here; a blank we can explain beats a guess" |
| **"not measured"** in the blast radius | "that replay could not be measured — it will not pretend it came back clean" |
| a **refused retire** | "the cure has not merged; the band-aid is the only thing holding this shut" |
| a **refused protected LB** | "that one is off-limits, and the override would be recorded" |

## Screenshots

Checked in under [`docs/images/`](images/):

| Shot | File |
|---|---|
| Scan — the target form and its scrollable run log | [`1-scan.png`](images/1-scan.png) |
| Review — hero band + findings + report buttons | [`2-review.png`](images/2-review.png) |
| Simulate — blast radius before anything is applied | [`3-simulate.png`](images/3-simulate.png) |
| Mitigate — per-finding live apply | [`4-mitigate.png`](images/4-mitigate.png) |
| Retire — four-state ledger + audit trail | [`6-retire.png`](images/6-retire.png) |
| The shareable HTML report | [`report.png`](images/report.png) |

To regenerate: `python3 demo/build_demo_out.py`, then `VPCOPILOT_OUT=demo/out vpcopilot console`,
and capture each step at 1200px wide / 2× device pixel ratio.

Point the console at a **credential-free** `.env` when you do (`VPCOPILOT_ENV=…`). With XC creds
loaded, the hero band renders a deep link carrying your tenant hostname and namespace, and the
BIG-IP panel renders your appliance's tenants — both would ship in the image.
`build_demo_out.py` curates `actor`/`host`/`out_dir` in the fixture for the same reason: no real
machine identity in a shared dataset.
