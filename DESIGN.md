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
- **triage** — for each finding, selects the strongest **band-aid coverage** (one control
  or a stack) from the XC toolbox, marks `recommended`, states `residual_risk`, and sets
  `code_cure_required` (always true). `no_bandaid` is set only when nothing at the edge can
  mitigate (rare).
- **generate** — emits the XC config for the chosen band-aid control (service_policy,
  api_schema, waf/data_guard, malicious_user, bot_defense, rate_limit). Its prompt carries
  the demo-proven service-policy rules (FIRST_MATCH; specific DENY then catch-all ALLOW
  because XC default-denies; path-regex starts alphanumeric; `body_matcher` for JSON).
- **remediate** — writes the real code fix as a unified diff + PR title/body (the cure).

### Triage: band-aid first, cure always
Two principles drive triage:
1. **Band-aid first, cure always.** Find the strongest XC mitigation (single control or a
   stack); a code-fix PR is *always* produced too. `no_bandaid` is reserved for issues the
   edge genuinely can't touch (e.g. plaintext-password storage). Always state residual risk.
2. **Use the whole toolbox**, not just service policies:

| Control | Best band-aid for | Side |
|---|---|---|
| `waf` | injection (SQLi/XSS/cmd), common attacks | request |
| `waf_data_guard` | structured secrets (CCN/SSN/token) leaked in responses | response |
| `service_policy` | a single field/param/path/method constraint (positive security) | request |
| `api_schema` | type/range/required/unknown-field across many endpoints (import OpenAPI) | request |
| `malicious_user` | enumeration (BOLA/IDOR probing), velocity, repeat abuse | behavioral |
| `bot_defense` | credential stuffing, ATO, scraping, carding | behavioral |
| `rate_limit` | brute force / enumeration scale / velocity | request rate |

**Schema-preferred, with nuance:** for input/type/range flaws prefer `api_schema` when a
spec exists or the flaw spans many fields; fall back to a surgical `service_policy` for a
lone field (so Nimbus's negative-amount stays a service policy). The edge blocks exploit
*paths*; it cannot change app *logic* — that is what the code cure is for. `service_policy`
is request-side only; response data is `waf_data_guard`.

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
- **Audit trail:** every mutating action in the finding lifecycle appends one JSON line to `<out>/audit.log`, stamped
  centrally with `run_id` / `actor` / `host` / `tool_version` and carrying `finding_id`,
  `namespace`, the LB, the XC object it touched, `rolled_back` **and** `kept` (rolled-back alone
  can't say whether the change is still live), plus the before/after exploit proof. Dry runs are
  not recorded — nothing changed, so there is nothing to answer for. See *Audit + provenance*.
- **Secrets:** scoped XC token + provider keys in env / secret store, never in git.

## XC integration (`xc.py`, done)
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

## Audit + provenance (`audit.py`, `runmeta.py`, `export.py`)
A band-aid is a change to production infrastructure. The question a change board asks is not "did
it work" but **"why was this load balancer changed, by whom, in which tenant, and is it still
live?"** These three modules exist to answer exactly that — and nothing more: they are evidence for
a human reviewer, not a compliance certification.

**What one entry carries.** Every mutating action appends a JSON line to `<out>/audit.log`:

| stamped centrally (`audit.record`) | supplied by the action |
|---|---|
| `ts` · `run_id` · `actor` · `host` · `tool_version` | `finding_id` · `namespace` · `lb` · the XC object (`policy` / `app_firewall` / `apidef` / …) · `passed` \| `config_enabled` \| `enabled` · `rolled_back` · `kept` · `attempts` · `before_after` |

15 actions emit records: the 7 `apply_*`, the 3 `create_*`, `refine_apply`, `apply_timing`,
`open_pr`, `retire`, `rollback_failed`.

### The decisions
1. **Identity is stamped inside `audit.record`, never at the call sites.** Nineteen `record()` call
   sites write the trail — `apply.py`, `refiner.py`, `engine.py`, `pr.py`, `retire.py`, the console.
   Asking each to remember `run_id`/`actor`/`host`/`tool_version` guarantees one eventually forgets
   — and an entry that can't say who made the change, from where, as part of which run, is not an
   audit record. `record()` also **strips** those keys out of `**detail`, so a caller cannot
   override them. Only the per-action facts (`finding_id`, `namespace`, the object, the outcome)
   stay at the call site, because only the call site knows them. `engine.ApplyContext` carries
   `finding_id` for the same reason: a rollback failure raised deep in the spine must still be
   attributable to the vulnerability that justified the change.
2. **Run identity lives in `<out>/run.json`, keyed by `run_id`.** `runmeta.run_id(out)` mints an id
   on first use and persists it (atomic replace), so a scan and a `vpcopilot apply` an hour later
   **in a separate process** against the same out dir stamp the same run — the join key is the
   directory, not process memory. `write_manifest` never clobbers an existing `run_id`, so a
   re-scan keeps the identity the entries already on disk join to. Provenance sits beside it:
   scanned repo + commit/branch/dirty, config path, per-agent models, caps, counts,
   started/finished, actor/host/tool_version. Because it lives *in the run dir*, an exported bundle
   is self-describing — it doesn't need this machine, this checkout, or this console to be read.
3. **Write heterogeneous → normalize at export.** The log stays append-only and per-action: each
   record keeps exactly the fields that mattered for that action (a WAF's `config_enabled` is not a
   service policy's `passed`). That is right for a log and wrong for a reviewer, who needs one
   sortable shape. So `export.build_audit_events` does the flattening at **read** time — coalescing
   `passed ?? config_enabled ?? enabled` into one `outcome`, resolving `finding` → `finding_id`,
   recovering a finding from the `policies.json` index when an older entry names none, and joining
   the ledger + `findings.json` for title/class/severity/state. Normalizing at write time would
   have cost per-action fidelity permanently and frozen the schema; normalizing at export keeps
   both, and lets old logs improve as the normalizer learns their shapes. It keeps **every** entry:
   the report's impact table filters to entries with `before_after` or `behavioral`, which would
   silently drop `retire`, `open_pr`, every `create_*` and every config-only apply — an export that
   quietly loses rows is worse than no export.
4. **The export is read-only and stdlib-only.** `zipfile` / `csv` / `hashlib`, no new dependencies;
   it touches neither XC, GitHub, nor the run's artifacts. Evidence gathering must never be able to
   change the thing it is evidence of. The bundle carries the normalized events (`audit.csv` +
   `audit-events.json`, with `detail` keeping the raw JSON so flattening loses nothing), the raw
   `audit.log` **verbatim**, `run.json`, the scan artifacts, the exact XC configs pushed
   (`policies/*`), the pre-change LB snapshots (`snapshots/*`), and a `manifest.json` that SHA-256s
   every member — plus an explicit `caveats` list stating what the trail does *not* cover.
5. **Provenance writing is fail-soft.** `git_provenance` on a non-git target contributes nothing;
   a `write_manifest` failure logs a warning and returns. Provenance is evidence, not a gate — it
   must never fail a scan that already succeeded. Same instinct as the ledger: a half-written
   manifest reads as `{}` rather than raising.

**Surfaces** (repo convention: console and CLI call the same module function) —
`GET /api/audit-events` (the Retire step *shows* the trail before anyone exports it, so you can
check what leaves the machine), `GET /api/audit-export?scope=run|all`, `GET /api/runs`; and
`vpcopilot export [--out DIR] [--output PATH] [--all] [--root DIR]`.

**Honest limits.** Dry runs are unrecorded by design. `apply_timing` exists only for
console-driven live applies. Entries written by older builds lack `finding_id`/`namespace`/`actor`
and export as blank cells rather than inferred ones. `VPCOPILOT_ACTOR` overrides the OS user — set
it in CI or on a shared jump host so changes name the engineer, not the service account.

## Repo layout
```
src/vpcopilot/
  schemas.py        typed agent I/O (the cross-model contract)
  config.py         per-agent model registry (+ AGENT_NAMES)
  harness.py        LiteLLM + instructor (model independence)
  repo_scan.py      collect candidate source files
  agents/           discover, verify, triage, generate, remediate, probe, refine
  pipeline.py       deterministic orchestration (scan → artifacts + run.json)
  engine.py         SafeApply spine: snapshot → self-test → attach → validate → keep/rollback
  controls.py       registry of the 7 XC controls (attach/detach inverse, validation kind)
  apply.py          per-control apply entry points (CLI + console both call these)
  refiner.py        validate → refine → retry until the band-aid blocks (or gives up honestly)
  xc.py / probe.py  XC API client · executable exploit + legit request per finding
  ledger.py         found → mitigated → remediated → retired
  audit.py          append-only audit log (stamps run_id/actor/host/tool_version)
  runmeta.py        run identity + provenance (<out>/run.json, VPCOPILOT_ACTOR)
  export.py         evidence bundle (.zip): normalized events + raw artifacts + manifest
  report.py         standalone HTML report · retire.py detach · pr.py the cure
  console/          FastAPI ops console (app.py + static/index.html)
  cli.py            scan · apply · export · console · bench-model · …
config/agents*.yaml model-per-agent, one config per model
tests/              offline tests against fakes (no API needed)
```

## Roadmap
1. **Brain (done):** discover → verify → triage → generate → remediate, read-only. ✅
2. **XC client + deploy/apply (done):** ✅ create/snapshot/attach + idempotent PUT
   self-test + validate on the live LB (propagation-polled) + auto-rollback. Validated on
   `nimbus-www`: attach `nimbus-bizlogic-policy` → negative-pay 403 / legit 200 → rollback.
   Commands: `vpcopilot apply` (`--dry-run` / `--keep`), `vpcopilot xc-status`.
3. **Malicious-user branch (done):** ✅ `vpcopilot apply-maluser` enables XC Malicious-User
   Detection on the LB (oneof flip `disable`→`enable` + ensure user identification), with
   snapshot + PUT self-test + **config-level validation (readback)** + rollback; also a
   console action. Validated via a round-trip on `nimbus-www`. Behavioral mitigation builds
   from real attack traffic (not single-request testable).
4. **GitHub PRs (done):** ✅ `remediate` emits `patched_content` (full corrected file);
   `vpcopilot pr --repo <slug> [--finding <id>] --base <branch>` opens a PR via the GitHub
   API (full-file `update_file`, no diff apply; token from `GITHUB_TOKEN` or `gh auth token`).
   Validated: opened a real SSRF-fix PR into the `vuln-lab` branch.
5. **Ops console (done — MVP):** ✅ localhost FastAPI app (`vpcopilot console`): results
   dashboard (findings/triage/band-aids/residual risk/policies), gated Apply band-aid +
   Open PR actions (guardrails preserved, confirm prompts), background Run scan, XC status,
   and an Admin panel that reads/writes the local `.env`. TODO: remediation ledger, richer
   before/after panel. _(superseded original bullet below)_
   ~~review → approve → apply → undo, with a live before/after panel and the remediation ledger.~~
6. **Audit + evidence export (done):** ✅ every LB/object-mutating record now carries `finding_id`
   + `namespace` (and `kept`), with `run_id`/`actor`/`host`/`tool_version` stamped centrally in
   `audit.record`; `<out>/run.json` (`runmeta.py`) gives a run its identity and provenance so a
   scan and a later apply join up; `export.py` normalizes the log and zips the run's evidence
   (`vpcopilot export [--all]`, `GET /api/audit-export?scope=run|all`); the console's Retire step
   shows the trail — when · action · justified by · control · LB · outcome · by — before you export
   it. `VPCOPILOT_ACTOR` names who a change is attributed to.

## Open decisions
- Remediation output starts as **GitHub PRs** (confirmed).
- Validation target: **live LB** with snapshot/rollback (confirmed).
- Language: **Python** (confirmed).
