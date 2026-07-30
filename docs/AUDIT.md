# Audit trail & evidence export

Every change the copilot makes to live F5 XC config is written to an append-only log, stamped with
who made it, from where, and which run it belongs to — and can be exported as a self-describing
`.zip` for a change board or an auditor.

The question this exists to answer: **"why was this load balancer changed, by whom, in which
tenant, and is the change still live?"**

Source of truth: `src/vpcopilot/audit.py` (the sink), `runmeta.py` (identity + provenance),
`export.py` (normalization + bundle). Read those if this doc and the code ever disagree.

---

## 1. What is recorded — and what is not

**Recorded:** every mutating action in the **finding lifecycle** — creating an XC object,
attaching/enabling a band-aid on an LB, a refine-and-retry loop, opening a code-fix PR, retiring a
band-aid, and a rollback that failed. One JSON object per line in `<out>/audit.log`, never rewritten.

Also recorded: every **gate decision** — the pre-apply drift check refusing, being overridden,
skipping an unchanged apply, or reporting that an apply detached another policy — and every
**reconcile decision**: a band-aid that outlived its TTL, a merged cure that did not actually fix
the bug, and an unattended retire. Nothing changed on the LB in most of those cases, which is
exactly why they belong here. "We looked and refused" and "we looked
and overrode it anyway" are questions an auditor asks, and only the log can answer them.

That scope is the whole band-aid path, but it is not literally every XC write the tool can make: the
lab/teardown utilities `vpcopilot lab-create` (`lab.py`) and `vpcopilot xc-rm` (`cli.py`) mutate XC
outside the finding lifecycle and write **no** audit record. They are setup/cleanup helpers, not
remediation — but if you use them against a real tenant, the trail will not show it.

**Not recorded:**

| Not in the trail | Why |
|---|---|
| Dry runs (`--dry-run`) | Nothing changed, so there is nothing to answer for. A dry run does a GET, computes a diff, and prints it — the LB is byte-identical afterwards. Logging previews would pad the trail with non-events and make "N changes to this LB" a lie. |
| Scans | Read-only. The scan's own outputs (`findings.json`, `triage.json`, …) are the record, and `run.json` describes the run. |
| Failed *attempts* inside a refine loop | `refine_apply` records one terminal entry per invocation with `attempts=N`. The per-attempt narration is in the console job log, not the audit log. |
| Anything XC did on its own side | This is the record of what the **copilot** sent. XC's own tenant audit log is the authority for what XC received and enforced. |
| `apply_timing` on CLI runs | Written only by the console's Mitigate step (see §2). |

The bundle manifest states these caveats **in-band** (`manifest.json → caveats`), so an exported
zip can never imply more coverage than it has:

```json
"caveats": [
  "Dry runs are not recorded: nothing was changed, so nothing is logged. This is the record of changes MADE, not of every attempt.",
  "apply_timing entries are written only by the console's Mitigate step on a live (non-dry) apply; a CLI-driven run has none.",
  "Entries written by older builds may lack finding_id / namespace / actor — those cells are blank rather than inferred."
]
```

### Honest limits

- A bundle can be **signed** (`VPCOPILOT_MINISIGN_KEY`, see `docs/USAGE.md`), which binds it to
  the holder of a key. That is a statement about *who exported it*, not about whether the log is
  true — everything below still applies to a signed bundle.
- The log is written by the same process that makes the change, to a local file. It is **not
  tamper-evident** — anyone who can write the out dir can edit `audit.log`. The manifest's SHA-256s
  prove a bundle was not altered *after export*; they say nothing about the authenticity of the log
  before it. If you need tamper-evidence, ship the out dir to append-only storage.
- `actor` is self-asserted (`VPCOPILOT_ACTOR`, else the OS user) — it is attribution, not
  authentication.
- Nothing in `export.py` calls XC or GitHub. The trail says what the tool *did*; the LB itself is
  the authority for what is live *now*.
- The bundle is evidence for a human reviewer. It is not a compliance certification.

---

## 2. The audit entry

`audit.record(out_dir, action, **detail)` writes one line to `<out>/audit.log`.

### Always present — stamped centrally

Identity is stamped inside `record()`, not at the call sites, so no mutating path can forget it and
no caller can spoof it. The reserved keys are stripped from `**detail` before the entry is built:

```python
_STAMPED = ("ts", "run_id", "actor", "host", "tool_version")
detail = {k: v for k, v in detail.items() if k not in _STAMPED}
```

| Field | Meaning |
|---|---|
| `ts` | UTC ISO-8601 timestamp (`runmeta.utc_now()`) |
| `action` | one of the 24 below |
| `run_id` | 12-hex id of the run dir — joins the entry to `<out>/run.json`. Minted on first use and persisted, so a scan and a later `vpcopilot apply` against the same dir share it |
| `actor` | `VPCOPILOT_ACTOR` if set, else the OS user, else `unknown` |
| `host` | `socket.gethostname()`, else `unknown` |
| `tool_version` | `vpcopilot.__version__` |

Everything else is per-action detail.

### The 24 actions

| action | category | what it means | key detail fields |
|---|---|---|---|
| `apply_service_policy` | mitigate | A service policy was attached to an LB and validated by firing the real exploit + a legit request | `finding_id` `lb` `namespace` `policy` `passed` `rolled_back` `kept` `before_after` |
| `create_service_policy` | create | A service policy object was created in the namespace (from-scan path, before attach) | `finding_id` `policy` `namespace` |
| `apply_malicious_user` | mitigate | Malicious-User detection enabled on the LB; validated by config readback (behavioral — not single-request testable) | `finding_id` `lb` `namespace` `enabled` `rolled_back` `kept` |
| `apply_rate_limit` | mitigate | Rate limiting set on the LB; optionally validated by driving a real burst | `finding_id` `lb` `namespace` `enabled` `passed` `rolled_back` `kept` `rate` `behavioral` |
| `apply_bot_defense` | mitigate | Bot Defense enabled on the LB; config readback | `finding_id` `lb` `namespace` `enabled` `rolled_back` `kept` |
| `create_app_firewall` | create | A **Blocking** `app_firewall` object was created (cloned from a template) because the named one did not exist | `finding_id` `name` `namespace` `mode` |
| `apply_waf` | mitigate | An `app_firewall` was attached to the LB; config readback plus an exploit probe (a single-request block is payload-dependent, so it is not scored pass/fail) | `finding_id` `lb` `namespace` `app_firewall` `config_enabled` `rolled_back` `kept` `before_after` |
| `apply_data_guard` | mitigate | Data Guard rules attached (reusing the LB's existing WAF); config readback | `finding_id` `lb` `namespace` `app_firewall` `enabled` `rolled_back` `kept` |
| `create_api_definition` | create | An OpenAPI spec was uploaded and an `api_definition` created/replaced | `finding_id` `name` `namespace` `swagger` |
| `apply_api_schema` | mitigate | The validation-block `api_specification` was attached to the LB and validated live | `finding_id` `lb` `namespace` `apidef` `passed` `rolled_back` `kept` `before_after` |
| `refine_apply` | refine | One full self-healing service-policy loop: apply → validate → diagnose → refine → retry, up to `max_refine`. Exactly one terminal entry per invocation | `finding_id` `namespace` `control` `policy` `lb` `passed` `attempts` + one of `rolled_back`/`before_after`, `unfixable`+`recommend`, or `reason` |
| `retire` | retire | A live band-aid was detached from the LB and the ledger marked `retired` | `finding_id` `control` `lb` `namespace` `forced` |
| `open_pr` | cure | The code-fix PR (the cure) was opened on GitHub | `finding_id` `finding` `repo` `url` `number` |
| `rollback_failed` | rollback | The LB could **not** be confirmed restored to its pre-apply snapshot after N retries. The one entry that must never be anonymous — the LB may be left in a changed state | `finding_id` `lb` `namespace` `reason` |
| `apply_timing` | timing | Wall-clock + outcome for one console Mitigate click. Feeds MTTM on the hero panel and policy quality in the model benchmark | `control` `finding_id` `passed` `elapsed_s` `attempts` `before_after` `unfixable` `reason` `kept` |
| `drift_detected` | gate | The live LB differs from the snapshot the last apply left — someone edited it outside this tool. Carries the full field-level diff | `lb` `policy` `snapshot` `changes` |
| `policy_displaced` | gate | Attaching replaces `active_service_policies` wholesale, so this apply **detached** another service policy. `protects_exploit` is true when the displaced policy is what currently blocks this finding's exploit | `lb` `policy` `displaced` `rules` `denies` `protects_exploit` |
| `apply_skipped_no_change` | gate | The policy asked for was already the attached one. Nothing was pushed — no LB PUT, no snapshot, no run artifact | `lb` `policy` |
| `drift_block` | gate | The apply was **refused**: an ALLOW inside the policy matched the exploit before its DENY, so under FIRST_MATCH the band-aid would have attached cleanly and blocked nothing | `lb` `policy` `conflicts` |
| `drift_override` | gate | The same conflict, applied anyway via `--force` / the console's **apply anyway**. The override is the point of the entry | `lb` `policy` `conflicts` |
| `simulate_override` | gate | A policy that shadow simulation flagged as over-broad was promoted anyway. Written by `simulate.promotion_gate`, which **both** apply paths call — it used to be written only by the console, so a CLI apply neither refused nor recorded the override (K1) | `finding_id` `policy` `lb` `block_rate` `threshold` `reason` |
| `escalation` | reconcile | A band-aid outlived its TTL with no merged cure. The control is **left in place** (`kept: true`) — an escalation is a notification, never a removal | `finding_id` `lb` `control` `policy` `cure_url` `cure_state` `applied_at` `expires_at` `ttl_hours` `age_hours` `escalation_count` `kept` `notified` `trigger` `pass_id` + denormalized `title` `vuln_class` `severity` |
| `fix_ineffective` | reconcile | The cure PR merged, but the exploit still reproduces **at the origin** — the code fix did not work. The band-aid is held | `finding_id` `lb` `control` `policy` `cure_url` `reason` `kept` `origin_probe` `trigger` `pass_id` + denormalized finding fields |
| `reconcile_retire` | reconcile | An unattended pass detached a band-aid after proving at origin that the exploit no longer reproduces. Written **alongside** the normal `retire` entry, not instead of it, so every existing consumer of `retire` keeps working | `finding_id` `lb` `control` `cure_url` `origin_probe` `trigger` `pass_id` |

Notes read from the source:

- `open_pr` and `apply_timing` carry **no** `namespace`, and `apply_timing` carries no `lb` either
  — it is a wrapper around whichever action just ran, and that action logged the LB and namespace
  itself on the adjacent line.
- `apply_timing.passed` is **optimistic**: it is the wrapped action's `passed`, else
  `config_enabled is not False` (`console/app.py::_run_action`). An action reporting neither key
  records `passed: true` having proved nothing, and `impact.py` counts that toward MTTM. For actual
  proof, read `exploit_before → exploit_after` on the adjacent entry, not this one.
- `apply_rate_limit`'s live proof is `behavioral` — `{sent, limited, passed, codes}` — not
  `before_after`.
- `before_after` is `{"before": {…}, "after": {…}}` where each side is the normalized probe result
  `{exploit_status, exploit_blocked, legit_ok}`.
- `apply_timing` is written by the console only, and only when `dry_run` is false
  (`console/app.py::_run_action`). A CLI-driven run has none — MTTM and `elapsed_s` are simply
  absent, not zero.
- The six **gate** actions are the only ones that record a moment when the LB did **not** change.
  Their `outcome` in the normalized export is the decision itself — `refused`, `overridden`,
  `no_change`, `displaced`, `drift_detected` — never `passed`/`failed`, because there was no apply
  to score. Dry runs remain unlogged: a gate decision is a real decision about a real apply, a dry
  run is a preview.
- The three **reconcile** actions are written by `vpcopilot reconcile`, which is report-only unless
  given `--apply`. A report-only pass that finds an overdue patch still writes `escalation` — the
  notification is the point — but it never writes `reconcile_retire`. A pass where nothing changed
  writes nothing at all, so a nightly cron does not grow the log by N lines a night forever.
- Every reconcile record carries `pass_id` and `trigger` (`cli` / `console` / `cron` / `mcp`). An
  agent session driving the MCP server (K1) records `mcp`, so the trail can say a reconcile pass came
  from an agent rather than a person — the fact a reviewer most wants and the one the log could not
  previously express. Cron invokes
  the CLI, so a scheduled pass is marked by exporting `VPCOPILOT_RECONCILE_TRIGGER=cron` in the
  crontab; without it a nightly pass is indistinguishable from someone typing the command. `run_id`
  cannot identify a pass — it is the identity of the out dir, and `audit.record` strips a
  caller-supplied one — so a year of nightly passes all share one `run_id` and are told apart by
  `pass_id`.
- Reconcile records **denormalize** `title`/`vuln_class`/`severity` onto the entry itself. Every
  other action lets the export join those from `findings.json` and `ledger.json` — but both are
  rewritten by the next scan, and an escalation is exactly the record most likely to be read months
  later. It carries its own justification rather than depending on a join that evaporates.
- Reconcile carries its probe as **`origin_probe`**, not `before_after`. There is no "before" — the
  band-aid was already live and the probe deliberately went around it — and `report.py`'s Band-aid
  impact table renders anything with a `before_after` key, marking it `fail` unless `passed` is set,
  so a successful auto-retire would have appeared there as a failure.
- `policy_displaced` is a **warning, not a veto**. Every apply replaces whatever was attached, so
  refusing would break every second apply; it is said out loud and written down instead. If you are
  auditing what protection an LB lost over time, this is the entry to read.

### Reading it raw

```sh
vpcopilot audit --out out          # rich table of the log
curl -s 127.0.0.1:8787/api/audit   # the raw entries, unnormalized
```

---

## 3. `run.json` — the run manifest

`<out>/run.json` is the per-run provenance record every audit entry points back to via `run_id`.
Written atomically (temp file + `os.replace`), merged never clobbered — a re-scan of the same dir
keeps its `run_id`, so audit entries already on disk stay joinable.

| Field | Source |
|---|---|
| `run_id` | `uuid4().hex[:12]`, minted on first use, never overwritten |
| `created` | UTC when the dir first got an identity |
| `repo` | absolute path of the scanned repo (`root.resolve()`) |
| `repo_commit` / `repo_branch` / `repo_dirty` | `runmeta.git_provenance(repo)` — `git rev-parse HEAD`, `rev-parse --abbrev-ref HEAD`, `git status --porcelain`. **Fail-soft**: a target that is not a git checkout contributes none of these keys at all |
| `config_path` | the `config/agents*.yaml` the scan ran with — **absent** when the scan used the default config (`runmeta.write_manifest` drops `None` fields) |
| `input_kind` | what was scanned: `repo`, `spec`, `manifest`, `advisory`, or a `+`-joined combination (`repo+spec`, `repo+manifest`, `repo+spec+manifest`). `advisory` is never combined — `--cve` is exclusive |
| `advisory` | H1 only: `{id, source, consulted, network_observable, fixed_version}` for a `--cve` scan |
| `spec` | H3: absolute path of the OpenAPI spec, when `--spec` was given |
| `manifests` | H2: absolute paths of the dependency manifests, when `--manifest` was given. The per-package detail is in `dependencies.json`, not here |
| `models` | `{agent: model}` for each of `config.AGENT_NAMES` = `resolve, discover, verify, triage, generate, remediate, probe, refine` |
| `caps` | `{min_confidence, max_files, max_bytes, draft_code_fixes}` — the limits the scan ran under |
| `counts` | `{candidates, verified, policies, code_fix_prs, dependency_upgrades}`. The last two are split on `RemediationPlan.kind`: a `code_fix` is a patch drafted against a file you own and is what `pr` opens; a `dependency_upgrade` (H1/H2) is a version bump in someone else's package, so **no PR was drafted and none can be**. Counting the two together overstated the cure half of the run on every surface that renders it |
| `started` / `finished` | UTC scan bounds |
| `actor` / `host` / `tool_version` / `out_dir` | re-stamped on every manifest write |

Two things to know:

1. **A dir where only `vpcopilot apply` ran has a minimal `run.json`** — just `run_id` and
   `created`, minted lazily by the first `audit.record()`. No repo, no models. That is expected, not
   a bug.
2. **`actor`/`host` in `run.json` describe whoever last wrote the manifest** (the last scan), not
   the actor of each change. Each audit entry stamps its own — trust the entry, not the manifest,
   for per-change attribution.

Manifest writing is fail-soft by design: `pipeline.run_pipeline` wraps it and logs
`⚠ could not write the run manifest (run.json): … — an audit export will lack provenance` rather
than failing a completed scan. Provenance is evidence, not a gate.

---

## 4. Attribution — `VPCOPILOT_ACTOR`

```python
def actor() -> str:
    explicit = (os.environ.get("VPCOPILOT_ACTOR") or "").strip()
    if explicit:
        return explicit
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
```

Resolution order: **`VPCOPILOT_ACTOR` → OS user → `"unknown"`**. It never returns blank, and it
never raises — a slim container with no passwd entry must not break an apply mid-flight.

Set it in CI or on a shared jump host so the trail names the engineer who asked for the change
rather than the service account it happens to run as:

```sh
VPCOPILOT_ACTOR="dhenley@utexas.edu" vpcopilot apply --from-scan out/policies/service_policy.deny-login-sqli.json \
  --lb crapi-lab --url https://lab.example.com --keep
```

It is stamped in `audit.record()`, so a caller passing `actor="someone-else"` is silently
overridden (`tests/test_audit_provenance.py::test_identity_cannot_be_overridden_by_a_caller`).
That stops accidental spoofing from a call site. It does **not** stop someone who controls the
environment — this is attribution, not authentication.

---

## 5. The normalized event model

`audit.log` is deliberately heterogeneous: each action records what mattered for that action. That
is right for a log and wrong for a reviewer. `export.build_audit_events(out_dir)` produces **one row
per entry**, newest first, joined against `ledger.json`, `findings.json` and the `policies.json`
index.

Every entry survives. `report.py`'s impact table filters to entries with `before_after` **or**
`behavioral`; an export that did the same would silently drop `retire`, `open_pr`, every `create_*`
and every config-only apply — so the exporter deliberately keeps them all.

### `export.COLUMNS`

| Column | Meaning |
|---|---|
| `ts` | UTC timestamp of the entry |
| `run_id` | run this change belongs to → `run.json` |
| `actor` | who |
| `host` | from where |
| `category` | `mitigate` · `create` · `refine` · `timing` · `cure` · `retire` · `rollback` (else `other`) — from `export.CATEGORY` |
| `action` | the raw action name |
| `finding_id` | the vulnerability that justified the change (see resolution below) |
| `title` | finding title, from `findings.json` else the ledger |
| `vuln_class` | e.g. `sqli`, `bola` — same fallback |
| `severity` | `critical` / `high` / … — same fallback |
| `ledger_state` | the finding's state **at export time**: `found → mitigated → remediated → retired`. Not the state when the change was made |
| `control` | the entry's `control`, else inferred from the action via `export.CONTROL` |
| `lb` | the load balancer touched |
| `namespace` | the XC namespace it lives in |
| `object` | the XC object named by the entry — first non-empty of `policy`, `app_firewall`, `apidef`, `name`, `rate`, `swagger` |
| `outcome` | one word for "did it stick, and did it work?" (below) |
| `attempts` | self-heal count — how many refine cycles it took |
| `exploit_before` | `"200 allowed"` — the exploit's status before the change |
| `exploit_after` | `"403 blocked"` — after |
| `legit_ok` | did legitimate traffic still pass after the change (over-block check) |
| `pr_url` | the cure PR — the entry's `url`, else the ledger's `cure.pr_url` |
| `tool_version` | version that wrote the entry |
| `detail` | the whole raw entry minus the stamped keys and `action` (each already has its own column). In CSV it is JSON, so the flattening loses nothing |

`finding_id` resolution: `entry.finding_id` → `entry.finding` (the legacy key `open_pr` used) →
`policies.json[policy_name == entry.policy].finding_id`. Blank if none of the three resolve.

### How `outcome` is derived

`export._outcome()`, in order:

1. **Fixed by action** — these have no pass/fail to coalesce:
   `rollback_failed → rollback_failed`, `retire → retired`, `open_pr → pr_opened`,
   `create_service_policy` / `create_app_firewall` / `create_api_definition` → `created`.
2. `unfixable` truthy → **`unfixable`** (the refiner gave up honestly: code fix required).
3. `rolled_back` truthy → **`rolled_back`**.
4. Otherwise coalesce the three success keys the apply paths disagree on:
   `ok = passed ?? config_enabled ?? enabled`.
   - all three absent → **`recorded`**
   - `ok` and `kept` → **`kept`** (the change is still live on the LB)
   - `ok` → **`passed`** (it worked, but was not kept)
   - else → **`failed`**

Two consequences worth knowing before you read a table:

- Step 3 runs **before** the coalesce, so a validated-then-rolled-back apply — the default without
  `--keep` — reads `rolled_back`, not `passed`. The proof it worked is still in
  `exploit_before → exploit_after`.
- A record that omits `kept` falls through to `passed`/`failed` rather than `kept`. Absence of
  `kept` is not evidence of a rollback — cross-check `ledger_state` and, for ground truth, the LB.

`kept` exists precisely because "was it rolled back?" alone cannot answer "is this change still
live?" — a `rolled_back: false` on a failed apply means something very different from a
`kept: true`.

---

## 6. The evidence bundle

A `.zip` for one run. Every file is added verbatim; nothing is re-rendered except the two derived
views.

```
manifest.json            what this bundle is + a SHA-256 per member + the caveats
audit.csv                the normalized events, flat, one row per event (export.COLUMNS)
audit-events.json        the same events with `detail` as real JSON
run.json                 the run manifest (§3)
audit.log                the raw append-only log, byte-for-byte
ledger.json              found → mitigated → remediated → retired, per finding
findings.json triage.json policies.json remediations.json
summary.json metrics.json probes.json correlations.json
lb_snapshot.json         the most recent pre-change LB state
simulation.json          the blast-radius replay result, when a simulation ran (G2)
dependencies.json        the dependency funnel, when the scan used --manifest (H2)
report.html              the standalone HTML report
policies/*               the exact XC configs that were pushed
snapshots/*              per-LB timestamped pre-change state (`<lb>-<UTC>.json`)
```

Missing members are skipped, not faked — an unscanned dir has no `findings.json`, and a run with no
live apply has no `snapshots/`. (`apply_timing` is an *entry inside* `audit.log`, not a member — a
CLI-driven run simply has none of those lines.)

**`dependencies.json` is not a clean bill of health**, and the manifest's `caveats` say so, because
this is the member most likely to be read as one. Four things a reviewer has to know:

- **`unpinned`** lists manifest entries whose exact version could not be established — a range like
  `flask>=2.0`, an editable install, an unresolved `${property}`, a version inherited from a parent
  POM. Those were **never queried**. Nothing is known about them; that is not the same as clean.
  They are excluded on purpose: OSV answers a version string it cannot parse with a larger, wrong
  advisory set rather than an error, so a guess would look like an answer.
- **`advisories[].disposition`** distinguishes what was assessed from what was merely found.
  `exploitable` and `declined` came back from the resolve agent. `below_severity` and `capped` were
  found and listed but never sent to one, so no band-aid was ever considered for them —
  `settings.min_severity` and `settings.max_advisories` record the thresholds that did it.
  `resolve_failed` is an advisory whose agent call errored.
- **`unchecked`** (with `funnel.packages_unchecked`) is a package OSV said has advisories and then
  could not be asked about — a 429, a timeout, a transport error on the follow-up query. Its
  advisories are **unknown, not absent**. Before this was its own list it appeared only as an
  `error` key inside `packages[]`, contributing no row, no counter and no warning, which read
  exactly like a package that came back clean.
- **`funnel`** reconciles the counts end to end, from `packages_parsed` through to `exploitable`.
  Note `packages_parsed` counts the entries that **were** pinned; `packages_unpinned` is a disjoint
  list, not a subset of it, so the queried count is `packages_parsed − packages_dev_excluded`.
  It reflects OSV.dev **on the run date only** — `run.json`'s `finished` is the as-of timestamp, and
  re-running later will legitimately produce different numbers.

`--all` produces one archive with each run under its own folder (`out-claude/`, `demo-out/`, …)
plus a top-level `index.json` listing `{out_dir, folder, events, run_id}` per run. Run dirs are
discovered by `export.find_runs`: everything matching `out*/` plus `demo/out`, keeping only dirs
that have an `audit.log` or a `findings.json`.

### The manifest

```json
{
  "kind": "vpcopilot-audit-bundle", "schema": 1, "tool_version": "0.1.0",
  "generated": "2026-07-26T19:04:11+00:00",
  "generated_by": "dhenley", "generated_on": "jump-01",
  "out_dir": "out-claude",
  "run": { "run_id": "9f2c1ab30e77", "repo": "…", "repo_commit": "…", "models": {…}, "caps": {…} },
  "events": 14,
  "actions": { "apply_service_policy": 3, "retire": 1, "open_pr": 2, … },
  "findings_touched": ["crapi-sqli-001", "crapi-bruteforce-004"],
  "caveats": [ … ],
  "members": { "audit.csv": {"bytes": 4211, "sha256": "…"}, "audit.log": {…}, … }
}
```

`manifest.json` itself is not in `members` (it is written after the hashes are computed). In a
multi-run bundle, member names are relative to that run's folder.

### Verifying a bundle after it leaves the machine

With vpcopilot to hand, one command does all of this and exits non-zero on any problem:

```sh
vpcopilot export --verify audit-bundle.zip [--pubkey vpcopilot.pub]
```

Without it — which is the case that matters, since the bundle is meant to leave the machine —
recompute every hash from the zip alone:

```sh
python3 - vpcopilot-audit-out-claude-20260726T190411Z.zip <<'PY'
import hashlib, json, sys, zipfile

z = zipfile.ZipFile(sys.argv[1])
bad = z.testzip()
if bad:
    sys.exit(f"corrupt member (CRC): {bad}")

names, fails = set(z.namelist()), 0
for mpath in sorted(n for n in names if n.endswith("manifest.json")):
    prefix = mpath[: -len("manifest.json")]          # "" for a single run, "<folder>/" for --all
    m = json.loads(z.read(mpath))
    run = (m.get("run") or {}).get("run_id", "?")
    print(f"\n{mpath}  run={run}  events={m['events']}  members={len(m['members'])}")
    for name, meta in sorted(m["members"].items()):
        full = prefix + name
        if full not in names:
            print(f"  MISSING  {name}"); fails += 1; continue
        got = hashlib.sha256(z.read(full)).hexdigest()
        ok = got == meta["sha256"] and len(z.read(full)) == meta["bytes"]
        fails += not ok
        print(f"  {'ok  ' if ok else 'BAD '} {name}  {got[:16]}")
    for c in m["caveats"]:
        print(f"  caveat: {c}")
print(f"\n{fails} mismatch(es)")
sys.exit(1 if fails else 0)
PY
```

What this proves: the bundle is internally consistent and was not edited after export. What it does
not prove: that `audit.log` was authentic when it was bundled (see §1, honest limits).

To re-derive `audit.csv` yourself and confirm the normalization added nothing, run
`vpcopilot export --out <dir>` against the unpacked run and diff.

---

## 7. How to get one

### Console — ⑥ Retire

```sh
vpcopilot console            # http://127.0.0.1:8787
```

The Retire step has a second card, **"Audit trail — every change made to a load balancer"**. It
*shows* the trail before anything is exported — you can check what leaves the machine first. One row
per change:

`when (UTC)` · `action` (+ category) · `justified by` (finding title, id, severity) · `control`
(+ the XC object) · `load balancer` (+ namespace) · `outcome` (with a `×N` self-heal badge and the
`200 allowed → 403 blocked` proof) · `by` (actor)

A filter box matches against the whole row, and `▸` expands any row to its raw JSON detail. Two
buttons: **Export evidence bundle (.zip)** (current run) and **All runs**.

Downloads are named by `_stamped_name()` so several can share a folder or a ticket without
ambiguity:

```
vpcopilot-audit-out-claude-20260726T190411Z.zip       # scope=run
vpcopilot-audit-all-out-claude-20260726T190411Z.zip   # scope=all
```

Backing endpoints, all read-only:

| Endpoint | Returns |
|---|---|
| `GET /api/audit-events` | `{out, events}` — the normalized events for the current out dir |
| `GET /api/audit-export?scope=run` | the `.zip` for the current run (`400` on an unknown scope) |
| `GET /api/audit-export?scope=all` | the `.zip` for every run dir on disk |
| `GET /api/runs` | `{current, runs}` — run dirs with something to export |
| `GET /api/audit` | the raw log, unnormalized |

### CLI

Console and CLI call the same module function — the bundles are identical.

```sh
vpcopilot export --out out                              # → out/audit-bundle.zip
vpcopilot export --out out-claude --output ~/tickets/SEC-412/evidence.zip
vpcopilot export --all --root . --output all-runs.zip   # every run dir, each in its own folder
```

`export` prints the path and the event count, and warns (without failing) when the run has no audit
entries yet — `no audit entries in out — nothing has changed a load balancer yet`.

---

## 8. Reading the trail for a specific question

All of the below run against `audit-events.json` from a bundle. Live, use
`curl -s 127.0.0.1:8787/api/audit-events | jq .events` instead.

### "Which vulnerability justified this LB change?"

```sh
jq -r '.[] | select(.lb=="crapi-lab")
       | [.ts, .action, .control, .object, .finding_id, .severity, .title] | @tsv' audit-events.json
```

That join is the whole point of the normalizer — `finding_id` → `title`/`severity`/`vuln_class` from
`findings.json`, falling back to the ledger. If `finding_id` is blank, the change predates the
attribution work or names a policy that is no longer in `policies.json` (§9).

### "What is still live on the LB right now?"

```sh
# changes that were kept (not rolled back)
jq -r '.[] | select(.outcome=="kept") | [.ts,.lb,.namespace,.control,.object,.finding_id] | @tsv' audit-events.json
# …minus anything later retired
jq -r '.[] | select(.action=="retire") | [.ts,.lb,.control,.finding_id] | @tsv' audit-events.json
```

Cross-check `ledger_state`: `mitigated` means a band-aid is live, `retired` means it was detached.
Caveat: this is the tool's record — **the LB is the authority**. For ground truth, `GET` the LB and compare against
`snapshots/<lb>-<UTC>.json` in the bundle.

### "Did the band-aid actually block the exploit?"

```sh
jq -r '.[] | select(.exploit_after != "")
       | [.finding_id, .control, .exploit_before, .exploit_after, .legit_ok, .attempts] | @tsv' audit-events.json
```

`200 allowed → 403 blocked` with `legit_ok=true` is the real proof: the exploit stopped working and
legitimate traffic still passed. `attempts > 1` means the refiner self-healed the policy that many
times before it worked.

Which controls can produce that proof:

| Control | Evidence |
|---|---|
| `service_policy`, `api_schema`, `refine_apply` | live exploit + legit probe → `exploit_before`/`exploit_after`/`legit_ok` |
| `waf` | probe recorded, but a single-request signature block is payload-dependent, so it is **not** scored pass/fail — `config_enabled` is the assertion |
| `rate_limit` | `detail.behavioral` = `{sent, limited, passed, codes}` — a real burst was driven and the excess 429'd |
| `malicious_user`, `bot_defense`, `waf_data_guard` | config readback only (`enabled`) — behavioral controls are not single-request testable |

`outcome=unfixable` is the honest negative: the refiner tried, could not make a band-aid work, and
said so. The finding stays `found` and needs the code fix.

### "Who made this change?"

```sh
jq -r '.[] | [.ts,.actor,.host,.run_id,.action,.lb,.finding_id] | @tsv' audit-events.json
jq '.run' manifest.json      # → repo, repo_commit, repo_branch, repo_dirty, models, caps
```

`run_id` ties every entry to the run manifest: which repo at which commit produced the finding, with
which models, under which caps. Blank `actor` means an entry from an older build (§9). Remember
`actor` is self-asserted.

---

## 9. Backward compatibility

The normalizer reads old logs without rewriting them. `audit.log` is append-only — nothing
back-fills it.

| Older shape | What the exporter does |
|---|---|
| No `run_id` / `actor` / `host` / `tool_version` | Those cells export **blank**. They are not inferred from the current environment — a guess in an audit trail is worse than a gap. |
| `open_pr` wrote `finding`, not `finding_id` | Resolved via the `finding` key. Current builds write **both** (`pr.py`), so old and new logs read the same way. |
| `apply_*` recorded no finding at all | Resolved through the `policies.json` index: `entry.policy` → `policy_name` → `finding_id`. Works only for entries that name a `policy`, and only while that scan's `policies.json` is still in the dir — **`vpcopilot audit-backfill` freezes it before that expires** (§9.1). Otherwise blank. |
| No `namespace` | Blank. The `lb` is still there; the tenant/namespace is not recoverable after the fact. |
| No `kept` | Older entries (and any action that omits it) fall through to `passed`/`failed` rather than `kept`. Absence of `kept` is not evidence of rollback. |
| Mixed success keys (`passed` / `config_enabled` / `enabled`) | Coalesced into one `outcome` (§5) — including the seeded demo dataset, which uses its own mix. |
| No `apply_timing` | Expected on any CLI-driven run: those entries come only from the console's Mitigate step on a live apply. MTTM and `elapsed_s` are absent, not zero. |

The seeded `demo/out/audit.log` is a good worked example of the legacy shape — no `run_id`, no
`actor`, `apply_rate_limit` with `behavioral` but no `namespace`. Export it and see exactly which
cells come out blank:

```sh
vpcopilot export --out demo/out --output /tmp/demo-evidence.zip
```

### 9.1 Attribution backfill (J4)

The `policies.json` fallback above has an expiry date, and it is easy to miss: **every scan rewrites
`policies.json`**. Re-scan into the same out dir and the mapping from an old entry's policy name back
to its finding is gone — the exporter quietly stops attributing those entries. Worse, if the new scan
generates a policy with the *same name* for a *different* finding, the lookup still succeeds and
attributes the old entry to the **wrong** finding: a confident wrong answer, in the artifact whose
entire job is to be trustworthy.

```sh
vpcopilot audit-backfill --out out            # freeze what is derivable right now
vpcopilot audit-backfill --out out --dry-run  # report it, write nothing
```

It writes `<out>/audit-backfill.json`, a sidecar the exporter reads beside the log, and ships it in
the evidence bundle so a reviewer receives both together.

Four properties are the whole point:

- **`audit.log` is never edited.** It is append-only and `record()` strips caller-supplied identity;
  a backfill that could rewrite an entry would destroy the property that makes the log worth keeping.
  The only thing appended is the backfill's own `audit_backfill` record.
- **Nothing is invented.** The sidecar carries **no `actor`, no `run_id`, no `host`** — there is
  nowhere to put one. It maps an entry to a finding and nothing else; identity stays on the log.
- **The frozen answer wins over the live lookup**, because after a re-scan the live index describes a
  different run.
- **`unknown` is sticky.** An entry the backfill looked at and could not resolve stays unresolved,
  so a later `policies.json` cannot supply an answer the backfill already declined to give. "We
  looked and could not establish this" is a fact worth keeping.

A second run writes nothing and records nothing. That matters more than tidiness: the command appends
its own entry, so without the check each run would see one more entry than the last, decide something
had changed, and append again.

The sidecar is keyed by the entry's index in the append-only log and verified against its
`(ts, action)`. If the log is ever rebuilt or truncated, mismatched rows are **dropped and counted**
rather than silently moved onto the wrong entry. It is written atomically (temp file plus rename),
because a half-written evidence file that will not parse is worse than none.

**Absent and unreadable are different answers.** No sidecar means nobody has frozen anything, so the
exporter falls back to the live policy index as it always did. A sidecar that is present and will
*not* parse means somebody did freeze attribution and it is now unreadable — and the live index is,
by definition, not the one those entries belong to. The cell is left blank rather than guessed.

#### What a forged sidecar could do — and what it could not

The log is append-only; a sidecar is an ordinary file. So state the limit plainly rather than leave
a reviewer to work it out.

A hand-edited `audit-backfill.json` can change an entry's `finding_id`, and through it the fields
joined *from* that id: `title`, `vuln_class`, `severity`, `ledger_state`, `pr_url`. It cannot change
anything the log itself stamped — `ts`, `actor`, `host`, `run_id`, `action`, `outcome`, `lb`,
`tool_version` all come straight from `audit.log` and are unreachable from the sidecar.

**This adds no trust assumption that the export did not already make.** `findings.json` and
`ledger.json` already drive exactly those joined columns, and they are the same kind of file in the
same directory — anyone who can forge the sidecar can forge those and get the same result. The
sidecar is digested in the bundle manifest like every other member (§6), so tampering *after* export
is caught by `export --verify`; tampering *before* export is a question about who has write access to
the run directory, which no artifact in it can answer.

The one thing that survives all of it is the log: append-only, identity stamped centrally, and
shipped verbatim in the bundle. If the sidecar and the log ever disagree, the log is the evidence.

---

## See also

- `docs/USAGE.md` — the full apply / PR / retire workflow
- `DESIGN.md` — where the audit sink sits in the architecture
- `src/vpcopilot/export.py` — `COLUMNS`, `CATEGORY`, `CONTROL`, `BUNDLE_FILES`
- Tests: `tests/test_audit_provenance.py` (what every entry must carry),
  `tests/test_export.py` (normalization, CSV, bundle, multi-run),
  `tests/test_console_audit_export.py` (the endpoints)
