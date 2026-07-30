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

### Scan a CVE instead of a repo (H1)

The vulnerabilities most people lose sleep over live in dependencies they do not own, where the
code cure is a version bump someone else has to ship and they then have to deploy. That gap is what
virtual patching is for.

```sh
vpcopilot scan --cve CVE-2024-23334 --out out       # or GHSA-…, PYSEC-…, GO-…, RUSTSEC-…
```

The advisory is resolved from **OSV.dev** (no credentials — `scan` stays safe to run anywhere), the
`resolve` agent derives its HTTP exploitation profile, and the result enters the same triage and
generate stages as a code finding. `--cve` and a repo path are mutually exclusive.

**The agent is expected to decline.** Many advisories cannot be virtually patched at a load
balancer — a malicious build-time dependency, a bug reachable only from a local file, memory
corruption with no request signature. Those route to `no_bandaid` with the residual risk stated,
and that routing is decided **in code**, not asked of the model: a hard requirement should not
depend on a prompt being honoured. An agent that obligingly invented a plausible path for every CVE
would be worse than no advisory input at all — it would produce confident band-aids that block
nothing while hiding a real vulnerability behind a green check.

**The cure is a version bump, never a patch.** `remediate` is not called on this path. The fixed
version is copied from OSV by code — it is the one string an operator acts on directly, so no model
goes near it — and `vpcopilot pr` reports the upgrade and opens nothing:

```
advisory: upgrade aiohttp to 3.9.2 — no PR to open (the fix is upstream, not in this repo)
```

Because no cure PR exists, the band-aid is never auto-retired and **`reconcile` escalates it at TTL
expiry**. That is deliberate: someone still has to ship the upgrade.

Three things about OSV worth knowing, each found by querying it:

- Asking for a **CVE id often returns the git-range record** — no package, and `fixed` values that
  are commit SHAs. The installable version lives on the GHSA/PYSEC alias, so the client follows
  aliases. Without that, `CVE-2024-23334` recommends "upgrade to 24a6d649…".
- When there genuinely is no released fix, it says so rather than offering a commit.
- `summary` is often empty and OS-level CVEs have no package at all; the prose in `details` is the
  real payload, and the CPE is the fallback identity.

Set `VPCOPILOT_ADVISORY_CACHE=<dir>` to cache advisories on disk so a demo does not depend on the
network.

### Scan an OpenAPI spec (H3)

A4 goes one way: you hand XC a schema and it enforces it. This is the other direction — read the
spec and find the flaws **in** it. A spec is a security artifact whether or not anyone treats it as
one, and it is often the only thing you have for a service you do not own.

```sh
vpcopilot scan --spec ./openapi.yaml --out out              # the contract alone
vpcopilot scan ./app --spec ./openapi.yaml --out out        # …and the code, plus the drift between them
```

`--spec` is **additive**: alone it scans the contract; alongside a repo it also compares the two.
(`--cve` is the exception — an advisory scan cannot be combined with either.)

**Split by what needs judgement.** A deterministic pass finds what the document leaves unstated —
a number with no `minimum`, a string with no `maxLength`, an operation with no `security`, an object
with `additionalProperties` open. Those are facts, so recall does not depend on which model is
configured. The agent then decides which of them *matter*: an unbounded `page` is nothing, an
unbounded `amount` on a transfer is a business-logic hole.

**Spec/code drift is a finding in both directions**, reported as `undocumented_or_orphaned`:

- **declared but unserved** — dead documentation, or a shadow API removed from one place and not
  the other
- **served but undeclared** — the one that bites: applying an `api_schema` band-aid built from this
  spec would start rejecting those routes

That finding is a comparison of two documents, so it skips the verify agent entirely — asking an
adversarial code reviewer to confirm a vulnerability in source it cannot see got it refuted at 0.10
confidence.

### Scan a dependency manifest (H2)

`--cve` answers "can a load balancer hold the line on *this* advisory". `--manifest` asks it of
every dependency you actually have — which is the form the question normally arrives in. Nobody
hands you a CVE id; they hand you a `requirements.txt`.

```sh
vpcopilot deps ./requirements.txt                                   # what a scan WOULD find — no model calls
vpcopilot scan --manifest ./requirements.txt --out out              # the dependency tree alone
vpcopilot scan ./app --manifest ./package-lock.json --out out       # …and the code, correlated together
vpcopilot scan --manifest ./requirements.txt --manifest ./pom.xml --out out    # repeatable
```

`--manifest` is **additive**, like `--spec`. Alone it resolves the dependency tree; alongside a repo
the code findings and the dependency findings correlate together, so one band-aid can cover both.
Formats: `requirements.txt`, `package-lock.json` (v1/v2/v3), `pom.xml`.

**Start with `vpcopilot deps`.** It parses the manifests, asks OSV which pinned packages have
advisories, and prints the whole funnel — with no model, no credentials and no tenant. It is the
cheap way to see what a scan would cost and to tune the two knobs below before paying for one.

**Two things it will not do, and both are the point:**

- **It never guesses a version.** `flask>=2.0`, a bare `cryptography`, `-e .`, a `${spring.version}`
  with no `<properties>` entry, a version inherited from a parent POM — each is listed under
  `unpinned` with a reason, and never sent to OSV. This matters more than it sounds: OSV does *not*
  error on a version string it cannot parse. Measured live, `aiohttp` at `not-a-version`,
  `1.0.0-SNAPSHOT` and `${project.version}` each returned **81 advisories**, against 70 for the real
  `3.9.1`. A guess does not fail loudly — it returns a bigger, wrong answer.
- **It never hides what it skipped.** *"We did not check this"* and *"this is clean"* must not read
  the same way, so every unpinned entry and every advisory held back by the filters is in
  `dependencies.json`, on the console preview and in the HTML report, carrying its reason. The same
  goes for what it could not check *despite trying*: a package OSV flagged and then failed to
  answer for (a 429, a timeout) is listed under `unchecked` — its advisories are unknown, not
  absent — and a manifest it could not read at all is an error on every surface, never an empty
  table. A `package.json` is refused outright rather than half-read: it names version *ranges*, so
  there are no installed versions to check; point at `package-lock.json`.

**Bounding the agent stage.** Listing is cheap; resolving is not. `aiohttp` pinned at `3.9.1` alone
returns 70 OSV records, and a modest manifest reaches several hundred advisories. So the *listing*
is always complete and only the *resolve agent* is bounded:

| flag | default | what it does |
|---|---|---|
| `--min-severity` | `high` | floor for reaching the agent. Below it: listed, not resolved. |
| `--max-advisories` | `25` | cap on the agent stage (`0` = no cap). |
| `--include-dev` | off | also resolve dev/test-scoped deps. A build-time package is not in the request path. |

The cap is **shared out across packages**, not consumed in sort order — every vulnerable package
gives up its worst advisory before any package gives up its second. On the fixture manifests a flat
ordering gave `aiohttp` 23 of 25 slots because it sorts first and carries 35 advisories; sharing the
budget covers 7 packages instead of 3 for the same cost.

**The fixed version is code's, never a model's** — as in H1, and with one addition H2 needs. The
recommendation is the smallest published fix **strictly greater than the version you have, for the
package you have**. An advisory that names several packages fixes each at its own version (Log4Shell
fixes `log4j-core` at 2.15.0 and `pax-logging-log4j2` at 1.10.8), and one package's fix is not
installable for another. Where nothing published is newer, `dependencies.json` says so rather than
naming the closest number.

**Declining is still the load-bearing behaviour.** Most dependency advisories are not observable in
an HTTP request, and those route to `no_bandaid` in code with the residual risk stated and the
upgrade named. On the fixture manifests a typical run resolves 6 advisories to 2 exploitable and 4
declined. A tool that invented a plausible path for all 6 would be worse than no tool.

**No cure PR, and the counts say so.** As with `--cve`, the cure is a version bump in someone
else's package, so `remediate` is never called and `pr` declines with the upgrade recommendation.
Because no PR is drafted and none *can* be, an upgrade is never counted as one: `summary.json` and
`run.json` carry `code_fix_prs` and `dependency_upgrades` separately, and the report shows
"upgrades to ship (no PR)" beside the PR count rather than folding them together. Someone still has
to ship it — `reconcile` (§6) holds the band-aid and escalates at TTL.

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

### Pre-apply drift check (I2)

Before anything is created or attached, a **read-only** comparison runs against the live LB. It
answers three questions and short-circuits or warns accordingly:

```sh
vpcopilot drift --lb <lb>                                          # what changed since the last apply
vpcopilot drift --lb <lb> --control service_policy --policy <name> --finding <id>
```

| finding | what happens | override |
|---|---|---|
| the policy is **already the attached one** | reports `no_change` and **writes nothing** — no LB PUT, no snapshot, no run artifact | `--force` |
| a field on the LB **changed since the last snapshot** (someone edited it in the XC console) | field-level diff printed and audited as `drift_detected`; the apply continues | — |
| applying will **detach** another service policy | warned and audited as `policy_displaced`, including whether the displaced policy is what currently blocks this exploit; the apply continues | — |
| an **ALLOW inside the policy being applied** matches the exploit before its DENY | refused — under FIRST_MATCH the band-aid would attach cleanly and block nothing | `--force`, or `--refine` (default), which reorders it instead |

`drift` exits `1` when it finds a conflict, so it composes in a script. The check never PUTs, never
writes a snapshot, and never touches the run directory — it is safe to run or poll at any time.

**Why displacement is a warning and not a refusal.** Attaching replaces `active_service_policies`
wholesale, so every apply detaches whatever was there. Replacing the previous band-aid is the
normal flow; refusing would break every second apply. It is said out loud and written down instead.

In the console the same check runs inside the Mitigate job, so its warnings appear in the live log.
A refusal renders an **apply anyway** button, and `no_change` renders as its own outcome rather
than a pass or a fail.

### Pre-apply blast-radius gate (G2)

If a simulation (§ *Blast radius*) found the policy would block too much of the recorded traffic,
applying it needs an explicit override:

```sh
vpcopilot apply --from-scan out/policies/<artifact>.json --lb <lb> --url <host> --allow-overbroad
```

Without it the apply refuses and names the rate and threshold; with it the apply proceeds and writes
a `simulate_override` audit record carrying the finding, the policy, the LB, the rate, the threshold
and the actor. Silent when nothing was simulated — G2 adds a check, never a prerequisite, so an
operator who never runs `simulate` sees exactly the behaviour they saw before it existed.

**This gate used to exist on only one surface**, and that is worth stating because it changes CLI
behaviour. `simulate.promotion_block` had a single production caller — the console — so
`vpcopilot apply --from-scan` would happily attach an over-broad policy the console refused, and the
`--allow-overbroad` flag this documentation described did not exist. The check now lives in
`simulate.promotion_gate`, called by both apply paths, so the CLI, the console and the MCP server
share one copy and cannot drift. A guard in one surface is not a guard.

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
vpcopilot patches-list            # I1: every live band-aid with age, TTL remaining and cure state
vpcopilot reconcile               # I1: check every live band-aid and report; add --apply to act
```

### Patch expiry and reconcile (I1)

Every applied control gets a **TTL** the moment it is applied — seven days by default,
`$VPCOPILOT_DEFAULT_TTL_HOURS` to change it. `reconcile` walks the live band-aids and decides:

| the cure PR | the exploit, fired at **origin** | what happens |
|---|---|---|
| merged | no longer reproduces | **retire** — the fix is real, detach the band-aid |
| merged | still reproduces | **`fix_ineffective`** — hold the band-aid, report loudly |
| not merged, past TTL | not fired | **escalate** — hold the band-aid, notify |

```sh
export VPCOPILOT_RECONCILE_TARGETS="crapi-lab=http://10.0.0.5:8888 vampi-lab=http://10.0.0.5:5000"
vpcopilot reconcile --out /abs/path/out           # report only — changes nothing
vpcopilot reconcile --out /abs/path/out --apply   # detach band-aids whose cure is proven
vpcopilot reconcile --finding <id> --force-probe  # debug one finding, ignoring the cooldown
vpcopilot patches-list --expired-only
```

**Why the probe fires at the origin, not the load balancer.** With the band-aid live, firing at the
LB proves nothing — a blocked exploit means the band-aid works, which you already knew. The only
way to ask *"is the bug actually gone?"* while leaving the patch in place is to go around the
patch, so reconcile fires at an operator-declared origin URL. Reconcile never detaches a control to
test it: that would turn an unattended evidence-gathering pass into a mutating one, and six of the
seven controls are LB-wide, so detaching for one finding drops protection for every other finding
on that LB.

**Targets are an explicit allowlist, never inferred.** `VPCOPILOT_RECONCILE_TARGETS` is
`lb=origin_url` pairs. An LB not listed is skipped; a protected LB is refused even if listed; with
the variable unset `reconcile` exits non-zero rather than guessing. A **bare `lb`** with no origin
means *"watch this, but never probe it"* — the right setting for an origin that refuses direct
access (one real lab origin sits behind a BIG-IP that answers `403 Direct origin access denied`).

**It refuses to guess.** No origin, an unreachable origin, a failing legit request, a probe that
cannot authenticate, a finding with no recorded probe, an unreadable cure PR — every one of these
holds the band-aid and says why. The dangerous failure mode is the opposite: a connection error
reading as "the exploit did not succeed", reading as "fixed", detaching a control that was
protecting a still-vulnerable app.

**Report-only unless `--apply`.** Authoring the crontab is the human gate, exercised once. Exits
`2` when anything escalated or a fix proved ineffective, so cron or CI goes red:

```
0 3 * * *  cd /srv/vpcopilot && VPCOPILOT_RECONCILE_TARGETS="crapi-lab=http://10.0.0.5:8888" \
           VPCOPILOT_RECONCILE_TRIGGER=cron \
           .venv/bin/vpcopilot reconcile --out /srv/vpcopilot/out --apply
```

`VPCOPILOT_RECONCILE_TRIGGER=cron` is what makes a scheduled pass distinguishable in the audit
trail — cron invokes the CLI, so without it every nightly record is stamped `cli`.

Use an **absolute** `--out`: cron has no working directory, and reconcile refuses to run rather
than minting an empty run dir and reporting zero patches forever. A second pass exits cleanly while
the first holds the lock — cron jobs that wait pile up.

**The destructive-replay cooldown.** These exploits genuinely move money and escalate roles, and
they feed the same Malicious-User telemetry the tenant reports on, so a finding's probe fires at
most once per `$VPCOPILOT_RECONCILE_MIN_INTERVAL_HOURS` (default 24). Only the probe is throttled —
the TTL and PR checks are free reads and run every pass, so an escalation is never delayed.

**Escalation delivery.** An audit record always, plus a POST to `$VPCOPILOT_ESCALATION_WEBHOOK`
when one is set (silent when not; a dead webhook never changes an outcome). Escalation fires once
and then only when something changes or after `$VPCOPILOT_RECONCILE_RENOTIFY_HOURS` (default 168) —
otherwise a nightly cron appends another escalation forever.

In the console this is the ⑥ Retire step: a patch-expiry table with age and TTL per band-aid, and
**Reconcile (report only)** / **Reconcile & retire proven fixes** buttons streaming the same live
log as an apply.
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

### Shipping the trail off the box (J3)

The log is written by the machine that made the change, which is the one machine someone who made
an unauthorised change would want to edit. Point `VPCOPILOT_AUDIT_SINK` at a collector and each
entry is copied there as it is written:

```sh
VPCOPILOT_AUDIT_SINK=https://collector.example.com/ingest   # POST the entry as the body
VPCOPILOT_AUDIT_SINK=syslog://10.0.0.9:514                  # …or syslog:///var/run/syslog
VPCOPILOT_AUDIT_SINK=stdout                                 # …or a JSON line for a log-scraping runtime
VPCOPILOT_AUDIT_SINK=off                                    # deliberately disabled
vpcopilot audit-sink --send                                 # prove it lands (exits non-zero if it does not)
```

Both keys are on the console's ⚙ **Setup** page, which has the same readout and a **Send test
event** button. `off` is a value rather than a blank field because the `.env` writer drops empty
updates — a sink switched on from that page has to be switchable off from it.

**The local `audit.log` stays authoritative.** The line is written to disk first and the sink gets
the same string, so the two cannot disagree; if the local write fails, nothing is delivered.
Delivery is fail-soft and can never change the outcome of the action being recorded — a dead
collector costs one warning on stderr and one timeout, then goes quiet for a minute rather than
stalling every subsequent entry. A sink that is *misconfigured* reports as unusable with the
reason, because "we are shipping nothing" must never read the same as "nothing is configured".

What a sink does **not** do is make the log tamper-evident. A delivered copy raises the cost of
editing the local file afterwards; a missing one proves nothing, because the transport is allowed
to fail. See **[AUDIT.md §10](AUDIT.md)** for what the collector receives, the measured syslog size
limit, and what the sink attests.

**Signing a bundle (optional).** Point `VPCOPILOT_MINISIGN_KEY` at an *unencrypted* minisign secret
key and every export gains `manifest.json.minisig` beside the manifest:

```sh
minisign -G -W -s ~/.minisign/vpcopilot.key   # -W = no passphrase; this tool never holds one
export VPCOPILOT_MINISIGN_KEY=~/.minisign/vpcopilot.key
vpcopilot export --out out
```

A reviewer verifies with your **public** key:

```sh
unzip -o audit-bundle.zip manifest.json manifest.json.minisig
minisign -V -p vpcopilot.pub -m manifest.json
```

What that signature **does** attest: this manifest was signed by the holder of that key, and — since
the manifest SHA-256s every member — that no file in the bundle changed after it was signed.

What it **does not** attest: that the audit log inside is truthful. The log is written by the same
process that made the changes, to a local file; a signature proves who exported it, not that what it
says happened. And get the public key **out of band** — a key shipped inside a bundle proves nothing
about that bundle.

Signing is optional at every level. No key, no `minisign` on PATH, or a signer that fails all mean
an unsigned bundle and a successful export — never a failed one.

**Verifying a bundle.** `--verify` re-reads a bundle and checks it against its own manifest:

```sh
vpcopilot export --verify audit-bundle.zip                       # digests only
vpcopilot export --verify audit-bundle.zip --pubkey vpcopilot.pub  # digests + signature
```

It exits non-zero on any problem, so it drops into CI. Four member verdicts, because a file *added*
to a bundle is as suspicious as one altered: `ok`, `mismatch`, `missing` (listed but absent), and
`unlisted` (present but in no manifest).

The signature is reported as one of `absent`, `verified`, `failed`, or **`present-unverified`** —
a signature exists but no public key was supplied, so it could not be checked. That is deliberately
**not** a failure: a reviewer without the key must still be able to check the digests, and reporting
"I cannot check this" the same way as "this is forged" would destroy the distinction that matters
most.

Note the two layers are independent. Tampering with a *member* while leaving the manifest alone
leaves the signature **verified** and fails the digest — it is the chain, not either half, that
catches it.

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
| **① Scan** | point at a repo — or a CVE, an OpenAPI spec, or dependency manifests — and run the pipeline. Read-only, no XC/GitHub writes. **Preview (no model calls)** shows the H2 dependency funnel before you spend anything. Auto-advances to Review when it finishes |
| **② Review** | verified findings + the recommended band-aid; click a row for exploit / code / generated policy. **Open HTML report ↗** + **Download** |
| **③ Simulate** | replay a recorded sample against each candidate through a **spare** LB and report what it would block; over-threshold policies warn at the gate |
| **④ Mitigate** | apply each band-aid (or **Mitigate ALL**, one at a time, continuing past failures) and watch `before → after` stream, with a *self-healed in N attempts* badge |
| **⑤ Cure** | open the code-fix PR per finding, or all of them |
| **⑥ Retire** | the four-state ledger track, plus the **Audit trail** table and **Export evidence bundle (.zip)** / **All runs** |
| **⑦ Benchmark** | build a model-tagged report from this run, then compare models side by side per target app |
| **⚙ Setup** | credentials (writes `.env`), XC status, the per-agent model wiring, and the report buttons |

## 8. MCP server mode (K1)

The same pipeline as MCP tools over stdio, so an agent session gets a band-aid proposal inline
instead of shelling out. No extra install — the transport is stdlib.

```sh
vpcopilot mcp                    # read-only (default)
vpcopilot mcp --write            # also expose apply, pr, retire, reconcile, simulate
```

Register it with any MCP client. For Claude Code:

```sh
claude mcp add vpcopilot -- /path/to/.venv/bin/python -m vpcopilot.cli mcp
```

**Read-only by default, and the write tools are *absent* rather than present-and-refusing.** A tool
an agent can see is a tool it will try, so enabling them is an explicit act: `--write`, or
`VPCOPILOT_MCP_WRITE=1`. Authoring the client config that does it is the human action, exercised
once — the same argument `reconcile --apply` makes about the crontab.

| Tool | What it does | Costs |
|---|---|---|
| `scan_result` | the band-aid proposal from a finished run: findings, triage, generated policies, cures, dependency funnel | nothing |
| `patches_list` | live band-aids with age, TTL remaining, cure state, escalations | nothing |
| `ledger` · `impact` | the four-state lifecycle; the headline numbers | nothing |
| `deps` | what a `--manifest` scan would find, without a model call | reaches OSV.dev |
| `simulation_result` | a previous blast-radius replay's numbers | nothing |
| `drift` | live LB vs last snapshot vs proposed, read-only | XC credentials |
| `verify_bundle` | re-check an evidence bundle against its own manifest | nothing |
| `scan_start` · `scan_status` | start a scan, then poll it | **model calls**, minutes |
| `apply` · `pr` · `retire` · `reconcile` · `simulate` | *only with writes enabled* | mutates |

**Three things are deliberate.**

*`apply`, `pr` and `retire` default to `dry_run=true`* — the opposite of every module function, whose
default is a real run. The CLI and console each pass a choice a human made at a keyboard; an MCP call
is issued by a model, so the default has to be the one that changes nothing, and applying for real
has to be a second explicit call. `reconcile` is report-only unless `apply=true`, as on the CLI.

*`simulate` is a write tool, though the roadmap listed it as read-only.* A simulation creates a
throwaway policy object, attaches it to the load balancer, replays through it and deletes it again.
Cleaning up after itself makes it safe, not read-only. `simulation_result` is the ungated way to read
the numbers.

*`apply` takes a policy **name**, not a path*, and derives the artifact from the run directory — an
interface that accepts a caller-supplied filesystem path is an arbitrary-file reader, and a tool a
model invokes is a worse place for one than an endpoint a human drives (the J2 precedent). The name
must be a generated slug; anything carrying a path separator is refused.

**What the opt-in does not do is supply the human.** MCP clients are expected to confirm tool calls
with a user, but that is the client's behaviour, not something this server can enforce or verify —
which is exactly why the write tools are off by default. What the server *can* guarantee is that a
write tool calls the same module function the CLI and console call, so it inherits `guard_lb` for a
protected load balancer, `PROTECTED_POLICIES` for a protected name, `drift.preflight` for drift and a
self-shadowing DENY, the G2 blast-radius gate, rollback-unless-`keep`, and an audit record whose
identity is stamped centrally. Reconcile passes `trigger="mcp"`, so the trail says an agent session
did it.

`force_probe` is deliberately not exposed at all: its guard requires a single `--finding` because
replaying every destructive exploit at once is not something to do by accident, and a model deciding
to pass it is exactly that accident.

**stdout carries the protocol and nothing else.** The server points `sys.stdout` at stderr for its
lifetime and writes frames to a private handle, so a stray `print` anywhere beneath it — the pipeline
defaults `log=print`, and `rprint` is used throughout the CLI — lands on stderr, which the MCP spec
reserves for logging, instead of corrupting the message stream.

## 9. Pull-request review in CI (K2)

Scan the diff on a pull request and comment the proposed band-aid on it, so a developer sees the
virtual patch in the review where they introduced the hole.

```sh
vpcopilot ci-review --repo src/api --base origin/main            # prints the comment
vpcopilot ci-review --repo src/api --base origin/main --post --pr-repo owner/name --pr 42
```

Ships as a composite action (`.github/actions/vpcopilot-scan/`) with an example workflow. Scans only
what the branch changed, against the merge base; posts nothing when there is nothing above the
threshold; and **never touches an XC tenant** — `ci.py` imports no tenant client at all, so a CI job
needs a GitHub token and nothing else. The blast-radius number cannot be produced in CI (measuring it
means attaching a policy to a load balancer), so the comment reports it only from a real tenant run's
`simulation.json` and otherwise says plainly that no measurement was made.

Full reference: **[CI.md](CI.md)**.

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
- **Pre-apply drift check:** before any create or attach, the live LB is compared against the last
  snapshot and against what is about to be pushed — see [Pre-apply drift check](#pre-apply-drift-check-i2).
  Re-applying an unchanged policy writes nothing; a policy that could never fire is refused.
- **Reversible:** every apply snapshots the LB and rolls back on validation failure (or by
  default). Every change is written to the append-only audit log — the finding that justified it,
  the control and the XC object, the load balancer and its namespace, whether it was kept or rolled
  back, and who ran it (`VPCOPILOT_ACTOR`, else the OS user) on which host, under which run id.
  Dry runs are not recorded: nothing changed, so there is nothing to answer for.
- **Band-aids are temporary — and now provably so:** every finding also gets a code-fix PR; the
  ledger tracks each finding to `retired` (band-aid removed once the cure merges). Every applied
  control also carries a TTL, and `reconcile` escalates one that outlives it. See
  [Patch expiry and reconcile](#patch-expiry-and-reconcile-i1).
- **Reconcile never removes protection it cannot justify:** it detaches only with `--apply`, and
  only after firing the finding's real exploit at the app's origin — around the band-aid — and
  watching it fail. Every branch that cannot establish that fact holds the control instead.

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
