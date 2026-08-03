# CI — scan a pull request's diff and comment the band-aid (K2)

The shift left: a developer sees the F5 Distributed Cloud virtual patch that would hold their new
hole closed **in the review where they introduced it**, before it is anyone's incident.

```
.github/actions/vpcopilot-scan/action.yml   the action
.github/workflows/pr-review.yml             an example workflow that uses it
vpcopilot ci-review                          the CLI the action shells out to
```

---

## 1. What it does

On a pull request it takes the diff **against the merge base**, scans only the changed code files,
and leaves one comment carrying, per finding above a severity threshold:

- the finding, its severity, its file and line;
- the F5 XC control triage routed it to — or `no_bandaid` with the residual risk, when a load
  balancer cannot see the problem at all;
- the generated policy name;
- the blast radius, **if and only if** a real measurement exists (see §4).

A pull request with no findings above the threshold gets **no comment at all**. A bot that says "all
clear" on every PR trains people to stop reading it.

Re-running updates the same comment rather than adding another — it is anchored on a hidden marker,
so a branch pushed ten times has one comment that keeps up instead of ten that argue.

## 2. Use it

Already wired for this repo in `.github/workflows/pr-review.yml`. For your own source tree, change
one line:

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # git merge-base needs history on both sides
      - uses: ./.github/actions/vpcopilot-scan
        with:
          repo-path: src/api      # <- your source directory
          min-severity: high
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

| input | default | what it does |
|---|---|---|
| `repo-path` | `.` | directory within the checkout to scan |
| `base` | the PR's base branch | branch to diff against, via the **merge base** |
| `min-severity` | `high` | report at or above this: `critical`/`high`/`medium`/`low` |
| `min-confidence` | `0.5` | drop verified findings below this confidence |
| `max-files` | `40` | cap on changed files scanned — a PR diff is small and each file costs model calls, so this is far below a full scan's 200 |
| `comment` | `true` | post/update the comment |
| `fail-on-findings` | `false` | whether a finding turns the check red |
| `simulation-json` | — | a `simulation.json` from a real tenant run, to get blast-radius numbers (§4) |
| `anthropic-api-key` | *required* | model credential |
| `github-token` | `github.token` | needs `pull-requests: write` |

Locally, the same thing without GitHub:

```sh
vpcopilot ci-review --repo src/api --base origin/main            # prints the comment
vpcopilot ci-review --repo src/api --base origin/main --post --pr-repo owner/name --pr 42
```

Exit codes: `0` nothing reported · `1` at least one finding reported (information, not failure —
`fail-on-findings` decides whether the check goes red) · `2` a real error.

## 3. It never writes to XC, structurally

The acceptance criterion is *never writes to XC from CI*, and it is enforced by construction rather
than by care: `ci.py` imports no tenant client, no apply path, no refiner and no simulate, so **there
is no code path from CI to a load balancer**. A test reads the module's own source and fails if any
of them appears — the only version of this guarantee that survives someone adding a convenient import
later. The action declares no XC inputs, so there is nothing to pass one through.

An XC credential sitting in a CI environment is a credential every workflow on the repo can reach.
If `ci-review` finds one in its environment it says so and carries on, because it has no use for it.

The band-aid in the comment is a **proposal**. Nothing is created, attached, or enabled.

## 4. Blast radius: the acceptance criterion contradicted itself

K2's acceptance asked for "one comment carrying the policy **and the simulation result**" while also
requiring "never writes to XC from CI". Those cannot both hold. G2's blast-radius measurement works by
creating a throwaway policy object, **attaching it to a load balancer**, replaying recorded traffic
through it, and deleting it — three writes to a live tenant. There is no offline evaluator to fall
back on: G1 was deferred, deliberately, in 2026-07.

So a would-block count is **not computed in CI**, and the comment says exactly that:

> **Blast radius: not measured.** A would-block count requires attaching this policy to a load
> balancer and replaying recorded traffic through it — three writes to the tenant, which this job
> deliberately cannot make. Run `vpcopilot simulate` against a spare LB before promoting it.

Neither silence nor `0%` would do: both read as *measured and safe*.

To get real numbers into the comment, measure them where measuring is legitimate — against a spare
LB — and hand the artifact to the action:

```sh
vpcopilot simulate --logs traffic.jsonl --lb vpcopilot-lab --out out    # on a workstation, once
```

```yaml
        with:
          simulation-json: evidence/simulation.json
```

Each policy then reports `would block N of M recorded requests (R%)` and whether it tripped the
threshold. A number carried forward from an earlier replay is labelled as such (`carried_from`), so a
stale measurement is never presented as this policy's fresh result.

## 5. Fork pull requests get no review

The workflow uses `pull_request`, not `pull_request_target`. That is the safe choice: it runs against
the merge commit with a read-only token and cannot be induced by a fork to leak secrets. The
consequence is that a fork PR has no model credential and therefore no review, and the job skips
rather than failing a check nobody can fix from a fork.

`pull_request_target` would fix that by running trusted workflow code with secrets against untrusted
head code — which is the standard way repositories leak their secrets. Not worth a review comment.

## 6. What it does not cover, and says so

Every boundary is disclosed in the comment rather than left for the reader to assume:

- **Changed files outside the scanned directory** — counted and named as not looked at. This one is
  load-bearing: `git diff` answers relative to the repository root while the scanner matches relative
  to `repo-path`, and getting that wrong produces a *clean-looking review that scanned nothing*.
- **Files the collector declined** — over `--max-bytes`, beyond `--max-files`, in a vendored
  directory, or an unsupported file type — reported as not covered, including on an otherwise-clean
  comment, because an all-clear that hides an unscanned remainder is the one output this feature must
  never produce. Truncation of an oversized comment cuts the *finding list*, never these lines.
- **The whole diff size** — the header's denominator is every changed file, not just the ones the
  scanner supports, so "scanned 1 of 1" cannot stand in for a fourteen-file change.
- **Findings below the threshold** — counted when nothing is reported, so "we did not report this"
  never reads as "there was nothing".
- **A diff with nothing scannable in it** — gets a comment saying *nothing was reviewed*, and saying
  that it is not a clean bill of health. Nothing is posted to the PR (there is nothing to report), but
  the step summary a human reads must distinguish "we looked and it is fine" from "we did not look".
- **A review that crashed** — the step summary says so explicitly. `if: always()` means it runs after
  a failure too, and it used to write "no findings at or above the threshold" for a diff that was
  never analysed.
- **Deleted files** — excluded; there is nothing left to scan.
- **The cure** — `ci-review` does not draft code fixes. The developer is editing the file by hand
  right now; the band-aid and the finding are what CI can add.

**Only findings that survived verification are reported.** `findings.json` is the *discover* contract —
every candidate, including the ones `verify` refuted as false positives — so the comment is built from
the findings that have a triage decision. Putting refuted false positives in front of a developer with
a band-aid attached is the fastest way to teach a team to ignore the bot.

**A blast-radius number is only shown when it means something.** Beyond the not-measured case above,
two states from G2 are carried through rather than flattened into a rate: a simulation that could not
confirm the edge was *enforcing* the policy before counting (G2's first live defect — an unenforced
policy blocked 0 of 200 and looked harmless), and one that evaluated *zero* requests because they all
failed in transit. Both say so. Neither is a low block rate.

## 6b. The `live` suite — proofs anyone can re-run

Every roadmap item was proven by hand against the real thing, and until 2026-08-02 **not one of
those proofs was repeatable by anyone but the person who ran it**. `pytest -m live` collected zero
tests out of 959. The `live` suite exists to close that.

```sh
pytest -m "not live and not bench"        # what CI runs — unchanged, never touches the network
VPCOPILOT_LIVE_NET=1 pytest -m live       # the OSV suite: no credential, no tenant, no model
BIGIP_URL=… BIGIP_PASSWORD=… VPCOPILOT_LIVE_ORIGIN=… pytest -m live -k emitter
```

**Absent credentials are a skip, never a failure and never a false pass.** `tests/live.requires()`
raises `Skipped` rather than returning a flag, so a test body cannot fall through it and report a
pass having done nothing — and an empty or whitespace value counts as absent, which is the trap K2
hit when GitHub's `required: true` did not reject an empty secret.

**A live test that ran and observed nothing fails.** The `evidence` fixture makes each test declare
what it actually established, because a live test passes very easily by doing nothing: the API
returns an empty list, the loop body never runs, and the test is green. That is J3's fabricated
records and K2's zero-file diff in test form.

**A live test restores what it mutates**, and `restoring()` fails loudly if the cleanup does not
stick — a test that leaves a WAF policy attached has changed the estate for the next demo. The
emitter suite goes further and *proves* the restore by re-firing the exploit afterwards: if it no
longer works, the policy was not removed.

What runs today: the OSV client against `api.osv.dev` (H2's alias hop, CVSS v4 bucketing, GHSA/PYSEC
duplication, and the junk-version refusal), and L1's end-to-end proof against the lab BIG-IP — emit,
attach, fire, **assert the balance did not move**, restore. Still to write: the safety spine on
`vpcopilot-lab`, `drift.check` read-only, and the MCP handshake.

**The nightly job deliberately still runs `-m bench` only.** Widening it to `-m "live or bench"`
before those tests exist would reinstate exactly the problem the suite was written to fix — a job
whose name promises coverage it does not have. Restore the four secrets and widen the selector when
they land, not before.

## 7. Cost and time

Measured on this repo's Nimbus fixture, one changed file introducing three real flaws (a negative
amount, a SQL injection, and a missing ownership check): **77 seconds wall clock**, 69 s of it
pipeline, against the acceptance budget of three minutes. It produced four policies across
`service_policy`, `waf`, `malicious_user` and `rate_limit`.

Cost scales with **changed** files, not repository size, which is the point of diffing. `max-files`
is the ceiling; raise it deliberately.
