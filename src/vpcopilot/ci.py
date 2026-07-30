"""K2 — scan a pull request's diff and comment the proposed band-aid on it.

The point is the shift left: a developer sees the F5 XC virtual patch that would hold their new hole
closed, in the review where they introduced it, before it is anyone's incident.

**This module never touches the tenant, and that is structural rather than promised.** It imports no
`xc`, no `apply`, no `refiner` and no `simulate`, so there is no code path from CI to a load
balancer — pinned by a test that reads this module's own source. CI gets a `GITHUB_TOKEN` to comment
and nothing else; an XC credential in a CI environment is a credential that can be exfiltrated by
any workflow, and the band-aid is a proposal at this stage, not a deployment.

**The acceptance criterion contradicted itself, and this is the honest resolution.** It asked for
"one comment carrying the policy **and the simulation result**" while also requiring "never writes to
XC from CI" — but G2's blast-radius measurement works by creating a throwaway policy, ATTACHING it to
a load balancer, replaying traffic through it and deleting it. That is three XC writes. A would-block
count cannot be produced in CI at all. So the comment reports the blast radius **only when a
`simulation.json` from a real tenant run is available** (committed, or restored as a CI artifact), and
otherwise says in as many words that no measurement was made and why. Reporting a number nobody
measured would be worse than reporting none; rendering its absence as if the policy were known-safe
would be worse still.
"""
from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path

from .repo_scan import CODE_EXT

# The anchor that makes a re-run update its comment instead of adding another. A pushed branch gets
# many runs, and a bot that appends every time is a bot people mute.
MARKER = "<!-- vpcopilot:pr-review -->"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def rebase_onto(changed: set[str], scan_root: str, git_root: str) -> tuple[set[str], int]:
    """Translate git-root-relative diff paths into paths relative to the directory being scanned.

    This is the difference between a working review and a silent all-clear. `git diff --name-only`
    answers relative to the repository root, `collect_files` matches relative to the directory it is
    given, and this project's own app fixture lives eight levels down
    (`bench/fixtures/nimbus-vuln-lab/app/src/app/api`). Compared directly, the two never match: zero
    files are scanned, no findings are produced, and the pull request is told it is clean. Any
    reviewer of this feature would have to notice the absence of an error to catch it.

    Returns the rebased set plus a count of changed files that fall OUTSIDE the scanned directory, so
    the comment can say that part of the diff was not looked at rather than implying it was.
    """
    root, scan = Path(git_root).resolve(), Path(scan_root).resolve()
    inside: set[str] = set()
    outside = 0
    for rel in changed:
        p = (root / rel).resolve()
        try:
            inside.add(str(p.relative_to(scan)))
        except ValueError:
            outside += 1
    return inside, outside


def changed_files(repo: str = ".", base: str = "origin/main", head: str = "HEAD",
                  *, log: Callable = print) -> tuple[set[str], str, int]:
    """The changed scannable paths, the merge base compared against, and the RAW diff size.

    `git diff --name-only <base>...<head>` — three dots, so the comparison is against the MERGE BASE
    rather than the tip of `base`. With two dots, every commit landing on main between the branch
    point and now reads as a change in this PR, so a busy main makes every PR look like it touched
    half the tree and the scan stops being about the diff at all.

    Deleted files are excluded (`--diff-filter=d`): there is nothing left to scan, and passing a
    path that no longer exists to the collector would report it as skipped rather than as gone.

    **`-z`, because git quotes paths by default.** With plain `--name-only`, a non-ASCII filename
    comes back as `"caf\\303\\251.py"` — C-style octal escapes, surrounded by literal quotes. Its
    suffix then reads as `.py"`, which is not a known code extension, so the file was dropped from
    the scan set *and* not counted as outside it: it vanished, and the pull request was told it was
    clean. NUL-separated output is not quoted at all, which also settles spaces and newlines.
    """
    def git(*args) -> str:
        return subprocess.check_output(["git", "-C", repo, *args], text=True)

    try:
        merge_base = git("merge-base", base, head).strip()
    except subprocess.CalledProcessError as e:
        raise CIError(f"cannot find a merge base between {base!r} and {head!r}: {e}. In CI, fetch "
                      "enough history — actions/checkout defaults to a single commit "
                      "(fetch-depth: 0).") from e
    try:
        out = git("diff", "--name-only", "-z", "--diff-filter=d", f"{merge_base}..{head}")
    except subprocess.CalledProcessError as e:
        raise CIError(f"git diff failed: {e}") from e
    names = {n for n in out.split("\0") if n.strip()}
    code = {n for n in names if Path(n).suffix in CODE_EXT}
    log(f"diff {base}...{head} (merge-base {merge_base[:9]}): {len(names)} file(s) changed, "
        f"{len(code)} scannable")
    # The RAW total travels with the filtered set. Without it the comment's "scanned N of M" used the
    # post-filter count as its denominator, so a diff of eleven files with one scannable read as
    # "1 of 1" — a complete-looking review of a diff it mostly did not support.
    return code, merge_base, len(names)


class CIError(RuntimeError):
    """A precondition CI could not establish. Raised rather than degraded, because a review that
    silently scanned nothing is indistinguishable from a review that found nothing."""


def _blast_radius(out_dir: str) -> tuple[dict[str, dict], dict]:
    """Per-policy would-block numbers from a PREVIOUS tenant run, plus the run-level metadata that
    says whether those numbers can be believed.

    Never measured here — see the module docstring. Keyed by policy name.

    The metadata is returned rather than dropped because of one case in particular:
    `bodies_available` is false when the traffic sample came from XC access logs, which capture no
    request body. A `body_matcher` service policy then matches nothing during replay and scores a
    perfectly clean **0%** — a rate `simulate` itself declared unjudgeable, rendered by us as
    "under the threshold". Keeping only the inner dicts threw away the one field that says so."""
    p = Path(out_dir) / "simulation.json"
    if not p.is_file():
        return {}, {}
    try:
        doc = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}, {}
    per_policy = {pol["policy_name"]: pol
                  for pol in doc.get("policies") or [] if pol.get("policy_name")}
    meta = {"bodies_available": doc.get("bodies_available", True),
            "caveats": doc.get("caveats") or [], "records": doc.get("records"),
            "source": doc.get("source", ""), "ts": doc.get("ts", "")}
    return per_policy, meta


def render_comment(findings: list[dict], triage: dict, policies: list[dict], *,
                   min_severity: str, changed: int, sim: dict | None = None,
                   scanned: int = 0, base: str = "", truncated: int = 0,
                   outside: int = 0, diff_total: int | None = None,
                   sim_meta: dict | None = None) -> str:
    """The comment body. Deterministic — code, not a model.

    An agent drafting this would be an agent free to round a would-block rate or soften a severity,
    and these are the numbers a developer decides with."""
    sim = sim or {}
    sim_meta = sim_meta or {}
    floor = SEVERITY_RANK.get(min_severity, 1)
    shown = [f for f in findings if SEVERITY_RANK.get(f.get("severity", "low"), 3) <= floor]
    shown.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "low"), 3))
    pol_by_finding: dict[str, list[dict]] = {}
    for p in policies:
        pol_by_finding.setdefault(p.get("finding_id", ""), []).append(p)

    # The denominator is the RAW diff size when we know it, not the post-filter count: "1 of 1" for a
    # diff of eleven files reads as a complete review of the whole change.
    scope = (f"Scanned **{scanned}** of {changed} scannable file(s)"
             + (f" ({diff_total} changed in total)" if diff_total and diff_total != changed else "")
             if changed else f"Scanned **{scanned}** changed file(s)")
    L = [MARKER, "## 🩹 Virtual Patch Copilot",
         "", scope + (f" in this diff against `{base[:9]}`" if base else " in this diff") + ".", ""]
    if not shown:
        held = len(findings) - len(shown)
        L += [f"**No findings at or above `{min_severity}`.**"]
        if held:
            L += ["", f"_{held} lower-severity finding(s) were found and not reported here — "
                       f"raise the threshold below `{min_severity}` to see them._"]
        # An all-clear that hides an unscanned remainder is the one output this feature must never
        # produce: it is the difference between "we looked and it is fine" and "we did not look".
        if truncated:
            L += ["", f"_{truncated} changed file(s) were **not scanned** — over `--max-bytes`, beyond "
                       "`--max-files`, in a vendored directory, or an unsupported file type — so "
                       "this is not a clean bill of health for them._"]
        if outside:
            L += ["", f"_{outside} changed file(s) sit outside the scanned directory and were not "
                       "looked at._"]
        return "\n".join(L)

    L += [f"**{len(shown)} finding(s) at or above `{min_severity}`.** Each row is the band-aid that "
          "would hold the hole closed at the edge while the code fix ships — a proposal, not a "
          "deployment: this job has no tenant credentials and changes nothing.", ""]

    for f in shown:
        fid = f.get("id", "")
        sev = f.get("severity", "?")
        loc = f.get("file") or f.get("source") or ""
        line = f.get("line")
        where = f"`{loc}`" + (f":{line}" if line else "")
        L += [f"### `{sev}` — {f.get('title', fid)}", "", f"{where} · `{fid}`", ""]
        if f.get("description"):
            L += [str(f["description"]).strip(), ""]
        d = triage.get(fid) or {}
        bandaids = d.get("bandaids") or []
        if d.get("no_bandaid"):
            L += ["**No band-aid.** " + (d.get("residual_risk") or
                  "Nothing observable in a request to block — this one needs the code fix."), ""]
        elif bandaids:
            names = ", ".join(f"`{b['control']}`" + ("" if b.get("recommended") else " (alt)")
                              for b in bandaids)
            L += [f"**Proposed control(s):** {names}", ""]
        for pol in pol_by_finding.get(fid, []):
            name = pol.get("policy_name", "")
            L += [f"**Generated policy:** `{pol.get('control')}` / `{name}`"]
            s = sim.get(name)
            if s is None:
                # Not "0%" and not silence. Both would read as "measured and safe".
                L += ["", "> **Blast radius: not measured.** A would-block count requires attaching "
                          "this policy to a load balancer and replaying recorded traffic through it "
                          "— three writes to the tenant, which this job deliberately cannot make. "
                          "Run `vpcopilot simulate` against a spare LB before promoting it."]
            elif not s.get("enforcement_confirmed", True):
                # G2's FIRST live defect: attaching a policy and replaying immediately counted an
                # UNENFORCED policy as harmless — 0 of 200 blocked, including the exploit. A rate
                # measured before the edge was confirmed enforcing measures nothing, so it must not
                # be shown as a rate at all.
                L += ["", "> **Blast radius: unconfirmed.** The simulation could not confirm the "
                          "edge was enforcing this policy before counting, so its numbers measure "
                          "an unenforced policy and not this one. Re-run `vpcopilot simulate`."]
            elif not s.get("evaluated"):
                # G2 treats zero evaluated as NO EVIDENCE, explicitly not as safe — every replayed
                # request failed in transit, so there is no rate to report. Rendering
                # "would block 0 of 0 (0.0%) — under the threshold" would turn a measurement that
                # failed into the most reassuring line in the comment.
                L += ["", "> **Blast radius: no evidence.** A simulation ran but evaluated **zero** "
                          "requests"
                          + (f" — {s['reason']}" if s.get("reason") else "")
                          + ". That is not a low block rate; nothing was measured."]
            else:
                rate = s.get("block_rate")
                verdict = ("⚠️ **over the blast-radius threshold**" if s.get("blocked_promotion")
                           else "under the threshold")
                L += ["", f"> **Blast radius** (from a previous tenant run): would block "
                          f"**{s.get('would_block')}** of {s.get('evaluated')} recorded requests"
                          + (f" (**{rate:.1%}**)" if isinstance(rate, (int, float)) else "")
                          + f" — {verdict}."]
                if not sim_meta.get("bodies_available", True):
                    # G2 sets this false for XC access-log samples, which carry no request body. A
                    # `body_matcher` policy matches nothing against them and scores a clean 0% —
                    # a rate the simulation itself declared unjudgeable.
                    L += ["> _The replayed sample carried **no request bodies** (XC access logs), so "
                          "a policy that matches on the body could not be judged from it. Treat a "
                          "low rate here as unmeasured, not safe._"]
                if s.get("carried_from"):
                    L += [f"> _Carried forward from an earlier replay ({s['carried_from']}); this "
                          "number was not measured by the most recent simulation._"]
            L += [""]
        L += ["---", ""]

    # The disclosures and the footer are assembled SEPARATELY from the finding list, because
    # truncation drops the tail — and the tail is exactly where "we did not look at these files"
    # lives. Cutting the finding list while keeping these is the whole point.
    tail: list[str] = []
    if truncated:
        tail += [f"_{truncated} changed file(s) were not scanned — over `--max-bytes`, beyond "
                 "`--max-files`, in a vendored directory, or an unsupported file type. They are "
                 "not covered by this review._", ""]
    if outside:
        tail += [f"_{outside} changed file(s) sit outside the scanned directory and were not looked "
                 "at._", ""]
    tail += ["<sub>Band-aid buys time; the cure is the code fix. "
             "`vpcopilot scan` locally for the full run.</sub>"]
    return _fit("\n".join(L), "\n".join(tail), len(shown))


# GitHub rejects an issue-comment body over 65536 characters. A PR touching forty files could reach
# it, and the failure mode is the whole comment being lost to an API error — the review silently not
# happening. Truncated with the count of what was dropped, so the comment is never a partial list
# passing itself off as the whole one.
MAX_BODY = 65_536


def _fit(body: str, tail: str, n_findings: int) -> str:
    """Keep the body under GitHub's cap while PRESERVING the disclosures.

    The naive version truncated the whole comment from the end — which is where the "N changed files
    were not scanned" and "N sit outside the scanned directory" lines are, so exactly the sentences
    that stop a partial review reading as a complete one were the first thing dropped. The finding
    list is cut instead, and the disclosures plus a count of what is hidden are always kept."""
    full = body + "\n" + tail
    if len(full) <= MAX_BODY:
        return full
    notice_room = 400 + len(tail)
    head = body[:MAX_BODY - notice_room]
    # cut at a finding boundary so the last entry is not left half-rendered
    if "\n---\n" in head:
        head = head[:head.rfind("\n---\n") + 1]
    hidden = n_findings - head.count("\n### ")
    return (head
            + f"\n---\n\n> **This comment was truncated.** {hidden} of {n_findings} finding(s) are "
              "not shown — GitHub caps a comment at 65,536 characters. Run `vpcopilot ci-review` "
              "locally, or raise `min-severity`, to see the rest.\n\n"
            + tail)


def upsert_comment(repo_slug: str, pr_number: int, body: str, *, token: str | None = None,
                   dry_run: bool = False, log: Callable = print) -> dict:
    """Post the comment, or update the one this tool left last time.

    Keyed on `MARKER`, so a branch pushed ten times has one comment that keeps up rather than ten
    that argue with each other."""
    from .pr import _resolve_token
    if dry_run:
        log(f"[dry-run] would upsert a {len(body)} char comment on {repo_slug}#{pr_number}")
        return {"posted": False, "dry_run": True, "chars": len(body)}
    try:
        from github import Github
    except ImportError as e:
        raise CIError("PyGithub is not installed — `pip install -e '.[deploy]'`") from e
    gh = Github(_resolve_token(token))
    pr = gh.get_repo(repo_slug).get_pull(int(pr_number))
    for c in pr.get_issue_comments():
        # STARTSWITH, not `in`. Our comments always begin with the marker; a human quoting the bot in
        # a reply produces `> <!-- vpcopilot:pr-review -->`, which `in` would match — and we would
        # then overwrite that person's comment with our review.
        if (c.body or "").startswith(MARKER):
            c.edit(body)
            log(f"updated comment {c.id} on {repo_slug}#{pr_number}")
            return {"posted": True, "updated": True, "comment_id": c.id}
    c = pr.create_issue_comment(body)
    log(f"created comment {c.id} on {repo_slug}#{pr_number}")
    return {"posted": True, "updated": False, "comment_id": c.id}


def review(repo: str = ".", *, base: str = "origin/main", head: str = "HEAD",
           out_dir: str = "out-ci", min_severity: str = "high", min_confidence: float = 0.5,
           max_files: int = 40, max_bytes: int = 60_000, config_path: str | None = None,
           repo_slug: str | None = None, pr_number: int | None = None,
           post: bool = False, dry_run: bool = False, token: str | None = None,
           log: Callable = print) -> dict:
    """Scan the diff, build the comment, and post it when asked to.

    `draft_code_fixes` is off: a PR review wants the band-aid and the finding, and drafting the cure
    is the expensive half of a scan for something the developer is already editing by hand.
    """
    if os.environ.get("XC_API_TOKEN") or os.environ.get("XC_API_URL"):
        # Not a machine veto — a refusal to be handed something it should never have. CI needs a
        # GitHub token and nothing else; an XC credential present in a CI environment is one any
        # workflow on the repo can reach, and this path has no use for it.
        log("  ⚠ XC credentials are present in this environment — this review never uses them and "
            "no CI job should carry them")

    changed, merge_base, diff_total = changed_files(repo, base, head, log=log)
    try:
        git_root = subprocess.check_output(["git", "-C", repo, "rev-parse", "--show-toplevel"],
                                          text=True).strip()
    except (subprocess.CalledProcessError, OSError) as e:
        raise CIError(f"{repo!r} is not inside a git working tree: {e}") from e
    changed, outside = rebase_onto(changed, repo, git_root)
    if outside:
        log(f"  {outside} changed file(s) are outside {repo!r} and were NOT scanned")
    if not changed:
        why = ("no scannable files changed" if not outside else
               f"every changed file is outside {repo!r} — nothing in the scanned directory changed")
        log(f"{why} — nothing to review")
        # A comment body even though nothing will be POSTED. The early return used to hand back
        # `comment: ""`, so `--comment-out` wrote nothing and the action's step summary fell through
        # to "no findings at or above the threshold" — a clean bill of health for a diff that was
        # never reviewed. Nothing is posted to the PR (there is nothing to report), but the surface a
        # human actually reads has to say which of the two happened.
        body = "\n".join([
            MARKER, "## 🩹 Virtual Patch Copilot", "",
            f"**Nothing was reviewed.** {why}.", "",
            f"Of {diff_total} file(s) changed in this diff, {len(changed)} were scannable"
            + (f" and {outside} sit outside `{repo}`" if outside else "") + ".", "",
            "_This is **not** a clean bill of health — no code was analysed._"])
        return {"changed": 0, "scanned": 0, "findings": [], "candidates": 0, "refuted": 0,
                "reported": 0, "comment": body, "posted": False, "outside": outside,
                "diff_total": diff_total, "reason": why}

    from .pipeline import run_pipeline
    summary = run_pipeline(repo, out_dir=out_dir, config_path=config_path,
                           min_confidence=min_confidence, max_files=max_files, max_bytes=max_bytes,
                           draft_code_fixes=False, only_files=changed, log=log)

    def rj(name, default):
        p = Path(out_dir) / name
        try:
            return json.loads(p.read_text()) if p.is_file() else default
        except (OSError, json.JSONDecodeError):
            return default

    candidates = rj("findings.json", [])
    triage = {d.get("finding_id"): d for d in rj("triage.json", [])}
    policies = rj("policies.json", [])
    metrics = rj("metrics.json", {})
    scanned = (metrics.get("discovery") or {}).get("files", 0)
    truncated = max(0, len(changed) - scanned)

    # `findings.json` is the DISCOVER contract — every candidate, including the ones `verify`
    # refuted as false positives. Triage runs only over the verified set, so a triage decision is
    # what "survived verification" looks like on disk. Reporting straight from findings.json put
    # refuted false positives in front of a developer with a proposed band-aid attached, which is the
    # fastest way to teach a team to ignore this bot.
    findings = [f for f in candidates if f.get("id") in triage]
    refuted = len(candidates) - len(findings)
    if refuted:
        log(f"  {refuted} candidate(s) were refuted by verify and are not reported")

    floor = SEVERITY_RANK.get(min_severity, 1)
    reported = [f for f in findings
                if SEVERITY_RANK.get(f.get("severity", "low"), 3) <= floor]

    sim, sim_meta = _blast_radius(out_dir)
    body = render_comment(findings, triage, policies, min_severity=min_severity,
                          changed=len(changed), sim=sim, scanned=scanned,
                          base=merge_base, truncated=truncated, outside=outside,
                          diff_total=diff_total, sim_meta=sim_meta)
    res = {"changed": len(changed), "scanned": scanned, "findings": findings,
           "candidates": len(candidates), "refuted": refuted, "diff_total": diff_total,
           "reported": len(reported), "comment": body, "posted": False,
           "outside": outside, "summary": summary, "out": out_dir}

    if not reported:
        # "A PR with no new findings posts nothing." Silence is the correct output: a bot that
        # comments "all clear" on every PR trains people to stop reading it.
        log(f"no findings at or above {min_severity} — posting nothing")
        res["reason"] = f"no findings at or above {min_severity}"
        return res

    if post:
        if not (repo_slug and pr_number):
            raise CIError("posting needs both --repo (owner/name) and --pr (number)")
        res.update(upsert_comment(repo_slug, int(pr_number), body, token=token,
                                  dry_run=dry_run, log=log))
    return res
