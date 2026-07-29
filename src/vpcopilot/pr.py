"""Open a GitHub PR for a code-fix remediation.

Uses the full corrected file (remediation.patched_content) via the GitHub Contents API —
no fragile local diff application, no local clone. Needs GITHUB_TOKEN with repo scope.
The deterministic 'hands' for the cure side; agents never call this."""
from __future__ import annotations

import os
import subprocess
from typing import Callable


def _resolve_token(token: str | None = None) -> str:
    if token:
        return token
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:  # fall back to the gh CLI's auth
        return subprocess.check_output(["gh", "auth", "token"], text=True).strip()
    except Exception as e:  # noqa: BLE001
        raise RuntimeError("no GITHUB_TOKEN in env and `gh auth token` unavailable") from e


def open_pr(remediation: dict, repo_slug: str, *, base: str = "main", path_prefix: str = "",
            token: str | None = None, dry_run: bool = False, out_dir: str = "out",
            log: Callable = print) -> dict:
    fid = remediation["finding_id"]
    rel = remediation.get("file") or ""
    path = f"{path_prefix.rstrip('/')}/{rel}" if path_prefix else rel
    branch = f"vpcopilot/fix-{fid}"
    content = remediation.get("patched_content")
    plan = {"repo": repo_slug, "base": base, "branch": branch, "path": path,
            "title": remediation.get("pr_title", "")}

    # H1 — a dependency CVE's cure is a version bump in someone else's package. There is nothing of
    # ours to patch, so this reports the upgrade and touches GitHub not at all: no token needed, no
    # branch created, nothing to review. Checked FIRST, so it is reachable in a dry run too.
    if remediation.get("kind") == "dependency_upgrade" and not content:
        target = remediation.get("fixed_version")
        rec = (f"upgrade {remediation.get('package') or 'the affected package'} to {target}"
               if target else remediation.get("summary", "no fixed version published"))
        log(f"advisory: {rec} — no PR to open (the fix is upstream, not in this repo)")
        return {"mode": "advisory", "recommendation": rec, "finding_id": fid,
                "package": remediation.get("package", ""),
                "ecosystem": remediation.get("ecosystem", ""),
                "fixed_version": target or "",
                "vulnerable_range": remediation.get("vulnerable_range", "")}

    # Order matters: the dry run must be able to REPORT a missing patch rather than raising
    # identically to a live run. This check used to sit above it, so `--dry-run` could not preview
    # anything that lacked content.
    if dry_run:
        log(f"[dry-run] would open PR against {repo_slug}@{base}: branch {branch}, file {path}")
        return {"mode": "dry_run", "has_patch": bool(content), **plan}
    if not content:
        raise RuntimeError(f"remediation {fid} has no patched_content — re-run the scan")
    if not rel:
        # model_dump() always emits defaulted keys, so an absent file is "" rather than a KeyError —
        # and "" would reach repo.get_contents() as a directory listing and AttributeError on .sha.
        raise RuntimeError(f"remediation {fid} names no file to patch")

    from github import Github, GithubException

    gh = Github(_resolve_token(token))
    repo = gh.get_repo(repo_slug)
    base_sha = repo.get_branch(base).commit.sha
    try:
        repo.create_git_ref(f"refs/heads/{branch}", base_sha)
        log(f"created branch {branch} from {base}")
    except GithubException as e:
        if e.status != 422:  # 422 == ref already exists
            raise
        log(f"branch {branch} already exists — updating file")

    existing = repo.get_contents(path, ref=branch)
    repo.update_file(path, remediation["pr_title"], content, existing.sha, branch=branch)
    pr = repo.create_pull(title=remediation["pr_title"], body=remediation["pr_body"],
                          head=branch, base=base)
    log(f"opened PR #{pr.number}: {pr.html_url}")
    from . import audit, ledger
    ledger.mark_remediated(out_dir, fid, pr_url=pr.html_url, pr_number=pr.number)
    # `finding_id` is the key every other action uses; `finding` is kept so logs written by older
    # builds and the ones written now read the same way.
    audit.record(out_dir, "open_pr", finding_id=fid, finding=fid, repo=repo_slug, url=pr.html_url,
                 number=pr.number)
    return {"mode": "opened", "number": pr.number, "url": pr.html_url, **plan}
