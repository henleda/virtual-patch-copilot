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
    rel = remediation["file"]
    path = f"{path_prefix.rstrip('/')}/{rel}" if path_prefix else rel
    branch = f"vpcopilot/fix-{fid}"
    content = remediation.get("patched_content")
    plan = {"repo": repo_slug, "base": base, "branch": branch, "path": path,
            "title": remediation.get("pr_title", "")}

    if not content:
        raise RuntimeError(f"remediation {fid} has no patched_content — re-run the scan")
    if dry_run:
        log(f"[dry-run] would open PR against {repo_slug}@{base}: branch {branch}, file {path}")
        return {"mode": "dry_run", **plan}

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
    audit.record(out_dir, "open_pr", finding=fid, repo=repo_slug, url=pr.html_url, number=pr.number)
    return {"mode": "opened", "number": pr.number, "url": pr.html_url, **plan}
