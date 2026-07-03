"""CLI entrypoint. `vpcopilot scan <repo>` runs the read-only brain (no XC/GitHub
writes) and drops findings, triage, policy specs, and code-fix PR drafts into ./out."""
from __future__ import annotations

import typer
from dotenv import load_dotenv
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from .pipeline import run_pipeline

app = typer.Typer(add_completion=False, help="Virtual Patch Copilot")


def _version_cb(value: bool):
    if value:
        from . import __version__

        rprint(f"virtual-patch-copilot {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(False, "--version", callback=_version_cb, is_eager=True,
                                 help="show version and exit"),
):
    """Virtual Patch Copilot — find vulns, triage to XC controls, generate patches + code-fix PRs."""


@app.command()
def scan(
    repo: str = typer.Argument(..., help="path to the target application repo"),
    out: str = typer.Option("out", help="output directory for findings/policies/PRs"),
    config: str = typer.Option(None, "--config", help="path to agents.yaml"),
    min_confidence: float = typer.Option(0.5, "--min-confidence", help="drop verified findings below this confidence"),
):
    """Discover -> verify -> triage -> generate policies + code-fix PRs (read-only)."""
    summary = run_pipeline(repo, out_dir=out, config_path=config, min_confidence=min_confidence,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit(
        "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in summary.items()),
        title="virtual-patch-copilot",
    ))


@app.command()
def bench(
    repo: str = typer.Argument(..., help="app dir to scan (e.g. the vuln-lab api dir)"),
    key: str = typer.Option("bench/answer_key.yaml", help="answer key path"),
    out: str = typer.Option("out", help="output directory"),
    config: str = typer.Option(None, "--config", help="path to agents.yaml"),
    rescore: bool = typer.Option(False, "--rescore", help="score the existing out/ without re-scanning"),
    min_confidence: float = typer.Option(0.5, "--min-confidence", help="drop verified findings below this confidence"),
):
    """Run the scan and SCORE it against the answer key (discovery, triage, cure)."""
    from .bench import run_bench

    res = run_bench(repo, key, out_dir=out, config_path=config, scan=not rescore,
                    min_confidence=min_confidence, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    t = Table(title="benchmark")
    t.add_column("vuln"); t.add_column("found"); t.add_column("triage"); t.add_column("matched id")
    for r in res["rows"]:
        found = "[green]found[/green]" if r["found"] else "[red]MISS[/red]"
        tri = "—" if r["triage_ok"] is None else ("[green]ok[/green]" if r["triage_ok"] else "[yellow]wrong[/yellow]")
        t.add_row(r["key"], found, tri, r["matched"] or "")
    rprint(t)
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res["score"].items()), title="score"))
    if res["extras"]:
        rprint(f"[dim]extra findings not in key: {', '.join(res['extras'])}[/dim]")


@app.command()
def apply(
    policy: str = typer.Option("nimbus-bizlogic-policy", help="existing service policy to attach"),
    from_scan: str = typer.Option(None, "--from-scan", help="generated policy artifact to create then apply"),
    name: str = typer.Option(None, "--name", help="override the policy name (for --from-scan)"),
    lb: str = typer.Option("nimbus-www", help="HTTP LB name"),
    url: str = typer.Option("https://www.banknimbus.com", help="live host to validate against"),
    create_only: bool = typer.Option(False, "--create-only", help="create the policy in XC but do not attach"),
    dry_run: bool = typer.Option(False, "--dry-run", help="no mutation"),
    keep: bool = typer.Option(False, "--keep", help="leave attached on success (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb", help="permit mutating a protected LB"),
    out: str = typer.Option("out", help="output directory"),
):
    """Gated apply: (create from scan) -> snapshot -> self-test -> attach -> validate -> rollback."""
    kw = dict(dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb, out_dir=out,
              log=lambda m: rprint(f"[dim]{m}[/dim]"))
    if from_scan:
        from .apply import apply_from_scan
        res = apply_from_scan(from_scan, lb, url, name=name, create_only=create_only, **kw)
    else:
        from .apply import apply_service_policy
        res = apply_service_policy(lb, policy, url, **kw)
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply"))


@app.command(name="apply-maluser")
def apply_maluser(
    lb: str = typer.Option("nimbus-www", help="HTTP LB name"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run", help="no mutation; show current + would-be change"),
    keep: bool = typer.Option(False, "--keep", help="leave detection enabled (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb", help="permit mutating a protected LB"),
    out: str = typer.Option("out", help="output directory"),
):
    """Enable XC Malicious-User Detection on an LB (behavioral control; config-level validation)."""
    from .apply import apply_malicious_user

    res = apply_malicious_user(lb, dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb,
                              finding_id=finding, out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-maluser"))


@app.command(name="apply-ratelimit")
def apply_ratelimit(
    lb: str = typer.Option("nimbus-www", help="HTTP LB name"),
    requests: int = typer.Option(100, help="requests per unit"),
    unit: str = typer.Option("MINUTE", help="SECOND | MINUTE | HOUR"),
    burst: int = typer.Option(1, help="burst multiplier (>0)"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep: bool = typer.Option(False, "--keep", help="leave enabled on success (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable XC rate limiting on an LB (config-level validation + rollback)."""
    from .apply import apply_rate_limit

    res = apply_rate_limit(lb, requests=requests, unit=unit, burst=burst, finding_id=finding,
                           dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb,
                           out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-ratelimit"))


@app.command(name="apply-bot")
def apply_bot(
    lb: str = typer.Option("nimbus-www", help="HTTP LB name"),
    dry_run: bool = typer.Option(True, "--dry-run/--live", help="dry-run (default); --live needs the add-on + a policy"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable XC Bot Defense on an LB. Requires the Bot Defense add-on + a policy; dry-run by default."""
    from .apply import apply_bot_defense

    res = apply_bot_defense(lb, dry_run=dry_run, allow_protected=allow_protected_lb,
                            out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-bot"))


@app.command(name="xc-rm")
def xc_rm(name: str = typer.Argument(..., help="service policy name to delete")):
    """Delete a service policy (guarded against protected demo policies)."""
    from .apply import PROTECTED_POLICIES
    from .xc import XC

    if name in PROTECTED_POLICIES:
        rprint(f"[red]refusing to delete protected policy '{name}'[/red]")
        raise typer.Exit(code=1)
    XC().delete_service_policy(name)
    rprint(f"deleted service policy '{name}'")


@app.command()
def pr(
    repo_slug: str = typer.Option(..., "--repo", help="owner/name, e.g. henleda/nimbus-demo"),
    finding: str = typer.Option(None, "--finding", help="finding id (default: all in remediations.json)"),
    base: str = typer.Option("main", help="base branch to PR against"),
    path_prefix: str = typer.Option("", "--path-prefix", help="prepend to each remediation's file path (repo-relative)"),
    out: str = typer.Option("out", help="output directory"),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what would be opened; no writes"),
):
    """Open GitHub PR(s) for code-fix remediations (full-file via the API; no diff apply)."""
    import json as _json
    from pathlib import Path as _Path

    from .pr import open_pr

    rems = _json.loads((_Path(out) / "remediations.json").read_text())
    if finding:
        rems = [r for r in rems if r["finding_id"] == finding]
    if not rems:
        rprint("[yellow]no matching remediations in remediations.json[/yellow]")
        raise typer.Exit(code=1)
    for r in rems:
        res = open_pr(r, repo_slug, base=base, path_prefix=path_prefix, dry_run=dry_run,
                      out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
        rprint(res)


@app.command()
def audit(out: str = typer.Option("out", help="output directory")):
    """Show the audit log of applied / rolled-back changes."""
    from .audit import load

    entries = load(out)
    if not entries:
        rprint("[yellow]no audit entries yet[/yellow]")
        raise typer.Exit()
    t = Table(title="audit log")
    for c in ["ts", "action", "detail"]:
        t.add_column(c)
    for e in entries:
        detail = ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("ts", "action"))
        t.add_row(e.get("ts", ""), e.get("action", ""), detail)
    rprint(t)


@app.command()
def ledger(out: str = typer.Option("out", help="output directory")):
    """Show the remediation ledger: found -> mitigated -> remediated -> retired."""
    from .ledger import load

    entries = load(out)
    if not entries:
        rprint("[yellow]no ledger yet — run a scan first[/yellow]")
        raise typer.Exit()
    order = {"found": 0, "mitigated": 1, "remediated": 2, "retired": 3}
    t = Table(title="remediation ledger")
    for c in ["finding", "state", "file", "band-aids", "mitigation", "cure"]:
        t.add_column(c)
    for e in sorted(entries.values(), key=lambda x: order.get(x.get("state"), 0)):
        mit, cure = e.get("mitigation"), e.get("cure")
        bands = ",".join(e.get("bandaids", [])) or ("no_bandaid" if e.get("no_bandaid") else "")
        t.add_row(e.get("finding_id", ""), e.get("state", ""), e.get("file", ""), bands,
                  (mit["control"] if mit else "—"), (cure["pr_url"] if cure else "—"))
    rprint(t)


@app.command(name="xc-status")
def xc_status(lb: str = typer.Option("nimbus-www", help="HTTP LB name")):
    """Read-only: confirm XC auth and show the LB's service-policy config + existing policies."""
    import json as _json

    from .xc import XC

    xc = XC()
    rprint(f"[bold]namespace[/bold]: {xc.ns}  ·  [bold]api[/bold]: {xc.base}")
    pols = xc.list_service_policies()
    names = [i.get("name") for i in pols.get("items", [])]
    rprint(f"[bold]existing service policies[/bold]: {names or '(none)'}")
    spec = xc.get_lb(lb).get("spec", {})
    sp = {k: v for k, v in spec.items() if "service_polic" in k}
    rprint(f"[bold]LB {lb}[/bold] service-policy config:")
    rprint(_json.dumps(sp, indent=2))


@app.command()
def console(host: str = typer.Option("127.0.0.1", help="bind host"),
            port: int = typer.Option(8787, help="bind port")):
    """Launch the ops console (localhost): dashboard, apply/PR actions, scan, admin panel."""
    import uvicorn

    rprint(f"[bold]ops console[/bold] → http://{host}:{port}")
    uvicorn.run("vpcopilot.console.app:app", host=host, port=port, log_level="warning")


def main():
    load_dotenv()  # pull provider keys (ANTHROPIC_API_KEY, etc.) from .env
    app()


if __name__ == "__main__":
    main()
