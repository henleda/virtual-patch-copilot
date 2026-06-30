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


@app.callback()
def _root():
    """Virtual Patch Copilot — find vulns, triage to XC controls, generate patches + code-fix PRs."""


@app.command()
def scan(
    repo: str = typer.Argument(..., help="path to the target application repo"),
    out: str = typer.Option("out", help="output directory for findings/policies/PRs"),
    config: str = typer.Option(None, "--config", help="path to agents.yaml"),
):
    """Discover -> verify -> triage -> generate policies + code-fix PRs (read-only)."""
    summary = run_pipeline(repo, out_dir=out, config_path=config,
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
):
    """Run the scan and SCORE it against the answer key (discovery, triage, cure)."""
    from .bench import run_bench

    res = run_bench(repo, key, out_dir=out, config_path=config, scan=not rescore,
                    log=lambda m: rprint(f"[dim]{m}[/dim]"))
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


def main():
    load_dotenv()  # pull provider keys (ANTHROPIC_API_KEY, etc.) from .env
    app()


if __name__ == "__main__":
    main()
