"""CLI entrypoint. `vpcopilot scan <repo>` runs the read-only brain (no XC/GitHub
writes) and drops findings, triage, policy specs, and code-fix PR drafts into ./out."""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.panel import Panel

from .pipeline import run_pipeline

app = typer.Typer(add_completion=False, help="Virtual Patch Copilot")


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


def main():
    app()


if __name__ == "__main__":
    main()
