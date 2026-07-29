"""CLI entrypoint. `vpcopilot scan <repo>` runs the read-only brain (no XC/GitHub
writes) and drops findings, triage, policy specs, and code-fix PR drafts into ./out."""
from __future__ import annotations

import os

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
    concurrency: int = typer.Option(8, "--concurrency", help="parallel workers for discover/verify"),
    max_files: int = typer.Option(200, "--max-files", help="max source files to scan (raise for large repos)"),
    max_bytes: int = typer.Option(60_000, "--max-bytes", help="skip source files larger than this many bytes"),
    code_fixes: bool = typer.Option(
        None, "--code-fixes/--no-code-fixes",
        help="also draft the code-fix PRs (default: on; env VPCOPILOT_SCAN_REMEDIATE=0 to default off). "
             "--no-code-fixes = band-aids only, saves ~half the tokens (use for band-aid benchmarks)"),
):
    """Discover -> verify -> triage -> generate policies + code-fix PRs (read-only)."""
    if code_fixes is None:  # match the console default (app.py /api/defaults) so headless == UI
        code_fixes = os.environ.get("VPCOPILOT_SCAN_REMEDIATE", "1").lower() not in ("0", "false", "no")
    summary = run_pipeline(repo, out_dir=out, config_path=config, min_confidence=min_confidence,
                           concurrency=concurrency, max_files=max_files, max_bytes=max_bytes,
                           draft_code_fixes=code_fixes,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit(
        "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in summary.items()),
        title="virtual-patch-copilot",
    ))


@app.command()
def bench(
    repo: str = typer.Argument(..., help="app dir to scan (e.g. bench/fixtures/nimbus-vuln-lab/app/src/app/api)"),
    key: str = typer.Option("bench/answer_key.yaml", help="answer key path"),
    out: str = typer.Option("out", help="output directory"),
    config: str = typer.Option(None, "--config", help="path to agents.yaml"),
    rescore: bool = typer.Option(False, "--rescore", help="score the existing out/ without re-scanning"),
    all_configs: bool = typer.Option(False, "--all-configs",
                                     help="score EVERY config/agents*.yaml and write benchmarks/RESULTS.md"),
    target: str = typer.Option(None, "--target", help="label for the scorecard (default: the repo path)"),
    skip: list[str] = typer.Option(None, "--skip", help="config tag to skip, repeatable (e.g. --skip dgx)"),
    min_confidence: float = typer.Option(0.5, "--min-confidence", help="drop verified findings below this confidence"),
    concurrency: int = typer.Option(8, "--concurrency", help="parallel workers for discover/verify"),
):
    """Run the scan and SCORE it against the answer key (discovery, triage, cure)."""
    if all_configs:
        from .scorecard import run_all_configs, write_results
        skipped = tuple(skip or ())
        res = run_all_configs(repo, key=key, min_confidence=min_confidence, concurrency=concurrency,
                              rescore=rescore, skip=skipped, log=lambda m: rprint(f"[dim]{m}[/dim]"))
        t = Table(title="model scorecard")
        for c in ["config", "model", "recall", "precision", "triage", "noise", "wall"]:
            t.add_column(c)
        for tag in sorted(res):
            r = res[tag]
            if r.get("error"):
                t.add_row(tag, r.get("model", "?"), "[red]failed[/red]", "", "", "", "")
                continue
            sc = r["score"]
            t.add_row(tag, r["model"], f"{sc['discovery_recall']:.2f}", f"{sc['verify_precision']:.2f}",
                      f"{sc['triage_accuracy']:.2f}", str(sc["noise"]), f"{sc['wall_time_s']:.0f}s")
        rprint(t)
        path = write_results(res, target=target or repo, key=key, skipped=skipped)
        rprint(f"wrote [bold]{path}[/bold]")
        return

    from .bench import run_bench

    res = run_bench(repo, key, out_dir=out, config_path=config, scan=not rescore,
                    min_confidence=min_confidence, concurrency=concurrency,
                    log=lambda m: rprint(f"[dim]{m}[/dim]"))
    t = Table(title="benchmark")
    t.add_column("vuln"); t.add_column("found"); t.add_column("triage"); t.add_column("matched id")
    for r in res["rows"]:
        found = "[green]found[/green]" if r["found"] else "[red]MISS[/red]"
        tri = "—" if r["triage_ok"] is None else ("[green]ok[/green]" if r["triage_ok"] else "[yellow]wrong[/yellow]")
        t.add_row(r["key"], found, tri, r["matched"] or "")
    rprint(t)
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res["score"].items()), title="score"))
    if res.get("noise"):
        rprint(f"[dim]noise (findings not in key or bonus): {', '.join(res['noise'])}[/dim]")


@app.command(name="bench-model")
def bench_model_cmd(
    tag: str = typer.Option(..., "--tag", help="model label for this run, e.g. claude / openai / dgx-llama"),
    out: str = typer.Option("out", help="the run's output dir to read"),
    target: str = typer.Option("", help="scan target, for the report header"),
    config: str = typer.Option(None, "--config", help="agents.yaml (to record the per-agent models)"),
    dest: str = typer.Option("benchmarks", help="where to write benchmark-<tag>.{json,md}"),
):
    """Build a model-tagged benchmark from a run: findings + generated policies + LIVE policy
    quality (did each applied band-aid actually block its exploit), for cross-model comparison."""
    from .bench_model import to_markdown, write

    b = write(out, tag, target=target, config_path=config, dest_dir=dest)
    rprint(to_markdown(b))
    rprint(f"[dim]wrote {dest}/benchmark-{tag}.json + benchmark-{tag}.md[/dim]")


@app.command(name="bench-compare")
def bench_compare_cmd(
    paths: list[str] = typer.Argument(..., help="benchmark-*.json files to compare"),
):
    """Compare model benchmark reports side by side (findings, policies, live pass rate)."""
    from .bench_model import compare

    rprint(compare(paths))


@app.command()
def apply(
    policy: str = typer.Option("nimbus-bizlogic-policy", help="existing service policy to attach"),
    from_scan: str = typer.Option(None, "--from-scan", help="generated policy artifact to create then apply"),
    name: str = typer.Option(None, "--name", help="override the policy name (for --from-scan)"),
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    url: str = typer.Option("https://lab.banknimbus.com", help="live host to validate against"),
    create_only: bool = typer.Option(False, "--create-only", help="create the policy in XC but do not attach"),
    dry_run: bool = typer.Option(False, "--dry-run", help="no mutation"),
    keep: bool = typer.Option(False, "--keep", help="leave attached on success (default: rollback)"),
    probe: bool = typer.Option(False, "--probe/--no-probe", help="in --dry-run, actually fire the exploit at the live app (default: off — a dry-run makes no requests)"),
    refine: bool = typer.Option(True, "--refine/--no-refine", help="refine the policy until it actually blocks the exploit (default on)"),
    refine_attempts: int = typer.Option(None, "--refine-attempts", help="max refine attempts (default $VPCOPILOT_REFINE_ATTEMPTS or 3)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb", help="permit mutating a protected LB"),
    probe_user: str = typer.Option(None, "--probe-user", help="validation login username for an auth-protected app (or set VPCOPILOT_PROBE_USER)"),
    probe_pass: str = typer.Option(None, "--probe-pass", help="validation login password (or VPCOPILOT_PROBE_PASS)"),
    probe_login_path: str = typer.Option(None, "--probe-login-path", help="login endpoint path, default /api/login (or VPCOPILOT_PROBE_LOGIN_PATH)"),
    probe_token: str = typer.Option(None, "--probe-token", help="bearer token for validation instead of user/pass (or VPCOPILOT_PROBE_TOKEN)"),
    finding: str = typer.Option(None, "--finding", help="finding id whose probe (out/probes.json) validates this policy; overrides the ledger lookup"),
    force: bool = typer.Option(False, "--force", help="apply despite the pre-apply drift check: re-attach a policy that is already attached, or push past a conflicting ALLOW on another attached policy"),
    out: str = typer.Option("out", help="output directory"),
):
    """Gated apply: (create from scan) -> snapshot -> self-test -> attach -> validate -> refine/rollback."""
    import os
    # Auth for the validation probe (auth-protected targets). Set env so it reaches every
    # _run_validation call inside apply/refine via _probe_auth_from_env — the single chokepoint.
    for flag, key in ((probe_user, "VPCOPILOT_PROBE_USER"), (probe_pass, "VPCOPILOT_PROBE_PASS"),
                      (probe_login_path, "VPCOPILOT_PROBE_LOGIN_PATH"), (probe_token, "VPCOPILOT_PROBE_TOKEN")):
        if flag:
            os.environ[key] = flag
    logf = lambda m: rprint(f"[dim]{m}[/dim]")  # noqa: E731
    kw = dict(dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb, probe=probe,
              finding_id=finding, out_dir=out, log=logf)
    if from_scan and refine and not dry_run and not create_only:
        from .refiner import refine_apply_service_policy
        res = refine_apply_service_policy(from_scan, lb, url, name=name, keep=keep,
                                          allow_protected=allow_protected_lb, max_refine=refine_attempts,
                                          finding_id=finding, force=force, out_dir=out, log=logf)
    elif from_scan:
        from .apply import apply_from_scan
        res = apply_from_scan(from_scan, lb, url, name=name, create_only=create_only, force=force, **kw)
    else:
        from .apply import apply_service_policy
        res = apply_service_policy(lb, policy, url, **kw)
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply"))


@app.command(name="apply-maluser")
def apply_maluser(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run", help="no mutation; show current + would-be change"),
    keep: bool = typer.Option(False, "--keep", help="leave detection enabled (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb", help="permit mutating a protected LB"),
    user_id_header: str = typer.Option(None, "--user-id-header", help="key detection on this request header (e.g. X-Agent-Id) instead of client IP"),
    user_id_name: str = typer.Option(None, "--user-id-name", help="user_identification object name (default <lb>-user-id)"),
    out: str = typer.Option("out", help="output directory"),
):
    """Enable XC Malicious-User Detection on an LB (behavioral control; config-level validation)."""
    from .apply import apply_malicious_user

    res = apply_malicious_user(lb, dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb,
                              finding_id=finding, user_id_header=user_id_header,
                              user_identification_name=user_id_name,
                              out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-maluser"))


@app.command(name="apply-ratelimit")
def apply_ratelimit(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    requests: int = typer.Option(100, help="requests per unit"),
    unit: str = typer.Option("MINUTE", help="SECOND | MINUTE | HOUR"),
    burst: int = typer.Option(1, help="burst multiplier (>0)"),
    behavioral: bool = typer.Option(False, "--behavioral", help="B3: drive a burst + confirm 429s (not just config)"),
    behavioral_path: str = typer.Option("/login", "--behavioral-path", help="path to burst for --behavioral (use the rate-limited endpoint)"),
    url: str = typer.Option("https://lab.banknimbus.com", help="live host for the behavioral burst"),
    user_id_header: str = typer.Option(None, "--user-id-header", help="key the limit per this request header (e.g. X-Agent-Id) instead of LB-wide"),
    user_id_name: str = typer.Option(None, "--user-id-name", help="user_identification object name (default <lb>-user-id)"),
    burst_header: list[str] = typer.Option(None, "--burst-header", help="header sent on every behavioral burst request, name=value (repeatable)"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep: bool = typer.Option(False, "--keep", help="leave enabled on success (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable XC rate limiting on an LB (config validation + rollback; --behavioral drives traffic)."""
    from .apply import apply_rate_limit

    burst_headers = {}
    for h in (burst_header or []):
        if "=" in h:
            k, v = h.split("=", 1)
            burst_headers[k.strip()] = v.strip()

    res = apply_rate_limit(lb, requests=requests, unit=unit, burst=burst, behavioral=behavioral,
                           behavioral_path=behavioral_path, burst_headers=burst_headers or None,
                           user_id_header=user_id_header, user_identification_name=user_id_name,
                           target_url=url, finding_id=finding, dry_run=dry_run, keep=keep,
                           allow_protected=allow_protected_lb, out_dir=out,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-ratelimit"))


@app.command(name="apply-bot")
def apply_bot(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    dry_run: bool = typer.Option(True, "--dry-run/--live", help="dry-run (default); --live needs the add-on + a policy"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable XC Bot Defense on an LB. Requires the Bot Defense add-on + a policy; dry-run by default."""
    from .apply import apply_bot_defense

    res = apply_bot_defense(lb, dry_run=dry_run, allow_protected=allow_protected_lb,
                            out_dir=out, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-bot"))


@app.command(name="apply-waf")
def apply_waf_cmd(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    app_firewall: str = typer.Option("vpcopilot-lab-waf", help="app_firewall to attach (created Blocking if missing)"),
    template: str = typer.Option("nimbus-waf", help="app_firewall to clone for the Blocking WAF"),
    url: str = typer.Option("https://lab.banknimbus.com", help="live host to validate against"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep: bool = typer.Option(False, "--keep", help="leave WAF attached on success (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable WAF blocking on an LB (create Blocking app_firewall + attach + SQLi-validate)."""
    from .apply import apply_waf

    res = apply_waf(lb, app_firewall=app_firewall, template=template, target_url=url, finding_id=finding,
                    dry_run=dry_run, keep=keep, allow_protected=allow_protected_lb, out_dir=out,
                    log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-waf"))


@app.command(name="apply-dataguard")
def apply_dataguard_cmd(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    app_firewall: str = typer.Option("vpcopilot-lab-waf", help="app_firewall to ensure (created Blocking if missing); an already-attached, differently-named WAF is reused, never clobbered"),
    template: str = typer.Option("nimbus-waf", help="app_firewall to clone for the Blocking WAF"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep: bool = typer.Option(False, "--keep", help="leave Data Guard on (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable WAF Data Guard on an LB (mask sensitive data in responses; config validation)."""
    from .apply import apply_data_guard

    res = apply_data_guard(lb, app_firewall=app_firewall, template=template, finding_id=finding,
                           dry_run=dry_run, keep=keep,
                           allow_protected=allow_protected_lb, out_dir=out,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-dataguard"))


@app.command(name="apply-apischema")
def apply_apischema_cmd(
    lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name"),
    url: str = typer.Option("https://lab.banknimbus.com", help="live host to validate against"),
    openapi_file: str = typer.Option(None, "--openapi-file", help="OpenAPI/Swagger JSON to enforce (default: built-in Nimbus spec)"),
    validate_properties: str = typer.Option(
        "PROPERTY_HTTP_HEADERS,PROPERTY_QUERY_PARAMETERS,PROPERTY_HTTP_BODY", "--validate-properties",
        help="comma-separated request parts XC validates against the spec (default: headers, query "
             "params and body — body-only enforces nothing on a bodyless GET)"),
    finding: str = typer.Option(None, "--finding", help="link to a finding id for the ledger"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    keep: bool = typer.Option(False, "--keep", help="leave validation enabled on success (default: rollback)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """Enable XC OpenAPI request-schema validation (block mode): upload spec -> api_definition ->
    attach validation; validate a schema-violating request is blocked. --openapi-file feeds a real spec."""
    import json as _json
    from pathlib import Path as _Path

    from .apply import apply_api_schema

    openapi = _json.loads(_Path(openapi_file).read_text()) if openapi_file else None
    props = [p.strip() for p in (validate_properties or "").split(",") if p.strip()] or None
    res = apply_api_schema(lb, openapi=openapi, target_url=url, finding_id=finding, dry_run=dry_run,
                           request_validation_properties=props,
                           keep=keep, allow_protected=allow_protected_lb, out_dir=out,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in res.items()), title="apply-apischema"))


@app.command()
def report(
    out: str = typer.Option("out", help="scan output directory to read"),
    output: str = typer.Option(None, "--output", help="report path (default: <out>/report.html)"),
    open_browser: bool = typer.Option(False, "--open", help="open the report in a browser"),
):
    """Build a standalone, shareable HTML report from an existing scan's out/ dir."""
    import os
    from .report import write_report

    path = write_report(out, output)
    rprint(f"wrote [bold]{path}[/bold]")
    if open_browser:
        import webbrowser
        webbrowser.open("file://" + os.path.abspath(path))


@app.command(name="lab-create")
def lab_create(
    domain: str = typer.Option(..., "--domain", help="hostname for the test LB, e.g. vampi.banknimbus.com"),
    origin: str = typer.Option(..., "--origin", help="app origin host:port, e.g. 16.59.6.127:5000"),
    name: str = typer.Option(None, "--name", help="base name (default: first label of the domain)"),
    origin_tls: bool = typer.Option(False, "--origin-tls", help="origin serves HTTPS (default: HTTP)"),
):
    """Stand up a clean-slate XC test LB for an app origin (pool + LB), then print the DNS to add."""
    from .lab import create_lab

    res = create_lab(domain, origin, name=name, origin_tls=origin_tls,
                     log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit(
        f"[bold]LB[/bold]: {res['lb']}\n[bold]pool[/bold]: {res['pool']} -> {res['origin']}\n"
        f"[bold]URL[/bold]: {res['url']}", title="lab-create"))
    a, acme = res["dns_records"]["a"], res["dns_records"]["acme"]
    rprint("\n[bold]Add these DNS records to the banknimbus.com zone:[/bold]")
    if a and a.get("value"):
        rprint(f"  A      {a['name']}  ->  {a['value']}")
    if acme and acme.get("value"):
        rprint(f"  CNAME  {acme['name']}  ->  {acme['value']}")
    else:
        rprint("  [yellow](ACME challenge record not ready yet — re-check the LB in a minute)[/yellow]")
    base = name or domain.split(".")[0]
    rprint(f"\nOnce DNS resolves + the cert issues, scan the app and apply against [bold]{res['url']}[/bold]:")
    rprint(f"  [dim]vpcopilot scan <app-repo> --out out-{base}[/dim]")
    rprint(f"  [dim]vpcopilot apply --from-scan out-{base}/policies/<artifact>.json --lb {res['lb']} --url {res['url']} --keep[/dim]")


@app.command()
def retire(
    finding: str = typer.Option(None, "--finding", help="retire one finding's band-aid"),
    all_findings: bool = typer.Option(False, "--all", help="retire every mitigated finding whose cure PR merged"),
    force: bool = typer.Option(False, "--force", help="skip the PR-merged check (manual retire)"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb"),
    out: str = typer.Option("out"),
):
    """C2: retire a band-aid once its code-fix PR merges — detach the control + mark ledger retired."""
    from .retire import retire_all, retire_finding

    logf = lambda m: rprint(f"[dim]{m}[/dim]")  # noqa: E731
    if finding:
        results = [retire_finding(out, finding, force=force, dry_run=dry_run,
                                  allow_protected=allow_protected_lb, log=logf)]
    elif all_findings:
        results = retire_all(out, force=force, dry_run=dry_run, allow_protected=allow_protected_lb, log=logf)
    else:
        rprint("[yellow]specify --finding <id> or --all[/yellow]")
        raise typer.Exit(1)
    for r in results:
        extra = f" ({r.get('control')} on {r.get('lb')})" if r.get("control") else ""
        rprint(f"[bold]{r.get('finding_id')}[/bold]: {r.get('status')}{extra}")


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
    repo_slug: str = typer.Option(..., "--repo", help="owner/name, e.g. octocat/hello-world"),
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
def simulate(
    out: str = typer.Option("out", help="run directory holding the generated policies"),
    logs: str = typer.Option(None, "--logs", help="traffic sample: .har / .json (HAR) or .jsonl"),
    from_tenant: bool = typer.Option(False, "--from-tenant", help="read observed requests from XC access logs"),
    lb: str = typer.Option("vpcopilot-lab", help="spare LB to replay through (never a protected one)"),
    url: str = typer.Option("https://lab.banknimbus.com", help="base URL of that LB"),
    source_lb: str = typer.Option(None, "--source-lb", help="with --from-tenant: the LB whose traffic to read"),
    since: str = typer.Option("1h", "--since", help="with --from-tenant: window back from now, e.g. 30m / 6h"),
    limit: int = typer.Option(500, help="max records to pull from the tenant"),
    max_records: int = typer.Option(200, help="max records to actually replay (each is one live request)"),
    threshold: float = typer.Option(None, help="would-block rate that flags a policy (default 0.01)"),
    policy: str = typer.Option(None, "--policy", help="simulate only this policy"),
):
    """Replay a recorded traffic sample against each generated band-aid and report what it WOULD
    block, before anything reaches the gate. Read-only against the sample; the spare LB is
    snapshotted and restored."""
    import os
    from .simulate import DEFAULT_THRESHOLD, candidates_from_out, simulate_policies, write_result

    cands = candidates_from_out(out, policy)
    if not cands:
        rprint(f"[yellow]no service_policy artifacts in {out} — nothing to simulate[/yellow]")
        raise typer.Exit(code=1)

    records, redacted, src, window = _load_traffic(logs, from_tenant, source_lb or lb, since, limit)
    if not records:
        rprint("[yellow]no records ingested — supply --logs or --from-tenant[/yellow]")
        raise typer.Exit(code=1)
    rprint(f"[dim]{len(records)} record(s) from {src}"
           + (f"; redacted {sum(v for k, v in redacted.items() if not k.startswith('_'))} value(s)" if redacted else "")
           + "[/dim]")

    thr = threshold if threshold is not None else float(os.environ.get("VPCOPILOT_SIM_THRESHOLD", DEFAULT_THRESHOLD))
    res = simulate_policies(cands, records, lb=lb, url=url, out_dir=out, threshold=thr,
                            max_records=max_records, source=src, window=window, redacted=redacted,
                            log=lambda m: rprint(f"[dim]{m}[/dim]"))
    path = write_result(out, res)
    t = Table(title="blast radius")
    for c in ["policy", "evaluated", "would block", "rate", "verdict"]:
        t.add_column(c)
    for p in res.policies:
        verdict = ("[red]over threshold[/red]" if p.blocked_promotion
                   else ("[yellow]error[/yellow]" if p.error else "[green]ok[/green]"))
        t.add_row(p.policy_name, str(p.evaluated), str(p.would_block), f"{p.block_rate:.1%}", verdict)
    rprint(t)
    rprint(f"wrote [bold]{path}[/bold]")


def _load_traffic(logs, from_tenant, source_lb, since, limit):
    """Traffic comes from a file, the tenant, or both — the two sources are additive on purpose:
    a HAR carries bodies the access logs cannot."""
    import datetime as _dt

    from . import traffic
    records, redacted, srcs = [], {}, []
    window = ""
    if logs:
        recs, red = traffic.load(logs)
        records += recs
        redacted.update(red)
        srcs.append(f"file:{logs}")
    if from_tenant:
        from .xc import XC
        n = int("".join(ch for ch in since if ch.isdigit()) or 1)
        unit = since.strip()[-1].lower()
        delta = _dt.timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}.get(unit, "hours"): n})
        now = _dt.datetime.now(_dt.timezone.utc)
        start, end = now - delta, now
        rows = XC().access_logs(start=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                end=end.strftime("%Y-%m-%dT%H:%M:%SZ"), limit=limit, lb=source_lb)
        recs, red = traffic.from_xc_logs(rows, lb=source_lb)
        records += recs
        for k, v in red.items():
            redacted[k] = redacted.get(k, 0) + v
        srcs.append(f"xc:{source_lb}")
        window = f"{start:%Y-%m-%dT%H:%M:%SZ}..{end:%Y-%m-%dT%H:%M:%SZ}"
    return records, redacted, " + ".join(srcs), window


@app.command()
def export(
    out: str = typer.Option("out", help="run directory to export"),
    output: str = typer.Option(None, "--output", help="bundle path (default: <out>/audit-bundle.zip)"),
    all_runs: bool = typer.Option(False, "--all", help="bundle every run dir on disk, each in its own folder"),
    root: str = typer.Option(".", help="where to look for run dirs when --all is used"),
    verify: str = typer.Option(None, "--verify", help="check an existing bundle instead of writing one"),
    pubkey: str = typer.Option(None, "--pubkey", help="minisign public key, to check the signature too"),
):
    """Export the audit evidence bundle for a run: every change made to a load balancer, the finding
    that justified it, the exact XC config pushed, and the pre-change snapshot — with a manifest that
    SHA-256s every member. Same bundle the console's Retire step downloads."""
    from .export import build_audit_events, verify_bundle, write_bundle, write_bundle_all

    if verify:
        r = verify_bundle(verify, pubkey=pubkey, log=lambda m: rprint(f"[dim]{m}[/dim]"))
        if r["error"]:
            rprint(f"[red]{r['error']}[/red]")
            raise typer.Exit(code=1)
        t = Table(title=f"verify {verify}")
        for c in ["run", "run id", "members", "signature"]:
            t.add_column(c)
        sig_style = {"verified": "green", "failed": "red", "absent": "dim",
                     "present-unverified": "yellow"}
        for run in r["runs"]:
            st = sig_style.get(run["signature"], "")
            t.add_row(run["run"], run["run_id"] or "—", str(run["members"]),
                      f"[{st}]{run['signature']}[/{st}]" if st else run["signature"])
        rprint(t)
        for pb in r["problems"]:
            rprint(f"  [red]{pb['problem'].upper()}[/red] {pb['run']}{pb['member']} — {pb['detail']}")
        if r["ok"]:
            rprint(f"[green]OK[/green] — {r['members_checked']} member digest(s) match the manifest")
            if any(run["signature"] == "present-unverified" for run in r["runs"]):
                rprint("[yellow]note:[/yellow] a signature is present but was not checked — "
                       "pass --pubkey with the signer's key, obtained out of band")
            return
        rprint(f"[red]FAILED[/red] — {len(r['problems'])} problem(s)")
        raise typer.Exit(code=1)

    if all_runs:
        path = write_bundle_all(root, output)
        rprint(f"wrote [bold]{path}[/bold] (all runs under {root})")
        return
    events = build_audit_events(out)
    if not events:
        rprint(f"[yellow]no audit entries in {out} — nothing has changed a load balancer yet[/yellow]")
    path = write_bundle(out, output)
    rprint(f"wrote [bold]{path}[/bold] · {len(events)} audit event(s)")


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


@app.command()
def drift(
    lb: str = typer.Option(..., "--lb", help="load balancer to inspect"),
    out: str = typer.Option("out", help="run directory holding the snapshots to compare against"),
    control: str = typer.Option(None, "--control", help="the control you are about to apply"),
    policy: str = typer.Option(None, "--policy", help="service-policy name you are about to attach"),
    finding: str = typer.Option(None, "--finding", help="use this finding's exploit for the shadowing check"),
    artifact: str = typer.Option(None, "--artifact", help="the generated policy artifact you are about to apply; without it the shadowing check has no rules to walk"),
):
    """What is on the LB now, versus what the last run left, versus what you are about to push.

    Read-only: no PUT, no snapshot written, nothing in the run dir touched."""
    import json as _json
    from pathlib import Path as _Path

    from .apply import _load_probe
    from .drift import check

    load_dotenv()
    exploit = (_load_probe(out, finding) or {}).get("exploit") if finding else None
    art = artifact or (str(_Path(out, "policies", f"service_policy.{policy}.json")) if policy else None)
    spec = _json.loads(_Path(art).read_text()) if art and _Path(art).is_file() else None
    r = check(lb, out_dir=out, control=control, policy_name=policy, exploit=exploit, spec=spec,
              log=lambda m: rprint(f"[dim]{m}[/dim]"))
    lvs = r["live_vs_snapshot"]
    t = Table(title=f"drift · {lb}")
    for c in ["field", "last snapshot", "live now"]:
        t.add_column(c)
    for c in lvs["changes"]:
        t.add_row(c["path"], _json.dumps(c["was"])[:60], _json.dumps(c["now"])[:60])
    if lvs["changes"]:
        rprint(t)
    elif lvs["snapshot"]:
        rprint(f"[green]no drift[/green] since {lvs['snapshot']}")
    else:
        rprint("[dim]no snapshot for this LB yet — nothing to compare against[/dim]")
    rprint(f"attached controls: {', '.join(r['attached']) or '(none)'}")
    if r["proposed"]["no_change"]:
        rprint(f"[yellow]no_change[/yellow] — {r['proposed']['policy_name']} is already attached")
    elif r["proposed"]["note"]:
        rprint(f"[dim]{r['proposed']['note']}[/dim]")
    for d in r["displaces"]:
        detail = "contents unreadable" if d.get("unreadable") else f"{d['rules']} rule(s), {d['denies']} DENY"
        rprint(f"[yellow]⚠ applying will DETACH[/yellow] '{d['policy']}' ({detail})"
               + ("  [red]— and it is what currently blocks this exploit[/red]"
                  if d["protects_exploit"] else ""))
    for c in r["conflicts"]:
        rprint(f"[red]CONFLICT[/red] {c['reason']}")
    for w in r["warnings"]:
        rprint(f"[yellow]⚠ {w}[/yellow]")
    if not r["ok_to_apply"]:
        raise typer.Exit(code=1)


@app.command(name="xc-status")
def xc_status(lb: str = typer.Option("vpcopilot-lab", help="HTTP LB name")):
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
