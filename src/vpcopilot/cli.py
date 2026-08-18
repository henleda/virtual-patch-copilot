"""CLI entrypoint. `vpcopilot scan <repo>` runs the read-only brain (no XC/GitHub
writes) and drops findings, triage, policy specs, and code-fix PR drafts into ./out."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

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
    repo: str = typer.Argument(None, help="path to the target application repo (omit when using --cve)"),
    cve: str = typer.Option(None, "--cve", help="scan a security advisory instead of a repo: CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx, PYSEC-YYYY-NN, GO-… or RUSTSEC-…"),
    spec: str = typer.Option(None, "--spec", help="an OpenAPI/Swagger spec to scan for flaws IN THE CONTRACT — alone, or alongside a repo to also report spec/code drift"),
    manifest: list[str] = typer.Option(None, "--manifest", help="a dependency manifest (requirements.txt, package-lock.json, pom.xml) to resolve against OSV — repeatable, alone or alongside a repo"),
    min_severity: str = typer.Option("high", "--min-severity", help="--manifest: floor for reaching the resolve agent (critical|high|medium|low). Advisories below it are still listed in dependencies.json"),
    max_advisories: int = typer.Option(25, "--max-advisories", help="--manifest: cap on advisories sent to the resolve agent (0 = no cap). What the cap held back is listed and counted, never dropped silently"),
    include_dev: bool = typer.Option(False, "--include-dev", help="--manifest: also resolve dev/test-scoped dependencies (default: runtime only — a build-time package is not in the request path)"),
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
    """Discover -> verify -> triage -> generate policies + code-fix PRs (read-only).

    With --cve the input is a security advisory instead of a repo: the advisory is resolved from
    OSV.dev, an agent derives its HTTP exploitation profile (or says there isn't one), and the
    result enters the same triage and generate stages.

    With --manifest the input is a dependency manifest, and the same happens for every exploitable
    advisory affecting a package it pins. Additive: pass a repo too and the code findings and the
    dependency findings correlate together."""
    if cve and (repo or spec or manifest):
        raise typer.BadParameter("--cve scans one advisory; it cannot be combined with a repo, "
                                 "--spec or --manifest")
    if not (repo or cve or spec or manifest):
        raise typer.BadParameter("pass a repo path, --cve, --spec, or --manifest")
    if min_severity not in ("critical", "high", "medium", "low"):
        raise typer.BadParameter(f"--min-severity must be critical, high, medium or low, not "
                                 f"'{min_severity}'")
    if code_fixes is None:  # match the console default (app.py /api/defaults) so headless == UI
        code_fixes = os.environ.get("VPCOPILOT_SCAN_REMEDIATE", "1").lower() not in ("0", "false", "no")
    summary = run_pipeline(repo, out_dir=out, config_path=config, min_confidence=min_confidence,
                           concurrency=concurrency, max_files=max_files, max_bytes=max_bytes,
                           draft_code_fixes=code_fixes, advisory=cve, spec_path=spec,
                           manifest_paths=list(manifest or []) or None, min_severity=min_severity,
                           max_advisories=max_advisories, include_dev=include_dev,
                           log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit(
        "\n".join(f"[bold]{k}[/bold]: {v}" for k, v in summary.items()),
        title="virtual-patch-copilot",
    ))


@app.command()
def deps(
    manifest: list[str] = typer.Argument(..., help="dependency manifests: requirements.txt, package-lock.json, pom.xml"),
    min_severity: str = typer.Option("high", "--min-severity", help="floor a scan would resolve at (critical|high|medium|low)"),
    max_advisories: int = typer.Option(25, "--max-advisories", help="cap a scan would apply (0 = no cap)"),
    include_dev: bool = typer.Option(False, "--include-dev", help="also count dev/test-scoped dependencies"),
    json_out: str = typer.Option(None, "--json", help="write the full report to this path"),
    show: int = typer.Option(20, "--show", help="advisory rows to print (0 = all)"),
):
    """List what a --manifest scan would find, without spending a single model call.

    Read-only and credential-free: it parses the manifests, asks OSV which pinned packages have
    advisories, and prints the funnel a scan would run — including every entry it could NOT pin,
    which is the half a dependency scanner usually leaves out."""
    if min_severity not in ("critical", "high", "medium", "low"):
        raise typer.BadParameter(f"--min-severity must be critical, high, medium or low, not "
                                 f"'{min_severity}'")
    from .inputs.deps import survey_report
    rep = survey_report(list(manifest), min_severity=min_severity, max_advisories=max_advisories,
                        include_dev=include_dev, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    f = rep["funnel"]
    t = Table(title="dependency advisories")
    for c in ["severity", "package", "installed", "advisory", "fixed", "disposition"]:
        t.add_column(c)
    rows = rep["advisories"] if not show else rep["advisories"][:show]
    for a in rows:
        t.add_row(a["severity"], a["package"], a["installed"], a["advisory_id"],
                  a["fixed_version"] or "[yellow]none[/yellow]", a["disposition"])
    rprint(t)
    if show and len(rep["advisories"]) > show:
        rprint(f"[dim]… {len(rep['advisories']) - show} more (--show 0 for all)[/dim]")
    rprint(Panel.fit("\n".join(f"[bold]{k}[/bold]: {v}" for k, v in f.items()),
                     title="funnel"))
    if rep["unpinned"]:
        # The loud half: a package whose version we could not establish was never checked, and
        # that must not read the same way as a package that was checked and came back clean.
        rprint(f"[yellow]{len(rep['unpinned'])} entry(ies) could not be pinned and were NOT "
               f"checked[/yellow] — {', '.join(sorted({u['reason'] for u in rep['unpinned']}))}")
    for u in rep.get("unchecked") or []:
        # Flagged as having advisories, then the follow-up query failed. Unknown, not absent.
        rprint(f"[red]could not check {u['ecosystem']}/{u['name']} {u['version']}[/red] — "
               f"{u['error']}; its advisories are UNKNOWN, not absent")
    for e in rep["errors"]:
        rprint(f"[red]{e['path']}: {e['error']}[/red]")
    if json_out:
        Path(json_out).write_text(json.dumps(rep, indent=2))
        rprint(f"wrote [bold]{json_out}[/bold]")


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
    url: str = typer.Option("https://your-app.example.com", envvar="VPCOPILOT_DEFAULT_URL", help="live host to validate against"),
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
    allow_overbroad: bool = typer.Option(False, "--allow-overbroad", help="apply despite the G2 blast-radius gate: a policy a simulation found too broad. Writes a simulate_override audit record"),
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
                                          finding_id=finding, force=force,
                                          allow_overbroad=allow_overbroad, out_dir=out, log=logf)
    elif from_scan:
        from .apply import apply_from_scan
        res = apply_from_scan(from_scan, lb, url, name=name, create_only=create_only, force=force,
                              allow_overbroad=allow_overbroad, **kw)
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
    url: str = typer.Option("https://your-app.example.com", envvar="VPCOPILOT_DEFAULT_URL", help="live host for the behavioral burst"),
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
    url: str = typer.Option("https://your-app.example.com", envvar="VPCOPILOT_DEFAULT_URL", help="live host to validate against"),
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
    url: str = typer.Option("https://your-app.example.com", envvar="VPCOPILOT_DEFAULT_URL", help="live host to validate against"),
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
    domain: str = typer.Option(..., "--domain", help="hostname for the test LB, e.g. vampi.example.com"),
    origin: str = typer.Option(..., "--origin", help="app origin host:port, e.g. 16.59.6.127:5000"),
    name: str = typer.Option(None, "--name", help="base name (default: first label of the domain)"),
    origin_tls: bool = typer.Option(False, "--origin-tls", help="origin serves HTTPS (default: HTTP)"),
    pool_template: str = typer.Option(None, "--pool-template", help="origin pool to clone for its required XC fields (default: $VPCOPILOT_LAB_POOL_TEMPLATE)"),
    lb_template: str = typer.Option(None, "--lb-template", help="HTTP LB to clone, then strip every security control from (default: $VPCOPILOT_LAB_LB_TEMPLATE)"),
):
    """Stand up a clean-slate XC test LB for an app origin (pool + LB), then print the DNS to add.

    The lab is built by CLONING a known-good pool and LB, so every required XC field is present,
    and then stripping the copy back to a clean slate. Which objects to clone is configuration:
    `--pool-template` / `--lb-template`, or `$VPCOPILOT_LAB_POOL_TEMPLATE` /
    `$VPCOPILOT_LAB_LB_TEMPLATE`. The templates are only ever READ."""
    from .lab import create_lab

    res = create_lab(domain, origin, name=name, origin_tls=origin_tls,
                     pool_template=pool_template, lb_template=lb_template,
                     log=lambda m: rprint(f"[dim]{m}[/dim]"))
    rprint(Panel.fit(
        f"[bold]LB[/bold]: {res['lb']}\n[bold]pool[/bold]: {res['pool']} -> {res['origin']}\n"
        f"[bold]URL[/bold]: {res['url']}", title="lab-create"))
    a, acme = res["dns_records"]["a"], res["dns_records"]["acme"]
    rprint("\n[bold]Add these DNS records to the example.com zone:[/bold]")
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
def emit(
    finding: str = typer.Option(None, "--finding", help="finding id to emit for (default: every finding with a generated band-aid)"),
    target: str = typer.Option("bigip-awaf", "--target", help="enforcement point: bigip-awaf | nginx-app-protect | xc"),
    out: str = typer.Option("out", "--out", help="run directory to read findings, policies and probes from"),
    output: str = typer.Option(None, "--output", help="write the emitted policy here (default: <out>/emitted/)"),
    protocol: str = typer.Option("http", "--protocol", help="protocol of the virtual server the policy will hang off — part of the URL's identity in ASM, not a hint"),
):
    """L1: emit a finding's band-aid for an enforcement point other than XC.

    A **declarative WAF policy**, which BIG-IP Advanced WAF and F5 WAF for NGINX (App Protect) both
    consume — so one finding covers the XC control it already generates *and* the enforcement points
    a customer already owns. The two differ only in `policy.template.name`.

    The constraint is derived **by code** from the finding's recorded exploit and legit requests, not
    by a model: the exploit sends a negative amount and the legit request does not, so the field, its
    type and the bound between them are facts. Where the evidence does not establish exactly one such
    field, it declines rather than guessing.

    A control with no declarative equivalent (rate limiting, malicious-user, bot defense) reports
    `unsupported` with a named reason and emits nothing.

        vpcopilot emit --out out --target bigip-awaf
        vpcopilot emit --out out --finding neg-pay-001 --target nginx-app-protect
    """
    from rich.markup import escape

    from .emitters import TARGETS, EmitError
    from .emitters import emit as emit_one

    def _short(s: str, n: int = 60) -> str:
        """Truncate only when there IS more — an unconditional ellipsis marks a short reason as
        cut off, which is its own small lie about what the tool knows."""
        s = str(s)
        return s if len(s) <= n else s[:n] + "…"

    if target not in TARGETS:
        rprint(f"[red]unknown target '{target}'[/red] — known: {', '.join(sorted(TARGETS))}")
        raise typer.Exit(2)

    out_p = Path(out)

    def _load(name, default):
        """A corrupt artifact is a decline with a reason, not a traceback. `policies.json` and
        `probes.json` are rewritten by every scan and can be caught mid-write; the J4 precedent is
        that an unreadable index means nothing can be established, which is an answer."""
        p = out_p / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError) as e:
            rprint(f"[red]cannot read {escape(str(p))}: {escape(str(e))}[/red]")
            raise typer.Exit(1)

    policies = _load("policies.json", [])
    probes = _load("probes.json", [])
    by_finding = {p.get("finding_id"): p for p in probes if isinstance(p, dict)}
    if not policies:
        rprint(f"[yellow]no policies.json in {escape(out)} — run a scan first[/yellow]")
        raise typer.Exit(1)

    rows, emitted = [], []
    for entry in policies:
        fid = entry.get("finding_id")
        if finding and fid != finding:
            continue
        control, name = entry.get("control", ""), entry.get("policy_name", "")
        spec_path = out_p / "policies" / f"{control}.{name}.json"
        try:
            spec = json.loads(spec_path.read_text()) if spec_path.exists() else None
        except (json.JSONDecodeError, OSError):
            spec = None      # the declarative targets do not read it; xc will decline for want of it
        try:
            res = emit_one(target=target, control=control, policy_name=name, spec=spec,
                           probe=by_finding.get(fid), protocol=protocol)
        except EmitError as e:
            rprint(f"[red]{escape(str(e))}[/red]")
            raise typer.Exit(1)
        rows.append((fid, control, name, res))
        if res.supported:
            emitted.append(res)

    if not rows:
        rprint(f"[yellow]nothing to emit{f' for finding {escape(finding)}' if finding else ''}[/yellow]")
        raise typer.Exit(1)

    t = Table(title=f"emit → {TARGETS[target].display}")
    for c in ("finding", "control", "policy", "emitted", "why not"):
        t.add_column(c)
    for fid, control, name, res in rows:
        mark = "[green]yes[/green]" if res.supported else "[yellow]unsupported[/yellow]"
        # EVERY cell is escaped: `policy_name` and `finding_id` are free strings a MODEL chose
        # (schemas.py calls policy_name a "kebab-case XC object name" but nothing validates it), and
        # Rich parses markup inside table cells. A name carrying `[` raised MarkupError, printed a
        # traceback and wrote NOTHING — after the constraint had derived correctly.
        t.add_row(escape(fid or ""), escape(control), escape(name), mark,
                  "" if res.supported else escape(_short(res.reason)))
    rprint(t)

    dest = Path(output) if output else out_p / "emitted"
    dest.mkdir(parents=True, exist_ok=True)
    for res in emitted:
        # `policy_name` is a free string a MODEL chose, and it is being interpolated into a
        # filename. A name carrying `/` or `..` walks straight out of the output directory
        # (`emitted/bigip-awaf.../../etc/x.json` resolves outside `emitted/`) — the K1 precedent,
        # where a policy name reaching a path was refused rather than trusted.
        safe = re.sub(r"\.{2,}", ".", re.sub(r"[^A-Za-z0-9._-]", "_", res.policy_name))
        safe = safe.strip("._") or "policy"
        p = dest / f"{target}.{safe}.json"
        if not p.resolve().is_relative_to(dest.resolve()):
            rprint(f"[red]refusing to write outside {escape(str(dest))}[/red]")
            raise typer.Exit(1)
        p.write_text(json.dumps(res.policy, indent=2))
        rprint(f"[dim]wrote {escape(str(p))}[/dim]")
        if res.reason:      # a caveat on a policy that WAS emitted (e.g. a nested parameter)
            rprint(f"[yellow]⚠ {escape(res.reason)}[/yellow]")
    if not emitted:
        rprint("[yellow]nothing was emitted — every candidate declined, with a reason above[/yellow]")
        raise typer.Exit(1)
    rprint(f"[dim]{len(emitted)} policy(ies) → {dest}. "
           f"Load one onto the lab appliance to prove it blocks: see docs/USAGE.md §7c[/dim]")


@app.command(name="bigip-lab")
def bigip_lab(
    action: str = typer.Argument(..., help="create | rm | status"),
    tenant: str = typer.Option("vpcopilot_lab", "--tenant", help="AS3 tenant — the blast-radius boundary; everything lands under it and nothing outside it can be touched"),
    origin: str = typer.Option(None, "--origin", help="app origin host:port behind the appliance, e.g. 10.30.10.22:8080 (create)"),
    virtual_address: str = typer.Option(None, "--virtual-address", help="address the virtual server listens on (create)"),
    virtual_port: int = typer.Option(80, "--virtual-port", help="port the virtual server listens on"),
    app_name: str = typer.Option("lab", "--app", help="AS3 application name inside the tenant"),
    allow_protected: bool = typer.Option(False, "--allow-protected-tenant", help="mutate a tenant listed in $VPCOPILOT_PROTECTED_BIGIP_TENANTS"),
    dry_run: bool = typer.Option(False, "--dry-run", help="ask AS3 what it WOULD change; writes nothing"),
    out: str = typer.Option("out", "--out", help="run directory the audit record is written to"),
):
    """L2: stand up (or tear down) the BIG-IP lab the declarative WAF emitter is validated against.

    An HTTP virtual server in front of one origin, deliberately **clean-slate** — no WAF policy is
    attached, because the point of the lab is to watch the copilot attach one and watch the exploit
    stop working.

    Unlike `lab-create` this has an explicit inverse and writes an audit record, which are the two
    gaps the XC version has. The guard is the AS3 tenant: `/Common` is refused outright, and
    anything in `$VPCOPILOT_PROTECTED_BIGIP_TENANTS` needs `--allow-protected-tenant`.

        vpcopilot bigip-lab status
        vpcopilot bigip-lab create --origin 10.30.10.22:8080 --virtual-address 10.30.10.190
        vpcopilot bigip-lab rm --tenant vpcopilot_lab
    """
    from rich.markup import escape

    from . import bigip_lab as lab
    from .bigip_lab import LabRefused

    # An appliance error string can contain a JSON body with brackets, which Rich reads as markup
    # and silently drops — the J4 precedent, where the one word that mattered vanished.
    escape_ = lambda s: escape(str(s))  # noqa: E731


    # `escape`, because these messages legitimately contain `[dry-run]` and Rich reads that as a
    # markup tag and silently drops it — the J4 precedent, where the one word telling an operator
    # nothing was written was the word that vanished.
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731

    if action == "status":
        st = lab.status()
        if not st["configured"]:
            rprint(Panel.fit("[yellow]no BIG-IP configured[/yellow]\n"
                             "[dim]set BIGIP_URL, BIGIP_USER and BIGIP_PASSWORD[/dim]",
                             title="bigip-lab"))
            raise typer.Exit()
        if not st.get("reachable"):
            rprint(Panel.fit(f"[red]unreachable[/red]: {escape_(st['reason'])}", title="bigip-lab"))
            raise typer.Exit(1)
        if st.get("as3_installed") is False or st.get("as3") is None:
            # Reachable but unusable, which is NOT the same as unreachable and needs a different
            # fix — every PAYG image ships without AS3, and this lab hit exactly that.
            rprint(Panel.fit(f"[red]AS3 unavailable[/red]: {escape_(st['reason'])}",
                             title="bigip-lab"))
            raise typer.Exit(1)
        # `tenants` is empty for two different reasons — genuinely none, or we could not ask — so
        # a `reason` alongside an empty list must not read as "this appliance has no tenants".
        tenants = ", ".join(st["tenants"]) or ("[yellow]unknown[/yellow]" if st.get("reason") else "(none)")
        body = (f"[bold]AS3[/bold]: {st['as3']}\n"
                f"[bold]tenants[/bold]: {tenants}\n"
                f"[bold]protected[/bold]: {', '.join(st.get('protected') or [])}")
        if st.get("reason"):
            body += f"\n[yellow]{escape_(st['reason'])}[/yellow]"
        rprint(Panel.fit(body, title="bigip-lab status"))
        raise typer.Exit()

    # A refused guard is an ANSWER, not a crash: it exits non-zero so a script or a CI gate can act
    # on it, and it prints the reason rather than a traceback. Found by running this live — the
    # guard fired correctly and then reported itself as a Python error with exit code 0, which is
    # the one way a refusal can be worse than no guard at all.
    try:
        if action == "create":
            if not origin or not virtual_address:
                rprint("[red]--origin and --virtual-address are required for create[/red]")
                raise typer.Exit(2)
            res = lab.create(tenant, origin, virtual_address, app=app_name, virtual_port=virtual_port,
                             allow_protected=allow_protected, dry_run=dry_run, out_dir=out, log=log)
            title = "bigip-lab create (dry run)" if dry_run else "bigip-lab create"
            rprint(Panel.fit(f"[bold]tenant[/bold]: {res['tenant']}\n[bold]AS3[/bold]: {res['code']} {res['message']}\n"
                             f"[bold]URL[/bold]: {res['url']}", title=title))
            raise typer.Exit()

        if action == "rm":
            res = lab.remove(tenant, allow_protected=allow_protected, dry_run=dry_run, out_dir=out, log=log)
            if not res["removed"] and res.get("reason"):
                rprint(Panel.fit(f"[yellow]{res['reason']}[/yellow]", title="bigip-lab rm"))
                raise typer.Exit()
            rprint(Panel.fit(f"[bold]tenant[/bold]: {res['tenant']}\n"
                             f"{'[dim]dry run — nothing removed[/dim]' if res.get('dry_run') else '[bold]removed[/bold]'}",
                             title="bigip-lab rm"))
            raise typer.Exit()
    except typer.Exit:
        # `typer.Exit` SUBCLASSES RuntimeError, so a bare `except RuntimeError` swallows every
        # successful exit and re-reports it as a refusal — success rendering as a red failure with
        # exit 1. Caught and re-raised first; found by running the real create/rm cycle, because
        # the offline tests only ever exercised the guard path, where the two are indistinguishable.
        raise
    except LabRefused as e:
        # A policy decision: the tool declined. Exit 3, so a script can tell it from a transport
        # failure — the two need opposite responses (fix the request vs retry).
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title=f"bigip-lab {action}"))
        raise typer.Exit(3)
    except RuntimeError as e:
        # Everything else reaching here is the appliance or the path to it — an unreachable box, a
        # dropped tunnel, missing credentials, an AS3 rejection. Labelling those "refused" told an
        # operator the tool had declined on policy grounds when in fact nobody could reach the box.
        rprint(Panel.fit(f"[red]appliance error[/red]: {escape(str(e))}", title=f"bigip-lab {action}"))
        raise typer.Exit(1)

    rprint(f"[red]unknown action '{action}' — expected create, rm or status[/red]")
    raise typer.Exit(2)


@app.command(name="apply-bigip")
def apply_bigip_cmd(
    finding: str = typer.Option(..., "--finding", help="finding id to apply the Advanced-WAF band-aid for"),
    url: str = typer.Option(..., "--url", envvar="VPCOPILOT_DEFAULT_URL", help="the app's URL, to validate the exploit against"),
    tenant: str = typer.Option("vpcopilot_lab", "--tenant", help="AS3 tenant the app lives in (from bigip-lab create)"),
    app_name: str = typer.Option("lab", "--app", help="AS3 application name inside the tenant"),
    dry_run: bool = typer.Option(False, "--dry-run", help="ask AS3 what it would change; writes nothing"),
    keep: bool = typer.Option(False, "--keep", help="leave the band-aid enforcing (default: roll back after a passing smoke)"),
    allow_protected: bool = typer.Option(False, "--allow-protected-tenant", help="mutate a tenant in $VPCOPILOT_PROTECTED_BIGIP_TENANTS"),
    out: str = typer.Option("out", "--out", help="run dir to read the band-aid from + write the audit record"),
):
    """Attach a finding's declarative WAF band-aid to your own BIG-IP (Advanced WAF), validate it
    against the finding's real exploit, and roll it back if it does not block. Requires
    `vpcopilot bigip-lab create` to have stood the tenant up first. The AS3 tenant is the blast-radius
    boundary; `/Common` and `$VPCOPILOT_PROTECTED_BIGIP_TENANTS` are refused."""
    from rich.markup import escape

    from .bigip import BigIPError
    from .bigip_apply import apply_bigip
    from .bigip_lab import LabRefused
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731
    try:
        res = apply_bigip(finding, tenant=tenant, app=app_name, url=url, dry_run=dry_run, keep=keep,
                          allow_protected=allow_protected, out_dir=out, log=log)
    except LabRefused as e:
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title="apply-bigip"))
        raise typer.Exit(3)
    except (BigIPError, RuntimeError) as e:
        rprint(Panel.fit(f"[red]appliance error[/red]: {escape(str(e))}", title="apply-bigip"))
        raise typer.Exit(1)
    if not res.get("applied"):
        if res.get("dry_run"):
            rprint(Panel.fit(f"[bold]{escape(res['policy_name'])}[/bold] would deploy to "
                             f"{escape(tenant)}/{escape(app_name)} — [dim]dry run, nothing changed[/dim]",
                             title="apply-bigip (dry run)"))
        else:
            rprint(Panel.fit(f"[yellow]no Advanced-WAF band-aid[/yellow]: {escape(res.get('reason', ''))}",
                             title="apply-bigip"))
        raise typer.Exit()
    verdict = ("[green]blocked ✓ kept[/green]" if res["kept"] else
               "[green]blocked ✓[/green] [dim]rolled back (smoke)[/dim]" if res["passed"] else
               "[red]did not block — rolled back[/red]")
    rprint(Panel.fit(f"[bold]finding[/bold]: {escape(finding)}\n"
                     f"[bold]tenant[/bold]: {escape(tenant)}/{escape(app_name)}\n"
                     f"[bold]policy[/bold]: {escape(res['policy_name'])}\n"
                     f"[bold]result[/bold]: {verdict}", title="apply-bigip"))
    raise typer.Exit(0 if res["passed"] else 1)


@app.command(name="retire-bigip")
def retire_bigip_cmd(
    finding: str = typer.Option(..., "--finding", help="finding id whose BIG-IP band-aid to detach"),
    tenant: str = typer.Option("vpcopilot_lab", "--tenant", help="AS3 tenant the app lives in"),
    app_name: str = typer.Option("lab", "--app", help="AS3 application name inside the tenant"),
    allow_protected: bool = typer.Option(False, "--allow-protected-tenant"),
    out: str = typer.Option("out", "--out"),
):
    """Detach a finding's BIG-IP band-aid: redeploy the app without the WAF. The app stays up — only
    the temporary control comes off."""
    from rich.markup import escape

    from .bigip import BigIPError
    from .bigip_apply import retire_bigip
    from .bigip_lab import LabRefused
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731
    try:
        retire_bigip(finding, tenant=tenant, app=app_name, allow_protected=allow_protected, out_dir=out, log=log)
    except LabRefused as e:
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title="retire-bigip"))
        raise typer.Exit(3)
    except (BigIPError, RuntimeError) as e:
        rprint(Panel.fit(f"[red]appliance error[/red]: {escape(str(e))}", title="retire-bigip"))
        raise typer.Exit(1)
    rprint(Panel.fit(f"[green]retired[/green] {escape(finding)} — WAF detached from "
                     f"{escape(tenant)}/{escape(app_name)}", title="retire-bigip"))


@app.command(name="nginx-lab")
def nginx_lab_cmd(
    action: str = typer.Argument(..., help="create | rm | status"),
    server: str = typer.Option("vpcopilot.lab", "--server", help="server_name the copilot owns — the blast-radius boundary"),
    origin: str = typer.Option(None, "--origin", help="app origin host:port the vhost proxies to, e.g. 10.30.10.22:8080 (create)"),
    location: str = typer.Option("/", "--location", help="location the band-aid attaches to"),
    listen: int = typer.Option(80, "--listen", help="port the vhost listens on"),
    allow_protected: bool = typer.Option(False, "--allow-protected-site", help="mutate a server in $VPCOPILOT_PROTECTED_NGINX_SITES"),
    dry_run: bool = typer.Option(False, "--dry-run", help="stage + nginx -t; writes nothing"),
    out: str = typer.Option("out", "--out", help="run directory the audit record is written to"),
):
    """L2: stand up (or tear down) the copilot's NGINX vhost the App Protect emitter is validated
    against — a reverse proxy to one origin, deliberately **clean-slate** (App Protect OFF until the
    copilot attaches a band-aid). The guard is the server_name: the catch-all `_` is refused outright,
    and anything in `$VPCOPILOT_PROTECTED_NGINX_SITES` needs `--allow-protected-site`.

        vpcopilot nginx-lab status
        vpcopilot nginx-lab create --origin 10.30.10.22:8080 --server vpcopilot.lab
        vpcopilot nginx-lab rm --server vpcopilot.lab
    """
    from rich.markup import escape

    from . import nginx_lab as lab
    from .nginx_lab import LabRefused
    escape_ = lambda s: escape(str(s))  # noqa: E731
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731

    if action == "status":
        st = lab.status()
        if not st["configured"]:
            rprint(Panel.fit("[yellow]no NGINX box configured[/yellow]\n"
                             "[dim]set NGINX_SSH_HOST / NGINX_SSH_USER / NGINX_SSH_KEY[/dim]",
                             title="nginx-lab"))
            raise typer.Exit()
        if not st.get("reachable"):
            rprint(Panel.fit(f"[red]unreachable[/red]: {escape_(st['reason'])}", title="nginx-lab"))
            raise typer.Exit(1)
        body = (f"[bold]nginx[/bold]: {escape_(st.get('version', ''))}\n"
                f"[bold]App Protect[/bold]: {'loaded' if st.get('app_protect') else 'NOT loaded'}\n"
                f"[bold]protected[/bold]: {', '.join(st.get('protected') or [])}")
        rprint(Panel.fit(body, title="nginx-lab status"))
        raise typer.Exit()

    try:
        if action == "create":
            if not origin:
                rprint("[red]--origin is required for create[/red]")
                raise typer.Exit(2)
            res = lab.create(server, origin, location=location, listen=listen,
                             allow_protected=allow_protected, dry_run=dry_run, out_dir=out, log=log)
            title = "nginx-lab create (dry run)" if dry_run else "nginx-lab create"
            rprint(Panel.fit(f"[bold]server[/bold]: {escape(res['server'])}\n"
                             f"[bold]URL[/bold]: {escape(res['url'])}", title=title))
            raise typer.Exit()
        if action == "rm":
            res = lab.remove(server, allow_protected=allow_protected, dry_run=dry_run, out_dir=out, log=log)
            rprint(Panel.fit(f"[bold]server[/bold]: {escape(res['server'])}\n"
                             f"{'[dim]dry run — nothing removed[/dim]' if res.get('dry_run') else '[bold]removed[/bold]'}",
                             title="nginx-lab rm"))
            raise typer.Exit()
    except typer.Exit:
        raise
    except LabRefused as e:
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title=f"nginx-lab {action}"))
        raise typer.Exit(3)
    except RuntimeError as e:
        rprint(Panel.fit(f"[red]box error[/red]: {escape(str(e))}", title=f"nginx-lab {action}"))
        raise typer.Exit(1)

    rprint(f"[red]unknown action '{action}' — expected create, rm or status[/red]")
    raise typer.Exit(2)


@app.command(name="apply-nginx")
def apply_nginx_cmd(
    finding: str = typer.Option(..., "--finding", help="finding id to apply the App Protect band-aid for"),
    url: str = typer.Option(..., "--url", envvar="VPCOPILOT_DEFAULT_URL", help="the app's URL THROUGH the box, to validate the exploit against"),
    server: str = typer.Option("vpcopilot.lab", "--server", help="server_name the copilot owns (from nginx-lab create)"),
    location: str = typer.Option("/", "--location", help="location to attach the band-aid to"),
    dry_run: bool = typer.Option(False, "--dry-run", help="stage + nginx -t; writes nothing"),
    keep: bool = typer.Option(False, "--keep", help="leave the band-aid enforcing (default: roll back after a passing smoke)"),
    allow_protected: bool = typer.Option(False, "--allow-protected-site", help="mutate a server in $VPCOPILOT_PROTECTED_NGINX_SITES"),
    out: str = typer.Option("out", "--out", help="run dir to read the band-aid from + write the audit record"),
):
    """Attach a finding's App Protect band-aid to your own NGINX+App-Protect box, validate it against
    the finding's real exploit, and roll it back if it does not block. Requires `vpcopilot nginx-lab
    create` first. The server_name is the blast-radius boundary; the catch-all `_` and
    `$VPCOPILOT_PROTECTED_NGINX_SITES` are refused."""
    from rich.markup import escape

    from .nginx import NginxError
    from .nginx_apply import apply_nginx
    from .nginx_lab import LabRefused
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731
    try:
        res = apply_nginx(finding, server=server, location=location, url=url, dry_run=dry_run,
                          keep=keep, allow_protected=allow_protected, out_dir=out, log=log)
    except LabRefused as e:
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title="apply-nginx"))
        raise typer.Exit(3)
    except (NginxError, RuntimeError) as e:
        rprint(Panel.fit(f"[red]box error[/red]: {escape(str(e))}", title="apply-nginx"))
        raise typer.Exit(1)
    if not res.get("applied"):
        if res.get("dry_run"):
            rprint(Panel.fit(f"[bold]{escape(res.get('policy_name', ''))}[/bold] would deploy to "
                             f"{escape(server)}{escape(location)} — [dim]dry run, nothing changed[/dim]",
                             title="apply-nginx (dry run)"))
        else:
            rprint(Panel.fit(f"[yellow]no App Protect band-aid[/yellow]: {escape(res.get('reason', ''))}",
                             title="apply-nginx"))
        raise typer.Exit()
    verdict = ("[green]blocked ✓ kept[/green]" if res["kept"] else
               "[green]blocked ✓[/green] [dim]rolled back (smoke)[/dim]" if res["passed"] else
               "[red]did not block — rolled back[/red]")
    rprint(Panel.fit(f"[bold]finding[/bold]: {escape(finding)}\n"
                     f"[bold]server[/bold]: {escape(server)}{escape(location)}\n"
                     f"[bold]policy[/bold]: {escape(res['policy_name'])}\n"
                     f"[bold]result[/bold]: {verdict}", title="apply-nginx"))
    raise typer.Exit(0 if res["passed"] else 1)


@app.command(name="retire-nginx")
def retire_nginx_cmd(
    finding: str = typer.Option(..., "--finding", help="finding id whose NGINX band-aid to detach"),
    server: str = typer.Option("vpcopilot.lab", "--server", help="server_name the band-aid is on"),
    location: str = typer.Option("/", "--location", help="location the band-aid is on"),
    allow_protected: bool = typer.Option(False, "--allow-protected-site"),
    out: str = typer.Option("out", "--out"),
):
    """Detach a finding's NGINX band-aid: remove the managed include and reload. The app stays up —
    only the temporary control comes off."""
    from rich.markup import escape

    from .nginx import NginxError
    from .nginx_apply import retire_nginx
    from .nginx_lab import LabRefused
    log = lambda m: rprint(f"[dim]{escape(str(m))}[/dim]")  # noqa: E731
    try:
        retire_nginx(finding, server=server, location=location, allow_protected=allow_protected,
                     out_dir=out, log=log)
    except LabRefused as e:
        rprint(Panel.fit(f"[red]refused[/red]: {escape(str(e))}", title="retire-nginx"))
        raise typer.Exit(3)
    except (NginxError, RuntimeError) as e:
        rprint(Panel.fit(f"[red]box error[/red]: {escape(str(e))}", title="retire-nginx"))
        raise typer.Exit(1)
    rprint(Panel.fit(f"[green]retired[/green] {escape(finding)} — App Protect detached from "
                     f"{escape(server)}{escape(location)}", title="retire-nginx"))


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

    from .engine import validate_xc_name
    try:
        # Parse first: the name is interpolated into the DELETE path, so `./nimbus-bizlogic-policy`
        # sailed past this membership test and then deleted the very policy it protects.
        name = validate_xc_name(name, "service policy")
    except RuntimeError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(code=1)
    if name.lower() in {p.lower() for p in PROTECTED_POLICIES}:
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
    url: str = typer.Option("https://your-app.example.com", envvar="VPCOPILOT_DEFAULT_URL", help="base URL of that LB"),
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
    from .simulate import candidates_from_out, simulate_policies, write_result

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

    from .simulate import effective_threshold
    thr = effective_threshold(threshold)
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
        # Require an explicit unit: `--since ""` used to IndexError on since[-1], and `--since 30`
        # silently parsed "0" as the unit and defaulted to hours — a window the user never asked for.
        m = re.fullmatch(r"(\d+)\s*([mhd])", since.strip().lower())
        if not m:
            raise typer.BadParameter(
                f"--since {since!r}: expected a number followed by a unit m/h/d (e.g. 30m, 6h, 2d)")
        n = int(m.group(1))
        unit = m.group(2)
        delta = _dt.timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})
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


@app.command(name="audit-backfill")
def audit_backfill(
    out: str = typer.Option("out", help="run directory to backfill"),
    dry_run: bool = typer.Option(False, "--dry-run", help="report what would be attributed, write nothing"),
):
    """J4: freeze the finding each audit entry belongs to, while it is still derivable.

    `audit.log` is append-only and is never edited — an entry that cannot say who made a change is
    not an audit record. This writes a sidecar, `<out>/audit-backfill.json`, that the exporter reads
    beside the log.

    Worth running before a re-scan. `policies.json` is rewritten by every scan, so the mapping from
    a policy name back to its finding decays — and if a later scan reuses a policy name for a
    different finding, the exporter's live lookup would attribute an old entry to the WRONG one.
    The sidecar records what is true now, and takes precedence afterwards.

    Nothing is invented: an entry whose finding cannot be established is marked `unknown`, which
    then stops the exporter guessing. A second run changes nothing and writes nothing."""
    from rich.markup import escape

    from .backfill import backfill

    # `escape`, because a log line here legitimately starts with `[dry-run]` and Rich reads that as
    # a markup tag and silently drops it — the marker telling you nothing was written is the one
    # word that must not vanish. (The same pattern appears in other commands; this fixes the one
    # whose messages actually contain brackets.)
    res = backfill(out, dry_run=dry_run, log=lambda m: rprint(f"[dim]{escape(str(m))}[/dim]"))
    body = (f"[bold]entries needing attribution[/bold]: {res['entries']}\n"
            f"[bold]resolved[/bold]: {res['resolved']}   "
            f"[bold]unknown[/bold]: {res['unknown']}")
    if res.get("stale_dropped"):
        body += f"\n[yellow]{res['stale_dropped']} stale row(s) discarded[/yellow]"
    if res.get("reason"):
        body += f"\n[dim]{res['reason']} — nothing written[/dim]"
    elif res["wrote"]:
        body += f"\n[dim]wrote {res['path']}[/dim]"
    rprint(Panel.fit(body, title="audit-backfill"))


@app.command(name="audit-sink")
def audit_sink_cmd(
    send: bool = typer.Option(False, "--send", help="deliver one test event to the configured sink"),
):
    """J3: is the off-box audit sink configured, usable, and reachable?

    `VPCOPILOT_AUDIT_SINK` ships every audit entry to a collector as it is written. A sink that is
    misconfigured, or configured against a collector that is not listening, would otherwise be
    invisible: the run succeeds either way and the only signal is one warning on stderr. This
    reports the configuration without touching the network, and `--send` proves delivery.

    The test event is not an audit record and is written to no `audit.log` — asking whether the
    sink works must not add to the evidence it carries."""
    from .audit_sink import check

    st = check(send=send)
    if not st["configured"]:
        rprint(Panel.fit(f"[yellow]{st['reason']}[/yellow]\n"
                         "[dim]set VPCOPILOT_AUDIT_SINK to https://…, syslog://…, stdout or off[/dim]",
                         title="audit-sink"))
        raise typer.Exit()
    if not st["usable"]:
        rprint(Panel.fit(f"[red]unusable[/red]: {st['reason']}", title="audit-sink"))
        raise typer.Exit(1)
    body = (f"[bold]kind[/bold]: {st['kind']}\n[bold]target[/bold]: {st['target']}\n"
            f"[bold]auth token[/bold]: {'set' if st['token_set'] else 'not set'}")
    if send:
        if st["delivery"] == "sent":
            body += "\n[bold]test delivery[/bold]: [green]sent[/green]"
        elif st["delivery"] == "sent-unconfirmed":
            # Not dressed up as success: a UDP datagram to a port with nothing bound succeeds at
            # the send call, so this says what was actually established and what was not.
            body += ("\n[bold]test delivery[/bold]: [yellow]sent, unconfirmed[/yellow]\n"
                     "[dim]UDP cannot acknowledge — this proves the datagram left this host, not "
                     "that anything received it. Check the collector.[/dim]")
        else:
            body += (f"\n[bold]test delivery[/bold]: [red]{st['delivery']}[/red] "
                     f"({st['last_error'] or 'no detail'})")
    body += "\n[dim]the local audit.log stays authoritative — a sink is a copy, never the record[/dim]"
    rprint(Panel.fit(body, title="audit-sink"))
    if send and not st["delivery"].startswith("sent"):
        raise typer.Exit(1)


@app.command(name="patches-list")
def patches_list_cmd(
    out: str = typer.Option("out", help="output directory"),
    expired_only: bool = typer.Option(False, "--expired-only", help="only patches past their TTL"),
):
    """Every live band-aid with its age, TTL remaining, and cure state.

    A pure read of the ledger — no XC, no GitHub, no exploit fired."""
    from .reconcile import list_patches

    rows = list_patches(out)
    if expired_only:
        rows = [r for r in rows if r["expired"]]
    if not rows:
        rprint("[green]no live band-aids[/green]" if not expired_only else "[green]nothing expired[/green]")
        raise typer.Exit()
    t = Table(title="live band-aids")
    for c in ["finding", "sev", "control", "lb", "age", "TTL left", "cure", "last reconcile"]:
        t.add_column(c)
    for r in rows:
        age = "—" if r["age_hours"] is None else f"{r['age_hours'] / 24:.1f}d"
        if r["remaining_hours"] is None:
            left = "[dim]no TTL[/dim]"
        elif r["expired"]:
            over = abs(r["remaining_hours"]) / 24
            left = f"[red]EXPIRED {over:.1f}d[/red]"
        else:
            left = f"{r['remaining_hours'] / 24:.1f}d"
        cure = r["cure_state"] or "none"
        if r["escalation_count"]:
            cure += f" [red](escalated ×{r['escalation_count']})[/red]"
        t.add_row(r["finding_id"], r.get("severity") or "", r["control"] or "", r["lb"] or "",
                  age, left, cure, r.get("outcome") or "—")
    rprint(t)


@app.command()
def reconcile(
    out: str = typer.Option("out", help="output directory"),
    apply: bool = typer.Option(False, "--apply", help="actually detach a band-aid whose cure is proven; without it the pass reports and changes nothing"),
    finding: str = typer.Option(None, "--finding", help="reconcile a single finding instead of every live patch"),
    force_probe: bool = typer.Option(False, "--force-probe", help="ignore the per-finding probe cooldown (only with --finding)"),
    allow_protected_lb: bool = typer.Option(False, "--allow-protected-lb", help="permit reconciling a protected LB"),
):
    """Walk the live band-aids: check each cure PR, re-fire its exploit at ORIGIN, and act.

    Retire when the cure merged and the exploit is gone; hold and report `fix_ineffective` when it
    merged and the exploit still reproduces; escalate when the TTL passed with no merged cure.
    Report-only unless `--apply`. Targets come from $VPCOPILOT_RECONCILE_TARGETS, never from the
    ledger. Exits 2 when anything escalated, so cron or CI goes red."""
    from .reconcile import reconcile as run

    load_dotenv()
    if force_probe and not finding:
        rprint("[red]--force-probe needs --finding[/red] — replaying every destructive exploit at "
               "once is not something to do by accident.")
        raise typer.Exit(code=1)
    logf = lambda m: rprint(f"[dim]{m}[/dim]")  # noqa: E731
    try:
        res = run(out, apply=apply, finding_id=finding, force_probe=force_probe, trigger="cli",
                  allow_protected=allow_protected_lb, log=logf)
    except RuntimeError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from None
    if res["lock"] == "busy":
        raise typer.Exit()
    rprint(Panel.fit(
        f"[bold]checked[/bold]: {res['checked']}   "
        f"[bold]retired[/bold]: {res['retired']}   "
        f"[bold]escalated[/bold]: {res['escalations']}   "
        f"[bold]fix_ineffective[/bold]: {res['fix_ineffective']}"
        + ("\n[dim]report-only — pass --apply to detach[/dim]" if not apply else ""),
        title=f"reconcile {res['pass_id']}"))
    if res["escalations"] or res["fix_ineffective"]:
        raise typer.Exit(code=2)


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


@app.command(name="ci-review")
def ci_review(
    repo: str = typer.Option(".", help="repository working tree to scan"),
    base: str = typer.Option("origin/main", "--base", help="branch the PR targets; compared against the MERGE BASE"),
    head: str = typer.Option("HEAD", "--head", help="branch/commit under review"),
    out: str = typer.Option("out-ci", help="run directory for this review's artifacts"),
    min_severity: str = typer.Option("high", "--min-severity", help="report findings at or above this (critical|high|medium|low)"),
    min_confidence: float = typer.Option(0.5, "--min-confidence", help="drop verified findings below this confidence"),
    max_files: int = typer.Option(40, "--max-files", help="cap on changed files scanned — a PR diff is small, and CI has a budget"),
    max_bytes: int = typer.Option(60_000, "--max-bytes", help="cap on bytes read per file"),
    pr_repo: str = typer.Option(None, "--pr-repo", help="GitHub slug owner/name, to post the comment"),
    pr: int = typer.Option(None, "--pr", help="pull request number to comment on"),
    post: bool = typer.Option(False, "--post", help="actually post/update the PR comment (needs --pr-repo and --pr)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="with --post, render and report without calling GitHub"),
    comment_out: str = typer.Option(None, "--comment-out", help="also write the rendered comment to this path"),
):
    """K2: scan a pull request's diff and comment the proposed band-aid on it.

    Scans only what the branch changed, against the merge base. Never touches an F5 XC tenant: this
    path imports no tenant client at all, so a CI job needs a GitHub token and nothing else. A
    would-block count cannot be produced here — measuring blast radius means attaching a policy to a
    load balancer — so the comment reports it only from a previous tenant run's `simulation.json`, and
    otherwise says plainly that no measurement was made.

    Prints the comment when `--post` is absent, so it composes in a pipeline. Exits 1 when it reports
    at least one finding, so a workflow can choose to fail the check."""
    from .ci import CIError, review

    load_dotenv()
    if min_severity not in ("critical", "high", "medium", "low"):
        # Unvalidated, an unknown value fell through `SEVERITY_RANK.get(..., 1)` to `high` — and the
        # comment then stated a threshold the run had not actually applied.
        rprint(f"[red]--min-severity must be critical, high, medium or low (got {min_severity!r})[/red]")
        raise typer.Exit(code=2)
    try:
        res = review(repo, base=base, head=head, out_dir=out, min_severity=min_severity,
                     min_confidence=min_confidence, max_files=max_files, max_bytes=max_bytes,
                     config_path=_active_config_path(), repo_slug=pr_repo, pr_number=pr,
                     post=post, dry_run=dry_run, log=lambda m: rprint(f"[dim]{m}[/dim]"))
    except CIError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(code=2) from None
    except Exception as e:  # noqa: BLE001
        # EXIT 2, not 1. Exit 1 means "findings were reported" and the action reads it that way, so
        # letting a crash exit 1 would make a review that never completed look like a completed one
        # with findings — and the workflow would go on to publish a comment file that does not exist.
        rprint(f"[red]ci-review failed: {type(e).__name__}: {e}[/red]")
        raise typer.Exit(code=2) from None
    # Written even when nothing is reported: the action's step summary reads this file, and its
    # absence used to be rendered as "no findings at or above the threshold" — including for a diff
    # that was never reviewed at all.
    if comment_out and res["comment"]:
        Path(comment_out).write_text(res["comment"])
        rprint(f"wrote [bold]{comment_out}[/bold]")
    rprint(Panel.fit(
        f"[bold]changed[/bold]: {res['changed']}   [bold]scanned[/bold]: {res['scanned']}   "
        f"[bold]reported[/bold]: {res['reported']}"
        + (f"\n[dim]{res['reason']}[/dim]" if res.get("reason") else "")
        + (f"\n[dim]comment {'updated' if res.get('updated') else 'created'}[/dim]"
           if res.get("posted") else ""),
        title="ci-review"))
    if not post and res["reported"]:
        print(res["comment"])
    if res["reported"]:
        raise typer.Exit(code=1)


def _active_config_path() -> str | None:
    """The config a CI run should use: whatever VPCOPILOT_CONFIG names, or the default."""
    return os.environ.get("VPCOPILOT_CONFIG") or None


@app.command()
def mcp(write: bool = typer.Option(None, "--write/--no-write",
                                   help="expose the mutating tools (apply, pr, retire, reconcile, "
                                        "simulate). Off unless this flag or VPCOPILOT_MCP_WRITE=1. "
                                        "They still route through the same gates as the CLI, and "
                                        "apply/pr/retire default to a dry run")):
    """Serve the pipeline as MCP tools over stdio, for an agent session (K1).

    Read-only by default: read a finished run (scan_result, impact, patches_list, ledger), survey
    dependencies against OSV (deps), inspect a load balancer (drift), verify an evidence bundle, and
    start or poll a scan. The mutating tools are ABSENT from the tool list unless writes are
    enabled — authoring the client config that enables them is the human action, exercised once, the
    same argument `reconcile --apply` makes about the crontab.

    Nothing is printed here: stdout carries the protocol and only the protocol. Progress and errors
    go to stderr, which the MCP spec reserves for exactly that."""
    import sys as _sys

    from .mcp import serve
    enabled = write if write is not None else \
        os.environ.get("VPCOPILOT_MCP_WRITE", "").lower() in ("1", "true", "yes")
    # stderr, never stdout — one stray character on stdout desynchronises the client.
    print(f"vpcopilot mcp: serving on stdio, writes {'ENABLED' if enabled else 'off'}",
          file=_sys.stderr, flush=True)
    serve(enable_writes=enabled)


def main():
    load_dotenv()  # pull provider keys (ANTHROPIC_API_KEY, etc.) from .env
    app()


if __name__ == "__main__":
    main()
