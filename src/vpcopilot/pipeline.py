"""The deterministic spine: discover -> verify -> triage -> generate + remediate.

The agents reason and return typed artifacts; this code orchestrates and (for now)
writes results to disk. No XC or GitHub writes happen here — that is the next increment,
behind a human approval gate with snapshot/rollback and live-LB validation.

Every verified finding gets a code-fix PR (the cure); band-aids are temporary."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from . import correlate, runmeta
from .agents import discover, generate, remediate, triage, verify
from .config import AGENT_NAMES
from .routes import collect_route_context
from .harness import Harness
from .repo_scan import collect_files, read_numbered


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sev(f):
    return f.severity.value if hasattr(f.severity, "value") else f.severity


def _vclass(f):
    return f.vuln_class.value if hasattr(f.vuln_class, "value") else f.vuln_class


def _dedup_findings(findings, log, counter: dict | None = None):
    """A6: collapse duplicate findings for one vuln — keyed on (file, vuln_class, endpoint-or-line);
    keeps the highest-severity representative so one vuln yields one band-aid + one code-fix PR.

    `counter` receives the number dropped, so the count reaches `metrics.json` instead of only the
    log — the residue the old `BACKLOG.md` per-stage-metrics item left behind."""
    kept, seen = [], {}
    for f in sorted(findings, key=lambda f: _SEV_RANK.get(_sev(f), 9)):
        # `f.file` is always set on the repo path (pipeline sets it after discover), so the
        # fallback is structurally unreachable there — advisory findings, which have no file,
        # would otherwise all key on ("", class, "L0") and silently collapse into one.
        ident = f.file or getattr(f, "source", "") or f.id
        key = (ident, _vclass(f), (getattr(f, "endpoint", "") or f"L{f.line}"))
        if key in seen:
            log(f"  dedup: {f.id} duplicates {seen[key]} ({ident} {key[1]} {key[2]}) — dropped")
            continue
        seen[key] = f.id
        kept.append(f)
    if counter is not None:
        counter["duplicates_dropped"] = len(findings) - len(kept)
    return kept


def validate_scan_inputs(repo_path: str | None = None, spec_path: str | None = None,
                         manifest_paths: list[str] | None = None) -> None:
    """Every input path must exist. Raises ValueError naming the offender.

    This check lived ONLY in mcp.py, so `vpcopilot scan /does/not/exist` and POST /api/scan both
    ran to completion and wrote a clean-bill-of-health summary.json for a directory that was never
    read — the exact behaviour `run_pipeline`'s own docstring calls "the failure mode not to
    extend", extended to two of the three surfaces.

    Public and separate from `run_pipeline` because the console starts scans on a worker thread:
    raising inside the pipeline there would surface as a job error AFTER a 200, so the console
    calls this on the request thread and refuses up front, as MCP already did.
    """
    for label, p in (("repo", repo_path), ("spec", spec_path),
                     *[("manifest", m) for m in (manifest_paths or [])]):
        if p and not Path(p).exists():
            raise ValueError(
                f"{label} path {p!r} does not exist — a scan of nothing would write a summary "
                f"saying nothing was found, which is not the same answer")


def run_pipeline(
    repo_path: str | None = None,
    out_dir: str = "out",
    config_path: str | None = None,
    min_confidence: float = 0.5,
    concurrency: int = 8,
    max_files: int = 200,
    max_bytes: int = 60_000,
    draft_code_fixes: bool = True,   # off = skip remediation (band-aids only); saves ~half the tokens
    log: Callable[[str], None] = print,
    advisory: str | None = None,     # H1: appended AFTER log so no positional call can shift
    spec_path: str | None = None,    # H3: an OpenAPI spec — alone, or alongside a repo
    manifest_paths: list[str] | None = None,   # H2: dependency manifests — alone, or alongside
    min_severity: str = "high",                # H2: floor for reaching the resolve agent
    max_advisories: int = 25,                  # H2: cap on the agent stage (0 = no cap)
    include_dev: bool = False,                 # H2: dev/test-scoped dependencies too
    only_files: set[str] | None = None,        # K2: restrict the walk to a PR's changed files
) -> dict:
    # H1 — exactly one input. Deliberately a hard error rather than a silent no-op: today
    # `run_pipeline("/does/not/exist")` completes and writes a full set of empty artifacts, and
    # that is the failure mode not to extend.
    # H1/H2/H3 — repo and advisory are alternatives; a spec and a manifest are additive. `--spec`
    # alone scans the contract, and with a repo also cross-checks the two for orphans; `--manifest`
    # alone scans the dependency tree, and with a repo covers the code and its dependencies in one
    # run, where correlation can collapse band-aids that overlap across the two.
    if advisory and (repo_path or spec_path or manifest_paths):
        raise ValueError("--cve scans one advisory; it cannot be combined with a repo, "
                         "--spec or --manifest")
    if not (repo_path or advisory or spec_path or manifest_paths):
        raise ValueError("pass a repo path, an advisory id (--cve), an OpenAPI spec (--spec), "
                         "or a dependency manifest (--manifest)")
    validate_scan_inputs(repo_path, spec_path, manifest_paths)
    h = Harness(config_path)
    h.warmup()   # B6: warm instructor's mode registry before ANY fan-out — both inputs need it
    t0, started = time.perf_counter(), runmeta.utc_now()
    dedup_counter: dict = {}
    root = Path(repo_path) if repo_path else None
    files, skipped = [], []
    file_code: dict[str, str] = {}
    file_raw: dict[str, str] = {}
    route_ctx = None
    findings: list = []
    spec_code: dict[str, str] = {}      # H3: spec name -> the text handed to discover
    spec_orphans: dict | None = None
    # H1 supplied exactly one of each; H2 supplies many, so both are keyed by finding id. A finding
    # with a forced decision skips triage, one with a forced remediation skips the remediate agent,
    # and everything without either behaves exactly as it did before this change.
    forced_decisions: dict[str, object] = {}
    forced_remediations: dict[str, object] = {}
    advisory_ids: set[str] = set()      # findings with no source to verify against
    advisory_meta: dict | None = None
    deps_report: dict | None = None

    if advisory:
        # H1 — an advisory produces ONE finding and then joins the ordinary stages. There is no
        # repo to walk, nothing to verify a second time (OSV already asserts the vulnerability is
        # real; re-litigating it against source we do not have would only invent doubt), so the
        # branch supplies `findings` directly and everything from triage down runs unchanged.
        from .inputs.cve import resolve_advisory
        res = resolve_advisory(h, advisory, log=log)
        findings = [res["finding"]]
        advisory_ids.add(res["finding"].id)
        if res["decision"] is not None:
            forced_decisions[res["finding"].id] = res["decision"]
        forced_remediations[res["finding"].id] = res["remediation"]
        advisory_meta = {"id": res["advisory"]["id"], "source": "osv",
                         "consulted": res["advisory"]["consulted"],
                         "network_observable": res["profile"].network_observable,
                         "fixed_version": res["remediation"].fixed_version}
        discover_s = time.perf_counter() - t0
    else:
        if repo_path:
            files, skipped = collect_files(repo_path, max_bytes=max_bytes, max_files=max_files,
                                           only=only_files)
        log(f"scanning {len(files)} files (caps: --max-files {max_files}, --max-bytes {max_bytes}; "
            f"{len(skipped)} skipped)"
            + (f"; restricted to {len(only_files)} changed file(s)" if only_files is not None else ""))
        for reason in ("max-files-reached", "too-large"):
            n = sum(1 for _, r in skipped if r == reason)
            if n:
                log(f"  ⚠ {n} file(s) skipped ({reason}) — raise --max-files/--max-bytes to include them")

        # Ground endpoints in the app's DECLARED routes (OpenAPI spec / framework registrations) so a
        # weaker model looks a finding's path up instead of hallucinating it — and warn loudly if none.
        route_ctx = collect_route_context(repo_path) if repo_path else None
        if spec_path:
            # H3 — the spec is fed to `discover` as one more file rather than through a fourth
            # agent. Its whole job is "read this and tell me what is wrong with it", and routing
            # the spec through the existing stage means these findings verify, triage and generate
            # exactly like a code finding, with no parallel path to keep in step.
            from .inputs.openapi import as_scan_input, load_spec, orphans
            spec_name, spec_text = as_scan_input(spec_path)
            spec_code[spec_name] = spec_text
            log(f"reading OpenAPI spec {spec_path} as a discovery input")
            if repo_path and route_ctx:
                o = orphans(load_spec(spec_path), route_ctx.splitlines())
                spec_orphans = o
                # Say what was ESTABLISHED and what was not. A sweep that matched nothing is not
                # a spec whose endpoints are all unserved — it is a sweep that failed, and the two
                # used to print identically.
                if not o["swept"]:
                    log("  spec vs code: the route sweep found NO routes in the source, so the "
                        "comparison did not run. This is not 'no orphans' — file-based routing "
                        "and dynamically mounted routers leave no line to match.")
                else:
                    log(f"  spec vs code: {len(o['matched'])} matched, "
                        f"{len(o['code_only'])} served-but-undeclared, "
                        f"{len(o['spec_unverified'])} declared endpoint(s) the sweep did not find "
                        f"(NOT reported as orphaned — a source sweep cannot prove absence)")
        if manifest_paths:
            # H2 — a manifest yields findings the same way an advisory does (H1's resolve agent,
            # H1's deterministic no_bandaid route, H1's OSV-sourced cure), so they are appended to
            # `findings` here and every stage below treats them as advisory findings. Additive: with
            # a repo alongside, the code findings and the dependency findings correlate together,
            # which is the point — one band-aid may cover both.
            from .inputs.deps import resolve_manifests
            dres = resolve_manifests(h, manifest_paths, min_severity=min_severity,
                                     max_advisories=max_advisories, include_dev=include_dev,
                                     concurrency=concurrency, log=log)
            deps_report = dres["report"]
            for f in dres["findings"]:
                findings.append(f)
                advisory_ids.add(f.id)
            forced_decisions.update(dres["decisions"])
            forced_remediations.update(dres["remediations"])
        if repo_path and route_ctx:
            log("route context: found the app's declared routes — grounding finding endpoints (no guessing)")
        elif repo_path or spec_path:
            log("  ⚠ NO app route context found (no OpenAPI/Swagger spec or route registrations detected) "
                "— finding endpoints are INFERRED and may be inaccurate")

    # 1) discover (per file, parallel) --------------------------------------
    # One bad file fails soft (below), but a TOTAL discover failure (missing/invalid
    # ANTHROPIC_API_KEY, wrong model id, unreachable provider) makes EVERY file fail soft to 0
    # findings — and without the aggregate check after the fan-out that writes a clean "nothing
    # found" summary and exits 0, the exact false all-clear `validate_scan_inputs` refuses up
    # front. `list.append` is atomic under the GIL, so the worker threads can share this directly.
    discover_failures: list[str] = []

    def _discover(p):
        rel = str(p.relative_to(root))
        try:
            code = read_numbered(p)
            return rel, code, p.read_text(errors="replace"), discover.run(h, rel, code, route_context=route_ctx)
        except Exception as e:  # noqa: BLE001 — B6: one bad file must not kill the whole scan
            discover_failures.append(rel)
            log(f"  ⚠ discover failed on {rel}: {e} — skipping this file")
            from .schemas import FindingList
            return rel, "", "", FindingList(findings=[])

    # B6: instructor's mode registry is warmed at the top of run_pipeline (its lazy init isn't
    # thread-safe) — discover every file in parallel with per-file error isolation. ex.map
    # preserves order.
    disc_results = []
    if files:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            disc_results.extend(ex.map(_discover, files))
        if len(discover_failures) == len(files):
            # Every file errored — this is not "genuinely 0 findings" (that path leaves
            # discover_failures empty); it is a scan that never ran. Hard-fail like
            # validate_scan_inputs rather than write a summary saying nothing was found.
            raise RuntimeError(
                f"discover failed on all {len(files)} file(s) — no file was successfully "
                f"analysed, so a summary reporting 'nothing found' would be a false all-clear. "
                f"Check the model/provider configuration (the API key for the configured provider, "
                f"the model id, and network reachability); the per-file '⚠ discover failed' log "
                f"lines above carry the underlying error.")
    for spec_name, spec_text in spec_code.items():
        # The spec joins the same result list, so it flows through verify/triage/generate unchanged.
        try:
            disc_results.append((spec_name, spec_text, spec_text,
                                 discover.run(h, spec_name, spec_text, route_context=route_ctx)))
        except Exception as e:  # noqa: BLE001 — a bad spec must not kill a repo scan alongside it
            from .schemas import FindingList
            log(f"  ⚠ discover failed on {spec_name}: {e} — skipping the spec")
            disc_results.append((spec_name, spec_text, spec_text, FindingList(findings=[])))
    # A4: the pipeline owns finding ids — a model may reuse one across files. Seeded from findings
    # already present so an H2 advisory id cannot be handed out twice (empty on a repo-only run).
    used_ids: set[str] = {f.id for f in findings}
    for rel, code, raw, res in disc_results:
        file_code[rel] = code
        file_raw[rel] = raw
        for f in res.findings:
            if rel in spec_code:
                # H3 — a spec is ONE file declaring MANY endpoints, so `file` is the wrong identity
                # for it: `endpoint_of("pay-api.yaml")` is the same string for every finding, and
                # all six would collapse onto one service_policy coverage key with five of them
                # logged "already covered". Leave `file` empty and let the endpoint be the identity,
                # exactly as an advisory does.
                f.source, f.file, f.line = f"openapi:{rel}", "", 0
            else:
                f.file = rel
            # J5 — DISCARD anything the model wrote into the classification fields. They are on
            # `Finding`, so they are in the schema instructor hands the discover agent, descriptions
            # and all; a model that fills them would otherwise sail past the choke point's
            # `if not cwe_source` guard, which cannot tell a code-set value from a model-set one.
            # Verified: a response carrying cwe="CWE-840" (PROHIBITED by MITRE) and
            # cwe_source="advisory" was persisted verbatim and labelled a FACT. `file` is
            # overwritten unconditionally two lines up for the same reason.
            f.cwe = f.owasp = f.cwe_source = ""
            base, fid, n = (f.id or "finding"), (f.id or "finding"), 1
            while fid in used_ids:
                n += 1
                fid = f"{base}-{n}"
            f.id = fid
            used_ids.add(fid)
            findings.append(f)
        if res.findings:
            log(f"  {rel}: {len(res.findings)} candidate finding(s)")
    if not advisory:
        discover_s = time.perf_counter() - t0
        log(f"discovered {len(findings)} candidate finding(s)")

    # 2) verify (adversarial, per finding, parallel) ------------------------
    t_verify = time.perf_counter()
    verified = []
    refuted = dropped = 0
    confidences: list[float] = []

    def _verify(f):
        try:
            return f, verify.run(h, f, file_code.get(f.file, ""), route_context=route_ctx)
        except Exception as e:  # noqa: BLE001 — B6: a failed verify drops that finding, not the scan
            log(f"  ⚠ verify failed on {f.id}: {e} — dropping (fail-closed)")
            return f, None

    # A7: severity-weighted gate — critical/high get a lower bar (miss cost is high),
    # medium/low a higher bar (noise cost dominates), both anchored on min_confidence.
    def _threshold(f):
        shift = -0.1 if _sev(f) in ("critical", "high") else 0.1
        return max(0.0, min(1.0, min_confidence + shift))

    # H1/H2 — an advisory finding has no source to read, and verify's entire method is reading the
    # offending code. OSV already asserts the vulnerability is real; re-litigating it against code we
    # do not have would only manufacture doubt. The resolve agent's own confidence is the gate
    # instead. Per-finding rather than per-run, because H2 puts code findings and dependency
    # findings in the same list and only the code ones can be verified.
    to_verify = [f for f in findings if f.id not in advisory_ids]
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for f, v in ex.map(_verify, to_verify):
            if v is None:  # B6: verify errored — count as dropped, keep going
                dropped += 1
                continue
            thr = _threshold(f)
            if v.is_real and v.confidence >= thr:
                verified.append(f)
                confidences.append(v.confidence)
                log(f"  verify {f.id}: REAL ({v.confidence:.2f} ≥ {thr:.2f} for {_sev(f)})")
            elif v.is_real:
                dropped += 1
                log(f"  verify {f.id}: REAL but below {thr:.2f} ({_sev(f)}) — dropped ({v.confidence:.2f})")
            else:
                refuted += 1
                log(f"  verify {f.id}: refuted ({v.confidence:.2f})")
    if spec_orphans and spec_orphans.get("code_only"):
        # Deterministic, no agent: this is a comparison of two documents. Both directions matter and
        # they fail differently — a declared-but-unserved endpoint is dead documentation or a shadow
        # API, while a served-but-undeclared route is what an api_schema band-aid built from this
        # spec would start rejecting the moment it is applied.
        from .schemas import Finding
        # ONLY the served-but-undeclared direction raises a finding now. The other direction is a
        # claim of ABSENCE — "nothing serves this endpoint" — and the route sweep is a line-wise
        # grep that cannot establish absence: file-based routing (app/api/pay/route.js) declares a
        # route with no line to match, and a dynamically mounted router never appears literally.
        # This used to raise a medium finding asserting exactly that, on evidence that could not
        # support it — and it bypasses verify, so nothing downstream ever challenged it. The
        # unmatched declarations are still REPORTED, as `spec_unverified`, phrased as what they
        # are: not checked.
        so, co = [], spec_orphans["code_only"]
        bits = []
        if co:
            bits.append("served by the code but absent from the spec: "
                        + ", ".join(co[:15]) + (f" (+{len(co) - 15} more)" if len(co) > 15 else ""))
        orphan = Finding(
            id="undocumented_or_orphaned",
            title="Spec and code disagree about which endpoints exist",
            vuln_class="other", severity="medium", source=f"openapi:{Path(spec_path).name}",
            description="; ".join(bits) + ". "
            + ("An endpoint nobody serves is dead documentation or a shadow API that was removed "
               "from one place and not the other. " if so else "")
            + ("An endpoint the spec does not declare is outside whatever a schema-based control "
               "enforces — and applying an api_schema band-aid built from this spec would begin "
               "rejecting it." if co else ""),
            exploit_sketch=("Undeclared routes are the surface an attacker reaches that a "
                            "schema-based control never sees." if co
                            else "Declared-but-unserved endpoints indicate the spec and the "
                                 "deployment have drifted; the schema may not describe what is "
                                 "actually exposed."))
        # Appended AFTER verify, to both lists: this is a comparison of two documents, not a claim
        # about code. Sending it through the verify agent asked a reviewer to confirm a
        # vulnerability in source it cannot see, and it duly refuted it at 0.10 confidence.
        findings.append(orphan)
        verified.append(orphan)
        log(f"  undocumented_or_orphaned: {len(so)} declared-but-unserved, "
            f"{len(co)} served-but-undeclared")

    verified += [f for f in findings if f.id in advisory_ids]
    verify_s = time.perf_counter() - t_verify
    if to_verify or not advisory_ids:   # a run with nothing to verify still reported "0 verified"
        log(f"{len(verified)} finding(s) verified real (min-confidence {min_confidence})")

    # 3-5) triage -> generate band-aids -> remediate (code cure) ------------
    t_synth = time.perf_counter()
    decisions, artifacts, remediations, correlations, probes = [], [], [], [], []
    seen_keys: dict[str, str] = {}  # coverage_key -> owning finding_id (B1)
    if verified:
        from .apply import lint_generated_spec
        from .agents import probe as probe_agent

        # A6: collapse duplicate findings so one vuln -> one band-aid + one code-fix PR
        verified = _dedup_findings(verified, log, dedup_counter)
        by_id = {f.id: f for f in verified}

        # 3) triage — band-aid coverage per finding. Chunk the batch so a big app (dozens of
        # findings) never sends one giant call that blows the per-call timeout; chunks run in
        # parallel and their decisions are concatenated.
        TRIAGE_CHUNK = 12
        # H1/H2 — an advisory with no network-observable exploitation pattern cannot be mitigated by
        # any control at a load balancer. That is a fact about the advisory, not a judgement call,
        # and the acceptance requires it: routing it to `no_bandaid` in code rather than asking
        # triage nicely is what makes it a guarantee instead of a hope. Everything else is triaged
        # normally, so a manifest run that declines half its advisories still triages the other half.
        decisions = [forced_decisions[f.id] for f in verified if f.id in forced_decisions]
        to_triage = [f for f in verified if f.id not in forced_decisions]
        if not to_triage:
            pass
        elif len(to_triage) <= TRIAGE_CHUNK:
            decisions += triage.run(h, to_triage).decisions
        else:
            chunks = [to_triage[i:i + TRIAGE_CHUNK] for i in range(0, len(to_triage), TRIAGE_CHUNK)]
            log(f"triaging {len(to_triage)} findings in {len(chunks)} batches of ≤{TRIAGE_CHUNK}")

            def _triage(ch):
                try:
                    return triage.run(h, ch).decisions
                except Exception as e:  # noqa: BLE001 — one bad batch shouldn't lose the rest
                    log(f"  ⚠ triage batch failed ({e}); routing those {len(ch)} to code-only")
                    from .schemas import TriageDecision
                    return [TriageDecision(finding_id=f.id, bandaids=[], no_bandaid=True,
                                           residual_risk="triage failed — code fix only") for f in ch]

            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                for ds in ex.map(_triage, chunks):
                    decisions.extend(ds)   # extend, never reassign: the forced ones are already in

        # AGENTS REASON, CODE ACTS — reconcile the decision set against the verified set, in code.
        #
        # `TriageDecision.finding_id` is filled by the TRIAGE AGENT, and every downstream stage keys
        # off it. Nothing checked that the ids the model returned were the ids it was given, so:
        #   * a finding the agent OMITTED was dropped silently — no band-aid, no ledger entry, no
        #     log line. Measured: three verified findings in, one band-aid out, nothing said.
        #   * a finding the agent RENAMED produced a PHANTOM ledger row keyed on an id no finding
        #     has, carrying `title: null, severity: null, file: null`.
        # Both are the J5 defect's shape: a model-supplied value trusted as a code-set fact. A
        # verified vulnerability silently losing its mitigation is the worst outcome this pipeline
        # has, so it is reconciled here rather than hoped for in a prompt.
        seen: set[str] = set()
        kept: list = []
        for d in decisions:
            if d.finding_id not in by_id:
                log(f"  ⚠ triage returned a decision for '{d.finding_id}', which is not one of the "
                    f"{len(by_id)} verified findings — discarding it (the agent renamed or invented "
                    f"an id; a phantom ledger entry is worse than a missing one)")
                continue
            if d.finding_id in seen:
                log(f"  ⚠ triage returned two decisions for '{d.finding_id}' — keeping the first")
                continue
            seen.add(d.finding_id)
            kept.append(d)
        for f in verified:
            if f.id in seen:
                continue
            # Fail CLOSED and LOUD, exactly as verify does when it cannot parse a verdict. A
            # code-cure-only decision is the safe default: it never claims a band-aid exists.
            log(f"  ⚠ triage returned NO decision for verified finding '{f.id}' ({f.title[:50]}) — "
                f"routing it to code-cure-only rather than dropping it silently")
            from .schemas import TriageDecision
            kept.append(TriageDecision(
                finding_id=f.id, bandaids=[], no_bandaid=True,
                residual_risk="triage returned no decision for this finding — no band-aid was "
                              "chosen, so this vulnerability is UNMITIGATED at the edge"))
        decisions = kept

        # A2: derive validation probes BEFORE generate, so each band-aid is built against the
        # finding's CONCRETE exploit (exact method + full path) and spares its legit request.
        bandaided = [by_id[d.finding_id] for d in decisions if not d.no_bandaid and d.finding_id in by_id]

        def _probe(f):
            try:
                return probe_agent.run(h, f, file_raw.get(f.file, "")).model_dump()
            except Exception:  # noqa: BLE001
                return None

        if bandaided:
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                probes = [p for p in ex.map(_probe, bandaided) if p]
            log(f"generated {len(probes)} finding-derived validation probe(s)")
        probe_by_id = {p["finding_id"]: p for p in probes}

        # 4) generate recommended band-aid(s), skipping ones an earlier finding covers
        def _try_bandaids(d, f, options, *, only_one: bool) -> int:
            """Generate from `options`, claiming each control's coverage slot. Returns how many
            artifacts were produced. `only_one` stops after the first success — a fallback exists
            to stop a finding ending bare, not to deploy the whole non-recommended stack."""
            pr = probe_by_id.get(d.finding_id) or {}
            exploit, legit = pr.get("exploit"), pr.get("legit")
            made = 0
            for b in options:
                key = correlate.coverage_key(
                    b.control.value, f.file,
                    identity=f.endpoint or getattr(f, "source", "") or f.id)
                if key in seen_keys:
                    # An LB-wide control has ONE instance per load balancer, so the slot really is
                    # taken — but the policy in it was generated against the OWNING finding's
                    # exploit, not this one's, and it was validated against that probe too. Saying
                    # so in the record is the difference between "one control covers both" and a
                    # confident claim of protection nobody measured.
                    shared = b.control.value in correlate.LB_WIDE
                    correlations.append({
                        "finding_id": d.finding_id, "control": b.control.value,
                        "covered_by": seen_keys[key], "coverage_key": key,
                        "note": (f"{b.control.value} is LB-wide: the attached policy was "
                                 f"generated and validated against {seen_keys[key]}'s exploit, "
                                 f"not this one's" if shared else
                                 "same endpoint — one policy covers both")})
                    log(f"  correlate {d.finding_id}: {b.control.value} already covered by "
                        f"{seen_keys[key]} — skip duplicate band-aid")
                    continue
                seen_keys[key] = d.finding_id
                try:  # B6: a model that can't emit this band-aid must not kill the scan (or vanish silently)
                    arts = generate.run(h, f, b.control, b.rationale,
                                        exploit=exploit, legit=legit).items
                except Exception as e:  # noqa: BLE001
                    seen_keys.pop(key, None)  # coverage wasn't established — let a sibling retry it
                    log(f"    ⚠ generate produced no {b.control.value} band-aid for {d.finding_id}: "
                        f"{e} — code fix only")
                    continue
                made += len(arts)
                # AGENTS REASON, CODE ACTS. `GeneratedArtifact.finding_id` and `.control` are on the
                # generate agent's response_model, so they are whatever the MODEL echoed back — but
                # this call site already KNOWS both: we asked for `b.control` on finding `f`. They
                # were written verbatim into policies.json, which is the policy->finding index every
                # apply / refine / simulate / emit / backfill path keys off, so a model that echoed
                # a different id filed the band-aid against the wrong vulnerability — or against one
                # that does not exist. Overwritten unconditionally, like `Finding.file` and the J5
                # classification fields, because a fact code holds must never be taken from a model.
                for a in arts:
                    a.finding_id, a.control = d.finding_id, b.control
                for a in arts:  # A3/A9: lint the consumed-spec controls now; refiner corrects at apply
                    iss = lint_generated_spec(a.control.value, a.spec, exploit)
                    if iss:
                        log(f"    ⚠ lint {a.policy_name}: {'; '.join(iss)} — "
                            "refine will correct at apply")
                artifacts.extend(arts)
                if only_one:
                    break
            return made

        # PASS 1 — every finding's RECOMMENDED band-aids, exactly as before H2.
        bare: list = []
        for d in decisions:
            f = by_id.get(d.finding_id)
            if not f:
                continue
            if d.no_bandaid:
                log(f"  triage {d.finding_id} -> NO BAND-AID (code cure only)")
                continue
            tags = ", ".join(
                f"{b.control.value}({b.coverage.value}{'*' if b.recommended else ''})"
                for b in d.bandaids
            )
            log(f"  triage {d.finding_id} -> {tags}")
            preferred = [b for b in d.bandaids if b.recommended] or d.bandaids
            if not _try_bandaids(d, f, preferred, only_one=False) and preferred is not d.bandaids:
                bare.append((d, f))

        # PASS 2 — findings whose every recommended control was claimed by another finding used to
        # end the loop with nothing, silently, while `correlations.json` recorded them as covered.
        # Found by the first live H2 run: Log4Shell's only recommended control was the LB-wide
        # `waf`, which an aiohttp header-injection advisory owned, so the critical finding got no
        # band-aid and the shipped WAF (`waf-block-header-injection-nullbyte-crlf`) addressed
        # nothing about JNDI.
        #
        # This runs as a SECOND PASS, after every recommended claim above, and takes only the
        # first alternative that generates. Both parts are load-bearing. Interleaved (the first
        # cut of this change), a non-recommended alternate could claim an LB-wide slot BEFORE a
        # later finding that actually recommended that control got to ask for it — reinflicting
        # the very bug this fixes on a different finding, and deploying up to three controls
        # triage never recommended. Deferred, the recommended tier always wins the slot, so a run
        # where it succeeds is byte-identical to before.
        for d, f in bare:
            alternates = [b for b in d.bandaids if not b.recommended]
            if not alternates:
                continue
            log(f"    every recommended band-aid for {d.finding_id} was already covered by "
                f"another finding — trying its alternative(s) rather than leaving it bare")
            _try_bandaids(d, f, alternates, only_one=True)

        # 5) every verified finding gets a real code fix (band-aid != cure) — A5: over ALL
        # verified findings, in parallel, not only those triage handed a band-aid. Skippable
        # (draft_code_fixes) to save the biggest chunk of tokens when only band-aids are wanted.
        # H1/H2 — the cure for a dependency advisory is a version bump in someone else's package.
        # There is no file of ours to patch, and asking a model to draft a diff against vendor code
        # it cannot see is how you get a confident, wrong patch. The version comes from OSV;
        # `remediate` is never called for those findings. Code findings alongside them still get one.
        remediations = [forced_remediations[f.id] for f in verified if f.id in forced_remediations]
        for r in remediations:
            log(f"cure: {r.summary}")
        to_remediate = [f for f in verified if f.id not in forced_remediations]
        if not to_remediate:
            pass
        elif draft_code_fixes:
            def _remediate(f):
                r = remediate.run(h, f, file_raw.get(f.file, ""))
                # AGENTS REASON, CODE ACTS. `kind` and the package/version fields are on the
                # remediate agent's response_model, and `RemediationPlan`'s own docstring says they
                # are "filled from OSV by code, never by a model" — but nothing enforced it. A
                # repo-scan cure relabelled `dependency_upgrade` makes `pr.py` skip writing the
                # patch and report a model-INVENTED "upgrade <package> to <version>" instead, which
                # is a version number an operator acts on directly.
                #
                # This branch handles findings from SOURCE, where the answer is known: there is a
                # file to patch, so it is a code_fix. The advisory path (`forced_remediations`) sets
                # these from OSV in code and never reaches here.
                r.finding_id = f.id
                if r.kind != "code_fix":
                    log(f"  ⚠ remediate labelled the cure for {f.id} '{r.kind}', but this finding "
                        f"came from source, not an advisory — recording it as a code fix")
                r.kind = "code_fix"
                r.package = r.ecosystem = r.vulnerable_range = r.fixed_version = ""
                return r

            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                remediations += list(ex.map(_remediate, to_remediate))
        else:
            log(f"skipping code-fix drafting for {len(to_remediate)} finding(s) (draft_code_fixes=off)")
    synth_s = time.perf_counter() - t_synth

    # D2) per-stage metrics: timing, discovery, verify precision, dedup ------
    metrics = {
        "timing_s": {"discover": round(discover_s, 2), "verify": round(verify_s, 2),
                     "synthesize": round(synth_s, 2), "total": round(time.perf_counter() - t0, 2)},
        "discovery": {"files": len(files), "skipped_files": len(skipped), "candidates": len(findings),
                      "duplicates_dropped": dedup_counter.get("duplicates_dropped", 0)},
        "verify": {"candidates": len(findings), "verified": len(verified), "refuted": refuted,
                   "dropped_low_confidence": dropped,
                   "confirm_rate": round(len(verified) / len(findings), 2) if findings else 0.0,
                   "avg_confidence": round(sum(confidences) / len(confidences), 2) if confidences else 0.0,
                   "min_confidence": min_confidence},
        "synthesize": {"policies": len(artifacts), "dupe_bandaids_collapsed": len(correlations),
                       "code_fix_prs": sum(1 for r in remediations if r.kind == "code_fix"),
                       "dependency_upgrades": sum(1 for r in remediations
                                                  if r.kind == "dependency_upgrade")},
    }
    # J5 — classify every finding the advisory tier did not already stamp. ONE choke point, and
    # it runs before `_write_out`, so `findings.json` carries the classification while the
    # *discover* contract stays untouched: the agent is never asked for these fields, which is
    # what keeps G4's committed four-provider recall scorecard from moving.
    from .weakness import stamp as _stamp_weakness
    _probe_by_id = {p.get("finding_id"): p for p in (probes or []) if isinstance(p, dict)}
    for _f in findings:
        if not getattr(_f, "cwe_source", ""):   # never overwrite an advisory-sourced fact
            _stamp_weakness(_f, probe=_probe_by_id.get(_f.id))
    summary = _write_out(out_dir, findings, verified, decisions, artifacts, remediations,
                         correlations, skipped, metrics, probes, deps_report)
    # F3) run manifest — what was scanned, at which commit, by whom, with which models and caps.
    # Every audit entry carries this run_id, so an exported bundle explains its own provenance.
    # Fail-soft: provenance is evidence, not a gate — never fail a completed scan over it.
    try:
        cfg = getattr(h, "cfg", None)
        runmeta.write_manifest(
            out_dir, repo=str(root.resolve()) if root else None, advisory=advisory_meta,
            # Joined in a fixed order, so every combination that existed before H2 — "repo",
            # "spec", "repo+spec", "advisory" — still renders byte-identically.
            input_kind=("advisory" if advisory else "+".join(
                k for k, on in (("repo", repo_path), ("spec", spec_path),
                                ("manifest", manifest_paths)) if on)),
            spec=str(Path(spec_path).resolve()) if spec_path else None,
            manifests=([str(Path(m).resolve()) for m in manifest_paths] if manifest_paths else None),
            config_path=config_path, started=started,
            models={a: cfg.for_agent(a).model for a in AGENT_NAMES} if cfg else None,
            caps={"min_confidence": min_confidence, "max_files": max_files, "max_bytes": max_bytes,
                  "draft_code_fixes": draft_code_fixes},
            counts={"candidates": len(findings), "verified": len(verified), "policies": len(artifacts),
                    "code_fix_prs": sum(1 for r in remediations if r.kind == "code_fix"),
                    "dependency_upgrades": sum(1 for r in remediations
                                               if r.kind == "dependency_upgrade")},
            finished=runmeta.utc_now(), **(runmeta.git_provenance(root) if root else {}))
    except Exception as e:  # noqa: BLE001
        log(f"  ⚠ could not write the run manifest (run.json): {e} — an audit export will lack provenance")
    from . import report  # E3: drop a standalone shareable HTML dashboard of the results
    log(f"wrote {report.write_report(out_dir)}")
    return summary


def _write_out(out_dir, findings, verified, decisions, artifacts, remediations, correlations,
               skipped, metrics=None, probes=None, deps_report=None) -> dict:
    out = Path(out_dir)
    (out / "policies").mkdir(parents=True, exist_ok=True)
    (out / "remediations").mkdir(parents=True, exist_ok=True)

    (out / "findings.json").write_text(json.dumps([f.model_dump() for f in findings], indent=2))
    (out / "triage.json").write_text(json.dumps([d.model_dump() for d in decisions], indent=2))
    (out / "remediations.json").write_text(json.dumps([r.model_dump() for r in remediations], indent=2))
    (out / "correlations.json").write_text(json.dumps(correlations, indent=2))
    (out / "probes.json").write_text(json.dumps(probes or [], indent=2))  # finding-derived exploit probes
    for a in artifacts:
        (out / "policies" / f"{a.control.value}.{a.policy_name}.json").write_text(
            json.dumps(a.spec, indent=2)
        )
    (out / "policies.json").write_text(json.dumps(  # index: policy -> finding, for apply/ledger linkage
        [{"finding_id": a.finding_id, "control": a.control.value, "policy_name": a.policy_name} for a in artifacts],
        indent=2))
    for r in remediations:
        (out / "remediations" / f"{r.finding_id}.patch").write_text(r.diff)
        (out / "remediations" / f"{r.finding_id}.pr.md").write_text(f"# {r.pr_title}\n\n{r.pr_body}\n")

    (out / "metrics.json").write_text(json.dumps(metrics or {}, indent=2))
    if deps_report is not None:
        # NOT `manifest.json`: `export.verify_bundle` locates each run inside an evidence bundle by
        # finding every member whose name ends `manifest.json`, so an artifact by that name would be
        # read as a second evidence manifest and break verification of the bundle it ships in.
        (out / "dependencies.json").write_text(json.dumps(deps_report, indent=2))
    else:
        # Every other member here is rewritten unconditionally, so a re-scan replaces it. This one
        # is written only when a manifest was given, so without this a later scan of the SAME out
        # dir would inherit the previous run's dependency data — and the report, `GET /api/deps`
        # and the evidence bundle would all present it as this run's. (G4 shipped the same class of
        # bug with leftover `policies/` artifacts.)
        (out / "dependencies.json").unlink(missing_ok=True)
    summary = {
        "candidates": len(findings),
        "verified": len(verified),
        "metrics": metrics or {},
        "triage": {
            d.finding_id: ([b.control.value for b in d.bandaids] or "no_bandaid")
            for d in decisions
        },
        "no_bandaid": [d.finding_id for d in decisions if d.no_bandaid],
        "policies": [f"{a.control.value}/{a.policy_name}" for a in artifacts],
        # H1/H2: split by `kind`, the discriminator `pr.py` already decides on. A
        # `dependency_upgrade` is a cure someone else has to ship — no PR was drafted and none
        # can be — so counting it as a code-fix PR overstates the cure half of the story on
        # every surface that renders it. A repo scan's remediations are all `code_fix`, so this
        # list is unchanged there; only the advisory paths (--cve, --manifest) move.
        "code_fix_prs": [r.finding_id for r in remediations if r.kind == "code_fix"],
        "dependency_upgrades": [r.finding_id for r in remediations if r.kind == "dependency_upgrade"],
        "correlations": [f"{c['finding_id']} covered-by {c['covered_by']} ({c['control']})" for c in correlations],
        "skipped_files": len(skipped),
        "out_dir": str(out),
    }
    if deps_report is not None:
        summary["dependencies"] = deps_report["funnel"]
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    from . import ledger  # seed the remediation ledger (found)
    ledger.init_from_scan(out_dir, [f.model_dump() for f in findings],
                          [d.model_dump() for d in decisions],
                          [r.model_dump() for r in remediations])
    return summary
