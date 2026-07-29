"""F3 — audit export: turn a run's artifacts into evidence someone else can review.

`audit.log` is append-only and deliberately heterogeneous — each action records what mattered for
that action. That is right for a log and wrong for a reviewer, who needs one shape they can sort,
filter and hand to a change board. `build_audit_events` normalizes it: one row per auditable event,
joined against the ledger and the scan artifacts so every LB change carries the vulnerability that
justified it, its severity, and the outcome.

`write_bundle` packages the whole run — the normalized events, the raw log verbatim, the exact XC
configs that were pushed, and the pre-change LB snapshot — with a manifest that SHA-256s every
member, so a bundle can be checked for completeness after it leaves this machine.

Read-only: nothing here touches XC, GitHub, or the run's artifacts."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

from typing import Callable

from . import __version__, audit, ledger, runmeta
from .sign import sign_bytes, verify_bytes


def _quiet(_msg: str) -> None:
    """Default log sink — the export is a library call first, a command second."""

# What each action DID, for a reviewer scanning a column rather than reading action names.
CATEGORY = {
    "apply_service_policy": "mitigate", "apply_malicious_user": "mitigate",
    "apply_rate_limit": "mitigate", "apply_bot_defense": "mitigate", "apply_waf": "mitigate",
    "apply_data_guard": "mitigate", "apply_api_schema": "mitigate",
    "create_service_policy": "create", "create_app_firewall": "create",
    "create_api_definition": "create",
    "refine_apply": "refine", "apply_timing": "timing",
    "open_pr": "cure", "retire": "retire", "rollback_failed": "rollback",
    # Gate decisions. Nothing changed on the LB, which is exactly why they belong in the export:
    # "we looked and refused" and "we looked and overrode" are both answers an auditor needs, and
    # only the log has them.
    "drift_detected": "gate", "policy_displaced": "gate", "drift_block": "gate",
    "drift_override": "gate", "apply_skipped_no_change": "gate", "simulate_override": "gate",
    # I1 — what the unattended reconcile loop decided. `reconcile_retire` is deliberately separate
    # from `retire`: reconcile still writes a plain `retire` entry through retire_finding, so every
    # existing consumer of that action keeps working, and this one carries the extra proof (the
    # origin probe) that justified doing it without a human present.
    "escalation": "reconcile", "fix_ineffective": "reconcile", "reconcile_retire": "reconcile",
}
# The XC control each action acted on, where the action name alone implies it.
CONTROL = {
    "apply_service_policy": "service_policy", "create_service_policy": "service_policy",
    "refine_apply": "service_policy", "apply_malicious_user": "malicious_user",
    "apply_rate_limit": "rate_limit", "apply_bot_defense": "bot_defense",
    "apply_waf": "waf", "create_app_firewall": "waf", "apply_data_guard": "waf_data_guard",
    "apply_api_schema": "api_schema", "create_api_definition": "api_schema",
    "drift_detected": "service_policy", "policy_displaced": "service_policy",
    "drift_block": "service_policy", "drift_override": "service_policy",
    "apply_skipped_no_change": "service_policy", "simulate_override": "service_policy",
}
# Flat CSV columns, in reading order: when · who · what · why · where · outcome.
COLUMNS = ["ts", "run_id", "actor", "host", "category", "action", "finding_id", "title",
           "vuln_class", "severity", "ledger_state", "control", "lb", "namespace", "object",
           "outcome", "attempts", "exploit_before", "exploit_after", "legit_ok", "pr_url",
           "tool_version", "detail"]
# Every artifact worth carrying as evidence. Missing ones are simply skipped — an unscanned dir has
# no findings.json, a run with no live apply has no lb_snapshot.json.
BUNDLE_FILES = ["run.json", "audit.log", "ledger.json", "findings.json", "triage.json",
                "policies.json", "remediations.json", "summary.json", "metrics.json",
                "probes.json", "correlations.json", "lb_snapshot.json", "simulation.json",
                "report.html"]


def _rj(out: Path, name: str, default):
    p = out / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return default


def _outcome(e: dict) -> str:
    """One word for 'did the change stick, and did it work?'. The apply paths disagree on the key
    they use for success (`passed` vs `config_enabled` vs `enabled`, and the curated demo dataset
    uses yet another mix), so coalesce rather than trust one name."""
    fixed = {"rollback_failed": "rollback_failed", "retire": "retired", "open_pr": "pr_opened",
             "create_service_policy": "created", "create_app_firewall": "created",
             "create_api_definition": "created",
             # Gate decisions: the outcome IS the decision. Falling through to the pass/fail
             # coalescing below would label a refusal "recorded", which reads like a no-op.
             "drift_detected": "drift_detected", "policy_displaced": "displaced",
             "drift_block": "refused", "drift_override": "overridden",
             "apply_skipped_no_change": "no_change",
             "simulate_override": "overridden",
             # An escalation that fell through to "recorded" would read as a no-op — the exact
             # opposite of a band-aid that is now overdue and still live.
             "escalation": "escalated", "fix_ineffective": "fix_ineffective",
             "reconcile_retire": "retired"}.get(e.get("action", ""))
    if fixed:
        return fixed
    if e.get("unfixable"):
        return "unfixable"
    if e.get("rolled_back"):
        return "rolled_back"
    ok = e.get("passed")
    if ok is None:
        ok = e.get("config_enabled")
    if ok is None:
        ok = e.get("enabled")
    if ok is None:
        return "recorded"
    return "kept" if (ok and e.get("kept")) else ("passed" if ok else "failed")


def _ba(e: dict, side: str) -> dict:
    return ((e.get("before_after") or {}).get(side) or {}) if isinstance(e.get("before_after"), dict) else {}


def _exploit(cell: dict) -> str:
    """`403 blocked` / `200 allowed` — the actual proof a band-aid worked, flattened for a cell."""
    blocked = cell.get("exploit_blocked")
    if blocked is None:
        return ""
    return f"{cell.get('exploit_status', '')} {'blocked' if blocked else 'allowed'}".strip()


def _object(e: dict) -> str:
    """The XC object the action touched, whichever field the action happens to name it in."""
    for k in ("policy", "app_firewall", "apidef", "name", "rate", "swagger"):
        if e.get(k):
            return str(e[k])
    return ""


def build_audit_events(out_dir: str = "out") -> list[dict]:
    """Normalized, newest-first audit events for a run. Every entry in audit.log survives — an
    export that silently drops `retire`, `open_pr` or a failed rollback is worse than no export."""
    out = Path(out_dir)
    entries = audit.load(out_dir)
    led = ledger.load(out_dir)
    findings = {f.get("id"): f for f in _rj(out, "findings.json", [])}
    # a policy name is often the only link back to a finding on older entries
    by_policy = {a.get("policy_name"): a.get("finding_id") for a in _rj(out, "policies.json", [])}

    events = []
    for e in entries:
        # `open_pr` wrote `finding` before every other action settled on `finding_id`; older logs
        # attributed nothing at all, so fall back to the policy index.
        fid = e.get("finding_id") or e.get("finding") or by_policy.get(e.get("policy"))
        f, le = findings.get(fid, {}), (led.get(fid) or {})
        before, after = _ba(e, "before"), _ba(e, "after")
        detail = {k: v for k, v in e.items()
                  if k not in ("ts", "action", "run_id", "actor", "host", "tool_version")}
        events.append({
            "ts": e.get("ts", ""), "run_id": e.get("run_id", ""), "actor": e.get("actor", ""),
            "host": e.get("host", ""),
            "category": CATEGORY.get(e.get("action", ""), "other"), "action": e.get("action", ""),
            # The record's OWN copy wins over the join. Reconcile denormalizes these precisely
            # because findings.json and ledger.json are rewritten by the next scan — reading the
            # join first would throw away the value that was preserved for that reason.
            "finding_id": fid or "",
            "title": e.get("title") or f.get("title") or le.get("title") or "",
            "vuln_class": e.get("vuln_class") or f.get("vuln_class") or le.get("vuln_class") or "",
            "severity": e.get("severity") or f.get("severity") or le.get("severity") or "",
            "ledger_state": le.get("state", ""),
            "control": e.get("control") or CONTROL.get(e.get("action", ""), ""),
            "lb": e.get("lb", ""), "namespace": e.get("namespace", ""), "object": _object(e),
            "outcome": _outcome(e), "attempts": e.get("attempts", ""),
            "exploit_before": _exploit(before),
            "exploit_after": _exploit(after or (e.get("origin_probe") or {})),
            "legit_ok": after.get("legit_ok", ""),
            "pr_url": e.get("url") or (le.get("cure") or {}).get("pr_url") or "",
            "tool_version": e.get("tool_version", ""), "detail": detail,
        })
    events.sort(key=lambda x: x["ts"], reverse=True)
    return events


def to_csv(events: list[dict]) -> str:
    """Flat CSV for a spreadsheet or a change board. `detail` keeps the raw JSON so nothing that was
    recorded is lost in the flattening."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for e in events:
        w.writerow({**e, "detail": json.dumps(e.get("detail", {}), sort_keys=True)})
    return buf.getvalue()


def build_manifest(out_dir: str = "out", *, members: dict | None = None) -> dict:
    """What this bundle is, which run it covers, and a SHA-256 per member so it can be checked for
    completeness later. `caveats` states out loud what the trail does NOT contain — an export that
    implies more coverage than it has is the one way this feature could mislead someone."""
    events = build_audit_events(out_dir)
    return {
        "kind": "vpcopilot-audit-bundle", "schema": 1, "tool_version": __version__,
        "generated": runmeta.utc_now(), "generated_by": runmeta.actor(), "generated_on": runmeta.host(),
        "out_dir": str(out_dir), "run": runmeta.load(out_dir),
        "events": len(events),
        "actions": {a: sum(1 for e in events if e["action"] == a) for a in sorted({e["action"] for e in events})},
        "findings_touched": sorted({e["finding_id"] for e in events if e["finding_id"]}),
        "caveats": [
            "Dry runs are not recorded: nothing was changed, so nothing is logged. This is the record "
            "of changes MADE, not of every attempt.",
            "apply_timing entries are written only by the console's Mitigate step on a live (non-dry) "
            "apply; a CLI-driven run has none.",
            "Entries written by older builds may lack finding_id / namespace / actor — those cells are "
            "blank rather than inferred.",
            "If manifest.json.minisig is present it signs THIS manifest, which SHA-256s every "
            "member — so it attests who exported the bundle, not that the audit log inside is "
            "truthful. Verify it with the signer's public key obtained OUT OF BAND; a key shipped "
            "inside a bundle proves nothing about that bundle.",
            "simulation.json, when present, describes ONE recorded sample replayed through a spare "
            "load balancer — not production traffic in general. Its records are redacted at ingest "
            "(see `redacted`); read the window and record count with the rate.",
        ],
        "members": members or {},
    }


def write_bundle(out_dir: str = "out", output: str | None = None, *, log: Callable = _quiet) -> str:
    """Zip the run's evidence to `output` (default `<out>/audit-bundle.zip`) and return the path."""
    path = Path(output) if output else Path(out_dir) / "audit-bundle.zip"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bundle_bytes(out_dir, log=log))
    return str(path)


def bundle_bytes(out_dir: str = "out", *, prefix: str = "", log: Callable = _quiet) -> bytes:
    """The evidence bundle as bytes, so the console can stream it without touching disk."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        _add_run(z, out_dir, prefix, log=log)
    return buf.getvalue()


def _add_run(z: zipfile.ZipFile, out_dir: str, prefix: str = "", *, log: Callable = _quiet) -> dict:
    """Write one run into an open archive under `prefix`, returning its manifest (so a multi-run
    bundle can index what it contains)."""
    out = Path(out_dir)
    events = build_audit_events(out_dir)
    members: dict[str, dict] = {}

    def add(name: str, data: bytes) -> None:
        z.writestr(f"{prefix}{name}", data)
        members[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    add("audit.csv", to_csv(events).encode())
    add("audit-events.json", json.dumps(events, indent=2).encode())
    for name in BUNDLE_FILES:
        p = out / name
        if p.exists() and p.is_file():
            add(name, p.read_bytes())  # raw and verbatim — audit.log especially
    # the exact XC configs that were pushed, plus every per-LB snapshot taken before a change
    for sub in ("policies", "snapshots"):
        for p in sorted((out / sub).glob("*")):
            if p.is_file():
                add(f"{sub}/{p.name}", p.read_bytes())

    manifest = build_manifest(out_dir, members=members)
    # Sign the EXACT bytes that ship: signing a different serialization would make every
    # verification fail, or pass against something the reviewer never received.
    blob = json.dumps(manifest, indent=2).encode()
    z.writestr(f"{prefix}manifest.json", blob)
    # The trusted comment is SIGNED and travels with the bundle, so it carries the run identity —
    # not the exporter's filesystem path, which a real round-trip showed it was leaking.
    run_id = (manifest.get("run") or {}).get("run_id") or "unknown-run"
    sig = sign_bytes(blob, log=log,
                     comment=f"vpcopilot {__version__} evidence bundle · run {run_id}")
    if sig:
        z.writestr(f"{prefix}manifest.json.minisig", sig)
    return manifest


def find_runs(root: str = ".") -> list[str]:
    """Run dirs on disk worth exporting — anything with an audit log or scan results. Matches how
    the console's output-dir picker discovers runs (out*/ plus the seeded demo/out)."""
    base = Path(root)
    cands = [p for p in sorted(base.glob("out*")) if p.is_dir()]
    demo = base / "demo" / "out"
    if demo.is_dir():
        cands.append(demo)
    return [str(p) for p in cands if (p / "audit.log").exists() or (p / "findings.json").exists()]


def bundle_all_bytes(root: str = ".", *, log: Callable = _quiet) -> bytes:
    """Every run on disk in one archive, each under its own folder, with a top-level index. For the
    case an auditor asks for "everything", not one engagement."""
    runs = find_runs(root)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        index = []
        for r in runs:
            try:  # name folders by the run dir RELATIVE to root, so an absolute root doesn't
                rel = Path(r).relative_to(root)  # bury each run under its full filesystem path
            except ValueError:
                rel = Path(r)
            folder = str(rel).replace("/", "-").replace("\\", "-").strip("-") or "run"
            m = _add_run(z, r, prefix=f"{folder}/", log=log)
            index.append({"out_dir": str(r), "folder": folder, "events": m["events"],
                          "run_id": (m.get("run") or {}).get("run_id", "")})
        z.writestr("index.json", json.dumps({
            "kind": "vpcopilot-audit-bundle-multi", "schema": 1, "tool_version": __version__,
            "generated": runmeta.utc_now(), "generated_by": runmeta.actor(),
            "generated_on": runmeta.host(), "root": str(root), "runs": index}, indent=2))
    return buf.getvalue()


def write_bundle_all(root: str = ".", output: str | None = None, *, log: Callable = _quiet) -> str:
    path = Path(output) if output else Path(root) / "audit-bundle-all.zip"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bundle_all_bytes(root, log=log))
    return str(path)


# ---------------- J2: verify a bundle after it has left the machine ----------------
def verify_bundle(path: str, *, pubkey: str | None = None, log: Callable = _quiet) -> dict:
    """Re-read a bundle and check it against its own manifest.

    Read-only and stdlib-only for the digest half — the same check `docs/AUDIT.md` documents by
    hand, so a reviewer with neither this tool nor a key can still do it. Handles both layouts by
    finding every `manifest.json` in the archive, so an `--all` bundle verifies run by run.

    Four member verdicts, not two: a file **added** to a bundle is exactly as suspicious as one
    altered, and a check over only the listed members would wave it through."""
    problems: list[dict] = []
    runs: list[dict] = []
    checked = 0
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:  # noqa: BLE001 — a corrupt or missing file is a finding, not a crash
        return {"ok": False, "error": f"cannot read {path}: {e}", "problems": [], "runs": [],
                "members_checked": 0}
    with z:
        bad_crc = z.testzip()
        if bad_crc:
            return {"ok": False, "error": f"corrupt member (CRC): {bad_crc}", "problems": [],
                    "runs": [], "members_checked": 0}
        names = set(z.namelist())
        manifests = sorted(n for n in names if n.endswith("manifest.json"))
        if not manifests:
            return {"ok": False, "error": "no manifest.json in this archive — not a vpcopilot bundle",
                    "problems": [], "runs": [], "members_checked": 0}

        accounted = {"index.json"}
        for mpath in manifests:
            prefix = mpath[: -len("manifest.json")]
            accounted.add(mpath)
            try:
                manifest = json.loads(z.read(mpath))
            except json.JSONDecodeError as e:
                problems.append({"run": prefix, "member": mpath, "problem": "unreadable-manifest",
                                 "detail": str(e)})
                continue
            members = manifest.get("members") or {}
            for name, meta in sorted(members.items()):
                full = prefix + name
                accounted.add(full)
                if full not in names:
                    problems.append({"run": prefix, "member": name, "problem": "missing",
                                     "detail": "listed in the manifest, absent from the archive"})
                    continue
                blob = z.read(full)
                checked += 1
                got = hashlib.sha256(blob).hexdigest()
                if got != meta.get("sha256") or len(blob) != meta.get("bytes"):
                    problems.append({"run": prefix, "member": name, "problem": "mismatch",
                                     "detail": f"sha256 {got[:16]}… != {str(meta.get('sha256'))[:16]}…"})

            sigpath = prefix + "manifest.json.minisig"
            accounted.add(sigpath)
            if sigpath in names:
                state = verify_bytes(z.read(mpath), z.read(sigpath), pubkey=pubkey, log=log)
                if state == "failed":
                    problems.append({"run": prefix, "member": "manifest.json.minisig",
                                     "problem": "signature", "detail": "signature did not verify"})
            else:
                state = "absent"
            runs.append({"run": prefix or "./", "signature": state,
                         "members": len(members),
                         "run_id": (manifest.get("run") or {}).get("run_id", "")})

        for extra in sorted(names - accounted):
            if extra.endswith("/"):
                continue
            problems.append({"run": "", "member": extra, "problem": "unlisted",
                             "detail": "present in the archive but not listed in any manifest"})

    return {"ok": not problems, "error": None, "problems": problems, "runs": runs,
            "members_checked": checked}
