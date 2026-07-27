"""F3 — audit export: the heterogeneous append-only log normalized into reviewable events, and the
evidence bundle built from a run. Nothing that was recorded may be dropped, and every LB change has
to carry the finding that justified it."""
import hashlib
import io
import json
import zipfile
from pathlib import Path

from vpcopilot import audit, export


def _seed(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps([
        {"id": "f-1", "title": "SQL injection in login", "vuln_class": "sqli", "severity": "critical",
         "file": "api/login.js"}]))
    (out / "policies.json").write_text(json.dumps([
        {"finding_id": "f-1", "control": "service_policy", "policy_name": "deny-login-sqli"}]))
    (out / "ledger.json").write_text(json.dumps({
        "f-1": {"finding_id": "f-1", "state": "remediated", "title": "SQL injection in login",
                "severity": "critical", "mitigation": {"control": "service_policy", "lb": "lab"},
                "cure": {"pr_url": "https://github.com/o/r/pull/7", "pr_number": 7}}}))
    (out / "summary.json").write_text(json.dumps({"candidates": 1, "verified": 1}))
    (out / "policies").mkdir(exist_ok=True)
    (out / "policies" / "service_policy.deny-login-sqli.json").write_text('{"spec": {}}')
    (out / "lb_snapshot.json").write_text('{"metadata": {"name": "lab"}}')


# ---- normalization ----
def test_every_audit_entry_survives_normalization(tmp_path):
    """report.py's impact table filters to entries with before/after — an EXPORT must not, or it
    silently loses retire, open_pr, create_* and every config-only apply."""
    out = str(tmp_path)
    _seed(tmp_path)
    audit.record(out, "apply_waf", finding_id="f-1", lb="lab", namespace="ns", config_enabled=True)
    audit.record(out, "create_app_firewall", finding_id="f-1", name="lab-waf", namespace="ns")
    audit.record(out, "open_pr", finding_id="f-1", finding="f-1", url="https://github.com/o/r/pull/7", number=7)
    audit.record(out, "retire", finding_id="f-1", control="service_policy", lb="lab", forced=False)
    audit.record(out, "rollback_failed", finding_id="f-1", lb="lab", reason="XC 503")
    events = export.build_audit_events(out)
    assert {e["action"] for e in events} == {"apply_waf", "create_app_firewall", "open_pr",
                                            "retire", "rollback_failed"}
    assert {e["outcome"] for e in events} >= {"created", "pr_opened", "retired", "rollback_failed"}


def test_events_join_the_finding_that_justified_the_change(tmp_path):
    out = str(tmp_path)
    _seed(tmp_path)
    audit.record(out, "apply_service_policy", finding_id="f-1", lb="lab", namespace="ns",
                 policy="deny-login-sqli", passed=True, kept=True)
    e = export.build_audit_events(out)[0]
    assert e["finding_id"] == "f-1" and e["title"] == "SQL injection in login"
    assert e["severity"] == "critical" and e["vuln_class"] == "sqli"
    assert e["ledger_state"] == "remediated" and e["control"] == "service_policy"
    assert e["lb"] == "lab" and e["namespace"] == "ns" and e["outcome"] == "kept"


def test_legacy_entries_still_attribute_via_finding_key_and_policy_index(tmp_path):
    """Logs written by older builds used `finding` on open_pr and recorded no finding_id at all on
    apply_*; both must still resolve rather than exporting as anonymous changes."""
    out = tmp_path
    _seed(out)
    (out / "audit.log").write_text(
        json.dumps({"ts": "2026-01-01T00:00:00+00:00", "action": "open_pr", "finding": "f-1",
                    "url": "https://github.com/o/r/pull/7"}) + "\n" +
        json.dumps({"ts": "2026-01-01T00:00:01+00:00", "action": "apply_service_policy",
                    "policy": "deny-login-sqli", "lb": "lab", "passed": True}) + "\n")
    events = export.build_audit_events(str(out))
    assert all(e["finding_id"] == "f-1" for e in events)
    assert all(e["title"] == "SQL injection in login" for e in events)


def test_before_after_and_self_heal_are_flattened_for_review(tmp_path):
    out = str(tmp_path)
    _seed(tmp_path)
    audit.record(out, "refine_apply", finding_id="f-1", control="service_policy", lb="lab",
                 policy="deny-login-sqli", passed=True, attempts=2,
                 before_after={"before": {"exploit_status": 200, "exploit_blocked": False},
                               "after": {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}})
    e = export.build_audit_events(out)[0]
    assert e["exploit_before"] == "200 allowed" and e["exploit_after"] == "403 blocked"
    assert e["attempts"] == 2 and e["legit_ok"] is True


def test_outcome_coalesces_the_three_success_keys(tmp_path):
    """apply_* disagree on passed / config_enabled / enabled, and the demo fixture uses yet another
    mix — one column has to mean the same thing across all of them."""
    out = str(tmp_path)
    for i, kw in enumerate(({"passed": True}, {"config_enabled": True}, {"enabled": True},
                            {"passed": False}, {"rolled_back": True}, {"unfixable": True})):
        audit.record(out, "apply_waf", finding_id=f"x-{i}", lb="lab", **kw)
    got = {e["detail"].get("finding_id"): e["outcome"] for e in export.build_audit_events(out)}
    assert got["x-0"] == got["x-1"] == got["x-2"] == "passed"
    assert got["x-3"] == "failed" and got["x-4"] == "rolled_back" and got["x-5"] == "unfixable"


def test_events_are_newest_first(tmp_path):
    out = str(tmp_path)
    for i in range(3):
        audit.record(out, "apply_waf", finding_id=f"f-{i}", lb="lab")
    ts = [e["ts"] for e in export.build_audit_events(out)]
    assert ts == sorted(ts, reverse=True)


def test_empty_run_dir_exports_cleanly(tmp_path):
    assert export.build_audit_events(str(tmp_path / "never-scanned")) == []
    assert export.to_csv([]).strip() == ",".join(export.COLUMNS)


# ---- CSV ----
def test_csv_has_every_column_and_one_row_per_event(tmp_path):
    out = str(tmp_path)
    _seed(tmp_path)
    audit.record(out, "apply_waf", finding_id="f-1", lb="lab", namespace="ns", config_enabled=True)
    audit.record(out, "retire", finding_id="f-1", control="waf", lb="lab", forced=True)
    rows = export.to_csv(export.build_audit_events(out)).strip().splitlines()
    assert rows[0] == ",".join(export.COLUMNS) and len(rows) == 3
    assert "SQL injection in login" in rows[1]


def test_csv_detail_keeps_the_raw_record(tmp_path):
    """Flattening must not lose anything that was recorded."""
    out = str(tmp_path)
    audit.record(out, "apply_rate_limit", finding_id="f-9", lb="lab", rate="5/MINUTE",
                 behavioral={"sent": 20, "limited": 15})
    body = export.to_csv(export.build_audit_events(out))
    assert "5/MINUTE" in body and "limited" in body


# ---- bundle ----
def test_bundle_carries_the_evidence_and_a_verifiable_manifest(tmp_path):
    out = tmp_path / "out-run"
    _seed(out)
    audit.record(str(out), "apply_service_policy", finding_id="f-1", lb="lab", namespace="ns",
                 policy="deny-login-sqli", passed=True, kept=True)
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(out))))
    names = set(z.namelist())
    assert {"manifest.json", "audit.csv", "audit-events.json", "audit.log", "ledger.json",
            "findings.json", "lb_snapshot.json",
            "policies/service_policy.deny-login-sqli.json"} <= names
    m = json.loads(z.read("manifest.json"))
    assert m["kind"] == "vpcopilot-audit-bundle" and m["events"] == 1
    assert m["findings_touched"] == ["f-1"] and m["caveats"]
    for name, meta in m["members"].items():
        assert hashlib.sha256(z.read(name)).hexdigest() == meta["sha256"]


def test_bundle_manifest_states_what_the_trail_omits(tmp_path):
    """The one way this feature could mislead: implying it covers attempts it never recorded."""
    caveats = " ".join(export.build_manifest(str(tmp_path))["caveats"]).lower()
    assert "dry run" in caveats and "apply_timing" in caveats


def test_bundle_includes_the_raw_log_verbatim(tmp_path):
    out = tmp_path / "out-run"
    audit.record(str(out), "apply_waf", finding_id="f-1", lb="lab")
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(out))))
    assert z.read("audit.log") == (out / "audit.log").read_bytes()


def test_write_bundle_returns_its_path(tmp_path):
    out = tmp_path / "out-run"
    audit.record(str(out), "retire", finding_id="f-1", control="waf", lb="lab")
    p = Path(export.write_bundle(str(out)))
    assert p.exists() and p.name == "audit-bundle.zip" and zipfile.is_zipfile(p)


# ---- multi-run ----
def test_find_runs_picks_up_run_dirs_with_something_to_export(tmp_path):
    (tmp_path / "out-a").mkdir()
    audit.record(str(tmp_path / "out-a"), "apply_waf", finding_id="f-1", lb="lab")
    (tmp_path / "out-empty").mkdir()          # no audit log, no findings — nothing to export
    (tmp_path / "demo" / "out").mkdir(parents=True)
    (tmp_path / "demo" / "out" / "findings.json").write_text("[]")
    runs = {Path(r).name for r in export.find_runs(str(tmp_path))}
    assert "out-a" in runs and "out" in runs and "out-empty" not in runs


def test_bundle_all_folders_each_run_under_an_index(tmp_path):
    for name in ("out-a", "out-b"):
        audit.record(str(tmp_path / name), "apply_waf", finding_id="f-1", lb="lab")
    z = zipfile.ZipFile(io.BytesIO(export.bundle_all_bytes(str(tmp_path))))
    names = z.namelist()
    assert "index.json" in names
    assert any(n.startswith("out-a/") for n in names) and any(n.startswith("out-b/") for n in names)
    idx = json.loads(z.read("index.json"))
    assert {r["folder"] for r in idx["runs"]} == {"out-a", "out-b"}
    assert all(r["events"] == 1 for r in idx["runs"])
