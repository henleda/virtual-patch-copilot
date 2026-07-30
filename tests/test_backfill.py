"""J4 — attribution backfill. Offline throughout: a run dir on disk, no network, no tenant."""
from __future__ import annotations

import json

import pytest

from vpcopilot import audit, backfill, export


def _run(tmp_path, entries, policies=None):
    """A run dir with an audit log and a policy index, written the way the pipeline writes them."""
    out = tmp_path
    for e in entries:
        audit.record(str(out), e.pop("action"), **e)
    (out / "policies.json").write_text(json.dumps(policies or []))
    return str(out)


POLICIES = [{"finding_id": "neg-pay-001", "control": "service_policy",
             "policy_name": "deny-negative-pay"},
            {"finding_id": "sqli-login-001", "control": "waf", "policy_name": "waf-block-sqli"}]


# ============================================================ deriving
def test_only_what_the_policy_index_proves_is_attributed(tmp_path):
    out = _run(tmp_path, [
        {"action": "create_service_policy", "policy": "deny-negative-pay"},   # derivable
        {"action": "apply_waf", "policy": "waf-block-sqli"},                  # derivable
        {"action": "apply_rate_limit", "lb": "lab"},                          # nothing to go on
        {"action": "apply_bot_defense", "policy": "never-generated-here"},    # not in the index
    ], POLICIES)
    rows = backfill.derive(out)
    got = {(r["action"], r["finding_id"], r["source"]) for r in rows}
    assert ("create_service_policy", "neg-pay-001", "policies.json") in got
    assert ("apply_waf", "sqli-login-001", "policies.json") in got
    assert ("apply_rate_limit", None, "unknown") in got
    assert ("apply_bot_defense", None, "unknown") in got


def test_an_entry_that_already_carries_its_finding_is_not_recorded(tmp_path):
    """There is nothing to freeze: the log is the better source, and `build_audit_events` reads the
    record's own copy first precisely because reconcile denormalizes it for that reason."""
    out = _run(tmp_path, [
        {"action": "apply_waf", "finding_id": "sqli-login-001", "policy": "waf-block-sqli"},
        {"action": "open_pr", "finding": "neg-pay-001"},         # the legacy field name
    ], POLICIES)
    assert backfill.derive(out) == []


def test_the_sidecar_carries_no_identity_at_all(tmp_path):
    """Acceptance: no entry gets an invented actor or run_id. Guaranteed by having nowhere to put
    one — identity lives in audit.log, which is append-only and never edited."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    doc = json.loads((tmp_path / backfill.SIDECAR).read_text())
    # keys, not a substring search — the document's own `note` explains that it carries no actor,
    # and a raw-text check would trip on the explanation rather than on a field.
    forbidden = {"actor", "run_id", "host"}
    assert not (set(doc) & forbidden)
    for row in doc["entries"]:
        assert set(row) == {"i", "ts", "action", "policy", "finding_id", "source"}
        assert not (set(row) & forbidden)


def test_the_audit_log_is_never_rewritten(tmp_path):
    """The log is append-only and `record()` strips caller-supplied identity. A backfill that could
    edit an entry would destroy the property that makes the log worth keeping."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    before = (tmp_path / "audit.log").read_text()
    backfill.backfill(out, log=lambda m: None)
    after = (tmp_path / "audit.log").read_text()
    assert after.startswith(before)               # only appended to
    assert len(after.splitlines()) == len(before.splitlines()) + 1   # by exactly its own record


# ============================================================ acceptance
def test_the_backfill_writes_its_own_audit_record(tmp_path):
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"},
                          {"action": "apply_rate_limit", "lb": "lab"}], POLICIES)
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] and res["recorded"]
    own = [e for e in audit.load(out) if e["action"] == "audit_backfill"]
    assert len(own) == 1
    assert own[0]["resolved"] == 1 and own[0]["unknown"] == 1 and own[0]["entries"] == 2
    assert own[0]["actor"] and own[0]["run_id"] is not None    # stamped centrally, as ever


def test_a_second_run_is_a_no_op(tmp_path):
    """Not tidiness. This function appends its OWN entry, so without the check every run would see
    one more entry than the last, decide something changed, and append again — a log that grows by a
    line every time anyone asks whether it needs backfilling."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    log_after_first = (tmp_path / "audit.log").read_text()
    side_after_first = (tmp_path / backfill.SIDECAR).read_text()

    second = backfill.backfill(out, log=lambda m: None)
    assert second["wrote"] is False and second["recorded"] is False
    assert second["reason"] == "no change"
    assert (tmp_path / "audit.log").read_text() == log_after_first
    assert (tmp_path / backfill.SIDECAR).read_text() == side_after_first

    third = backfill.backfill(out, log=lambda m: None)      # and it stays a no-op
    assert third["wrote"] is False
    assert (tmp_path / "audit.log").read_text() == log_after_first


def test_a_new_entry_makes_the_next_run_write_again(tmp_path):
    """A no-op must not mean "never runs again"."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    audit.record(out, "apply_waf", policy="waf-block-sqli")
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] and res["resolved"] == 2


def test_dry_run_writes_nothing(tmp_path):
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    before = (tmp_path / "audit.log").read_text()
    res = backfill.backfill(out, dry_run=True, log=lambda m: None)
    assert res["resolved"] == 1 and res["wrote"] is False and res["recorded"] is False
    assert not (tmp_path / backfill.SIDECAR).exists()
    assert (tmp_path / "audit.log").read_text() == before


def test_a_run_dir_with_no_audit_log_declines(tmp_path):
    res = backfill.backfill(str(tmp_path), log=lambda m: None)
    assert res["wrote"] is False and res["reason"] == "no audit log"
    assert not (tmp_path / backfill.SIDECAR).exists()


# ============================================================ what it is FOR
def test_a_rescan_no_longer_erases_the_attribution(tmp_path):
    """The reason this item exists. `policies.json` is rewritten by EVERY scan, so the exporter's
    live lookup stops attributing older entries as soon as the run dir is scanned again."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    assert export.build_audit_events(out)[0]["finding_id"] == "neg-pay-001"   # derivable today

    backfill.backfill(out, log=lambda m: None)
    (tmp_path / "policies.json").write_text(json.dumps([]))                   # a later scan

    ev = [e for e in export.build_audit_events(out) if e["action"] == "create_service_policy"]
    assert ev[0]["finding_id"] == "neg-pay-001", "the frozen attribution did not survive the re-scan"


def test_a_reused_policy_name_cannot_reattribute_an_old_entry(tmp_path):
    """The sharper half, and the reason the sidecar WINS over the live index rather than merely
    filling gaps: a later scan that reuses a policy name for a DIFFERENT finding would make the live
    lookup succeed and attribute the old entry to the wrong finding — a confident wrong answer in the
    artifact whose whole job is to be trustworthy."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    # a later scan of a different app generates the same policy name for another finding
    (tmp_path / "policies.json").write_text(json.dumps(
        [{"finding_id": "SOMETHING-ELSE-999", "control": "service_policy",
          "policy_name": "deny-negative-pay"}]))
    ev = [e for e in export.build_audit_events(out) if e["action"] == "create_service_policy"]
    assert ev[0]["finding_id"] == "neg-pay-001"
    assert ev[0]["finding_id"] != "SOMETHING-ELSE-999"


def test_unknown_is_sticky_so_a_later_index_cannot_invent_an_answer(tmp_path):
    """"We looked and could not establish this" is a fact worth keeping. Falling through to a newer
    `policies.json` would be inventing an answer the backfill already declined to give."""
    out = _run(tmp_path, [{"action": "apply_bot_defense", "policy": "not-in-any-index"}], POLICIES)
    backfill.backfill(out, log=lambda m: None)
    rows = json.loads((tmp_path / backfill.SIDECAR).read_text())["entries"]
    assert rows[0]["source"] == "unknown" and rows[0]["finding_id"] is None

    (tmp_path / "policies.json").write_text(json.dumps(
        [{"finding_id": "INVENTED-001", "control": "bot_defense",
          "policy_name": "not-in-any-index"}]))
    ev = [e for e in export.build_audit_events(out) if e["action"] == "apply_bot_defense"]
    assert ev[0]["finding_id"] == ""


def test_without_a_backfill_the_exporter_behaves_exactly_as_before(tmp_path):
    """No regression: the sidecar is absent until someone runs the command."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"},
                          {"action": "apply_rate_limit", "lb": "lab"}], POLICIES)
    ev = {e["action"]: e for e in export.build_audit_events(out)}
    assert ev["create_service_policy"]["finding_id"] == "neg-pay-001"    # live lookup still used
    assert ev["apply_rate_limit"]["finding_id"] == ""


# ============================================================ the log moving underneath it
def test_a_row_whose_entry_no_longer_matches_is_dropped_not_moved(tmp_path):
    """The sidecar is keyed by index, which is stable only because the log is append-only. If the log
    is rebuilt or truncated, the index still resolves — to a DIFFERENT entry. Verifying (ts, action)
    means losing an attribution rather than moving it onto the wrong record."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"},
                          {"action": "apply_waf", "policy": "waf-block-sqli"}], POLICIES)
    backfill.backfill(out, log=lambda m: None)
    assert len(backfill.load(out)) == 2

    lines = (tmp_path / "audit.log").read_text().splitlines()
    (tmp_path / "audit.log").write_text("\n".join(lines[1:]) + "\n")   # first entry removed
    assert backfill.stale_rows(out) > 0
    for i, row in backfill.load(out).items():
        assert (audit.load(out)[i]["ts"], audit.load(out)[i]["action"]) == (row["ts"], row["action"])


def test_a_corrupt_sidecar_does_not_fall_through_to_a_wrong_guess(tmp_path):
    """This test used to pin only "does not crash", and an adversarial review caught why that was
    not enough: its fixture left `policies.json` mapping the same policy to the same finding, so the
    live fallback happened to agree. With a re-scan that reused the name, the same code path produced
    a confidently WRONG attribution — in a bundle that then SHA-256s and signs it as evidence.

    Absent and unreadable are different answers. No sidecar means nobody froze anything, so the live
    index is the best available guess. A sidecar that exists and will not parse means somebody DID
    freeze attribution and it is now unreadable — and the live index is by definition not the one
    those entries belong to."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    # a later scan reuses the policy name for a DIFFERENT finding
    (tmp_path / "policies.json").write_text(json.dumps(
        [{"policy_name": "deny-negative-pay", "finding_id": "WRONG-999"}]))
    assert export.build_audit_events(out)[-1]["finding_id"] == "neg-pay-001"   # frozen wins

    (tmp_path / backfill.SIDECAR).write_text("{ not json")
    rows, ok = backfill.load_state(out)
    assert rows == {} and ok is False
    got = export.build_audit_events(out)[-1]["finding_id"]
    assert got == "", f"a torn sidecar guessed {got!r} from an index that is not these entries'"

    # …and with NO sidecar at all the live lookup is used exactly as it always was
    (tmp_path / backfill.SIDECAR).unlink()
    assert backfill.load_state(out) == ({}, True)
    assert export.build_audit_events(out)[-1]["finding_id"] == "WRONG-999"

    (tmp_path / backfill.SIDECAR).write_text("{ not json")
    assert backfill.backfill(out, log=lambda m: None)["wrote"] is True        # and it recovers


# ============================================================ one lookup, not three
def test_the_policy_lookup_lives_in_exactly_one_place():
    """J4 would have been the third copy. `ledger.policy_index` is the one; `find_finding_for_policy`
    and the exporter both go through it."""
    import inspect

    from vpcopilot import ledger
    assert "policy_index(out_dir).get(policy_name)" in inspect.getsource(
        ledger.find_finding_for_policy)
    src = inspect.getsource(export.build_audit_events)
    assert "ledger.policy_index(out_dir)" in src
    assert 'a.get("policy_name"): a.get("finding_id")' not in src   # the inline copy is gone


@pytest.mark.parametrize("label,doc,want", [
    ("normal",           [{"policy_name": "p", "finding_id": "f-1"}], "f-1"),
    # FIRST match wins. A dict comprehension lets a later duplicate overwrite an earlier one, which
    # silently changes which finding an apply validates against.
    ("duplicate names",  [{"policy_name": "p", "finding_id": "f-1"},
                          {"policy_name": "p", "finding_id": "f-2"}], "f-1"),
    ("name, no finding", [{"policy_name": "p"}], None),
    ("finding is null",  [{"policy_name": "p", "finding_id": None}], None),
    # A falsy finding_id comes back AS-IS rather than filtered to None: the backfill wants it
    # treated as unresolved, but that belongs at its call site, not in a lookup four paths share.
    ("finding is empty", [{"policy_name": "p", "finding_id": ""}], ""),
    ("empty list",       [], None),
])
def test_the_shared_index_preserves_the_old_semantics_exactly(tmp_path, label, doc, want):
    """No regression for the four production callers of `find_finding_for_policy` (refiner.py and
    apply.py x3). Measured against the previous implementation: consolidating two copies into one
    silently changed THREE behaviours — duplicate-name precedence, falsy finding_ids, and what
    happens to a corrupt file — before this pinned them."""
    from vpcopilot import ledger
    (tmp_path / "policies.json").write_text(json.dumps(doc))
    assert ledger.find_finding_for_policy(str(tmp_path), "p") == want


def test_a_corrupt_index_still_raises_for_the_apply_paths(tmp_path):
    """The apply paths use this to decide which probe validates a band-aid. Returning None because
    the index would not parse means applying with weaker validation and no explanation, so it raises
    as it always did — while the read-only exporter catches it instead."""
    from vpcopilot import ledger
    (tmp_path / "policies.json").write_text("{ corrupt")
    with pytest.raises(json.JSONDecodeError):
        ledger.find_finding_for_policy(str(tmp_path), "p")
    # …and the exporter is unaffected by the same file
    assert export.build_audit_events(str(tmp_path)) == []


def test_a_missing_index_is_empty_for_everyone(tmp_path):
    from vpcopilot import ledger
    assert ledger.find_finding_for_policy(str(tmp_path / "nowhere"), "x") is None
    assert ledger.policy_index(str(tmp_path / "nowhere")) == {}


# ============================================================ evidence + surfaces
def test_the_sidecar_ships_in_the_evidence_bundle(tmp_path):
    """A reviewer who gets the log without the sidecar cannot tell a frozen attribution from an
    invented one."""
    import zipfile
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    z = zipfile.ZipFile(tmp_path / "b.zip", "w")
    export._add_run(z, out)
    z.close()
    with zipfile.ZipFile(tmp_path / "b.zip") as zz:
        assert backfill.SIDECAR in zz.namelist()
        manifest = json.loads(zz.read("manifest.json"))
    assert backfill.SIDECAR in manifest["members"]      # and it is digested like every member


def test_both_surfaces_reach_the_same_module_function(tmp_path, monkeypatch):
    import inspect

    from fastapi.testclient import TestClient

    from vpcopilot import cli
    from vpcopilot.console import app as A
    assert "from .backfill import backfill" in inspect.getsource(cli.audit_backfill)

    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    monkeypatch.setattr(A, "OUT", tmp_path)
    r = TestClient(A.app).post("/api/audit-backfill", json={"dry_run": True})
    assert r.status_code == 200
    assert r.json()["resolved"] == 1 and r.json()["wrote"] is False
    assert not (tmp_path / backfill.SIDECAR).exists()

    r2 = TestClient(A.app).post("/api/audit-backfill", json={})
    assert r2.json()["wrote"] is True
    assert (tmp_path / backfill.SIDECAR).is_file()
    assert backfill.load(out)


def test_the_console_endpoint_takes_no_caller_supplied_path():
    """The J2 precedent: an endpoint that accepted a path would be an arbitrary-file writer, and
    localhost is not a reason to ship one."""
    from vpcopilot.console.app import BackfillReq
    assert set(BackfillReq.model_fields) == {"dry_run"}


@pytest.mark.parametrize("action", ["audit_backfill"])
def test_the_backfills_own_entries_are_never_backfilled(tmp_path, action):
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    assert all(r["action"] != action for r in backfill.derive(out))


def test_the_new_action_is_categorised_rather_than_falling_through_to_other(tmp_path):
    """A reviewer filters the CSV by category. `audit_backfill` is bookkeeping about the trail, not a
    change to a load balancer, so it gets its own category — falling through to "other"/"recorded"
    made it an unexplained row."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    ev = [e for e in export.build_audit_events(out) if e["action"] == "audit_backfill"]
    assert ev[0]["category"] == "evidence" and ev[0]["outcome"] == "attributed"


def test_a_forged_sidecar_cannot_move_anything_the_log_stamped(tmp_path):
    """The limit, stated because a sidecar is an ordinary file while the log is append-only. A forged
    sidecar reaches `finding_id` and the columns joined THROUGH it — no further. Everything the log
    stamped is unreachable, and `findings.json`/`ledger.json` already drive those same joins, so this
    adds no trust assumption the export did not already make."""
    out = _run(tmp_path, [{"action": "refine_apply", "policy": "deny-negative-pay", "lb": "lab",
                           "passed": True}], POLICIES)
    backfill.backfill(out, log=lambda m: None)
    before = {e["action"]: e for e in export.build_audit_events(out)}["refine_apply"]

    doc = json.loads((tmp_path / backfill.SIDECAR).read_text())
    doc["entries"][0]["finding_id"] = "sqli-login-001"
    (tmp_path / backfill.SIDECAR).write_text(json.dumps(doc))
    after = {e["action"]: e for e in export.build_audit_events(out)}["refine_apply"]

    assert after["finding_id"] == "sqli-login-001"           # it CAN move the attribution…
    for stamped in ("ts", "actor", "host", "run_id", "action", "outcome", "lb", "tool_version"):
        assert after[stamped] == before[stamped], stamped    # …and nothing the log stamped


def test_the_documented_limit_is_actually_written_down():
    """This project states its limits rather than leaving them to be discovered — the J1 precedent
    ("the signature attests who exported this bundle, not that the log is truthful")."""
    from pathlib import Path
    txt = (Path(__file__).resolve().parents[1] / "docs/AUDIT.md").read_text()
    assert "forged sidecar" in txt
    assert "no trust assumption that the export did not already make" in txt
    assert "the log is the evidence" in txt


def test_a_second_run_after_a_rescan_does_not_destroy_the_frozen_attribution(tmp_path):
    """Found by adversarial review — two reviewers independently, and it defeated the entire item.
    `derive` recomputed every row from the CURRENT policies.json, which is precisely what the sidecar
    is a defence against: run once, re-scan, run again, and every frozen attribution collapses to
    `unknown`. Because `unknown` is sticky, the loss was permanent — the second use of the feature
    undid the first."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    (tmp_path / "policies.json").write_text(json.dumps([]))          # a later scan

    second = backfill.backfill(out, log=lambda m: None)
    assert second["wrote"] is False and second["reason"] == "no change"
    rows = json.loads((tmp_path / backfill.SIDECAR).read_text())["entries"]
    assert rows[0]["finding_id"] == "neg-pay-001"
    ev = [e for e in export.build_audit_events(out) if e["action"] == "create_service_policy"]
    assert ev[0]["finding_id"] == "neg-pay-001"


def test_a_frozen_row_is_never_recomputed_even_when_the_index_would_disagree(tmp_path):
    """Monotonic in the same way as the log it annotates: rows are added, never revised. A later
    index that would map the same policy to a DIFFERENT finding must not rewrite history."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    (tmp_path / "policies.json").write_text(json.dumps(
        [{"policy_name": "deny-negative-pay", "finding_id": "SOMETHING-ELSE-999"}]))
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] is False
    rows = json.loads((tmp_path / backfill.SIDECAR).read_text())["entries"]
    assert rows[0]["finding_id"] == "neg-pay-001"


def test_new_entries_are_still_derived_after_a_rescan(tmp_path):
    """Monotonic must not mean frozen shut: an entry with no row yet is derived normally."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    audit.record(out, "apply_waf", policy="waf-block-sqli")
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] and res["resolved"] == 2
    got = {r["policy"]: r["finding_id"]
           for r in json.loads((tmp_path / backfill.SIDECAR).read_text())["entries"]}
    assert got == {"deny-negative-pay": "neg-pay-001", "waf-block-sqli": "sqli-login-001"}


def test_deleting_the_sidecar_is_the_way_to_force_a_fresh_derivation(tmp_path):
    """The escape hatch, and it is deliberately an explicit act rather than a side effect of running
    the command twice."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    (tmp_path / backfill.SIDECAR).unlink()
    (tmp_path / "policies.json").write_text(json.dumps([]))
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] and res["resolved"] == 0 and res["unknown"] == 1


def test_the_sidecar_is_written_atomically(tmp_path, monkeypatch):
    """It is evidence an exporter reads and a bundle ships. `write_text` truncates first, so a crash
    mid-write leaves a half-written file — and `load` swallows the resulting JSONDecodeError, so the
    failure mode is losing every frozen attribution without a word."""
    import inspect
    assert "os.replace" in inspect.getsource(backfill.backfill)

    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    assert (tmp_path / backfill.SIDECAR).is_file()
    assert not list(tmp_path.glob("*.tmp"))       # no debris left behind
    assert json.loads((tmp_path / backfill.SIDECAR).read_text())["entries"]


def test_the_bundle_caveats_describe_the_sidecar(tmp_path):
    """The bundle states what it does NOT prove. A derived sidecar that can supply a finding_id is
    exactly the kind of thing a reviewer must be told about."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}],
               POLICIES)
    backfill.backfill(out, log=lambda m: None)
    cav = " ".join(export.build_manifest(out)["caveats"])
    assert "audit-backfill.json" in cav
    assert "no actor, run_id or host" in cav
    assert "the log is the evidence" in cav


def test_a_corrupt_policy_index_declines_rather_than_tracebacking(tmp_path):
    """`ledger.policy_index` raises on a corrupt file DELIBERATELY, so the apply paths fail loudly
    rather than validating a band-aid against no probe. This command is not an apply: an unreadable
    index means it cannot establish anything, which is a decline — not a CLI traceback and an HTTP
    500 out of the console."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "deny-negative-pay"}])
    (tmp_path / "policies.json").write_text("{ corrupt")
    res = backfill.backfill(out, log=lambda m: None)
    assert res["wrote"] is False and res["recorded"] is False
    assert "unreadable policies.json" in res["reason"]
    assert not (tmp_path / backfill.SIDECAR).exists()

    from fastapi.testclient import TestClient
    from vpcopilot.console import app as A
    import vpcopilot.console.app as mod
    old = mod.OUT
    try:
        mod.OUT = tmp_path
        r = TestClient(A.app).post("/api/audit-backfill", json={})
        assert r.status_code == 200 and r.json()["wrote"] is False
    finally:
        mod.OUT = old


def test_the_dry_run_marker_survives_rich_markup():
    """Rich reads `[dry-run]` as a markup tag and silently drops it — the one word telling you
    nothing was written is exactly the one that must not vanish."""
    import inspect

    from vpcopilot import cli
    src = inspect.getsource(cli.audit_backfill)
    assert "escape(" in src, "log lines reach rprint unescaped"

    from rich.console import Console
    import io as _io
    buf = _io.StringIO()
    Console(file=buf, width=200, no_color=True).print(
        "[dim]" + __import__("rich.markup", fromlist=["escape"]).escape(
            "[dry-run] would attribute 3 entry(ies)") + "[/dim]")
    assert "[dry-run]" in buf.getvalue()


def test_duplicate_policy_names_resolve_first_wins_everywhere(tmp_path):
    """The two copies this consolidation removed DISAGREED: the exporter's inline dict was last-wins,
    `find_finding_for_policy` was first-wins. Preserving both is impossible, so first-wins is the
    deliberate unification — it matches the apply path, which is the safety-critical consumer.
    `policies.json` should never contain duplicates; this pins what happens when it does."""
    out = _run(tmp_path, [{"action": "create_service_policy", "policy": "dup"}],
               [{"policy_name": "dup", "finding_id": "FIRST"},
                {"policy_name": "dup", "finding_id": "LAST"}])
    from vpcopilot import ledger
    assert ledger.find_finding_for_policy(out, "dup") == "FIRST"
    assert export.build_audit_events(out)[0]["finding_id"] == "FIRST"
