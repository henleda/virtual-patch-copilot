"""The global live-band-aid inventory — the cross-session record that Retire + reconcile read, and
the write-through from `ledger.mark_*` that keeps it current without touching any apply call site.

The autouse `_isolated_inventory` fixture (conftest) points VPCOPILOT_INVENTORY_DIR at a fresh temp
dir per test, so each test starts with an empty inventory and never touches the repo."""
from __future__ import annotations

import json

from vpcopilot import inventory, ledger


def _seed_ledger(d, fid, *, state="mitigated", control="service_policy", lb="lab"):
    ledger.save(str(d), {fid: {"finding_id": fid, "state": state, "title": "t", "severity": "high",
                               "mitigation": {"control": control, "policy_name": "p", "lb": lb}}})


# ---- write-through from the apply chokepoint -------------------------------------------------

def test_mark_mitigated_writes_through_to_inventory(tmp_path):
    """Every apply path calls ledger.mark_mitigated; it must populate the global inventory too — with
    the finding's metadata, its TTL, and the session it was applied from — so none of the ~10 apply
    call sites need to know the inventory exists."""
    ledger.init_from_scan(str(tmp_path), [{"id": "f1", "title": "Neg transfer", "severity": "critical"}],
                          [{"finding_id": "f1", "bandaids": [{"control": "service_policy"}]}], [])
    ledger.mark_mitigated(str(tmp_path), "f1", control="service_policy", policy_name="deny-x", lb="lab")
    inv = inventory.load()
    assert "f1" in inv
    e = inv["f1"]
    assert e["mitigation"] == {"control": "service_policy", "policy_name": "deny-x", "lb": "lab"}
    assert e["session"] == str(tmp_path) and e["state"] == "mitigated"
    assert e["title"] == "Neg transfer" and e["severity"] == "critical"   # metadata carried for Retire
    assert e["ttl"]["applied_at"] and e["ttl"]["expires_at"] > e["ttl"]["applied_at"]


def test_live_excludes_retired_and_found(tmp_path):
    ledger.mark_mitigated(str(tmp_path), "live", control="waf", policy_name="p", lb="lab")
    ledger.mark_mitigated(str(tmp_path), "gone", control="waf", policy_name="p", lb="lab")
    ledger.mark_retired(str(tmp_path), "gone")
    live = inventory.live()
    assert set(live) == {"live"}                       # retired drops out of the live view
    assert inventory.load()["gone"]["state"] == "retired"   # ...but the row remains for the audit trail


def test_remediated_attaches_cure_only_to_a_tracked_bandaid(tmp_path):
    """A code-cure-only finding never had a band-aid — record_remediated must not mint a phantom
    inventory entry for it (the same honesty the impact 'mitigated live' guard enforces)."""
    ledger.mark_mitigated(str(tmp_path), "has-bandaid", control="waf", policy_name="p", lb="lab")
    ledger.mark_remediated(str(tmp_path), "has-bandaid", pr_url="https://x/pull/1", pr_number=1)
    ledger.mark_remediated(str(tmp_path), "cure-only", pr_url="https://x/pull/2", pr_number=2)
    inv = inventory.load()
    assert inv["has-bandaid"]["cure"]["pr_number"] == 1 and inv["has-bandaid"]["state"] == "remediated"
    assert "cure-only" not in inv                       # no band-aid → not in the inventory


def test_record_reconcile_merges_and_is_a_noop_for_untracked(tmp_path):
    ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    inventory.record_reconcile("f1", outcome="escalated", last_run_at="t1")
    inventory.record_reconcile("f1", cure_state="merged")            # merge, don't replace
    assert inventory.record_reconcile("ghost", outcome="x") is None  # untracked → no-op
    rec = inventory.load()["f1"]["reconcile"]
    assert rec["outcome"] == "escalated" and rec["cure_state"] == "merged"


# ---- migration from pre-split session ledgers ------------------------------------------------

def test_migrate_pulls_live_bandaids_and_tags_the_session(tmp_path):
    a, b = tmp_path / "out-a", tmp_path / "out-b"
    _seed_ledger(a, "old-live", state="mitigated", lb="nimbus-www")
    _seed_ledger(b, "dead", state="retired")                 # retired → not migrated
    _seed_ledger(b, "found-only", state="found", control=None)
    added = inventory.migrate_from_dirs([str(a), str(b)])
    assert added == 1
    live = inventory.live()
    assert set(live) == {"old-live"}
    assert live["old-live"]["session"] == str(a) and live["old-live"]["mitigation"]["lb"] == "nimbus-www"


def test_migrate_is_idempotent_and_never_overwrites(tmp_path):
    a = tmp_path / "out-a"
    _seed_ledger(a, "f1", state="mitigated", lb="lab")
    assert inventory.migrate_from_dirs([str(a)]) == 1
    # a later reconcile stamps the inventory entry; a re-migration must not clobber it back to the stale
    # ledger copy nor double-count it.
    inventory.record_reconcile("f1", outcome="escalated")
    assert inventory.migrate_from_dirs([str(a)]) == 0
    assert inventory.load()["f1"]["reconcile"]["outcome"] == "escalated"


def test_a_damaged_session_ledger_does_not_abort_the_migration(tmp_path):
    good, bad = tmp_path / "out-good", tmp_path / "out-bad"
    _seed_ledger(good, "f1", state="mitigated")
    bad.mkdir()
    (bad / "ledger.json").write_text("{ not json")
    assert inventory.migrate_from_dirs([str(bad), str(good)]) == 1   # the good one still lands


def test_inventory_dir_is_env_overridable(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_INVENTORY_DIR", str(tmp_path / "custom"))
    ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    assert (tmp_path / "custom" / "inventory.json").exists()
    assert json.loads((tmp_path / "custom" / "inventory.json").read_text())["f1"]["mitigation"]["lb"] == "lab"
