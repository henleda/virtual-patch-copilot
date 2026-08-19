"""The global live-band-aid inventory — the cross-session record that Retire + reconcile read, and
the write-through from `ledger.mark_*` that keeps it current without touching any apply call site.

Keyed by (lb, finding_id): a finding_id is a per-scan LLM slug that recurs across apps, so two live
band-aids that share a slug on different LBs must NOT collapse into one — that would orphan a control,
the exact failure this module exists to prevent.

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
    e = inventory.get("f1", "lab")
    assert e is not None
    assert e["mitigation"] == {"control": "service_policy", "policy_name": "deny-x", "lb": "lab"}
    assert e["session"] == str(tmp_path) and e["state"] == "mitigated"
    assert e["title"] == "Neg transfer" and e["severity"] == "critical"   # metadata carried for Retire
    assert e["ttl"]["applied_at"] and e["ttl"]["expires_at"] > e["ttl"]["applied_at"]


# ---- the collision the finder sweep caught: same slug, two LBs, must NOT orphan ---------------

def test_same_finding_id_on_two_lbs_are_distinct_bandaids(tmp_path):
    """finding_ids are reused across apps. Two live band-aids with the same slug on different LBs must
    both survive — keying by finding_id alone would overwrite the first and orphan a live control."""
    ledger.mark_mitigated(str(tmp_path), "neg-pay-001", control="service_policy", policy_name="p", lb="vampi-www")
    ledger.mark_mitigated(str(tmp_path), "neg-pay-001", control="service_policy", policy_name="p", lb="nimbus-www")
    live = inventory.live()
    assert len(live) == 2                                        # NOT collapsed into one
    lbs = {e["mitigation"]["lb"] for e in live.values()}
    assert lbs == {"vampi-www", "nimbus-www"}
    assert inventory.get("neg-pay-001", "vampi-www")["mitigation"]["lb"] == "vampi-www"
    assert inventory.get("neg-pay-001", "nimbus-www")["mitigation"]["lb"] == "nimbus-www"


def test_retiring_one_of_two_same_slug_bandaids_leaves_the_other(tmp_path):
    ledger.mark_mitigated(str(tmp_path), "f", control="waf", policy_name="p", lb="lb-a")
    ledger.mark_mitigated(str(tmp_path), "f", control="waf", policy_name="p", lb="lb-b")
    inventory.mark_retired("f", "lb-a")
    live = inventory.live()
    assert len(live) == 1 and next(iter(live.values()))["mitigation"]["lb"] == "lb-b"
    assert inventory.get("f", "lb-a")["state"] == "retired"      # row kept, just no longer live


# ---- lifecycle -------------------------------------------------------------------------------

def test_live_excludes_retired_and_found(tmp_path):
    ledger.mark_mitigated(str(tmp_path), "live", control="waf", policy_name="p", lb="lab")
    ledger.mark_mitigated(str(tmp_path), "gone", control="waf", policy_name="p", lb="lab")
    inventory.mark_retired("gone", "lab")
    assert {e["finding_id"] for e in inventory.live().values()} == {"live"}
    assert inventory.get("gone", "lab")["state"] == "retired"


def test_attach_cure_hits_every_lb_and_skips_code_cure_only(tmp_path):
    """A code fix cures the finding on every LB it was patched on; a code-cure-only finding has no
    band-aid, so attach_cure mints nothing (the impact 'mitigated live' honesty guard)."""
    ledger.mark_mitigated(str(tmp_path), "f", control="waf", policy_name="p", lb="lb-a")
    ledger.mark_mitigated(str(tmp_path), "f", control="waf", policy_name="p", lb="lb-b")
    assert inventory.attach_cure("f", pr_url="https://x/pull/1", pr_number=1) == 2     # both LBs
    assert inventory.get("f", "lb-a")["state"] == "remediated" and inventory.get("f", "lb-b")["cure"]["pr_number"] == 1
    assert inventory.attach_cure("cure-only", pr_url="https://x/pull/2", pr_number=2) == 0
    assert inventory.entries_for("cure-only") == []              # nothing minted


def test_record_reconcile_merges_and_is_a_noop_for_untracked(tmp_path):
    ledger.mark_mitigated(str(tmp_path), "f1", control="waf", policy_name="p", lb="lab")
    inventory.record_reconcile("f1", "lab", outcome="escalated", last_run_at="t1")
    inventory.record_reconcile("f1", "lab", cure_state="merged")            # merge, don't replace
    assert inventory.record_reconcile("f1", "other-lb", outcome="x") is None  # wrong lb → no-op
    assert inventory.record_reconcile("ghost", "lab", outcome="x") is None    # untracked → no-op
    rec = inventory.get("f1", "lab")["reconcile"]
    assert rec["outcome"] == "escalated" and rec["cure_state"] == "merged"


# ---- migration from pre-split session ledgers ------------------------------------------------

def test_migrate_pulls_live_bandaids_and_tags_the_session(tmp_path):
    a, b = tmp_path / "out-a", tmp_path / "out-b"
    _seed_ledger(a, "old-live", state="mitigated", lb="nimbus-www")
    _seed_ledger(b, "dead", state="retired")                 # retired → not migrated
    _seed_ledger(b, "found-only", state="found", control=None)
    added = inventory.migrate_from_dirs([str(a), str(b)])
    assert added == 1
    e = inventory.get("old-live", "nimbus-www")
    assert e["session"] == str(a) and e["mitigation"]["lb"] == "nimbus-www"


def test_migrate_keeps_same_slug_on_two_lbs(tmp_path):
    """The migration mirror of the collision guard: a slug live in two sibling sessions on two LBs must
    both migrate, not first-dir-wins."""
    a, b = tmp_path / "out-a", tmp_path / "out-b"
    _seed_ledger(a, "neg-pay-001", state="mitigated", lb="lb-a")
    _seed_ledger(b, "neg-pay-001", state="mitigated", lb="lb-b")
    assert inventory.migrate_from_dirs([str(a), str(b)]) == 2
    assert {e["mitigation"]["lb"] for e in inventory.live().values()} == {"lb-a", "lb-b"}


def test_migrate_is_idempotent_and_never_overwrites(tmp_path):
    a = tmp_path / "out-a"
    _seed_ledger(a, "f1", state="mitigated", lb="lab")
    assert inventory.migrate_from_dirs([str(a)]) == 1
    inventory.record_reconcile("f1", "lab", outcome="escalated")
    assert inventory.migrate_from_dirs([str(a)]) == 0            # idempotent, no double-count
    assert inventory.get("f1", "lab")["reconcile"]["outcome"] == "escalated"   # not clobbered


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
    data = json.loads((tmp_path / "custom" / "inventory.json").read_text())
    assert data["lab::f1"]["mitigation"]["lb"] == "lab"          # keyed by lb::finding_id
