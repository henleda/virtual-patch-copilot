"""F3 — every audit entry must answer: what changed, WHERE (LB + XC namespace), WHY (the finding),
WHO ran it, and as part of which run. An LB change that can't name its justification is not an
audit record."""
import json
import threading

import pytest

from vpcopilot import apply, audit, runmeta


def test_concurrent_first_writes_do_not_lose_an_audit_record(tmp_path):
    """Found while building J3's concurrency test, and pre-existing: `runmeta._save` named its temp
    file by PID only, so two threads minting a run_id for a fresh out dir raced on it and the loser
    got FileNotFoundError out of `os.replace` — raised from inside `audit.record`, i.e. a change
    already made to a load balancer that could not be recorded. The console starts every apply on
    its own daemon thread. Reproduced 12 times out of 12 before the fix."""
    errs = []

    def go(i):
        try:
            audit.record(str(tmp_path), "apply_waf", lb="lab", finding_id=f"f{i}")
        except Exception as e:  # noqa: BLE001
            errs.append(f"{type(e).__name__}: {e}")

    ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert errs == []
    assert len(audit.load(str(tmp_path))) == 8
    # …and all eight share one run identity, which is what run_id exists to guarantee.
    assert len({e["run_id"] for e in audit.load(str(tmp_path))}) == 1


@pytest.fixture(autouse=True)
def _fast(monkeypatch, noop_sleep):
    import vpcopilot.engine as engine
    real_init = engine.ApplyContext.__post_init__

    def patched(self):
        real_init(self)
        self.sleep = noop_sleep
    monkeypatch.setattr(engine.ApplyContext, "__post_init__", patched)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


def _use(monkeypatch, fake_xc):
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)


def _entries(out, action):
    return [e for e in audit.load(str(out)) if e["action"] == action]


# ---- identity stamped centrally ----
def test_every_entry_carries_run_actor_host_and_version(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_ACTOR", "sec-oncall")
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    e = audit.load(str(tmp_path))[0]
    assert e["actor"] == "sec-oncall" and e["run_id"] and e["host"] and e["tool_version"]


def test_identity_cannot_be_overridden_by_a_caller(tmp_path, monkeypatch):
    """Identity is stamped in audit.record, not at the call sites — so nothing can spoof it, and no
    mutating path can forget it."""
    monkeypatch.setenv("VPCOPILOT_ACTOR", "sec-oncall")
    audit.record(str(tmp_path), "apply_waf", lb="lab", actor="someone-else", run_id="forged")
    e = audit.load(str(tmp_path))[0]
    assert e["actor"] == "sec-oncall" and e["run_id"] != "forged"


def test_run_id_is_stable_across_processes_for_one_out_dir(tmp_path):
    """A scan and a later `vpcopilot apply` against the same dir belong to the same run."""
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    audit.record(str(tmp_path), "retire", lb="lab")
    a, b = audit.load(str(tmp_path))
    assert a["run_id"] == b["run_id"] == runmeta.run_id(str(tmp_path))


def test_actor_falls_back_to_the_os_user(tmp_path, monkeypatch):
    monkeypatch.delenv("VPCOPILOT_ACTOR", raising=False)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert audit.load(str(tmp_path))[0]["actor"]  # never blank


# ---- the finding + namespace on every live control ----
def test_malicious_user_records_finding_and_namespace(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    apply.apply_malicious_user("lab", keep=True, finding_id="f-1", out_dir=str(tmp_path), log=lambda m: None)
    e = _entries(tmp_path, "apply_malicious_user")[0]
    assert e["finding_id"] == "f-1" and e["namespace"] == fake_xc.ns and e["lb"] == "lab"


def test_rate_limit_records_finding_and_namespace(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    apply.apply_rate_limit("lab", requests=60, keep=True, finding_id="f-2",
                           out_dir=str(tmp_path), log=lambda m: None)
    e = _entries(tmp_path, "apply_rate_limit")[0]
    assert e["finding_id"] == "f-2" and e["namespace"] == fake_xc.ns


def test_bot_defense_records_finding_and_namespace(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    apply.apply_bot_defense("lab", keep=True, finding_id="f-3", out_dir=str(tmp_path), log=lambda m: None)
    e = _entries(tmp_path, "apply_bot_defense")[0]
    assert e["finding_id"] == "f-3" and e["namespace"] == fake_xc.ns


def test_waf_records_finding_namespace_and_the_object_it_created(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    apply.apply_waf("lab", target_url="http://x", keep=True, finding_id="f-4",
                    out_dir=str(tmp_path), log=lambda m: None)
    applied = _entries(tmp_path, "apply_waf")[0]
    created = _entries(tmp_path, "create_app_firewall")[0]
    assert applied["finding_id"] == "f-4" and applied["namespace"] == fake_xc.ns
    # "rolled back?" alone can't say the change is STILL LIVE — the trail has to record that
    assert applied["kept"] is True
    # the XC object creation is itself an auditable change and must be attributable too
    assert created["finding_id"] == "f-4" and created["namespace"] == fake_xc.ns


def test_data_guard_records_finding_and_namespace(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    apply.apply_data_guard("lab", keep=True, finding_id="f-5", out_dir=str(tmp_path), log=lambda m: None)
    e = _entries(tmp_path, "apply_data_guard")[0]
    assert e["finding_id"] == "f-5" and e["namespace"] == fake_xc.ns


def test_api_schema_records_finding_and_namespace(monkeypatch, fake_xc, tmp_path):
    _use(monkeypatch, fake_xc)
    monkeypatch.setattr(apply, "_run_validation",
                        lambda *a, **k: {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True})
    apply.apply_api_schema("lab", target_url="http://x", keep=True, finding_id="f-6",
                           out_dir=str(tmp_path), log=lambda m: None)
    for action in ("apply_api_schema", "create_api_definition"):
        e = _entries(tmp_path, action)[0]
        assert e["finding_id"] == "f-6" and e["namespace"] == fake_xc.ns, action
    assert _entries(tmp_path, "apply_api_schema")[0]["kept"] is True


def test_retire_records_the_namespace_it_detached_from(monkeypatch, fake_xc, tmp_path):
    """A detach is an LB change like any other — it has to name the tenant it happened in."""
    from vpcopilot import ledger, retire
    monkeypatch.setattr(retire, "XC", lambda *a, **k: fake_xc)
    ledger.mark_mitigated(str(tmp_path), "f-9", control="waf", policy_name="lab-waf", lb="lab")
    retire.retire_finding(str(tmp_path), "f-9", force=True, log=lambda m: None)
    e = _entries(tmp_path, "retire")[0]
    assert e["finding_id"] == "f-9" and e["namespace"] == fake_xc.ns and e["lb"] == "lab"


def test_rollback_failure_is_attributable(fake_xc, tmp_path, noop_sleep):
    """The single most important entry to attribute: the LB may be left in a changed state."""
    from vpcopilot.engine import ApplyContext, RollbackError, safe_rollback
    ctx = ApplyContext(xc=fake_xc, lb="lab", out_dir=str(tmp_path), log=lambda m: None,
                       sleep=noop_sleep, finding_id="f-7").load()
    ctx.put({"active_service_policies": {}})
    fake_xc.fail_put_lb = True
    with pytest.raises(RollbackError):
        safe_rollback(ctx, retries=2)
    e = _entries(tmp_path, "rollback_failed")[0]
    assert e["finding_id"] == "f-7" and e["namespace"] == fake_xc.ns and e["lb"] == "lab"


def test_apply_pins_the_finding_onto_the_context_so_a_rollback_can_name_it(monkeypatch, fake_xc, tmp_path):
    """The apply handlers hand finding_id to ApplyContext, which is what makes the entry above
    possible from deep inside the rollback spine."""
    _use(monkeypatch, fake_xc)
    seen = {}
    import vpcopilot.engine as engine
    real_load = engine.ApplyContext.load
    monkeypatch.setattr(engine.ApplyContext, "load",
                        lambda self: (seen.update(fid=self.finding_id), real_load(self))[1])
    apply.apply_malicious_user("lab", keep=True, finding_id="f-8", out_dir=str(tmp_path), log=lambda m: None)
    assert seen["fid"] == "f-8"


# ---- run manifest ----
def test_run_manifest_records_provenance_without_clobbering_the_run_id(tmp_path):
    rid = runmeta.run_id(str(tmp_path))
    runmeta.write_manifest(str(tmp_path), repo="/src/app", models={"discover": "anthropic/x"},
                           counts={"verified": 3})
    m = json.loads((tmp_path / "run.json").read_text())
    assert m["run_id"] == rid and m["repo"] == "/src/app"
    assert m["models"]["discover"] == "anthropic/x" and m["actor"] and m["tool_version"]


def test_git_provenance_is_fail_soft_on_a_non_repo(tmp_path):
    assert runmeta.git_provenance(str(tmp_path / "not-a-repo")) == {}
