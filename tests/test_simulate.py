"""G2 — shadow simulation. Replays a recorded sample against a candidate band-aid on a spare LB
and reports what it WOULD block, before anything reaches the human gate.

Offline: the LB is FakeXC and the replay is a stub transport, so no tenant and no network."""
import json

import pytest

from vpcopilot import simulate, traffic
from vpcopilot.schemas import RequestRecord

POLICY = {"metadata": {"name": "deny-negative-pay"}, "spec": {"rule_list": {"rules": [
    {"spec": {"action": "DENY", "path": {"exact_values": ["/api/pay"]},
              "http_method": {"methods": ["POST"]},
              "body_matcher": {"regex_values": ["amount[^0-9-]*-[0-9]"]}}},
    {"spec": {"action": "ALLOW", "path": {"prefix_values": ["/"]}}},
]}}}


def _recs(*paths):
    return [RequestRecord(path=p, method="POST") for p in paths]


def _fire(blocked_paths):
    """Stub replay: XC 403s exactly the paths named, everything else passes through."""
    def fire(rec, url):
        return (403, "") if rec.path in blocked_paths else (200, "ok")
    return fire


@pytest.fixture(autouse=True)
def _fast(monkeypatch, noop_sleep):
    import vpcopilot.engine as engine
    real = engine.ApplyContext.__post_init__

    def patched(self):
        real(self)
        self.sleep = noop_sleep
    monkeypatch.setattr(engine.ApplyContext, "__post_init__", patched)
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")


def _sim(monkeypatch, fake_xc, tmp_path, recs, blocked, **kw):
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(simulate, "_fire", _fire(blocked))
    return simulate.simulate_policies(
        [{"policy_name": "deny-negative-pay", "control": "service_policy",
          "finding_id": "f-1", "spec": POLICY}],
        recs, lb="lab", url="http://lab.test", out_dir=str(tmp_path), log=lambda m: None, **kw)


# ---- the acceptance case ----
def test_surgical_policy_blocks_the_exploit_and_no_legitimate_traffic(monkeypatch, fake_xc, tmp_path):
    recs = _recs("/api/pay", "/api/accounts", "/health", "/api/pay")
    res = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={"/api/pay"})
    p = res.policies[0]
    assert p.evaluated == 4 and p.would_block == 2
    assert p.block_rate == 0.5 and p.blocked_promotion is True   # 50% >> default threshold


def test_a_policy_blocking_only_the_exploit_path_stays_under_threshold(monkeypatch, fake_xc, tmp_path):
    recs = _recs("/api/pay", *[f"/legit/{i}" for i in range(199)])
    res = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={"/api/pay"})
    p = res.policies[0]
    assert p.would_block == 1 and p.blocked_promotion is False and p.reason == ""


def test_an_overbroad_policy_trips_the_threshold_with_a_reason(monkeypatch, fake_xc, tmp_path):
    recs = _recs("/a", "/b", "/c", "/d")
    res = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={"/a", "/b", "/c", "/d"})
    p = res.policies[0]
    assert p.block_rate == 1.0 and p.blocked_promotion is True
    assert "1.0" in p.reason or "100" in p.reason


def test_threshold_is_configurable(monkeypatch, fake_xc, tmp_path):
    recs = _recs("/api/pay", "/x", "/y", "/z")
    assert _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={"/api/pay"},
                threshold=0.5).policies[0].blocked_promotion is False


# ---- what the reviewer sees ----
def test_blocked_samples_and_top_paths_are_reported(monkeypatch, fake_xc, tmp_path):
    recs = _recs("/api/pay", "/api/pay", "/admin")
    p = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={"/api/pay", "/admin"}).policies[0]
    assert p.top_paths[0] == ["/api/pay", 2]
    assert p.samples and p.samples[0]["path"] in ("/api/pay", "/admin")


def test_sample_of_blocked_requests_is_capped(monkeypatch, fake_xc, tmp_path):
    recs = _recs(*[f"/p{i}" for i in range(100)])
    p = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked={f"/p{i}" for i in range(100)}).policies[0]
    assert p.would_block == 100 and len(p.samples) <= simulate.MAX_SAMPLES


# ---- safety: the LB must be left exactly as found ----
def test_the_lb_is_restored_after_a_replay(monkeypatch, fake_xc, tmp_path):
    before = json.dumps(fake_xc.lb["spec"], sort_keys=True)
    _sim(monkeypatch, fake_xc, tmp_path, _recs("/a"), blocked=set())
    assert json.dumps(fake_xc.lb["spec"], sort_keys=True) == before


def test_a_total_network_outage_leaves_the_lb_restored_and_measures_nothing(monkeypatch, fake_xc, tmp_path):
    """Every request failing is not a crash and not a 0% block rate — it is zero evidence."""
    before = json.dumps(fake_xc.lb["spec"], sort_keys=True)
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)

    def boom(rec, url):
        raise RuntimeError("network died mid-replay")
    monkeypatch.setattr(simulate, "_fire", boom)
    res = simulate.simulate_policies(
        [{"policy_name": "p", "control": "service_policy", "finding_id": "f", "spec": POLICY}],
        _recs("/a", "/b"), lb="lab", url="http://lab.test", out_dir=str(tmp_path), log=lambda m: None)
    p = res.policies[0]
    assert p.errored == 2 and p.evaluated == 0 and p.block_rate == 0.0
    assert p.blocked_promotion is False and p.enforcement_confirmed is False
    assert json.dumps(fake_xc.lb["spec"], sort_keys=True) == before


def test_the_lb_is_restored_when_the_attach_itself_fails(monkeypatch, fake_xc, tmp_path):
    """A policy-level failure (not a per-request one) is still reported, never raised past the
    restore — the spare LB must never be left carrying a rehearsal."""
    before = json.dumps(fake_xc.lb["spec"], sort_keys=True)
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(simulate, "_attach", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("XC 503")))
    res = simulate.simulate_policies(
        [{"policy_name": "p", "control": "service_policy", "finding_id": "f", "spec": POLICY}],
        _recs("/a"), lb="lab", url="http://lab.test", out_dir=str(tmp_path), log=lambda m: None)
    assert "XC 503" in res.policies[0].error
    assert json.dumps(fake_xc.lb["spec"], sort_keys=True) == before


def test_a_protected_lb_is_refused(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    with pytest.raises(RuntimeError, match="protected"):
        simulate.simulate_policies([], [], lb="nimbus-www", url="http://x",
                                   out_dir=str(tmp_path), log=lambda m: None)


def test_simulation_creates_no_audit_record(monkeypatch, fake_xc, tmp_path):
    """Evidence gathering never mutates what it records — a rehearsal is not a change."""
    from vpcopilot import audit
    _sim(monkeypatch, fake_xc, tmp_path, _recs("/a"), blocked=set())
    assert audit.load(str(tmp_path)) == []


# ---- artifact + the gate ----
def test_write_result_produces_the_artifact(monkeypatch, fake_xc, tmp_path):
    res = _sim(monkeypatch, fake_xc, tmp_path, _recs("/api/pay"), blocked={"/api/pay"})
    path = simulate.write_result(str(tmp_path), res)
    d = json.loads(open(path).read())
    assert d["policies"][0]["policy_name"] == "deny-negative-pay" and d["caveats"]


def test_bodies_unavailable_is_recorded_for_xc_sourced_records(monkeypatch, fake_xc, tmp_path):
    recs, _ = traffic.from_xc_logs([{"method": "GET", "req_path": "/a", "rsp_code": 200}])
    res = _sim(monkeypatch, fake_xc, tmp_path, recs, blocked=set())
    assert res.bodies_available is False
    assert any("body" in c.lower() for c in res.caveats)


def test_promotion_block_reads_the_artifact(tmp_path):
    (tmp_path / "simulation.json").write_text(json.dumps({"policies": [
        {"policy_name": "wide", "blocked_promotion": True, "block_rate": 0.9, "reason": "too wide"},
        {"policy_name": "ok", "blocked_promotion": False, "block_rate": 0.0}]}))
    assert simulate.promotion_block(str(tmp_path), "wide")
    assert simulate.promotion_block(str(tmp_path), "ok") is None


def test_promotion_block_is_silent_when_nothing_was_simulated(tmp_path):
    """No simulation must never block an apply — G2 adds a check, it does not add a prerequisite."""
    assert simulate.promotion_block(str(tmp_path), "anything") is None


# ---- propagation: a count taken before the edge enforces is not a measurement ----
def test_enforcement_is_confirmed_with_the_findings_own_exploit(monkeypatch, fake_xc, tmp_path):
    """Caught live: attaching and replaying immediately counted an unenforced policy as harmless —
    0/200 blocked, including the exploit. The canary polls until the policy actually bites."""
    (tmp_path / "probes.json").write_text(json.dumps([
        {"finding_id": "f-1", "exploit": {"method": "POST", "path": "/api/pay",
                                          "json_body": {"amount": -1}}}]))
    res = _sim(monkeypatch, fake_xc, tmp_path, _recs("/api/pay", "/health"), blocked={"/api/pay"})
    assert res.policies[0].enforcement_confirmed is True


def test_an_unconfirmed_run_says_so_rather_than_reading_as_safe(monkeypatch, fake_xc, tmp_path):
    """No probe -> no canary -> a 0% rate is unmeasured, not a clean bill of health."""
    res = _sim(monkeypatch, fake_xc, tmp_path, _recs("/a"), blocked=set())
    assert res.policies[0].enforcement_confirmed is False
    assert any("unconfirmed" in c.lower() or "unmeasured" in c.lower() for c in res.caveats)


def test_a_canary_that_never_blocks_does_not_confirm(monkeypatch, fake_xc, tmp_path):
    (tmp_path / "probes.json").write_text(json.dumps([
        {"finding_id": "f-1", "exploit": {"method": "POST", "path": "/api/pay"}}]))
    res = _sim(monkeypatch, fake_xc, tmp_path, _recs("/health"), blocked=set())
    assert res.policies[0].enforcement_confirmed is False


def test_one_transport_failure_does_not_discard_the_whole_replay(monkeypatch, fake_xc, tmp_path):
    """Caught live: a single transient SSL EOF aborted an entire policy's simulation."""
    calls = {"n": 0}

    def flaky(rec, url):
        calls["n"] += 1
        if rec.path == "/boom":
            raise RuntimeError("[SSL: UNEXPECTED_EOF_WHILE_READING]")
        return (403, "") if rec.path == "/api/pay" else (200, "ok")
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(simulate, "_fire", flaky)
    res = simulate.simulate_policies(
        [{"policy_name": "p", "control": "service_policy", "finding_id": "f", "spec": POLICY}],
        _recs("/api/pay", "/boom", "/health"), lb="lab", url="http://lab.test",
        out_dir=str(tmp_path), log=lambda m: None)
    p = res.policies[0]
    assert not p.error                       # the run completed
    assert p.errored == 1 and p.evaluated == 2 and p.would_block == 1
    assert p.block_rate == 0.5               # rate is over what actually reached the edge
    assert any("transit" in c.lower() for c in res.caveats)


# ---- the object lifecycle: simulate never rides on the operator's policies ----
def test_a_throwaway_policy_is_created_and_deleted(monkeypatch, fake_xc, tmp_path):
    """Caught live: attaching by name alone assumed the object already existed. A candidate
    straight from a scan does not, and referencing a missing policy breaks the LB config —
    every replayed request failed in transit, not just the ones under the rule."""
    _sim(monkeypatch, fake_xc, tmp_path, _recs("/api/pay"), blocked={"/api/pay"})
    assert simulate.sim_name("deny-negative-pay") == "deny-negative-pay-vpcsim"
    assert "deny-negative-pay-vpcsim" not in fake_xc.service_policies      # cleaned up
    assert "deny-negative-pay" not in fake_xc.service_policies             # never created either


def test_the_operators_own_policy_is_never_touched(monkeypatch, fake_xc, tmp_path):
    fake_xc.service_policies["deny-negative-pay"] = {"metadata": {"name": "deny-negative-pay"},
                                                     "spec": {"_theirs": True}}
    _sim(monkeypatch, fake_xc, tmp_path, _recs("/api/pay"), blocked={"/api/pay"})
    assert fake_xc.service_policies["deny-negative-pay"]["spec"] == {"_theirs": True}


def test_a_protected_policy_is_refused(monkeypatch, fake_xc, tmp_path):
    from vpcopilot.apply import PROTECTED_POLICIES
    name = sorted(PROTECTED_POLICIES)[0]
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(simulate, "_fire", _fire(set()))
    res = simulate.simulate_policies(
        [{"policy_name": name, "control": "service_policy", "finding_id": "f", "spec": POLICY}],
        _recs("/a"), lb="lab", url="http://lab.test", out_dir=str(tmp_path), log=lambda m: None)
    assert "protected" in res.policies[0].error


def test_zero_evaluated_is_reported_as_no_evidence_not_as_safe(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setattr(simulate, "XC", lambda *a, **k: fake_xc)
    monkeypatch.setattr(simulate, "_fire", lambda rec, url: (_ for _ in ()).throw(RuntimeError("down")))
    res = simulate.simulate_policies(
        [{"policy_name": "p", "control": "service_policy", "finding_id": "f", "spec": POLICY}],
        _recs("/a"), lb="lab", url="http://lab.test", out_dir=str(tmp_path), log=lambda m: None)
    p = res.policies[0]
    assert p.evaluated == 0 and "zero evidence" in p.reason
