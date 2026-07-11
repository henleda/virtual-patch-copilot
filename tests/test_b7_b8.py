"""B7 (atomic/locked ledger, per-LB snapshots) + B8 (env writer, XCError redaction, dry-run probe)."""
import json
import threading

from vpcopilot import apply, ledger


# ---- B7: ledger ----

def test_ledger_atomic_survives_bad_file(tmp_path):
    (tmp_path / "ledger.json").write_text("{ this is not valid json")
    assert ledger.load(str(tmp_path)) == {}  # tolerates a corrupt file instead of crashing
    ledger.save(str(tmp_path), {"a": {"finding_id": "a", "state": "found"}})
    assert ledger.load(str(tmp_path))["a"]["state"] == "found"
    assert not list(tmp_path.glob("*.tmp*"))  # temp file was renamed away, not left behind


def test_ledger_concurrent_marks_dont_clobber(tmp_path):
    ids = [f"f{i}" for i in range(25)]
    def worker(fid):
        ledger.mark_mitigated(str(tmp_path), fid, control="waf", policy_name="p", lb="lab")
    threads = [threading.Thread(target=worker, args=(i,)) for i in ids]
    for t in threads: t.start()
    for t in threads: t.join()
    entries = ledger.load(str(tmp_path))
    assert set(entries) == set(ids)  # every concurrent write landed; none lost to a race


def test_apply_writes_per_lb_timestamped_snapshot(monkeypatch, fake_xc, tmp_path, noop_sleep):
    import vpcopilot.engine as engine
    real = engine.ApplyContext.__post_init__
    monkeypatch.setattr(engine.ApplyContext, "__post_init__",
                        lambda self: (real(self), setattr(self, "sleep", noop_sleep))[0])
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    apply.apply_malicious_user("lab", keep=False, out_dir=str(tmp_path), log=lambda m: None)
    snaps = list((tmp_path / "snapshots").glob("lab-*.json"))
    assert len(snaps) == 1 and json.loads(snaps[0].read_text())["metadata"]["name"] == "lab"


# ---- B8: env writer ----

def test_env_writer_preserves_comments_and_quotes(tmp_path, monkeypatch):
    from vpcopilot.console import app
    env = tmp_path / ".env"
    env.write_text("# my creds\nXC_NAMESPACE=old-ns\n\n# keep me\nKEEP=1\n")
    monkeypatch.setattr(app, "ENV_PATH", env)
    app._write_env({"XC_NAMESPACE": "new-ns", "XC_DASHBOARD_URL": "https://a b/c", "BLANK": ""})
    txt = env.read_text()
    assert "# my creds" in txt and "# keep me" in txt and "KEEP=1" in txt  # comments/keys preserved
    assert "XC_NAMESPACE=new-ns" in txt and "old-ns" not in txt           # updated in place
    assert 'XC_DASHBOARD_URL="https://a b/c"' in txt                      # spaces -> quoted
    assert "BLANK" not in txt                                             # empty update ignored


# ---- B8: XCError token redaction ----

def test_xcerror_redacts_token(monkeypatch):
    from vpcopilot.xc import XC
    monkeypatch.setenv("XC_API_URL", "https://x/api")
    monkeypatch.setenv("XC_API_TOKEN", "SECRET-TOKEN-123")
    monkeypatch.setenv("XC_NAMESPACE", "ns")
    xc = XC()
    assert xc._redact("boom SECRET-TOKEN-123 boom") == "boom ***REDACTED*** boom"


# ---- B8: dry-run doesn't fire the exploit unless --probe ----

def test_dry_run_skips_probe_by_default(monkeypatch, fake_xc, tmp_path):
    monkeypatch.setenv("VPCOPILOT_PROTECTED_LBS", "nimbus-www")
    monkeypatch.setattr(apply, "XC", lambda *a, **k: fake_xc)
    def _boom(*a, **k):
        raise AssertionError("dry-run fired the exploit probe without --probe")
    monkeypatch.setattr(apply, "_run_validation", _boom)
    res = apply.apply_service_policy("lab", "p", "http://x", dry_run=True, out_dir=str(tmp_path), log=lambda m: None)
    assert res["mode"] == "dry_run" and res["probe_current"] is None
