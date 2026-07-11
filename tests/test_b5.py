"""B5: fail-closed validation — sharpened XC block detection, legit must actually succeed, and no
silent Nimbus fallback (require_probe returns a non-passing result instead of a bogus one)."""
from vpcopilot import apply, probe
from vpcopilot.probe import _blocked


def test_blocked_matches_xc_signals_not_app_text():
    assert _blocked(200, "The requested URL was rejected. Please consult... your support ID is 123")
    assert _blocked(403, "")                     # bare service-policy DENY
    assert _blocked(200, "Request Rejected")     # XC WAF page
    # an app's own 200 "login rejected" is NOT an XC block (the old 'rejected' substring was too broad)
    assert not _blocked(200, "Login rejected: bad password")
    assert not _blocked(401, "unauthorized")     # app auth error, reached the app


def test_probe_from_spec_legit_5xx_is_not_ok(monkeypatch):
    # exploit blocked (403), but the legit request 500s -> legit_ok must be False
    seq = iter([(403, ""), (500, "boom")])
    monkeypatch.setattr(probe, "_fire", lambda c, req: next(seq))
    monkeypatch.setattr(probe.httpx, "Client", _FakeClient)
    res = probe.probe_from_spec("http://x", {"exploit": {"path": "/e"}, "legit": {"path": "/l"}}, log=lambda m: None)
    assert res["exploit_blocked"] is True and res["legit_ok"] is False


def test_probe_from_spec_legit_401_is_ok(monkeypatch):
    seq = iter([(403, ""), (401, "unauthorized")])
    monkeypatch.setattr(probe, "_fire", lambda c, req: next(seq))
    monkeypatch.setattr(probe.httpx, "Client", _FakeClient)
    res = probe.probe_from_spec("http://x", {"exploit": {"path": "/e"}, "legit": {"path": "/l"}}, log=lambda m: None)
    assert res["legit_ok"] is True  # reached the app (auth-required), not XC-blocked


def test_run_validation_require_probe_fails_closed(tmp_path):
    called = {"n": 0}
    def fallback(url, log):
        called["n"] += 1
        return {"neg_status": 200, "neg_blocked": True, "legit_ok": True}
    res = apply._run_validation("http://x", "no-such", str(tmp_path), fallback, lambda m: None, require_probe=True)
    assert res["no_probe"] is True and res["exploit_blocked"] is None  # cannot pass
    assert called["n"] == 0                                            # fallback never fired


def test_run_validation_fallback_is_tagged_and_loud(tmp_path):
    res = apply._run_validation("http://x", None, str(tmp_path),
                                lambda url, log: {"neg_status": 200, "neg_blocked": False, "legit_ok": True},
                                lambda m: None)
    assert res.get("fallback") is True  # the Nimbus fallback is tagged so callers can distrust it


class _FakeClient:
    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def request(self, *a, **k): return type("R", (), {"status_code": 200, "text": ""})()
