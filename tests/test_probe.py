def test_probe_rate_limit_counts(monkeypatch):
    """probe_rate_limit tallies 429s vs passes and per-code counts over a burst."""
    from vpcopilot import probe

    seq = iter([200, 200, 429, 429, 429])

    class FakeResp:
        def __init__(self, s):
            self.status_code = s

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, path):
            return FakeResp(next(seq))

    monkeypatch.setattr(probe.httpx, "Client", FakeClient)
    r = probe.probe_rate_limit("http://x", count=5, path="/", log=lambda m: None)
    assert r == {"sent": 5, "limited": 3, "passed": 2, "codes": {200: 2, 429: 3}}


class _Resp:
    def __init__(self, s, t):
        self.status_code, self.text = s, t


def _fake_client(responses, default=(404, "")):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, path, **kw):
            s, t = responses.get((method, path), default)
            return _Resp(s, t)

    return FakeClient


def test_probe_from_spec_blocked(monkeypatch):
    """setup login (200) -> exploit blocked by XC (403 'Request Rejected') -> legit passes (200)."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/login"): (200, "ok"),
        ("PUT", "/users/v1/name1/password"): (200, "The requested URL was rejected"),  # WAF: 200 + reject body
        ("GET", "/users/v1"): (200, "[]"),
    }))
    spec = {"finding_id": "f1",
            "setup": [{"method": "POST", "path": "/login", "json_body": {"u": "x"}}],
            "exploit": {"method": "PUT", "path": "/users/v1/name1/password", "json_body": {"password": "h"}},
            "legit": {"method": "GET", "path": "/users/v1"}}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r == {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True}


def test_probe_from_spec_baseline_allowed(monkeypatch):
    """No band-aid yet: exploit reaches the app (200, not blocked)."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({}, default=(200, "ok")))
    r = probe.probe_from_spec("http://x", {"finding_id": "f1", "exploit": {"method": "GET", "path": "/x"}},
                              log=lambda m: None)
    assert r["exploit_blocked"] is False and r["exploit_status"] == 200 and r["legit_ok"] is True


def test_probe_from_spec_legit_app_4xx_is_ok(monkeypatch):
    """A legit request returning app-level 401 (auth-required) is NOT an over-block -> legit_ok True."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("PUT", "/users/v1/admin/password"): (403, "Request Rejected"),  # XC blocks the exploit
        ("GET", "/users/v1/me"): (401, '{"detail":"auth required"}'),    # legit: app 401, not an XC block
    }))
    spec = {"finding_id": "f1",
            "exploit": {"method": "PUT", "path": "/users/v1/admin/password"},
            "legit": {"method": "GET", "path": "/users/v1/me"}}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}


def test_load_probe(tmp_path):
    import json
    from vpcopilot.apply import _load_probe
    (tmp_path / "probes.json").write_text(json.dumps([{"finding_id": "f1", "exploit": {"path": "/x"}}]))
    assert _load_probe(str(tmp_path), "f1")["exploit"]["path"] == "/x"
    assert _load_probe(str(tmp_path), "nope") is None
    assert _load_probe(str(tmp_path), None) is None
