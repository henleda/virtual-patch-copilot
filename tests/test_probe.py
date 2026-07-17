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


# ---- auth-protected validation (Layer A token capture/injection, Layer B operator login) ----
def _rec_client(routes, *, cookie_on=None):
    """A fake httpx.Client that RECORDS each request's headers (to assert bearer injection),
    exposes a cookie jar, and can set a session cookie when a login path is hit. `calls` is a
    shared list the test inspects after the run; a route value may be a callable(headers)->(status,
    text) so a response can depend on whether the Authorization header was injected."""
    calls: list = []
    cookies: dict = {}

    class C:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        @property
        def cookies(self):
            return cookies

        def request(self, method, path, **kw):
            headers = dict(kw.get("headers") or {})
            calls.append((method, path, headers))
            r = routes.get((method, path), (404, ""))
            status, text = r(headers) if callable(r) else r
            if cookie_on and path == cookie_on and status < 400:
                cookies["session"] = "1"
            return _Resp(status, text)

    return C, calls


def test_probe_from_spec_captures_and_injects_token(monkeypatch):
    """Layer A: a token-based app — the setup login returns a bearer token in its JSON body, which
    the probe captures and injects as Authorization on the exploit + legit requests (the exploit is
    only 'blocked' here when the token was present, proving injection)."""
    from vpcopilot import probe

    def pay(headers):
        return (403, "denied") if headers.get("Authorization") == "Bearer T0k" else (200, "ok")

    C, calls = _rec_client({
        ("POST", "/login"): (200, '{"data": {"access_token": "T0k"}}'),  # token nested one level down
        ("POST", "/pay"): pay,
        ("GET", "/me"): (200, "[]"),
    })
    monkeypatch.setattr(probe.httpx, "Client", C)
    spec = {"finding_id": "f1",
            "setup": [{"method": "POST", "path": "/login", "json_body": {"u": "x"}}],
            "exploit": {"method": "POST", "path": "/pay", "json_body": {"amount": -1}},
            "legit": {"method": "GET", "path": "/me"}}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}
    hdr = {p: h for (_, p, h) in calls}
    assert hdr["/pay"].get("Authorization") == "Bearer T0k"   # injected on the exploit
    assert hdr["/me"].get("Authorization") == "Bearer T0k"    # and the legit request


def test_probe_from_spec_operator_login_cookie(monkeypatch):
    """Layer B, cookie app: the operator supplies real creds; the probe logs in FIRST over the shared
    session (cookie lands in the jar), so the exploit is demonstrated and the band-aid's 403 is seen —
    instead of a bare 401 from an unauthenticated probe."""
    from vpcopilot import probe
    C, calls = _rec_client({
        ("POST", "/api/login"): (200, "ok"),
        ("POST", "/pay"): (403, "Request Rejected"),
        ("GET", "/me"): (200, "ok"),
    }, cookie_on="/api/login")
    monkeypatch.setattr(probe.httpx, "Client", C)
    spec = {"finding_id": "f1", "exploit": {"method": "POST", "path": "/pay"},
            "legit": {"method": "GET", "path": "/me"}}
    auth = {"username": "real", "password": "pw", "login_path": "/api/login"}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None, auth=auth)
    assert r == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}
    assert calls[0][:2] == ("POST", "/api/login")  # operator login ran first


def test_probe_from_spec_operator_login_failure_is_loud(monkeypatch):
    """Layer B fail-loud: a bad credential/path establishes no session, so we return auth_failed and
    never fire the exploit — instead of a misleading 'not blocked' or a false auth_required."""
    from vpcopilot import probe
    C, calls = _rec_client({
        ("POST", "/api/login"): (401, "bad creds"),  # no 2xx, no cookie_on -> no session
        ("POST", "/pay"): (200, "ok"),
    })
    monkeypatch.setattr(probe.httpx, "Client", C)
    spec = {"finding_id": "f1", "exploit": {"method": "POST", "path": "/pay"}}
    auth = {"username": "wrong", "password": "x", "login_path": "/api/login"}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None, auth=auth)
    assert r["auth_failed"] is True and r["exploit_blocked"] is None
    assert not any(p == "/pay" for (_, p, _) in calls)  # exploit never fired


def test_probe_from_spec_operator_login_supersedes_guessed_setup(monkeypatch):
    """The operator login supersedes the model's guessed setup login to the same endpoint, so a wrong
    guessed credential can't clobber the real session — the login runs exactly once."""
    from vpcopilot import probe
    C, calls = _rec_client({
        ("POST", "/api/login"): (200, "ok"),
        ("POST", "/pay"): (403, "Request Rejected"),
    }, cookie_on="/api/login")
    monkeypatch.setattr(probe.httpx, "Client", C)
    spec = {"finding_id": "f1",
            "setup": [{"method": "POST", "path": "/api/login", "json_body": {"username": "guess"}}],
            "exploit": {"method": "POST", "path": "/pay"}}
    auth = {"username": "real", "password": "pw", "login_path": "/api/login"}
    probe.probe_from_spec("http://x", spec, log=lambda m: None, auth=auth)
    assert sum(1 for (_, p, _) in calls if p == "/api/login") == 1


def test_probe_auth_from_env(monkeypatch):
    """apply._probe_auth_from_env builds the operator-auth dict from VPCOPILOT_PROBE_* — the single
    injection point every _run_validation reads."""
    from vpcopilot.apply import _probe_auth_from_env
    for k in ("VPCOPILOT_PROBE_TOKEN", "VPCOPILOT_PROBE_USER", "VPCOPILOT_PROBE_PASS",
              "VPCOPILOT_PROBE_LOGIN_PATH"):
        monkeypatch.delenv(k, raising=False)
    assert _probe_auth_from_env() is None
    monkeypatch.setenv("VPCOPILOT_PROBE_USER", "u")
    monkeypatch.setenv("VPCOPILOT_PROBE_PASS", "p")
    a = _probe_auth_from_env()
    assert a == {"login_path": "/api/login", "username": "u", "password": "p",
                 "user_field": "username", "pass_field": "password"}
    monkeypatch.setenv("VPCOPILOT_PROBE_TOKEN", "T")
    assert _probe_auth_from_env()["token"] == "T"
