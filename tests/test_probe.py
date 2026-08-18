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

        def get(self, path, headers=None):
            return FakeResp(next(seq))

    monkeypatch.setattr(probe.httpx, "Client", FakeClient)
    r = probe.probe_rate_limit("http://x", count=5, path="/", log=lambda m: None)
    assert r == {"sent": 5, "limited": 3, "passed": 2, "codes": {200: 2, 429: 3}}


class _Resp:
    def __init__(self, s, t):
        self.status_code, self.text = s, t


def _core(r):
    """probe_from_spec also returns `blocked_by_edge` (I1: was it the F5 edge or the app itself?).
    These tests are about the exploit/legit verdicts, so compare those rather than the whole dict —
    the key is additive and nothing in src/ compares the shape exactly."""
    return {k: v for k, v in r.items() if k != "blocked_by_edge"}


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
    assert _core(r) == {"exploit_status": 200, "exploit_blocked": True, "legit_ok": True}


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
    assert _core(r) == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}


def test_probe_from_spec_leak_baseline_exposes_the_secret(monkeypatch):
    """Data Guard / response-masking finding, BEFORE the band-aid: the authed leak response carries
    the raw PAN, so it is NOT masked — exploit_blocked=False (the leak is real), legit_ok=True (the
    endpoint works). No `exploit`/`legit` is fired; the `leak` request drives everything."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/api/login"): (200, '{"token":"t"}'),
        ("GET", "/api/profile"): (200, '{"card_pan":"4111111111111111","govt_id":"078-05-1120"}'),
    }))
    spec = {"finding_id": "f-pii",
            "setup": [{"method": "POST", "path": "/api/login", "json_body": {"u": "x"}}],
            "leak": {"method": "GET", "path": "/api/profile"},
            "leak_secrets": ["4111111111111111", "078-05-1120"]}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r["leak"] is True and r["exploit_blocked"] is False and r["legit_ok"] is True
    assert set(r["leak_secrets_present"]) == {"4111111111111111", "078-05-1120"}


def test_probe_from_spec_leak_masked_after_band_aid(monkeypatch):
    """AFTER the band-aid: Data Guard masked the PAN and SSN on egress — the raw secrets are gone from
    a still-200 response — so exploit_blocked=True (harm neutralised) and legit_ok=True (not broken).
    This is what makes keep/rollback fire the same way it does for a blocked request."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/api/login"): (200, '{"token":"t"}'),
        ("GET", "/api/profile"): (200, '{"card_pan":"############1111","govt_id":"###-##-####"}'),
    }))
    spec = {"finding_id": "f-pii",
            "setup": [{"method": "POST", "path": "/api/login", "json_body": {"u": "x"}}],
            "leak": {"method": "GET", "path": "/api/profile"},
            "leak_secrets": ["4111111111111111", "078-05-1120"]}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r["exploit_blocked"] is True and r["legit_ok"] is True and r["leak_secrets_present"] == []


def test_probe_from_spec_leak_overblock_is_a_failure_not_a_mask(monkeypatch):
    """A response that is actually an ASM BLOCK page must NOT be mistaken for a successful mask — the
    secret is absent only because the whole response was rejected. That is over-blocking: a masked
    leak has to reach the caller as a real 200. exploit_blocked=False, legit_ok=False -> rollback."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/api/login"): (200, '{"token":"t"}'),
        ("GET", "/api/profile"): (200, "The requested URL was rejected. Your support ID is: 42"),
    }))
    spec = {"finding_id": "f-pii",
            "setup": [{"method": "POST", "path": "/api/login", "json_body": {"u": "x"}}],
            "leak": {"method": "GET", "path": "/api/profile"},
            "leak_secrets": ["4111111111111111"]}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r["exploit_blocked"] is False and r["legit_ok"] is False   # a block is not a mask


def test_probe_from_spec_leak_unobserved_401_is_not_a_mask(monkeypatch):
    """The honesty edge case: if the leak request returns 401 (auth didn't establish a session, or the
    endpoint needs auth we didn't supply), the secret is absent from the 401 body — but that is NOT
    masking, it's "we never saw the response". It must report exploit_blocked=False, legit_ok=False, and
    leak_observed=False so apply_bigip fails closed and surfaces a fixable cause — never a false 'masked'."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("GET", "/api/profile"): (401, '{"error":"authentication required"}'),
    }, default=(401, "auth")))
    spec = {"finding_id": "f-pii",
            "leak": {"method": "GET", "path": "/api/profile"},
            "leak_secrets": ["4111111111111111"]}
    r = probe.probe_from_spec("http://x", spec, log=lambda m: None)
    assert r["leak_observed"] is False
    assert r["exploit_blocked"] is False and r["legit_ok"] is False   # absent secret != masked


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
    assert _core(r) == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}
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
    assert _core(r) == {"exploit_status": 403, "exploit_blocked": True, "legit_ok": True}
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


# I1 — the edge/app distinction. `_blocked` deliberately conflates them (through the LB, "blocked"
# is all you need); reconcile fires at the ORIGIN to ask whether the APP was fixed, so an XC block
# page arriving from what was supposed to be the origin means the request went through a load
# balancer and the band-aid under test just vouched for its own removal.
def test_an_xc_block_page_is_flagged_as_an_edge_verdict(monkeypatch):
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/pay"): (403, "Request Rejected — your support ID is 1234"),
        ("GET", "/"): (200, "ok")}))
    r = probe.probe_from_spec("http://origin", {
        "exploit": {"method": "POST", "path": "/pay"}, "legit": {"method": "GET", "path": "/"}},
        log=lambda m: None)
    assert r["exploit_blocked"] is True and r["blocked_by_edge"] is True


def test_the_apps_own_403_is_not_an_edge_verdict(monkeypatch):
    """A bare 403 from the application — the fix landed and the app now rejects the exploit
    itself — must stay usable as proof, or reconcile could never retire anything."""
    from vpcopilot import probe
    monkeypatch.setattr(probe.httpx, "Client", _fake_client({
        ("POST", "/pay"): (403, '{"error":"amount must be positive"}'),
        ("GET", "/"): (200, "ok")}))
    r = probe.probe_from_spec("http://origin", {
        "exploit": {"method": "POST", "path": "/pay"}, "legit": {"method": "GET", "path": "/"}},
        log=lambda m: None)
    assert r["exploit_blocked"] is True and r["blocked_by_edge"] is False
