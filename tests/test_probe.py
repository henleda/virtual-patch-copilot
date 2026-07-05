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
