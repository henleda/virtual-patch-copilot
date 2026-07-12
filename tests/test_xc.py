"""D3: exercise the XC REST client's real request/error path via httpx.MockTransport — no network,
but the actual _req code (auth header, status handling, token redaction) runs."""
import httpx
import pytest


def _xc(monkeypatch, handler):
    monkeypatch.setenv("XC_API_URL", "https://tenant.console.ves.volterra.io/api")
    monkeypatch.setenv("XC_API_TOKEN", "SUPER-SECRET-TOKEN")
    monkeypatch.setenv("XC_NAMESPACE", "ns1")
    from vpcopilot.xc import XC
    xc = XC()
    xc._c = httpx.Client(transport=httpx.MockTransport(handler), headers=xc._c.headers)
    return xc


def test_get_lb_sends_auth_and_parses(monkeypatch):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"metadata": {"name": "lab"}, "spec": {}})

    xc = _xc(monkeypatch, handler)
    lb = xc.get_lb("lab")
    assert lb["metadata"]["name"] == "lab"
    assert seen["auth"] == "APIToken SUPER-SECRET-TOKEN"
    assert seen["url"].endswith("/config/namespaces/ns1/http_loadbalancers/lab")


def test_error_status_raises_xcerror_with_redacted_token(monkeypatch):
    def handler(request):
        # a server that unwisely echoes the token in its error body
        return httpx.Response(403, text="denied for APIToken SUPER-SECRET-TOKEN")

    xc = _xc(monkeypatch, handler)
    from vpcopilot.xc import XCError
    with pytest.raises(XCError) as ei:
        xc.get_lb("lab")
    msg = str(ei.value)
    assert "403" in msg and "SUPER-SECRET-TOKEN" not in msg and "***REDACTED***" in msg


def test_put_swagger_returns_object_url(monkeypatch):
    def handler(request):
        return httpx.Response(200, json={"metadata": {"url": "string:///lab-swagger"}})

    xc = _xc(monkeypatch, handler)
    url = xc.put_swagger("lab-swagger", {"openapi": "3.0.0", "paths": {}})
    assert url == "string:///lab-swagger"
