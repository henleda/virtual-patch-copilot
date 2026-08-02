"""Larkspur Bank — a small, deliberately vulnerable banking API for the L2 BIG-IP lab.

Stdlib only, so the container is a bare `python:3-slim` with nothing installed: no dependency can
drift, and `python3 app.py` runs it on any laptop with no venv.

It exists to be the *origin* behind the lab appliance — the thing an exploit is fired at so a
generated policy can be watched blocking it. It is NOT the scan benchmark (`bench/` stays calibrated
against `bench/fixtures/nimbus-vuln-lab`), and it is NOT a Nimbus Bank look-alike.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import api
import store

HERE = Path(__file__).resolve().parent
PORT = int(os.environ.get("PORT", "8080"))


class Handler(BaseHTTPRequestHandler):
    server_version = "larkspur/1.0"

    # -------------------------------------------------- plumbing
    def _send(self, code: int, payload, ctype="application/json"):
        body = api.dumps(payload) if isinstance(payload, dict) else payload
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _token(self) -> str | None:
        raw = self.headers.get("Authorization", "")
        return raw[7:] if raw.lower().startswith("bearer ") else None

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def log_message(self, fmt, *args):
        # One line per request on stdout — a container log a demo can tail while firing exploits.
        print(f"{self.address_string()} {fmt % args}", flush=True)

    # -------------------------------------------------- routes
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path.rstrip("/") or "/"

        if p == "/":
            return self._send(200, (HERE / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if p == "/api/health":
            return self._send(*api.health())
        if p == "/api/summary":
            return self._send(*api.summary(self._token()))
        if p == "/api/profile":
            return self._send(*api.profile(self._token()))
        if p == "/api/statements":
            return self._send(*api.statements((q.get("q") or [""])[0], self._token()))
        if p.startswith("/api/accounts/"):
            return self._send(*api.get_account(p.rsplit("/", 1)[-1], self._token()))
        if p.startswith("/api/transactions/"):
            return self._send(*api.list_transactions(p.rsplit("/", 1)[-1], self._token()))
        return self._send(404, {"error": "not found", "path": p})

    def do_POST(self):
        p = urlparse(self.path).path.rstrip("/") or "/"
        if p == "/api/login":
            return self._send(*api.login(self._body()))
        if p == "/api/transfer":
            return self._send(*api.transfer(self._body(), self._token()))
        if p == "/api/reset":
            # Not a vulnerability — a lab affordance. The exploit permanently inflates a balance, so
            # a demo has to be able to start from the seeded numbers again without a redeploy.
            store.reset()
            api.SESSIONS.clear()
            return self._send(200, {"ok": True, "reset": True})
        return self._send(404, {"error": "not found", "path": p})


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"larkspur-bank listening on 0.0.0.0:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
