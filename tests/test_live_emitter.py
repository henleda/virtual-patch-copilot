"""Live: the L1 emitter's policy actually blocks, on a real BIG-IP.

This is the proof L1 shipped on — *"the emitted policy, loaded onto a real BIG-IP with Advanced WAF,
blocks the recorded exploit and passes the recorded legit request"* — and until now it existed only
in one person's terminal. It is the newest instance of exactly what this suite exists to fix.

It mutates a real appliance, so it restores the lab to its clean-slate contract in a `finally`, and
`live.restoring` fails the test loudly if that cleanup does not stick: a live test that leaves a WAF
policy attached has changed the estate for the operator's next demo.

**The assertion is the balance, not the status code.** BIG-IP's blocking page returns HTTP 200 with
a support ID, so a naive status check reads a block as a pass — which is why the money, not the
response, is what this test believes.

Needs: `BIGIP_URL` (usually an SSM port-forward — see docs/USAGE.md §7b), `BIGIP_PASSWORD`, and
`VPCOPILOT_LIVE_ORIGIN` pointing at the app *through* the appliance.
"""
from __future__ import annotations

import base64
import json

import httpx
import pytest

from tests.live import requires, restoring
from vpcopilot import emitters

pytestmark = pytest.mark.live

TENANT = "vpcopilot_lab"
APP = "larkspur"

# The recorded pair, exactly as `probes.json` carries one.
PROBE = {
    "finding_id": "larkspur-neg-transfer-001",
    "setup": [{"method": "POST", "path": "/api/login",
               "headers": {"Content-Type": "application/json"},
               "json_body": {"username": "avery.stone", "password": "hunter2"}}],
    "exploit": {"method": "POST", "path": "/api/transfer",
                "headers": {"Content-Type": "application/json"},
                "json_body": {"from": "LK-1001", "to": "LK-2001", "amount_cents": -50000}},
    "legit": {"method": "POST", "path": "/api/transfer",
              "headers": {"Content-Type": "application/json"},
              "json_body": {"from": "LK-1001", "to": "LK-1002", "amount_cents": 2500}},
}


def _declaration(origin_host: str, origin_port: int, vip: str, policy: dict | None) -> dict:
    """The lab tenant, with the emitted policy attached or absent.

    `WAF_Policy.policy` is an `F5string` — a *reference*, not an inline object — so the document
    travels base64-encoded. Posting it inline is rejected with `Invalid data property:
    [object Object]`, which is the kind of thing only a real appliance tells you.
    """
    main = {"class": "Service_HTTP", "virtualAddresses": [vip], "virtualPort": 80, "pool": "lab_pool"}
    app: dict = {
        "class": "Application", "template": "http",
        "serviceMain": main,
        "lab_pool": {"class": "Pool", "monitors": ["http"],
                     "members": [{"servicePort": origin_port, "serverAddresses": [origin_host]}]},
    }
    if policy is not None:
        main["policyWAF"] = {"use": "vpcopilot_waf"}
        app["vpcopilot_waf"] = {
            "class": "WAF_Policy", "ignoreChanges": True,
            "policy": {"base64": base64.b64encode(json.dumps(policy).encode()).decode()},
        }
    return {"class": "AS3", "action": "deploy", "persist": True,
            "declaration": {"class": "ADC", "schemaVersion": "3.0.0", "id": "vpcopilot-live-test",
                            TENANT: {"class": "Tenant", APP: app}}}


def _deploy(bigip, decl):
    from vpcopilot.bigip import BigIPError
    try:
        return bigip.deploy(decl)
    except BigIPError as e:
        pytest.fail(f"AS3 refused the declaration: {e}")


def _balance(origin: str, token: str, acct: str = "LK-1001") -> int:
    r = httpx.get(f"{origin}/api/accounts/{acct}", headers={"Authorization": f"Bearer {token}"},
                  timeout=15)
    r.raise_for_status()
    return r.json()["balance_cents"]


def _login(origin: str) -> str:
    r = httpx.post(f"{origin}/api/login", json=PROBE["setup"][0]["json_body"], timeout=15)
    r.raise_for_status()
    return r.json()["token"]


def test_the_emitted_policy_blocks_the_exploit_and_passes_the_legit_request(evidence):
    env = requires("BIGIP_URL", "BIGIP_PASSWORD", "VPCOPILOT_LIVE_ORIGIN")
    origin = env["VPCOPILOT_LIVE_ORIGIN"].rstrip("/")
    origin_host = (env.get("VPCOPILOT_LIVE_ORIGIN_HOST") or "10.30.10.22")
    vip = env.get("VPCOPILOT_LIVE_VIP") or "10.30.10.190"

    from vpcopilot.bigip import BigIP
    bigip = BigIP()

    # The emitter is the thing under test — the policy is built here, not pasted in.
    res = emitters.emit(target="bigip-awaf", control="service_policy",
                        policy_name="vpcopilot-live-neg-transfer", probe=PROBE, protocol="http")
    assert res.supported, f"the emitter declined: {res.reason}"
    assert res.derived_from["parameter"] == "amount_cents"
    evidence.record(f"emitter derived {res.derived_from['parameter']} >= "
                    f"{res.derived_from['minimum']} from the recorded pair")

    httpx.post(f"{origin}/api/reset", timeout=15)
    token = _login(origin)
    before = _balance(origin, token)

    try:
        _deploy(bigip, _declaration(origin_host, 8080, vip, res.policy))
        evidence.record("policy attached via AS3")

        token = _login(origin)                       # the reset/attach may have dropped the session
        start = _balance(origin, token)
        ex = PROBE["exploit"]
        r = httpx.post(f"{origin}{ex['path']}", json=ex["json_body"],
                       headers={"Authorization": f"Bearer {token}"}, timeout=15)
        after = _balance(origin, token)

        # THE assertion. Not the status code: BIG-IP answers its blocking page with HTTP 200 and a
        # support id, so a status check would read this block as a pass.
        assert after == start, (
            f"the exploit MOVED MONEY despite the policy: {start} -> {after}. "
            f"(response was {r.status_code} {r.headers.get('content-type')})")
        assert "application/json" not in (r.headers.get("content-type") or ""), \
            "the app answered, so the request reached it — the policy did not block at the edge"
        evidence.record(f"exploit blocked at the edge; balance unchanged at {after}")

        lg = PROBE["legit"]
        r2 = httpx.post(f"{origin}{lg['path']}", json=lg["json_body"],
                        headers={"Authorization": f"Bearer {token}"}, timeout=15)
        assert r2.status_code == 200 and "application/json" in (r2.headers.get("content-type") or ""), \
            f"the legit request was blocked too — the band-aid over-blocks ({r2.status_code})"
        moved = _balance(origin, token)
        assert moved == after - lg["json_body"]["amount_cents"], \
            f"the legit transfer did not debit correctly: {after} -> {moved}"
        evidence.record(f"legit request passed; balance {after} -> {moved}")
    finally:
        # Back to the clean-slate contract `bigip-lab create` produces — no WAF attached. A live
        # test that leaves one on has changed the estate for the next demo.
        restoring(_deploy, bigip, _declaration(origin_host, 8080, vip, None))
        httpx.post(f"{origin}/api/reset", timeout=15)

    # …and prove the restore actually restored, rather than trusting the AS3 200.
    token = _login(origin)
    base = _balance(origin, token)
    ex = PROBE["exploit"]
    httpx.post(f"{origin}{ex['path']}", json=ex["json_body"],
               headers={"Authorization": f"Bearer {token}"}, timeout=15)
    assert _balance(origin, token) != base, \
        "the exploit no longer works after cleanup — the policy was NOT removed"
    httpx.post(f"{origin}/api/reset", timeout=15)
    evidence.record(f"clean slate confirmed: the exploit reproduces again (seeded balance {before}), "
                    f"so the policy is gone")
