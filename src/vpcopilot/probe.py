"""Validation prober: fire the negative-pay exploit + a legit payment at the live host
and report whether the exploit is blocked and legit traffic still passes.

Uses tiny amounts (-1 / +1) so repeated validation barely moves balances; the service
policy trips on the sign, not the magnitude."""
from __future__ import annotations

from typing import Callable

import httpx

DEMO_USER = {"username": "dthompson", "password": "nimbus2025"}


def _blocked(status: int, text: str) -> bool:
    t = text.lower()
    return status == 403 or "rejected" in t or "error page" in t


def normalize(res: dict | None) -> dict:
    """Collapse either probe's keys into a common {exploit_status, exploit_blocked, legit_ok}
    so before/after impact can be compared uniformly across controls."""
    if not res:
        return {"exploit_status": None, "exploit_blocked": None, "legit_ok": None}
    if "neg_status" in res:  # probe_negative_pay
        return {"exploit_status": res["neg_status"], "exploit_blocked": res["neg_blocked"],
                "legit_ok": res["legit_ok"]}
    return {"exploit_status": res.get("sqli_status"), "exploit_blocked": res.get("sqli_blocked"),
            "legit_ok": res.get("legit_ok")}


def probe_negative_pay(target_url: str, victim_account: str = "4001 2233 0002",
                       log: Callable = print) -> dict:
    with httpx.Client(base_url=target_url, timeout=15, follow_redirects=True) as c:
        c.post("/api/login", json=DEMO_USER)

        def fire(amount):
            r = c.post("/api/pay", json={
                "from_account": 1, "to_account_number": victim_account, "amount": amount,
            })
            return r.status_code, _blocked(r.status_code, r.text)

        neg_status, neg_blocked = fire(-1)
        pos_status, pos_blocked = fire(1)

    res = {
        "neg_status": neg_status,
        "neg_blocked": neg_blocked,
        "pos_status": pos_status,
        "legit_ok": (pos_status < 400) and not pos_blocked,
    }
    log(f"probe: negative-pay status={neg_status} blocked={neg_blocked} | "
        f"legit status={pos_status} ok={res['legit_ok']}")
    return res


def probe_sqli(target_url: str, log: Callable = print) -> dict:
    """Fire a SQLi login-bypass (WAF should block) + a legit login (should pass)."""
    with httpx.Client(base_url=target_url, timeout=15, follow_redirects=True) as c:
        r = c.post("/api/login", json={"username": "' OR '1'='1' --", "password": "x"})
        sqli_blocked = _blocked(r.status_code, r.text)
        r2 = c.post("/api/login", json=DEMO_USER)
        legit_ok = (r2.status_code < 400) and not _blocked(r2.status_code, r2.text)
    res = {"sqli_status": r.status_code, "sqli_blocked": sqli_blocked,
           "legit_status": r2.status_code, "legit_ok": legit_ok}
    log(f"probe: sqli status={r.status_code} blocked={sqli_blocked} | legit ok={legit_ok}")
    return res
