"""Larkspur Bank — the request handlers, and the deliberate flaws.

Every hole here is intentional and each one is chosen to route to a *different* F5 control family,
so one scan of this app exercises the breadth of the emitter rather than the same rule five times.
The flagship is `transfer`: a numeric business-logic flaw with no lower bound, which is the one case
where a declarative WAF policy (`dataType: integer`, `checkMinValue: true`, `minimumValue: 0`)
expresses the constraint itself rather than approximating it with a regex.

This file is meant to be READ by the discover agent, so the flaws are written the way they occur in
real code — a missing check, not a comment saying "vulnerable here".
"""
from __future__ import annotations

import json
import secrets

from store import DB, LOCK, account, next_tx_id, transactions_for

SESSIONS: dict[str, str] = {}       # token -> username


def _user_for(token: str | None) -> str | None:
    return SESSIONS.get(token or "")


# --------------------------------------------------------------------------- auth

def login(body: dict) -> tuple[int, dict]:
    """No attempt counter, no lockout, no backoff.

    Routes to rate_limit / malicious_user: the shape of the abuse is volume, which is not visible in
    any single request, so a per-request rule cannot see it.
    """
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    user = DB["users"].get(username)
    if not user or user["password"] != password:
        return 401, {"error": "invalid credentials"}
    token = secrets.token_hex(16)
    SESSIONS[token] = username
    return 200, {"token": token, "username": username,
                 "accounts": user["accounts"]}


# --------------------------------------------------------------------------- accounts

def get_account(acct_id: str, token: str | None) -> tuple[int, dict]:
    """Authenticated, but never checks that the caller OWNS this account.

    Routes to service_policy: the request is well-formed and the id is a legitimate value — what is
    wrong is *who* is asking, which an edge rule can only address by scoping the path.
    """
    if not _user_for(token):
        return 401, {"error": "authentication required"}
    acct = account(acct_id)
    if not acct:
        return 404, {"error": "no such account"}
    return 200, acct


def list_transactions(acct_id: str, token: str | None) -> tuple[int, dict]:
    if not _user_for(token):
        return 401, {"error": "authentication required"}
    return 200, {"account": acct_id, "transactions": transactions_for(acct_id)}


# --------------------------------------------------------------------------- the flagship

def transfer(body: dict, token: str | None) -> tuple[int, dict]:
    """Move money between accounts.

    THE flaw: `amount_cents` is never checked for a lower bound. A negative amount reverses the
    direction of both legs, so transferring -50000 from an account you control to any other account
    *credits* you 500.00 and debits them. The balance goes UP.

    `int()` rejects "abc" and a float, so the value reaching the ledger is a whole number — which is
    exactly why `dataType: "integer"` alone does not close this hole, and why the emitted policy has
    to carry `minimumValue`. F5 defines integer as "whole numbers only"; -50000 is a whole number.
    """
    if not _user_for(token):
        return 401, {"error": "authentication required"}
    src = str(body.get("from", ""))
    dst = str(body.get("to", ""))
    try:
        amount_cents = int(body.get("amount_cents"))
    except (TypeError, ValueError):
        return 400, {"error": "amount_cents must be a whole number of cents"}

    with LOCK:
        a, b = account(src), account(dst)
        if not a or not b:
            return 404, {"error": "unknown account"}
        if src == dst:
            return 400, {"error": "cannot transfer to the same account"}
        # The upper bound is checked. The lower bound is not — which is what makes this a business
        # logic flaw rather than a missing-validation typo: it looks like the author thought about
        # limits.
        if amount_cents > a["balance_cents"]:
            return 400, {"error": "insufficient funds"}

        a["balance_cents"] -= amount_cents
        b["balance_cents"] += amount_cents
        tx = next_tx_id()
        DB["transactions"].append({"id": tx, "account": src, "ts": _now(),
                                   "description": f"Transfer to {dst}", "amount_cents": -amount_cents})
        DB["transactions"].append({"id": next_tx_id(), "account": dst, "ts": _now(),
                                   "description": f"Transfer from {src}", "amount_cents": amount_cents})
        return 200, {"ok": True, "transaction": tx, "from": src, "to": dst,
                     "amount_cents": amount_cents,
                     "balance_cents": a["balance_cents"]}


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- data exposure

def profile(token: str | None) -> tuple[int, dict]:
    """Returns the whole stored profile, including the full card number and government id.

    Routes to waf_data_guard: the endpoint is legitimate and the caller is authorised — the defect
    is that the *response* carries more than it should, which is the one case an edge control fixes
    by masking on the way out rather than by blocking on the way in.
    """
    username = _user_for(token)
    if not username:
        return 401, {"error": "authentication required"}
    return 200, DB["profiles"].get(username, {})


def statements(query: str, token: str | None) -> tuple[int, dict]:
    """Filters statements by building the predicate from raw caller input.

    There is no SQL engine behind this lab, so the injection cannot exfiltrate anything — but the
    request carries a real injection payload, which is what a WAF signature matches on. Routes to
    waf.
    """
    if not _user_for(token):
        return 401, {"error": "authentication required"}
    predicate = "description LIKE '%" + query + "%'"
    matched = [t for t in DB["transactions"] if query.lower() in t["description"].lower()]
    return 200, {"query": predicate, "matched": matched}


# --------------------------------------------------------------------------- meta

def health() -> tuple[int, dict]:
    return 200, {"ok": True, "app": "larkspur-bank"}


def summary(token: str | None) -> tuple[int, dict]:
    """What the one-page UI renders: the caller's accounts and their recent activity."""
    username = _user_for(token)
    if not username:
        return 401, {"error": "authentication required"}
    ids = DB["users"][username]["accounts"]
    return 200, {
        "username": username,
        "accounts": [account(i) for i in ids if account(i)],
        "transactions": sorted(
            [t for t in DB["transactions"] if t["account"] in ids],
            key=lambda t: t["ts"], reverse=True)[:12],
        "everyone": [{"id": a["id"], "display": a["display"]} for a in DB["accounts"].values()],
    }


def dumps(payload: dict) -> bytes:
    return json.dumps(payload, indent=2).encode()
