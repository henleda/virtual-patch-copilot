"""Larkspur Bank — in-memory data. Seeded on import; nothing is persisted.

A restart is a clean slate, which is what a lab wants: the negative-amount exploit *creates money*,
so a demo that ran twice would otherwise drift further from its seeded state every time.
"""
from __future__ import annotations

import copy
import threading

# One lock around every mutation. The exploit here is a business-logic flaw, not a race, and a
# demo that produced different numbers depending on thread interleaving would make the one number
# the audience is watching — the balance — untrustworthy.
LOCK = threading.RLock()

# Deliberately not Nimbus Bank customers, and deliberately not real-looking enough to be mistaken
# for anything: this app exists to be exploited on camera.
_SEED = {
    "accounts": {
        "LK-1001": {
            "id": "LK-1001", "owner": "avery.stone", "display": "Avery Stone",
            "kind": "checking", "balance_cents": 482_15,
        },
        "LK-1002": {
            "id": "LK-1002", "owner": "avery.stone", "display": "Avery Stone",
            "kind": "savings", "balance_cents": 12_400_00,
        },
        # A second customer, so the missing ownership check on /api/accounts/<id> is demonstrable
        # rather than theoretical — there has to be someone else's account to read.
        "LK-2001": {
            "id": "LK-2001", "owner": "morgan.reyes", "display": "Morgan Reyes",
            "kind": "checking", "balance_cents": 3_119_44,
        },
    },
    "users": {
        # Plaintext because the point of this box is the *request*, not the password store. Said out
        # loud so nobody reads it as an oversight the scanner is meant to catch.
        "avery.stone": {"password": "hunter2", "accounts": ["LK-1001", "LK-1002"]},
        "morgan.reyes": {"password": "correct-horse", "accounts": ["LK-2001"]},
    },
    "transactions": [
        {"id": "TX-9001", "account": "LK-1001", "ts": "2026-07-24T09:12:04Z",
         "description": "Ferrymead Coffee", "amount_cents": -4_75},
        {"id": "TX-9002", "account": "LK-1001", "ts": "2026-07-24T18:40:11Z",
         "description": "Payroll — Alder Logistics", "amount_cents": 2_180_00},
        {"id": "TX-9003", "account": "LK-1001", "ts": "2026-07-25T08:02:55Z",
         "description": "Transit card top-up", "amount_cents": -40_00},
        {"id": "TX-9004", "account": "LK-1002", "ts": "2026-07-25T08:03:10Z",
         "description": "Transfer to savings", "amount_cents": 500_00},
        {"id": "TX-9005", "account": "LK-1001", "ts": "2026-07-26T12:31:47Z",
         "description": "Harborline Grocery", "amount_cents": -112_38},
        {"id": "TX-9006", "account": "LK-2001", "ts": "2026-07-26T15:20:02Z",
         "description": "Refund — Larkspur Cycles", "amount_cents": 89_99},
        {"id": "TX-9007", "account": "LK-1001", "ts": "2026-07-27T07:15:33Z",
         "description": "Standing order — rent", "amount_cents": -1_450_00},
    ],
    # Held only so the Data Guard demo has something with a recognisable shape to mask. These are
    # syntactically valid test values (the 4111… PAN is the universal Visa test number) and belong
    # to nobody.
    "profiles": {
        "avery.stone": {"full_name": "Avery Stone", "email": "avery@larkspur.test",
                        "card_pan": "4111111111111111", "govt_id": "078-05-1120",
                        "phone": "+1-555-0142"},
        "morgan.reyes": {"full_name": "Morgan Reyes", "email": "morgan@larkspur.test",
                         "card_pan": "4012888888881881", "govt_id": "219-09-9999",
                         "phone": "+1-555-0177"},
    },
}

DB: dict = copy.deepcopy(_SEED)
_tx_seq = [9100]


def reset() -> None:
    """Restore the seeded state. The UI exposes this so a demo can be run twice without a redeploy —
    the exploit permanently inflates a balance, and the second run should start from the same
    numbers the first one did."""
    global DB
    with LOCK:
        DB = copy.deepcopy(_SEED)
        _tx_seq[0] = 9100


def next_tx_id() -> str:
    with LOCK:
        _tx_seq[0] += 1
        return f"TX-{_tx_seq[0]}"


def account(acct_id: str) -> dict | None:
    return DB["accounts"].get(acct_id)


def transactions_for(acct_id: str) -> list[dict]:
    return [t for t in DB["transactions"] if t["account"] == acct_id]
