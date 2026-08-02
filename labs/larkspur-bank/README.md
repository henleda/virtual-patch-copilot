# Larkspur Bank — the copilot's own vulnerable origin (L2)

A small banking API that exists to be **exploited on camera**, so a policy the copilot generates can
be watched blocking a real request against a real app.

```sh
python3 app.py                      # stdlib only — no venv, no pip install
docker build -t larkspur . && docker run -p 8080:8080 larkspur
open http://127.0.0.1:8080/
```

## Why this exists, when the repo already has a vulnerable app

It is **not** a replacement for `bench/fixtures/nimbus-vuln-lab`, and the two must not be merged:

- `bench/fixtures/nimbus-vuln-lab` is **source only** — 13 files, no `package.json`, no compose, no
  Dockerfile. It is *scannable*, not *runnable*, and `bench/answer_key.yaml` plus `bench/BASELINE.md`
  are calibrated against that exact snapshot. Re-pointing them would invalidate the committed
  scorecard (`benchmarks/RESULTS.md`).
- **crAPI**, which *is* running and *is* the copilot's demo dataset, has **no numeric flaw at all** —
  its findings are SQLi, BOLA, mass assignment, rate abuse, sensitive data and broken auth.

So the single strongest result the declarative WAF emitter produces — a numeric constraint that is
*more faithful* than the XC regex it replaces — had **nowhere to run**. This app is that somewhere.

It is deliberately **not a Nimbus Bank look-alike**. Looking like Nimbus is exactly what would
re-confuse two demos that were separated on purpose: different name, different branding, different
customers, different account-number format.

## The flaws, and the control each one is for

One scan of this app should exercise the *breadth* of the emitter, not the same rule five times.

| endpoint | flaw | routes to |
|---|---|---|
| `POST /api/transfer` | **no lower bound on `amount_cents`** — the flagship | `service_policy` / declarative WAF numeric constraint |
| `POST /api/login` | no attempt counter, no lockout | `rate_limit` / `malicious_user` |
| `GET /api/accounts/<id>` | authenticated but never checks ownership | `service_policy` |
| `GET /api/profile` | returns full card PAN and government id | `waf_data_guard` |
| `GET /api/statements?q=` | predicate built from raw caller input | `waf` |

### The flagship, and why it is the interesting one

```sh
curl -XPOST localhost:8080/api/transfer -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"from":"LK-1001","to":"LK-2001","amount_cents":-50000}'
```

The attacker's balance goes **up** $500 and the victim's goes **down** $500. A negative amount
reverses both legs, so the app creates money.

The upper bound *is* checked (`insufficient funds`), which is what makes this a business-logic flaw
rather than a missing-validation typo — it looks like the author thought about limits.

And `int()` already rejects `"abc"` and `12.5`, so the value reaching the ledger is a whole number.
That is exactly why F5's `dataType: "integer"` **does not close this hole on its own** — F5 defines
integer as "whole numbers only", and `-50000` is a whole number. The rejection comes entirely from
`checkMinValue: true` + `minimumValue: 0`.

## The UI

`GET /` is one self-contained page: balances, a transfer form, and recent activity. It is there so
the exploit is visible from the victim's side rather than in a probe log — type `-500.00`, watch the
balance rise.

It also distinguishes **who answered**. When a band-aid is live at the edge, a blocked transfer comes
back as a non-JSON error page, and the UI says *"Blocked at the edge — the request never reached
Larkspur Bank"* rather than rendering it as an application error. That distinction is the entire
point of running this behind the appliance.

`POST /api/reset` restores the seeded state — the exploit permanently inflates a balance, so a demo
has to be able to start from the same numbers twice without a redeploy.

## What it is not

- **Not persistent.** State is in memory; a restart is a clean slate.
- **Not a password store.** Credentials are plaintext in `store.py` on purpose — the subject here is
  the *request*, not the hashing. Said out loud so it is not read as an oversight the scanner missed.
- **Not carrying anyone's data.** The card numbers are the standard test PANs and belong to nobody.
- **Not internet-published directly.** In the lab its security group admits only the BIG-IP and the
  VPC: traffic is supposed to arrive through the appliance under test.
