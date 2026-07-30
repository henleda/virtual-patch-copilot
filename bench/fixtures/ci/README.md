# K2 CI-review fixture

`refund-route.js` is a deliberately vulnerable Next.js route — a negative-amount hole, a SQL
injection, and a missing ownership check — used to exercise the pull-request review end to end
against a real model.

**It lives here, outside `nimbus-vuln-lab/`, on purpose.** The benchmark scans
`bench/fixtures/nimbus-vuln-lab/app/src/app/api` against `bench/answer_key.yaml`, and a new
vulnerable file inside that tree would produce findings listed in neither `expected` nor `bonus` —
which `bench.py` counts as **noise**. That would silently degrade the precision column of G4's
committed scorecard and `BASELINE.md`: a benchmark regression caused by a test fixture.

To reproduce the K2 live measurement, copy it into a branch and review the diff:

```sh
git checkout -b k2-demo
mkdir -p bench/fixtures/nimbus-vuln-lab/app/src/app/api/refund
cp bench/fixtures/ci/refund-route.js \
   bench/fixtures/nimbus-vuln-lab/app/src/app/api/refund/route.js
git add -A && git commit -m "introduce a vulnerable refund route"

vpcopilot ci-review --repo bench/fixtures/nimbus-vuln-lab/app/src/app/api --base main
```

Measured 2026-07-29: 77 s wall clock, three findings (critical negative-amount, critical SQLi, high
missing-authorization), four generated policies. Delete the branch afterwards so the answer key stays
the ground truth it claims to be.
