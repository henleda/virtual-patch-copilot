# Nimbus vuln-lab benchmark fixture

A **vendored snapshot** of the Nimbus Bank app's `app/src/app/api` tree, used as the
ground-truth target for `vpcopilot bench` (scored against `../../answer_key.yaml`).

- **Source:** `henleda/nimbus-demo`, branch `vuln-lab`, commit `80f0375`.
- **Scan target:** `bench/fixtures/nimbus-vuln-lab/app/src/app/api`
- **Cured reference:** the SSRF code-fix the copilot generated for this fixture lives on
  `nimbus-demo` branch `vpcopilot/fix-ssrf-fetch-001` (`bed11a3`), kept for comparison.

## These vulns are intentional — never deploy this

The tree carries deliberately vulnerable endpoints so the benchmark exercises every XC
control bucket: SQLi (`login`, `statements`), negative-amount transfer (`pay`), IDOR
(`transactions`), OTP brute-force (`verify-otp`), mass-assignment (`profile`), SSRF
(`avatar`), and missing function-level authz (`admin/users`). The rest of the endpoints
use parameterized queries and behave normally. This is a test fixture, not shippable code.

## Refreshing the snapshot

If the upstream fixture changes, re-vendor from `nimbus-demo`:

```
git archive vuln-lab app/src/app/api | tar -x -C bench/fixtures/nimbus-vuln-lab
```

Then update the source commit above and re-run the baseline (`bench/BASELINE.md`).
