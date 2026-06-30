# Benchmark baseline

- **Target:** Nimbus `vuln-lab` branch, `app/src/app/api` (9 labeled vulns; see `answer_key.yaml`)
- **Brain commit:** `87c403b` (band-aid-coverage triage) · **vuln-lab:** `nimbus-demo@80f0375`
- **Recorded:** 2026-07-01

| Metric | Result |
|---|---|
| Discovery recall | **9 / 9 = 1.00** |
| Triage accuracy | **9 / 9 = 1.00** |
| Bonus real findings (beyond the key) | 7 |
| Code cures | every finding |

## Triage routing produced
| Vuln | Control(s) |
|---|---|
| negative-amount-transfer | `service_policy` (api_schema alt) |
| sqli-login | `waf` (+ rate_limit) |
| sqli-statements | `waf` (+ rate_limit / service_policy) |
| plaintext-passwords | **`no_bandaid`** (cure only) |
| idor-transactions | `malicious_user` + `rate_limit` |
| otp-brute-force | `rate_limit` + `malicious_user` + `bot_defense` |
| mass-assignment-profile | `api_schema` + `service_policy` |
| ssrf-avatar | `service_policy` + `waf` |
| missing-authz-admin | `service_policy` |

## Bonus findings (real, not yet in the key)
auth-bypass, admin PII/password exposure, column-name injection in `/profile`, missing
overdraft check in `/pay`, statement error-leak, login error-leak. Track these toward a
`bonus:` section of the key (see `BACKLOG.md`).

## Re-run
- Full scan + score: `vpcopilot bench /path/to/banknimbus/app/src/app/api`
- Re-score the existing `out/` (no LLM calls): `vpcopilot bench <path> --rescore`
