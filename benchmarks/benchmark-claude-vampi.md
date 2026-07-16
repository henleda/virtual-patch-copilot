# Benchmark — claude-vampi

**Target:** `VAmPI`  
**Model:** anthropic/claude-opus-4-8

## Discovery
- candidates **14** → verified **12** (confirm rate 86%, avg confidence 0.87)
- by severity: critical 3, high 6, medium 3
- by class: mass_assignment 2, broken_object_authz 2, sqli 1, sensitive_data 5, broken_auth 1, other 1
- scan time: 125.88s

## Policies generated: 6
- by control: service_policy 2, malicious_user 1, rate_limit 1, waf 1, bot_defense 1
- code-only (no band-aid): plaintext-pw-006, plaintext-pass-003, hardcoded-secret-001
- code-fix PRs drafted: 0

## Policy quality (live)
- attempted **9** · **blocked** (real single-request exploit→403) **4** (44%) · applied-but-behavioral 5 · failed 0 · endpoint-missing 0 · needs-auth 0 · self-healed 2 · avg attempts 1.22

> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). _applied-but-behavioral_ = the control was enabled and validated at config level, but is behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a single request can't prove a block — it needs a burst / traffic over time.

| finding | sev | class | control | outcome | before→after | attempts |
|---|---|---|---|---|---|---|
| bola-update-password-002 | critical | broken_object_authz | rate_limit | 🟡 applied (behavioral) | — | 1 |
| mass-assign-admin-001-2 | critical | mass_assignment | service_policy | ✅ blocked | 200→403 | 1 |
| sqli-getuser-001 | critical | sqli | waf | 🟡 applied (behavioral) | 200→200 | 1 |
| mass-assign-admin-001 | high | mass_assignment | service_policy | ✅ blocked | 200→403 | 1 |
| sensitive-debug-002 | high | sensitive_data | service_policy | ✅ blocked | 200→403 | 2 |
| user-enum-003 | medium | broken_auth | bot_defense | 🟡 applied (behavioral) | — | 1 |
| bola-update-password-001 | — | — | rate_limit | 🟡 applied (behavioral) | — | 1 |
| debug-mode-001 | — | — | service_policy | ✅ blocked | 200→403 | 2 |
| user-enum-001 | — | — | bot_defense | 🟡 applied (behavioral) | — | 1 |
