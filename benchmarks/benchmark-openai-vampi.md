# Benchmark — openai-vampi

**Target:** `VAmPI`  
**Model:** openai/gpt-4.1

## Discovery
- candidates **6** → verified **5** (confirm rate 83%, avg confidence 0.97)
- by severity: critical 3, high 2
- by class: mass_assignment 1, broken_object_authz 2, sqli 1, sensitive_data 1
- scan time: 24.22s

## Policies generated: 5
- by control: service_policy 1, waf 1, malicious_user 1, rate_limit 1, waf_data_guard 1
- code-only (no band-aid): none
- code-fix PRs drafted: 0

## Policy quality (live)
- attempted **4** · **blocked** (real single-request exploit→403) **1** (25%) · applied-but-behavioral 3 · failed 0 · endpoint-missing 0 · needs-auth 0 · self-healed 0 · avg attempts 1.0

> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). _applied-but-behavioral_ = the control was enabled and validated at config level, but is behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a single request can't prove a block — it needs a burst / traffic over time.

| finding | sev | class | control | outcome | before→after | attempts |
|---|---|---|---|---|---|---|
| mass-assign-admin-001 | critical | mass_assignment | service_policy | ✅ blocked | 200→403 | 1 |
| sqli-user-001 | critical | sqli | waf | 🟡 applied (behavioral) | 200→200 | 1 |
| bola-books-001 | high | broken_object_authz | rate_limit | 🟡 applied (behavioral) | — | 1 |
| sensitive-user-002 | high | sensitive_data | waf_data_guard | 🟡 applied (behavioral) | — | 1 |
