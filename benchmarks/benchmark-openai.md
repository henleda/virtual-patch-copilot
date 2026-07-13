# Benchmark — openai

**Target:** `OWASP crAPI (whole repo)`  
**Model:** openai/gpt-4.1

## Discovery
- candidates **69** → verified **64** (confirm rate 93%, avg confidence 0.96)
- by severity: critical 10, high 38, medium 16
- by class: business_logic 11, broken_auth 3, broken_object_authz 12, command_injection 2, other 1, sensitive_data 13, ssrf 3, mass_assignment 6, sqli 1, xss 12
- scan time: 126.0s

## Policies generated: 14
- by control: service_policy 9, waf 1, api_schema 1, malicious_user 1, waf_data_guard 1, rate_limit 1
- code-only (no band-aid): hardcoded-secret-001, sensitive-data-001, sensitive-global-001, mass-assign-001-5
- code-fix PRs drafted: 0

## Policy quality (live)
- attempted **9** · **blocked** (real single-request exploit→403) **5** (56%) · applied-but-behavioral 1 · failed 3 · self-healed 1 · avg attempts 1.44

> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). _applied-but-behavioral_ = the control was enabled and validated at config level, but is behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a single request can't prove a block — it needs a burst / traffic over time.

| finding | sev | class | control | outcome | before→after | attempts |
|---|---|---|---|---|---|---|
| bola-vid-del-001 | critical | broken_object_authz | service_policy | ✅ blocked | 401→403 | 1 |
| cmdinj-001 | critical | command_injection | waf | ⚠️ unfixable | 404→404 | 1 |
| sql-toolkit-001 | critical | business_logic | service_policy | ✅ blocked | 404→403 | 3 |
| auth-bypass-001 | high | broken_auth | service_policy | ❌ not blocked | 404→403 | 3 |
| bola-validate-001 | high | broken_object_authz | malicious_user | 🟡 applied (behavioral) | — | 1 |
| coupon-amt-biz-001 | high | business_logic | service_policy | ✅ blocked | 404→403 | 1 |
| debug-pprof-001 | high | sensitive_data | service_policy | ✅ blocked | 404→403 | 1 |
| mass-assign-001 | high | mass_assignment | api_schema | ❌ not blocked | 404→404 | 1 |
| ssrf-debug-001 | high | ssrf | service_policy | ✅ blocked | 404→403 | 1 |
