# Benchmark — claude

**Target:** `OWASP crAPI (whole repo)`  
**Model:** anthropic/claude-opus-4-8

## Discovery
- candidates **92** → verified **40** (confirm rate 43%, avg confidence 0.82)
- by severity: critical 13, high 23, medium 4
- by class: sqli 2, broken_auth 13, ssrf 3, broken_object_authz 8, command_injection 3, business_logic 1, sensitive_data 5, mass_assignment 1, rate_abuse 2, other 2
- scan time: 398.09s

## Policies generated: 15
- by control: waf 1, service_policy 9, malicious_user 1, rate_limit 1, waf_data_guard 1, api_schema 1, bot_defense 1
- code-only (no band-aid): authz-broken-logic-002, rag-cross-session-001, apikey-cross-tenant-001, global-state-race-001, tls-noverify-001, mcp-tls-verify-004
- code-fix PRs drafted: 0

## Policy quality (live)
- attempted **13** · **blocked** (real single-request exploit→403) **9** (69%) · applied-but-behavioral 3 · failed 1 · self-healed 0 · avg attempts 1.0

> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). _applied-but-behavioral_ = the control was enabled and validated at config level, but is behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a single request can't prove a block — it needs a burst / traffic over time.

| finding | sev | class | control | outcome | before→after | attempts |
|---|---|---|---|---|---|---|
| apikey-no-validation-001 | critical | broken_auth | service_policy | ✅ blocked | 404→403 | 1 |
| auth-bypass-noheader-001 | critical | broken_auth | service_policy | ✅ blocked | 404→403 | 1 |
| cmd-inj-001 | critical | command_injection | service_policy | ✅ blocked | 401→403 | 1 |
| hardcoded-creds-001-3 | critical | broken_auth | service_policy | ✅ blocked | 404→403 | 1 |
| otp-bruteforce-001-2 | critical | business_logic | rate_limit | 🟡 applied (behavioral) | — | 1 |
| shell-injection-convert-video-001 | critical | command_injection | service_policy | ✅ blocked | 401→403 | 1 |
| sql-toolkit-001 | critical | sqli | service_policy | ✅ blocked | 404→403 | 1 |
| mcp-context-leak-003 | high | sensitive_data | waf_data_guard | 🟡 applied (behavioral) | — | 1 |
| mcp-path-traversal-001 | high | ssrf | service_policy | ✅ blocked | 404→403 | 1 |
| nosqli-validate-coupon-001 | high | sqli | service_policy | ✅ blocked | 401→403 | 1 |
| post-massassign-002 | high | mass_assignment | api_schema | ❌ not blocked | 401→401 | 1 |
| seed-cred-001 | high | sensitive_data | bot_defense | 🟡 applied (behavioral) | — | 1 |
| info-leak-001 | medium | sensitive_data | service_policy | ✅ blocked | 400→403 | 1 |
