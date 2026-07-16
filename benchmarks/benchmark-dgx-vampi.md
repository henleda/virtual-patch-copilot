# Benchmark — dgx-vampi

**Target:** `VAmPI`  
**Model:** openai/qwen3-coder:30b-a3b-q8_0

## Discovery
- candidates **13** → verified **5** (confirm rate 38%, avg confidence 0.95)
- by severity: critical 1, high 4
- by class: sqli 1, broken_object_authz 2, mass_assignment 1, sensitive_data 1
- scan time: 171.62s

## Policies generated: 4
- by control: waf 1, service_policy 1, api_schema 1, waf_data_guard 1
- code-only (no band-aid): none
- code-fix PRs drafted: 0

## Policy quality (live)
- attempted **6** · **blocked** (real single-request exploit→403) **1** (17%) · applied-but-behavioral 3 · failed 0 · endpoint-missing 1 · needs-auth 1 · self-healed 0 · avg attempts 1.33

> _blocked_ = a fired exploit was stopped at the edge (per-request positive security). _applied-but-behavioral_ = the control was enabled and validated at config level, but is behavioral (rate_limit / malicious_user / bot_defense) or response-masking (data_guard) so a single request can't prove a block — it needs a burst / traffic over time.

| finding | sev | class | control | outcome | before→after | attempts |
|---|---|---|---|---|---|---|
| sqli-001-2 | critical | sqli | waf | 🟡 applied (behavioral) | 200→200 | 1 |
| bola-001 | high | broken_object_authz | service_policy | 🔒 needs auth | 401→401 | 3 |
| bola-001-3 | high | broken_object_authz | service_policy | 🚫 endpoint missing | 404→403 | 1 |
| mass-assign-001 | high | mass_assignment | api_schema | ✅ blocked | 200→403 | 1 |
| sensitive-001 | high | sensitive_data | waf_data_guard | 🟡 applied (behavioral) | — | 1 |
| sensitive-data-001-2 | — | — | waf_data_guard | 🟡 applied (behavioral) | — | 1 |
