# Design spec — BIG-IP live-apply + docs for non-technical users

**Status:** proposed · **Scope:** promote BIG-IP from an *emit target* to a first-class *apply* target.

## Goal

Give bring-your-own-BIG-IP customers the same closed loop XC has —
**mitigate → validate → refine → keep/rollback → retire** — so the copilot doesn't just *emit a policy for*
your BIG-IP, it *applies and proves* the patch on your BIG-IP and manages its lifecycle.

Today (0.2.0) BIG-IP is two things: `emit --target bigip-awaf` (produces a declarative WAF policy **document**,
read-only) and `bigip-lab` (a **validation lab** that stands up a clean-slate AS3 tenant). Neither is the
production apply loop. This spec closes that gap.

The encouraging finding from a code audit: **most of the spine already exists and is reusable**. Four
well-bounded pieces of glue are missing.

---

## The XC → BIG-IP concept mapping

| F5 XC (today) | BIG-IP (this spec) | Status |
|---|---|---|
| namespace | AS3 **tenant** — a hard partition; a scoped delete can't escape it | exists (`bigip_lab`) |
| HTTP load balancer | AS3 **application** / `Service_HTTP` virtual server | exists |
| attach a control to the LB spec | hang a **`WAF_Policy`** on `serviceMain.policyWAF` | **glue #1** |
| `XC_API_URL/_TOKEN/_NAMESPACE` | `BIGIP_URL/_USER/_PASSWORD` + `--tenant` | exists (`BigIP()`) |
| `get_lb` / `put_lb` | `get_declaration` / `deploy` (AS3, honest `_checked`) | exists (`bigip.py`) |
| `VPCOPILOT_PROTECTED_LBS` · `guard_lb` | `VPCOPILOT_PROTECTED_BIGIP_TENANTS` · `guard_tenant` (+ `/Common` always) | exists |
| detach control (`controls.py`) | re-deploy the clean-slate app **without** `policyWAF` | **glue #3** |
| validate against the exploit (probe → VIP) | **identical** — the probe is black-box HTTP against the VIP | exists, unchanged |

---

## Part A — the build

### The apply loop (XC spine with BIG-IP analogues)

1. **Resolve config + guard the tenant** — `BigIP()` reads `BIGIP_URL/_USER/_PASSWORD`; `guard_tenant(t)`
   refuses `/Common` and gates `VPCOPILOT_PROTECTED_BIGIP_TENANTS`, before any write. *(reuse)*
2. **Snapshot the tenant's app sub-tree** — `get_declaration()` → capture *this tenant's* app sub-tree,
   persist `out/bigip_snapshot.json`. *(mostly reuse; extract + persist the sub-tree, don't replay the whole
   declaration — that would clobber other tenants)*
3. **Baseline-validate the exploit** — `_run_validation(vip_url, finding, …)` → `probe_from_spec`. *(reuse)*
4. **Emit the AWAF policy** — `emitters.emit(finding, target="bigip-awaf")`, derived by code from the
   recorded exploit/legit pair. *(reuse — `service_policy` form today)*
5. **Wrap as AS3 and attach to `policyWAF`** — the emitted `{"policy":{…}}` is **not AS3-shaped**; wrap as a
   base64 `WAF_Policy` on the app's `serviceMain.policyWAF`. **glue #1**
6. **Deploy (dry-run first)** — `BigIP.deploy(decl, dry_run=…)`; honest `_checked`; AS3's own
   `action: dry-run` reports what it *would* change. *(reuse)*
7. **Validate against the real exploit, polling** — `_run_validation` again → pass =
   `exploit_blocked && legit_ok`. BIG-IP blocks with HTTP 200 + "support id" / "the requested url was
   rejected"; the probe's block-markers already match those. *(reuse)*
8. **Keep, or roll back to clean-slate** — on fail/error, re-deploy the snapshot (app *without* `policyWAF`).
   `--keep` off = auto-rollback after a passing smoke. **glue #2**
9. **Refine on failure** — reuse `refine_agent.run` + `lint_service_policy`; re-emit → re-wrap → re-deploy →
   re-validate, up to `--attempts`, or give up honestly. *(reuse loop, new wiring)*
10. **Ledger + audit** — `ledger.mark_mitigated(control="bigip_awaf")` + `audit.record("apply_bigip_awaf", …)`
    — the chokepoints are target-neutral. *(reuse)*
11. **Retire / reconcile** — detach = re-deploy the clean-slate app (no `policyWAF`), *not* a tenant delete.
    **glue #3**

### The four missing glue pieces (this is the whole build)

**#1 · AS3 wrap layer** (new module `bigip_apply.py`). Promote the live-test helper into a real function:

```python
# emitted: {"policy": {...}}  ->  attach to the tenant's app
app["vpcopilot_waf"] = {"class": "WAF_Policy", "ignoreChanges": True,
    "policy": {"base64": b64encode(json.dumps(policy))}}   # inline is rejected — must be base64
serviceMain["policyWAF"] = {"use": "vpcopilot_waf"}
```

**#2 · BIG-IP SafeApply spine.** A `BigIPApplyContext` mirroring XC's `ApplyContext`: `load()` (snapshot the
tenant sub-tree), `deploy()`, `safe_rollback()` = re-deploy the clean-slate sub-tree, verified. Rollback
targets the **tenant sub-tree**, never the whole declaration.

**#3 · Retire / reconcile plumbing.** A detach entry (redeploy clean-slate) + a ledger `control` value + a
BIG-IP branch in `reconcile` (XC-shaped today). Reconcile still fires the exploit at the **origin**.

**#4 · Test seams.** Extend `FakeBigIP` (add `get_declaration` / `_checked` / WAF-policy modeling) and lift it
into `conftest.py` beside `FakeXC`, so the whole loop unit-tests with no appliance.

> **Everything else is reuse:** the emitter, the AS3 client + dry-run + honesty gate, the tenant guard, the
> probe/validator (byte-for-byte), the refine agent, and the ledger/audit/evidence-bundle spine.

### Control coverage — be honest about scope

| Control | On BIG-IP AWAF | When |
|---|---|---|
| `service_policy` (value constraint) | ✅ already emitted as an AWAF policy | **v1 / MVP** |
| `waf` (signatures) | ◑ emitter can build the AWAF form; declines today | phase 3 |
| `waf_data_guard` (response masking) | ◑ AWAF DataGuard rule; declines today | phase 3 |
| `api_schema` (OpenAPI) | ◑ AWAF OpenAPI import; declines today | phase 3 |
| `rate_limit` | ✗ LTM profile / iRule — not an AWAF object | XC-only |
| `malicious_user` | ✗ stateful cross-request scoring | XC-only |
| `bot_defense` | ✗ separate subscription product | XC-only |

When a finding's best control is `rate_limit`/`bot`/`malicious_user` and the target is BIG-IP, the UI must
say **"no AWAF band-aid — mitigate on XC, or ship the code fix"** rather than silently emitting nothing.

### CLI + console surface

```
vpcopilot apply --target bigip --finding crapi-sqli-001 \
    --tenant my_app --app main --url https://app.internal \
    --dry-run            # AS3 reports what it would change; writes nothing
    [--keep]             # leave it enforcing (default: rollback after a passing smoke)
    [--attempts 3] [--allow-protected-tenant]
```

- **Console (everyday path):** the **④ Mitigate** step gets a target toggle — **XC ▸ BIG-IP**. Choosing BIG-IP
  uses the creds from **⚙ Setup → BIG-IP** + a tenant / app / URL row. Same Preview → Apply → validate flow.
- **Config** comes from the existing BIG-IP env (or the Setup panel) — no new secret plumbing.

### Safety model (parity with XC, plus the tenant sandbox)

- **Tenant sandbox** — every write lands under `/<tenant>/`, a hard AS3 partition; `/Common` refused
  unconditionally.
- **Dry-run** — AS3's own `action: dry-run`; the appliance itself reports the diff first.
- **Snapshot + rollback** — capture the app sub-tree first; re-deploy clean-slate on any failure, verified.
- **Validate before keep** — kept only if the finding's real exploit is actually blocked and legit passes.
- **Honest deploy** — `_checked` catches AS3's "looks-applied-and-isn't" shapes; protected-tenants +
  `--keep`-off defaults.

### Phased build plan

| Phase | Effort | What |
|---|---|---|
| **0 · Spike** | ~½ day | Promote the live-test AS3 wrap into a module; deploy a real AWAF policy into a lab tenant and validate against the exploit. Needs the lab up (cost). |
| **1 · MVP** | ~2–3 days | `apply --target bigip` for `service_policy`: glue #1 (wrap) + #2 (SafeApply spine) + validate + ledger/audit + dry-run + `guard_tenant`. Glue #4 (extend `FakeBigIP` → conftest) so it unit-tests with no appliance. |
| **2 · Close the loop** | ~2 days | Refine-on-failure wiring + retire (glue #3) + the console XC▸BIG-IP toggle. |
| **3 · Breadth** | ~3–5 days | More AWAF control forms (`waf`, `waf_data_guard`, `api_schema`); the reconcile branch; the NGINX App Protect variant (same emit target, different transport). |

**Risks / dependencies:** the appliance must have **Advanced WAF (ASM) provisioned** and **AS3 installed**;
management reachability (often a tunnel); self-signed certs (`verify=False` already default). These become the
pre-flight checklist in Part B.

---

## Part B — docs for non-technical BIG-IP users

The apply loop is safe and automated; the barrier for a BIG-IP admin who isn't a DevOps/AS3 person is
conceptual and setup-shaped. The docs must remove that barrier, not just describe the feature.

### Who they are, and what trips them

| They know | They don't (don't assume) |
|---|---|
| the BIG-IP GUI: virtual servers, WAF/ASM policies, partitions | AS3 / declarative config, iControl REST, tokens |
| their app, its URL, roughly what a WAF does | tenants-as-partitions, base64 policy refs, dry-run semantics |
| change-control and "don't touch prod" | CLIs, `.env` files, SSM tunnels, self-signed-cert warnings |

### Five documentation principles

1. **Console-first.** Everything demoable in the GUI. The CLI is an "advanced" appendix, never the on-ramp.
2. **Plain language, jargon deferred.** No "AS3"/"declaration" on the first screen; one-line, GUI-anchored
   definitions when a term is unavoidable.
3. **Safety-forward.** Lead with *why you can't hurt production* (sandbox tenant, dry-run, auto-rollback) —
   that's what unblocks a cautious admin.
4. **Meet them in the GUI they know.** Map each concept to something they recognize (tenant → partition,
   `WAF_Policy` → the ASM policy they attach to a VS).
5. **Copy-paste minimal, screenshot-rich.** A wizard + pictures beat a wall of commands.

### The doc set

1. **"Connect your BIG-IP" — a Setup wizard.** Upgrade Setup → BIG-IP into a 4-step wizard: URL + user/password
   → **Test connection** (the status panel already distinguishes unreachable / no-AS3 / auth-failed) → pick a
   sandbox tenant → done. Inline plain-language errors, each with a one-click "how do I fix this?".
2. **"3 things to know" — one-page primer.**
   - **A tenant is a private sandbox.** The copilot only writes inside it — never `/Common` or your other apps.
   - **You never write AS3.** It's just how the copilot talks to your BIG-IP under the hood.
   - **Dry-run shows you first.** Every apply can preview the exact change; a real apply that doesn't block the
     exploit rolls itself back.
3. **Pre-flight checklist — "what your BIG-IP needs" (each with a GUI how-to):** Advanced WAF (ASM) provisioned
   (System ▸ Resource Provisioning ▸ ASM = Nominal), AS3 installed (Test-connection tells you), a user with
   AS3/partition rights, reachability (mgmt URL / tunnel), version (BIG-IP 16.1+ / recent AS3).
4. **The guided apply (GUI, screenshotted):** Scan → Review → Mitigate: choose BIG-IP, pick tenant + app URL →
   Preview (dry-run) → Apply → watch `exploit 200 → 403 blocked` → keep or it rolls back → Retire when the fix
   ships.
5. **Guardrails in plain words + troubleshooting** (error → plain fix): unreachable → URL/tunnel; AS3 not
   installed → install the package (link); auth failed → user/rights; AWAF not provisioned → turn on ASM;
   cert warning → expected for a self-managed box.
6. **A worked example, end to end** on a safe app (VAmPI/crAPI) or their own, exporting the evidence bundle for
   a change board.

### Where it lives

- **`docs/BIGIP.md`** — the BIG-IP on-ramp (primer + pre-flight + guided apply + troubleshooting).
- **`docs/TRY_IT.md`** — a "Path B · on your own BIG-IP" variant beside the XC one.
- **In-product** — the Setup wizard copy, tooltips (tenant / dry-run / retire), and the honest "no AWAF band-aid
  for this control" message.
- **The demo runbook** — a BIG-IP track (the L2 lab already validates; this adds the apply beat).
