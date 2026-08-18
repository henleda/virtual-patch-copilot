# Design spec — `waf_data_guard` AWAF band-aid (response masking)

Status: **BUILT and LIVE-PROVEN (2026-08-18).** The emitter form (`emitters._data_guard_policy`), the
leak/mask validation predicate (`probe.probe_from_spec`), and offline tests are shipped, and the whole
loop — apply → mask → keep → retire — was proven against a real AWS BIG-IP (v17.5, AS3 3.56). The one
trap the box exposed (and the schema could not) is recorded under "The band-aid" below: **Data Guard
masks only when `VIOL_DATA_GUARD` is alarm-only; with the template's default `block:true` it rejects the
whole response instead.** Originally written as a prep spec; updated after the proof.

## Why this form is different

The two forms before it BLOCK a request on the way in:
- `service_policy` (shipped, live-proven): a value constraint rejects the malicious request.
- `waf` (attack signatures): declined — ASM stages freshly-imported signatures, so it blocks nothing
  immediately (see `bigip-apply.md`).

**Data Guard does not block — it MASKS the response on the way out.** The request is legitimate and the
caller is authorised; the defect is that the *response* carries more than it should (a full PAN, an SSN).
The band-aid intercepts responses and masks the sensitive substrings. This is the one finding class an
edge control fixes by rewriting egress, not by rejecting ingress — so its **success predicate is
different from every other band-aid** and the validator has to grow a new leg (below).

Good news the schema implies: Data Guard is response interception (`maskData`), **not** a signature, so
it should sidestep the signature-staging trap that killed the `waf` form. That must still be confirmed
on a box — schema-valid shape lied once already.

## The target (already in the lab — no app work needed)

`labs/larkspur-bank` `GET /api/profile` (authed) returns the whole stored profile including
`card_pan: "4111111111111111"` (a Visa test PAN) and `govt_id: "078-05-1120"` (SSN-formatted). The
endpoint even carries a `# Routes to waf_data_guard` comment. The scan already classifies it as
`waf_data_guard`.

## The band-aid (schema-valid against `bigip-awaf-v17_1.json`, offline)

```json
{
  "policy": {
    "name": "mask-profile-pii",
    "template": {"name": "POLICY_TEMPLATE_FUNDAMENTAL"},
    "applicationLanguage": "utf-8",
    "enforcementMode": "blocking",
    "data-guard": {
      "enabled": true,
      "maskData": true,
      "creditCardNumbers": true,
      "usSocialSecurityNumbers": true,
      "enforcementMode": "ignore-urls-in-list"
    },
    "blocking-settings": {
      "violations": [{"name": "VIOL_DATA_GUARD", "block": false, "alarm": true}]
    }
  }
}
```

- **`VIOL_DATA_GUARD` must be alarm-only — the trap the live box exposed.** Data Guard has TWO actions:
  MASK the sensitive substrings on egress, or BLOCK the whole response. The violation's `block` flag chooses,
  and the FUNDAMENTAL template defaults it to `block:true`. So the shape WITHOUT this block (schema-valid,
  `maskData:true`) returned an ASM *"Request Rejected / support ID"* page instead of masking — the exact
  "looks applied, does the wrong thing" failure this project guards against. With `block:false, alarm:true`,
  `GET /api/profile` came back `200` with `card_pan: "************1111"`. **Invisible to schema validation;
  found only on the appliance** — same lesson as the signature-staging trap.
- `enforcementMode: "ignore-urls-in-list"` with an empty list = **enforce Data Guard on all URLs** (the
  list is the *exception* set). This is the "protect everything" default a band-aid wants.
- `creditCardNumbers` masks the PAN; `usSocialSecurityNumbers` masks the SSN-formatted `govt_id`. **Confirmed
  on the box:** ASM's built-in SSN pattern DID mask `078-05-1120` (`*******1120`) — no `customPatternsList`
  needed for this target. A site whose secret matches no built-in class would add a PCRE there.
- Emitted from `emitters._data_guard_policy(target, name)`. It derives nothing numeric from the probe — the
  sensitivity classes are fixed — so it routes before `derive_numeric_constraint`, the same place a signature
  form would have.

## The validation model — a new predicate

`apply.py::_run_validation` → `probe.probe_from_spec` today returns `{exploit_status, exploit_blocked,
legit_ok}`, where success = `exploit_blocked and legit_ok`. Data Guard never blocks, so `exploit_blocked`
is the wrong question. The probe needs a **leak predicate**:

- The probe spec gains a `leak` request (here `GET /api/profile`, authed) and a `secret` marker (the raw
  PAN/SSN string the response must NOT contain in the clear).
- **Before:** fire `leak`; assert the response body **contains** the secret (the leak is real).
- **After (band-aid on):** fire `leak`; success = the response body **no longer contains** the raw secret
  (it is masked). Legit shape/status unchanged (200, still valid JSON) so masking didn't break the app.
- Normalize to the same 3-key shape so keep/rollback plugs in unchanged, e.g. map `leak_masked` →
  `exploit_blocked` so `apply_bigip` needs no branching, OR add an explicit `leak_masked` leg. Prefer the
  mapping — fewer moving parts, and "the exploit's harm was neutralised" is the honest meaning of both.

This is the only real code beyond the emitter form, and it lives in `probe.probe_from_spec` (the
`_run_validation` chokepoint), so the console and CLI inherit it exactly as auth did. **As built:** the spec
carries a `leak` request and a `leak_secrets` list. The predicate fires the authed leak request, then:
`observed = (status < 400) and (not an ASM block page)`; `exploit_blocked = observed and (no secret present)`;
`legit_ok = observed`. Two guards are load-bearing and both are the same class as the block path's
`auth_failed` guard — an absent secret must never be misread as "masked":
- **over-block** — an ASM block page also lacks the secret, but a masked leak must reach the caller as a real
  200, so a block page is `observed=False` (a failure, not a mask);
- **unobserved** — a 4xx (auth required / wrong endpoint) means we never saw the response, so `observed=False`;
  `apply_bigip` then surfaces "couldn't observe the leak — check the path/credentials" rather than a verdict.

## Live-validation gate — PASSED (2026-08-18)

The `waf` signature form was schema-valid, imported cleanly, attached in blocking mode — and enforced
nothing, because ASM staged the signatures. **A WAF form is not "supported" until a real appliance proves
it enforces.** This form cleared that gate:

1. ✅ Lab up + tunnel; probe creds `VPCOPILOT_PROBE_USER=avery.stone VPCOPILOT_PROBE_PASS=hunter2`.
2. ✅ Deployed to `vpcopilot_lab/lab` (detach-first). First attempt **over-blocked** (ASM block page) — the
   `VIOL_DATA_GUARD block:true` default. Added `block:false, alarm:true`; `GET /api/profile` then returned
   `200` with `card_pan: "************1111"`, `govt_id: "*******1120"`. SSN matched the built-in class, so no
   `customPatternsList` was needed.
3. ✅ `_data_guard_policy` implemented, `emit()` flipped to `supported=True`, leak predicate wired, offline
   tests added (schema shape + the alarm-only violation + fake before/after/over-block probe responses). Full
   `apply-bigip` loop then passed end-to-end (leak → mask → keep), retire detached cleanly (leak returned),
   and the lab was torn down.

Shipped. The next form (`api_schema`) inherits this same gate.
