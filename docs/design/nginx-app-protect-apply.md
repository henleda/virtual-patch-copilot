# NGINX App Protect — live-apply design (L2)

The bring-your-own **F5 WAF for NGINX (App Protect / "NAP")** analogue of the BIG-IP
Advanced-WAF apply path (`src/vpcopilot/bigip_apply.py`). It lets an operator attach, validate,
keep, and retire a finding's declarative band-aid on **their own** NGINX + App Protect box, the way
`apply-bigip` does on their own BIG-IP.

**Iron rule (unchanged):** never ship a band-aid that "looks applied and blocks nothing." Every step
below exists to make that failure impossible — the box's own `nginx -t` self-test, an honest
post-deploy failure gate, and a live exploit/legit probe that can only PASS on real enforcement.

**Status:** design + adversarial review complete; **not yet built**. Several NAP runtime behaviors
are asserted from schema + docs but **unproven on a real box** — they are collected in
[§10 Verify on the live box](#10-verify-on-the-live-box-the-gate-before-trusting-a-form). Consistent
with how the three BIG-IP forms were shipped, **the live L2 proof on a real NAP box is the
tiebreaker** for every open question; nothing is trusted until it blocks a real exploit.

L1 (the declarative policy *document*) already ships: `emitters.py` carries a
`nginx-app-protect` target (`template.name = POLICY_TEMPLATE_NGINX_BASE`), reachable today via
`vpcopilot emit --target nginx-app-protect` and the console "Emit for another WAF" panel. This design
is the **L2** transport that deploys and proves that document on a live box.

---

## 1. File map

Mirrors the BIG-IP trio (`bigip.py` / `bigip_lab.py` / `bigip_apply.py`):

| BIG-IP file | NGINX file (new) | Role |
|---|---|---|
| `bigip.py` (`BigIP`) | `nginx.py` (`Nginx`, `NginxError`) | transport client + honest failure gate |
| `bigip_lab.py` (`guard_tenant`, `create`) | `nginx_lab.py` (`guard_site`, `create`/`remove`/`status`) | blast-radius guard + lab lifecycle |
| `bigip_apply.py` (`apply_bigip`, `retire_bigip`) | `nginx_apply.py` (`apply_nginx`, `retire_nginx`) | the apply/retire spine |

**Edited:** `reconcile.py` (a `_one` branch + `_retire_nginx`), `console/app.py`
(`NginxApplyReq` / `_run_nginx_apply` / `start_nginx_apply` + a `do_retire` branch), `report.py`
(`_impact_rows` label + generalize `_bigip_html` → target-parameterized), `cli.py`
(`apply-nginx` / `retire-nginx` / `nginx-lab`).

**Reused unchanged** (target-neutral chokepoints — the payoff of L1's "adding a target touches only
the emitter" discipline): `emitters.emit` (`target='nginx-app-protect'`), `apply._run_validation`,
`probe.probe_from_spec` / `probe_negative_pay`, `ledger.mark_mitigated` / `mark_retired` /
`record_reconcile`, `audit.record`.

The one new discriminator is the control string **`nginx_app_protect`**, wired at the same four
sites the BIG-IP `bigip_awaf` string touches: written at `mark_mitigated`; matched to route retire in
`do_retire` (console) and `reconcile._one`; stamped on the console job.

---

## 2. Transport — SSH + managed include + `nginx -t` + reload

**Chosen: SSH to the box → write the policy file → reference it from a copilot-owned managed
`include` → `nginx -t` → graceful reload.** Client class `Nginx` in `nginx.py`.

Why, over the alternatives (research: "NAP transport options for a BYO box"):

- **Least assumed infra for a single box.** Requires only that NAP is *already installed*. No
  separate control plane (NIM), no container orchestration. It is the closest 1:1 to
  "AS3-REST-to-BIG-IP minus the management appliance": push one file to the one box and reload.
- **Idempotent + cleanly reversible.** Same policy path + whole-file managed include + graceful
  reload → same state. Retire = remove that one managed include + reload; the user's own config is
  never touched.
- **Reachability is the operator's problem, deliberately** — the stance `bigip.py` already takes.
  `Nginx` takes an `NGINX_SSH_HOST` and does not care how it resolves (tunnel / bastion / VPN).

Rejected for v1: **NIM** (a whole separate licensed control-plane server + `nginx-agent` enrolment —
disproportionate for one box; the only option with a true declarative desired-state API, noted as a
future path). **Containerized NAP v5** (self-contained but assumes Docker + F5 registry creds — only
right if the box is *already* a v5 container stack).

### v4 vs v5 lives inside the `Nginx` client, not the spine

`nginx_apply.py` calls `nx.deploy(...)`; the client picks the mechanism from `NGINX_NAP_VERSION`:

- **v4 (monolithic module):** `app_protect_policy_file` → the raw emitted `.json`; the module
  compiles it inline at reload. True "copy JSON + reference + reload." **This is the v1 target** — it
  consumes the emitter's raw policy document directly, the cleanest proof.
- **v5 ("F5 WAF for NGINX", split):** the box runs `nginx` + `waf-enforcer` + `waf-config-mgr`;
  policy is a compiled `.tgz`. The client runs the local compiler to produce the bundle, then
  references the `.tgz`. **Never mix raw + compiled on one instance** ("Found mixed content of
  compiled and raw configuration"). Whether a standalone v5 host auto-compiles raw `.json` at reload
  is **unproven** ([§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)); the safe
  default is pre-compile.

---

## 3. `apply_nginx` — step-by-step mirror of `apply_bigip`

Constants (the `WAF_REF='vpcopilot_waf'` analogue):

```python
POLICY_PREFIX = "vpcopilot-"          # every file/include we own: vpcopilot-<finding_id>
INCLUDE_TAG   = "# vpcopilot-managed" # sentinel first line of a managed include — our on-disk marker
CONTROL       = "nginx_app_protect"   # the new ledger discriminator
```

Signature (mirror of `apply_bigip`), swapping the AS3 `tenant`/`app` blast-radius identity for the
NGINX `server`/`location`:

```python
def apply_nginx(finding_id: str, *, server: str, location: str, url: str,
                dry_run: bool = False, keep: bool = False, protocol: str = "http",
                out_dir: str = "out", allow_protected: bool = False,
                client: Nginx | None = None, log: Callable = print) -> dict:
```

| # | BIG-IP step | NGINX action |
|---|---|---|
| 1 | `guard_tenant` → `LabRefused` | **`guard_site(server, …)`** — refuses the box's `default_server` **unconditionally** (the `/Common` analogue; it fronts everything) and `$VPCOPILOT_PROTECTED_NGINX_SITES` unless overridden. The scoped boundary is the copilot server/location + the `vpcopilot-` managed include — a scoped apply can never reach another vhost. |
| 2 | `_emit_for_finding(target='bigip-awaf')` | **same, `target='nginx-app-protect'`** — identical wiring (read `policies.json`+`probes.json`, call `emit`), same three forms, `template.name='POLICY_TEMPLATE_NGINX_BASE'` (proven by `swap_target`). |
| 3 | honest decline if `not res.supported` → no deploy | **same**, host identity swapped. `emit` supplies the reason (`rate_limit`/`malicious_user`/`bot_defense` → `UNSUPPORTED`; `waf` → `WAF_STAGING_REASON`). |
| 4 | `bip.get_declaration()`; validate class; `_app_of` | **`nx.get_config()`** (an `nginx -T` dump — the snapshot every mutation compares against); **`_location_of(cfg, server, location)`** → clear "run `vpcopilot nginx-lab create` first" if absent. |
| 5 | snapshot clean-slate → `out/bigip_snapshot.json` | **`clean = _detach_policy(cfg, server, location)`** (desired state with **only our** `vpcopilot-` include stripped, never a user's own `app_protect_policy_file`); write `out/nginx_snapshot.json`. Both the rollback and retire target. |
| 6 | `_attach_waf(clean, app, res.policy)` | **`_attach_policy(clean, server, location, res.policy)`** — write `NGINX_POLICY_DIR/vpcopilot-<fid>.json` + a managed include (`INCLUDE_TAG` first line) carrying `app_protect_enable on;` + `app_protect_policy_file …;`. |
| 7 | AS3 dry-run self-test → return on failure | **`nx.deploy(desired, dry_run=True)`** = stage the files + `nginx -t`; on failure return `{applied:False, dry_run:True, reason}`. |
| 8 | deploy real; validate exploit/legit (`before` undefended, `after`) | **`nx.deploy(desired)`** (write + reload) then `_run_validation` **around the box** for `after`; `before` captured against the genuinely-undefended clean-slate (two-deploy discipline, so a no-op reload can't masquerade as a block). |
| 9 | `passed = after.exploit_blocked and after.legit_ok`; honest `_unvalidatable` | **same** (`probe_from_spec` reused unchanged; leak/mask predicate for `waf_data_guard`). |
| 10 | rollback if `not passed or not keep` | **`nx.deploy(clean)`** — redeploy without our include + reload. |
| 11 | `mark_mitigated(control='bigip_awaf', lb=f"{tenant}/{app}")` | **`mark_mitigated(control='nginx_app_protect', lb=_lb(server,location))`** iff kept. |
| 12 | `audit.record('apply_bigip_awaf', …, before_after={before,after})` | **`audit.record('apply_nginx_app_protect', …, policy_name=…, before_after={"before":…,"after":…})`** — the dict shape the report reads (the fix from PR #54 applies here from day one). |

### Honest-decline / failure return shape

```python
{"applied": False, "emitted": False, "reason": <emit reason>, "finding_id": …, "server": …}
```

### The `Nginx` client's honest failure gate (`nginx.py`, the `bigip._checked` analogue)

`nx.deploy` runs `nginx -t` **before** the reload and raises `NginxError` on a non-zero test — the
"never push a broken config" gate. After the reload, `nx.get_config()` (an `nginx -T` read-back)
**proves the config references our policy** — necessary but **not sufficient**: it does *not* prove
the enforcer daemon (v4 `bd` / v5 `waf-enforcer`) actually loaded it. **The live exploit probe is the
sole proof of enforcement** ([§5](#5-validation--why-the-live-probe-proves-real-enforcement)).

---

## 4. The three forms on NAP + the honest decline

All three port: the same policy object is emitted with only `template.name` swapped
(`POLICY_TEMPLATE_NGINX_BASE`); every field validates against the vendored NAP schema.

- **`service_policy` (value-constraint) — ports.** `parameters[].dataType:'decimal'`,
  `checkMinValue`, `VIOL_PARAMETER_NUMERIC_VALUE`, json-profile extraction — all present in the NAP
  schema. **Verify-live:** that a declared parameter constraint enforces the instant the policy loads
  and does **not** sit in an enforcement-readiness period (see [§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)).
- **`waf_data_guard` (response-masking) — ports, strongest.** NAP has a native `data-guard` section
  with the exact keys the form emits. **`VIOL_DATA_GUARD block:false / alarm:true` is load-bearing on
  NAP too** — with `block:true` in blocking mode NAP *rejects the whole response* instead of masking;
  it must never be dropped. Validated by the inverted leak/mask predicate; inherits the reconcile
  leak-probe path unchanged.
- **`api_schema` (API-contract) — ports, needs care.** The negative single-endpoint disallow
  (`urls[]` `isAllowed:false` + `VIOL_URL`, base template's `'*'` still allowed so documented
  endpoints pass). **Verify-live:** whether the disallowed URL blocks immediately or is subject to an
  enforcement-readiness / `performStaging` window — the emitted `enforcementReadinessPeriod:0` +
  URL-level `performStaging:false` are ASM-shaped keys whose NAP effect is **unproven** and must not
  be assumed to be no-ops ([§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)).

**`waf` (attack signatures) stays DECLINED** — the exact analogue of the BIG-IP waf-staging decline,
and *more* explicit on NAP: NAP ships first-class **time-based signature staging** (`performStaging`
default `true` at `signature-settings`) in which staged signatures "are reported in the security log
but will not block." A signature virtual patch would "look applied and block nothing." Mechanically
nothing new is needed — `emit` already returns `supported=False` with `WAF_STAGING_REASON`; STEP 3's
honest decline fires with no deploy. **Open:** `WAF_STAGING_REASON` is ASM-worded; on NAP the true
reason is NAP's own signature staging — reword target-neutrally or branch per target (verdict is
identical either way). `rate_limit` / `malicious_user` / `bot_defense` remain declined via
`UNSUPPORTED`.

---

## 5. Validation — why the live probe proves REAL enforcement

`_run_validation` → `probe_from_spec` reused **unchanged**: fire the derived exploit (must be
blocked) + the legit request (must pass); `passed = after.exploit_blocked and after.legit_ok`. Three
ways a fake could sneak past, and why each fails **closed**:

- **Transparent mode / entity staging** (the NAP "looks applied, blocks nothing" twin). A
  non-enforcing policy returns the real app response, not a block → `exploit_blocked=False` →
  `passed=False` → **rollback**. No false "applied" can ship.
- **Stale reload** (config cached; or a reload that didn't push policy into the enforcer daemon).
  `after` equals the undefended `before` → exploit still succeeds → **rollback**. The two-deploy
  discipline + the `nginx -T` read-back reinforce this.
- **Edge cache / around-vs-through the box.** The `url` must resolve **through** the NAP vhost. A
  cached exploit 200, or a probe that hits the origin *around* the box, reads as "not blocked" →
  fail-safe rollback (never a false pass). `probe.blocked_by_edge` separates an edge block from the
  app's own answer.

**Block recognition:** `probe._blocked` matches support-ID reject phrases ("the requested url was
rejected", "your support id is"). These are NAP's **default** block page — but NAP's block
status/body is **configurable**, so a customized box could make a genuine block read as "not blocked"
and silently roll back a working policy. Making block-detection NAP-aware (and verifying the target's
actual block response) is a [§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)
must-fix.

---

## 6. Retire + reconcile auto-retire

`retire_nginx` is a **redeploy-without-the-policy** (`nx.deploy(_detach_policy(cfg, server,
location))`), never a delete of the vhost. `_detach_policy` strips **only** the `vpcopilot-`prefixed
managed include (matched by `INCLUDE_TAG` + filename prefix), so a user's own `app_protect_policy_file`
on the same server is never clobbered — the surgical-detach trap. Idempotent: absent → no-op.

Reconcile auto-retire adds a sibling branch in `reconcile._one`, at the **same spot** as
`bigip_awaf` — before the XC-specific presence checks (`XC().get_lb(lb)`), because a bring-your-own
user has no XC:

```python
if mit.get("control") == "bigip_awaf":     return _retire_bigip(...)
elif mit.get("control") == "nginx_app_protect": return _retire_nginx(...)   # NEW
```

`_retire_nginx` mirrors `_retire_bigip`: `server, location = _unlb(mit['lb'])` → `retire_nginx(...)`
→ `audit.record('reconcile_retire', …)` → `ledger.record_reconcile(outcome='retired', …)`.

**Reconcile around-the-box problem ([§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)
must-fix):** reconcile confirms a genuine code fix by firing the exploit **at origin, around the
band-aid**, expecting **no** block — so a blocked request can't be mistaken for a fixed bug. On a
single BYO box the NAP vhost is often the *only* ingress, leaving no around-the-box vantage. The path
forward: require a direct-origin address for auto-retire (a `NGINX_ORIGIN_URL` / the lab origin
`10.30.10.22:8080`), and **refuse to auto-retire** (report-only) when no around-the-box path exists,
rather than retire on an unverifiable fix.

---

## 7. Console + report + CLI integration

- **Console apply:** `NginxApplyReq` + `_run_nginx_apply` + `POST /api/apply-nginx` (daemon thread,
  polled via the shared `GET /api/action`), stamping `control='nginx_app_protect'` on the job —
  mirror of `start_bigip_apply`.
- **Console retire:** a `do_retire` branch keyed on `control=='nginx_app_protect'` → `retire_nginx`,
  before the XC fallthrough.
- **Report impact label:** `_impact_rows` gains `"apply_nginx_app_protect": "F5 WAF for NGINX (App
  Protect)"`. The row already reads the target cell from `policy_name` and tolerates the
  `before_after` dict (PR #54), so it renders with no special-casing.
- **Report section:** generalize `_bigip_html` (hardcodes `target='bigip-awaf'` + `AWAF_FORMS`) into
  a target-parameterized `_declarative_waf_html(out_dir, *, target, forms, heading)` and call it
  twice — once for `bigip-awaf`, once for `nginx-app-protect`. The three form controls are identical
  across targets → a shared `DECLARATIVE_FORMS` registry is the single source of truth.
- **CLI:** `apply-nginx` / `retire-nginx` / `nginx-lab {create,rm,status}`, mirroring the
  `apply-bigip` / `retire-bigip` / `bigip-lab` option surface and exit-code contract (`LabRefused`→3,
  `(NginxError, RuntimeError)`→1, 0 iff `res['passed']`).

---

## 8. Config / creds — the `NGINX_*` `.env` vars

Mirroring `BIGIP_URL` / `BIGIP_USER` / `BIGIP_PASSWORD`, read by `Nginx.__init__`; a missing required
key raises `NginxError("… not set — add it to .env")`. The key/password is redacted from every
log/error/traceback (the `bigip._redact` pattern).

| NGINX var | Default | Notes |
|---|---|---|
| `NGINX_SSH_HOST` | *(required)* | box/IP; reachability is the operator's problem |
| `NGINX_SSH_PORT` | `22` | |
| `NGINX_SSH_USER` | *(required)* | must have write to policy + include dirs **and** reload rights |
| `NGINX_SSH_KEY` | *(one of KEY/PASSWORD)* | private-key path (**preferred**) |
| `NGINX_SSH_PASSWORD` | — | password fallback |
| `NGINX_RELOAD_CMD` | `sudo nginx -s reload` | the real gate — scoped-sudo/root/group |
| `NGINX_POLICY_DIR` | `/etc/app_protect/conf` (v4) | where `vpcopilot-<fid>.json`/`.tgz` lands |
| `NGINX_INCLUDE_DIR` | `/etc/nginx/conf.d` | where the managed include lands |
| `NGINX_NAP_VERSION` | *(autodetect)* → `v4`\|`v5` | picks raw-JSON-reload vs pre-compiled `.tgz` |
| `NGINX_ORIGIN_URL` | — | direct-origin address for reconcile's around-the-box probe (§6) |
| `VPCOPILOT_PROTECTED_NGINX_SITES` | — | `guard_site` protected set (`default_server` protected unconditionally) |

Reuses `VPCOPILOT_PROBE_USER` / `_PASS` / `_TOKEN` for validation auth and `VPCOPILOT_DEFAULT_URL`
for the CLI `--url`, unchanged.

---

## 9. Box gate — checklist to stand the box up

Confirm **all** before an apply can land:

- [ ] **Reachable** — `NGINX_SSH_HOST:PORT` reachable from where the copilot runs (tunnel/bastion OK).
- [ ] **NAP installed** — apply attaches/detaches; it never installs NAP. The module/processes load.
- [ ] **Generation known** — v4 (raw-JSON-reload) or v5 (3 processes up + a local compiler). Set
  `NGINX_NAP_VERSION` if autodetect is unsure.
- [ ] **Write access** for `NGINX_SSH_USER` to **both** `NGINX_POLICY_DIR` and `NGINX_INCLUDE_DIR`.
- [ ] **Reload rights (the real gate)** — the user can run `nginx -t` **and** `NGINX_RELOAD_CMD`
  (root, or `sudo NOPASSWD` scoped to the reload). A scp-only user **cannot apply**.
- [ ] **Credential present** — `NGINX_SSH_KEY` (preferred) or `NGINX_SSH_PASSWORD`.
- [ ] **Lab vhost/location exists** — `vpcopilot nginx-lab create` stood up the copilot server/location.
- [ ] **Validation URL goes THROUGH the box** — `--url` resolves to the NAP vhost, not a CDN in front
  or the origin behind.
- [ ] **Fail-mode known** — `app_protect_failure_mode_action` (default fail-open); a half-loaded
  enforcer passes traffic. The read-back + live probe catch it, but the operator should know.
- [ ] **NOT required** — NIM base URL/token; Docker socket / F5 registry creds (only for the v5
  container transport).

---

## 10. Verify on the live box — the gate before trusting a form

From the adversarial review. Each is a NAP runtime behavior asserted from schema+docs but **unproven
on a real box**; the live L2 proof settles it. None can ship a *false* "blocked" (the live probe
fails closed on all of them), but each must be resolved before the corresponding form is trusted, and
the design prose must not state the unverified behavior as fact.

1. **`api_schema` staging** — confirm a disallowed URL (`isAllowed:false` / `VIOL_URL`) blocks
   **immediately**, not after an enforcement-readiness / `performStaging` window. If NAP honors
   entity staging, add **policy-level** `performStaging:false` as a *per-target `emit` change* (not
   `swap_target`, which only flips `template.name`) and re-prove.
2. **`service_policy` staging** — the same, for a declared numeric-parameter constraint
   (`VIOL_PARAMETER_NUMERIC_VALUE`).
3. **Block-page detection** — read the target's actual NAP block response (status + body) and make
   `_blocked` NAP-aware, rather than relying on the incidental overlap with the XC support-ID markers.
   A customized block response otherwise rolls back every working policy.
4. **The reload/enforcer command** — pin, per generation, the command that actually re-applies the
   policy into the enforcer daemon (v4 `nginx -s reload` vs `apreload`/`bd` recompile; v5
   `waf-config-mgr`/`waf-enforcer` reconcile, or OSS-v5 `systemctl restart nginx`). If the default
   reload doesn't push policy to the enforcer, every after-probe fails and every apply rolls back
   (safe, but dead on arrival). Document that `nginx -T` proves *reference*, not *enforcement*.
5. **Reconcile around-the-box** (§6) — on a single BYO box, provide a direct-origin path
   (`NGINX_ORIGIN_URL`) or **refuse to auto-retire** rather than retire on an unverifiable fix.
6. **Verify uncited identifiers** — the `app_protect_failure_mode_action pass` directive
   name/spelling, the v5 bundle dir default (`/etc/app_protect/bundles`), and which compiler binary
   (`apcompile` vs the `waf-compiler` tool) exists on the target generation. Plausible but
   unconfirmed; don't state as fact in the box gate.

Additional open questions carried forward: `waf` decline wording (ASM- vs NAP-worded — same verdict);
one `app_protect_policy_file` per location (v1 assumes one finding per copilot location; stacking
needs merged forms or an honest refusal, which reshapes `_DEPENDS_ON` for NGINX); before-already-blocks
attribution (`passed` is after-only + baseline logged, mirroring BIG-IP); nested-JSON parameter
naming (undocumented on NAP, already flagged by the `service_policy` form).

---

## 11. Provisioning the proof box (no NAP box exists yet)

The design assumes a live NAP box; none exists, so standing one up is the first Task-B step. Plan
(mirrors `infra/vpcopilot-lab`, same `vpcopilot` profile / us-east-2, reuses the lab VPC
`10.30.0.0/16` + the Larkspur origin `10.30.10.22:8080`):

- A single **NGINX Plus + App Protect v4** EC2 (Ubuntu 22.04, ~`t3.medium`) fronting Larkspur as a
  reverse proxy — the minimal box that lets exploit/legit fire **through** NAP. Run it with the origin
  up and the BIG-IP left stopped (cheaper).
- NAP installed **out-of-band over SSH** during onboarding (the `bigip-onboard.sh` analogue), using
  the F5 subscription **JWT** for `pkgs.nginx.com` auth and NGINX Plus R33+ licensing. The JWT is
  delivered to the box at onboarding, never baked into `user_data` or Terraform state, and is
  `.gitignore`d.
- Then: `vpcopilot nginx-lab create` (stand up the copilot server/location) → prove **one form
  end-to-end live** → resolve the [§10](#10-verify-on-the-live-box-the-gate-before-trusting-a-form)
  must-fixes on the real box → build out `nginx_apply.py` and the remaining forms with the same
  build-and-prove-live discipline used for the three BIG-IP forms.

---

## 12. Phase-0 live-spike results (2026-08-18)

The box (`infra/vpcopilot-nap`) was stood up and onboarded, resolving the environment unknowns.
**NGINX Plus R37 (1.29.8) + the App Protect module** installs and a canned SQLi is blocked — proving
the install + enforcement before any copilot code exists.

- **Generation = v4-style module** (§2, §10.1): the install yields
  `/usr/lib/nginx/modules/ngx_http_app_protect_module.so`, **no** `waf-enforcer`/`waf-config-mgr`
  sidecars — driven by `load_module` + `app_protect_enable on;` + `app_protect_policy_file <raw JSON>`,
  enforcer = the **`nginx-app-protect` systemd service**. The raw-JSON transport the design chose is
  correct; v5 compile-to-`.tgz` is not in play.
- **Block-page detection CONFIRMED (§10.3, resolves the §5 hedge):** NAP's default block is the
  `Request Rejected … Your support ID is: <n>` page returned at **HTTP 200** — the *body*, not the
  status, signals the block. `probe._blocked`'s existing `_XC_BLOCK_MARKERS` match it verbatim, so
  `_run_validation` needs **no change** to recognise a NAP block. (A box that customises the block
  response still needs care — make the marker set NAP-aware defensively.)
- **Repo auth is client-cert, not the JWT:** `pkgs.nginx.com` is mutual-TLS (`400 No required SSL
  certificate was sent` to any JWT-in-a-header request); the JWT is *only* the R33+ runtime license
  (`/etc/nginx/license.jwt`). Install needs `nginx-repo.crt`+`.key`, three repos (plus /
  app-protect / app-protect-security-updates), two signing keys. Codified in `onboard/nap-onboard.sh`.

### Phase-1 (2026-08-18): the `service_policy` form proven end-to-end live

`nginx.py` + `nginx_apply.py` (the `bigip.py`/`bigip_apply.py` analogues; SSH transport, control
string `nginx_app_protect`) applied `larkspur-neg-transfer-001` to the box: **before** the band-aid
the negative transfer is processed; **after**, NAP blocks it (support-id page) while the legit
positive transfer passes → `passed=True`, then rolled back cleanly. Two more §10 gates resolved by
ground truth:

- **§10.2 RESOLVED:** NAP enforces the declared numeric-parameter constraint
  (`VIOL_PARAMETER_NUMERIC_VALUE`, JSON-body param via the content profile) **immediately** — no
  entity staging. The emitted policy needs no per-target `performStaging` change for this form.
- **§10.4 RESOLVED (and it was real):** NAP loads a policy into the enforcer **asynchronously** after
  a reload — a single-shot validation right after reload races the load and reports a false "still
  succeeds" (observed: `blocked=False, False, True` across ~6s). `apply_nginx` now **settle-polls**
  the validation until enforcement is live (bounded); it can never report a false block (a policy
  that genuinely does not block just polls to the timeout → rollback).

### Phase-2 (2026-08-18): full lifecycle + wiring, proven through the CLI

`nginx_lab.py` (guard_site + the copilot vhost) and the reconcile / console / report / CLI wiring all
landed, mirroring the BIG-IP sites the `bigip_awaf` string touches. The **complete lifecycle** runs
through the actual commands on the box: `vpcopilot nginx-lab create --server vpcopilot.lab --origin
10.30.10.22:8080` → `vpcopilot apply-nginx --finding larkspur-neg-transfer-001` blocks the negative
transfer (settle-poll `False, False, True`), legit passes, exit 0. Two bugs the live CLI caught (and
that the offline tests had not, because they only exercised a fake client): an `nginx -t` **rejection**
returned a benign `{dry_run:True}` that rendered as "would deploy" — now re-raised as a box error; and
`nginx_lab.create` left a broken vhost on an `nginx -t` failure — now rolled back. Both fixed + tested.

### Phase-3 (2026-08-18): all three forms proven live — §10.1 resolved

Both remaining forms applied through `vpcopilot apply-nginx` on the box:

- **`api_schema` (API-contract) — PROVEN, §10.1 RESOLVED.** The disallowed off-contract endpoint
  (`larkspur-orphan-reset-001`: POST `/api/reset`) is blocked after the settle-poll (`False,False,
  False,True`) while GET `/api/health` passes. NAP enforces the declared-URL disallow **immediately**
  — the emitter's `performStaging:false` + `general.enforcementReadinessPeriod:0` hold, no staging
  trap. (It loaded a poll slower than service_policy — the settle-poll covers it.)
- **`waf_data_guard` (response-masking) — PROVEN.** The leaked PAN `4111111111111111` + SSN
  `078-05-1120` (`larkspur-profile-pii-001`, GET `/api/profile`) come back **masked** (`secrets
  exposed: none`) after the policy loads. NAP's `data-guard` section masks the response and
  `VIOL_DATA_GUARD block:false` keeps it masking rather than rejecting — the same emit works for both
  targets, no NGINX-specific change.

**Form coverage COMPLETE and live-proven on NAP: `service_policy` ✓, `api_schema` ✓,
`waf_data_guard` ✓** — all via the one form-agnostic `apply_nginx` spine + settle-poll. `waf` stays
declined (§4). The three-way form parity with BIG-IP is done.

**Still open:** §10.5 (reconcile's around-the-box origin probe on a single-ingress box — the retire
routing is wired and unit-tested; the live around-vs-through vantage on a one-ingress topology is the
remaining gate).
