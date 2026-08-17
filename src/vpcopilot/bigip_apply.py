"""BIG-IP live-apply — the Advanced-WAF band-aid analogue of the XC apply loop.

emit the finding's declarative WAF policy → wrap it as AS3 (a base64 `WAF_Policy` hung on the app's
`serviceMain.policyWAF`) → deploy it into the sandbox tenant → validate against the finding's real
exploit → keep it, or roll the tenant back to clean-slate. The AS3 tenant is the blast-radius
boundary exactly as the XC namespace is for `apply.py`, so `guard_tenant` is `guard_lb`'s twin and a
scoped redeploy can never reach another app.

Precondition: the tenant/app already exists (from `vpcopilot bigip-lab create`). This attaches and
detaches a band-aid on it, the way `apply` attaches a control to an existing XC load balancer — it
does not stand the app up, so it never has to guess the app's origin or virtual address.

Reused wholesale from the XC path: the emitter (`emitters.emit`), the AS3 client with its real
dry-run and honest `_checked` failure gate (`bigip.BigIP`), the tenant guard, the probe/validator
(`apply._run_validation` → `probe_from_spec`, which is black-box HTTP and does not care whether XC or
BIG-IP sits in front of the VIP), and the target-neutral ledger/audit chokepoints. New here: the AS3
wrap, the snapshot/rollback against the tenant sub-tree, and the retire (detach = redeploy without
the WAF).
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Callable

from . import audit, ledger
from .apply import _run_validation
from .bigip import BigIP
from .bigip_lab import guard_tenant
from .emitters import emit as emit_policy
from .probe import probe_negative_pay

WAF_REF = "vpcopilot_waf"   # the AS3 WAF_Policy key the band-aid lands under, inside the app


def _adc(decl: dict) -> dict:
    """The ADC body of a `get_declaration()` result — AS3 nests it under `declaration`, or (for a
    freshly-built one) it is the dict itself. Mirrors `BigIP.tenants`' `decl.get('declaration', decl)`."""
    return decl.get("declaration", decl) or {}


def _envelope(tenant_name: str, tenant_obj: dict) -> dict:
    """A one-tenant AS3 declaration. Selective update (no `updateMode: complete`) touches ONLY this
    tenant, so deploying it can never disturb another app on the appliance."""
    return {"class": "AS3", "action": "deploy", "persist": True,
            "declaration": {"class": "ADC", "schemaVersion": "3.0.0",
                            "id": f"vpcopilot-{tenant_name}", tenant_name: tenant_obj}}


def _app_of(tenant_obj: dict, app: str) -> dict:
    a = tenant_obj.get(app) if isinstance(tenant_obj, dict) else None
    if not isinstance(a, dict) or a.get("class") != "Application":
        raise RuntimeError(
            f"application {app!r} not found in the tenant — run `vpcopilot bigip-lab create "
            f"--app {app}` first, or pass the right --app")
    return a


def _attach_waf(tenant_obj: dict, app: str, policy: dict) -> dict:
    """A COPY of the tenant with the emitted policy hung on the app's `serviceMain.policyWAF`.

    `WAF_Policy.policy` is an F5string — a *reference*, not an inline object — so the document travels
    base64-encoded; posting it inline is rejected by AS3 with `Invalid data property: [object Object]`
    (see `tests/test_live_emitter.py`)."""
    t = copy.deepcopy(tenant_obj)
    a = _app_of(t, app)
    a["serviceMain"]["policyWAF"] = {"use": WAF_REF}
    a[WAF_REF] = {"class": "WAF_Policy", "ignoreChanges": True,
                  "policy": {"base64": base64.b64encode(json.dumps(policy).encode()).decode()}}
    return t


def _detach_waf(tenant_obj: dict, app: str) -> dict:
    """A COPY with OUR band-aid removed — the clean-slate it was applied over. This is the rollback
    target and the retire action, never a `delete_tenant` (that would tear the whole app down, not
    just the band-aid). `policyWAF` is only stripped when it references OUR policy, so a user's own
    pre-existing WAF on the same virtual server is never clobbered by a rollback or a retire."""
    t = copy.deepcopy(tenant_obj)
    a = _app_of(t, app)
    main = a.get("serviceMain", {})
    if isinstance(main.get("policyWAF"), dict) and main["policyWAF"].get("use") == WAF_REF:
        main.pop("policyWAF", None)
    a.pop(WAF_REF, None)
    return t


def _emit_for_finding(out_dir: str, finding_id: str, protocol: str):
    """The finding's declarative Advanced-WAF policy — or an `EmitResult` that DECLINES with a named
    reason (e.g. the control is `rate_limit`/`bot`/`malicious_user`, which have no AWAF band-aid).
    Same finding→emit wiring the console's `/api/emit` uses."""
    pol_path = Path(out_dir) / "policies.json"
    if not pol_path.exists():
        raise RuntimeError(f"no {out_dir}/policies.json — scan first so there is a band-aid to apply")
    entry = next((e for e in json.loads(pol_path.read_text()) if e.get("finding_id") == finding_id), None)
    if entry is None:
        raise RuntimeError(f"no band-aid recorded for finding {finding_id!r} in {out_dir}/policies.json")
    probes_path = Path(out_dir) / "probes.json"
    probes = json.loads(probes_path.read_text()) if probes_path.exists() else []
    probe = next((p for p in probes if p.get("finding_id") == finding_id), None)
    res = emit_policy(target="bigip-awaf", control=entry.get("control", ""),
                      policy_name=entry.get("policy_name", ""), probe=probe, protocol=protocol)
    return res, entry


def _status(v: dict) -> dict:
    return {k: v.get(k) for k in ("exploit_status", "exploit_blocked", "legit_ok")}


def _unvalidatable(v: dict) -> str | None:
    """A validation result that could not actually exercise the exploit — surfaced as its own honest
    message rather than collapsed into 'exploit succeeds'. Rendering an `auth_failed` probe as
    'exploit STILL succeeds' tells a user their WAF failed when in truth the probe never logged in
    (e.g. wrong/stale VPCOPILOT_PROBE_* creds) — the exact false signal this project exists to avoid.
    The band-aid is still rolled back (an unconfirmed block never counts as passed); only the wording
    changes, from a false negative to a fixable instruction."""
    if v.get("auth_failed"):
        return ("validation could not authenticate — set VPCOPILOT_PROBE_USER/PASS (or "
                "VPCOPILOT_PROBE_TOKEN) to the app's credentials and re-run")
    if v.get("no_probe"):
        return "no finding-derived probe for this target — cannot validate the band-aid"
    return None


def apply_bigip(finding_id: str, *, tenant: str, app: str, url: str,
                dry_run: bool = False, keep: bool = False, protocol: str = "http",
                out_dir: str = "out", allow_protected: bool = False,
                client: BigIP | None = None, log: Callable = print) -> dict:
    """Apply one finding's AWAF band-aid to a user's BIG-IP, the full loop:

    guard tenant → snapshot the clean-slate → emit + wrap the policy → self-test (AS3 dry-run) →
    deploy → validate the exploit is blocked and legit still passes → keep or roll back → ledger/audit.
    """
    guard_tenant(tenant, allow_protected=allow_protected, dry_run=dry_run)

    res, _entry = _emit_for_finding(out_dir, finding_id, protocol)
    if not res.supported:
        # Honest decline — a named reason and NO deploy, never a policy that enforces nothing.
        log(f"  no BIG-IP Advanced-WAF band-aid for this finding: {res.reason}")
        return {"applied": False, "emitted": False, "reason": res.reason,
                "finding_id": finding_id, "tenant": tenant}

    bip = client or BigIP()
    tenant_obj = _adc(bip.get_declaration()).get(tenant)
    if not isinstance(tenant_obj, dict) or tenant_obj.get("class") != "Tenant":
        raise RuntimeError(f"tenant {tenant!r} not found on the appliance — run "
                           f"`vpcopilot bigip-lab create --tenant {tenant}` first")
    _app_of(tenant_obj, app)   # raises with a clear message if the app isn't there

    # The clean-slate (band-aid removed if a prior one lingered) is the rollback + retire target.
    clean = _detach_waf(tenant_obj, app)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "bigip_snapshot.json").write_text(json.dumps(_envelope(tenant, clean), indent=2))
    waf_decl = _envelope(tenant, _attach_waf(clean, app, res.policy))

    # Self-test: AS3's own dry-run says whether the declaration is even valid, before anything changes.
    dry = bip.deploy(waf_decl, dry_run=True)
    if dry_run:
        log("  [dry-run] AS3 accepted the declaration; nothing was changed")
        return {"applied": False, "dry_run": True, "finding_id": finding_id, "tenant": tenant,
                "app": app, "policy_name": res.policy_name, "as3": dry}

    # Deploy the clean-slate FIRST, for two reasons the live box exposed:
    #  1. Honest baseline — `before` must measure the app UNDEFENDED. If a band-aid of ours lingered
    #     from a prior run, validating against it would contaminate the baseline (it might already
    #     block), making a working new policy look like no improvement.
    #  2. Fresh import — the WAF_Policy carries `ignoreChanges: true` (so AS3 does not re-import an
    #     unchanged policy on every idempotent submit). But that also means a NEW policy posted under
    #     the same `vpcopilot_waf` ref while an old one is present is SILENTLY IGNORED — the stale
    #     policy stays and the new band-aid never lands. Removing the ref first makes the subsequent
    #     attach an add, which is always imported. `clean` strips only OUR ref, never a user's WAF.
    bip.deploy(_envelope(tenant, clean))
    before = _run_validation(url, finding_id, out_dir, probe_negative_pay, log)
    note = _unvalidatable(before)
    log(f"  ⚠ before: {note}" if note
        else f"  before: exploit {'blocked' if before.get('exploit_blocked') else 'succeeded'}")
    bip.deploy(waf_decl)   # the real apply
    after = _run_validation(url, finding_id, out_dir, probe_negative_pay, log)
    passed = bool(after.get("exploit_blocked") and after.get("legit_ok"))
    note = _unvalidatable(after)
    log(f"  ⚠ after:  {note} — cannot confirm the band-aid, rolling back" if note
        else f"  after:  exploit {'blocked ✓' if after.get('exploit_blocked') else 'STILL succeeds'}, "
             f"legit {'ok' if after.get('legit_ok') else 'BROKEN'}")

    rolled = False
    if not passed or not keep:
        bip.deploy(_envelope(tenant, clean))   # roll the tenant back to clean-slate
        rolled = True
    kept = passed and keep

    if kept:
        # lb carries tenant/app so retire (console or CLI) can recover both from the ledger — a
        # BIG-IP band-aid needs the app, not just the tenant, to know which serviceMain to detach.
        ledger.mark_mitigated(out_dir, finding_id, control="bigip_awaf",
                              policy_name=res.policy_name, lb=f"{tenant}/{app}")
    audit.record(out_dir, "apply_bigip_awaf", finding_id=finding_id, tenant=tenant, app=app,
                 policy_name=res.policy_name, passed=passed, kept=kept, rolled_back=rolled,
                 before_after=[_status(before), _status(after)])
    return {"applied": True, "passed": passed, "kept": kept, "rolled_back": rolled,
            "finding_id": finding_id, "tenant": tenant, "app": app,
            "policy_name": res.policy_name, "before": before, "after": after}


def retire_bigip(finding_id: str, *, tenant: str, app: str, out_dir: str = "out",
                 allow_protected: bool = False, client: BigIP | None = None,
                 log: Callable = print) -> dict:
    """Detach the band-aid: redeploy the app WITHOUT the WAF (the XC-retire analogue). Not a tenant
    delete — the app stays up, only the temporary control comes off."""
    guard_tenant(tenant, allow_protected=allow_protected, dry_run=False)
    bip = client or BigIP()
    tenant_obj = _adc(bip.get_declaration()).get(tenant)
    if not isinstance(tenant_obj, dict) or tenant_obj.get("class") != "Tenant":
        raise RuntimeError(f"tenant {tenant!r} not found on the appliance")
    bip.deploy(_envelope(tenant, _detach_waf(tenant_obj, app)))
    ledger.mark_retired(out_dir, finding_id)
    audit.record(out_dir, "retire_bigip_awaf", finding_id=finding_id, tenant=tenant, app=app)
    log(f"  retired {finding_id} — WAF detached from {tenant}/{app}")
    return {"retired": True, "finding_id": finding_id, "tenant": tenant, "app": app}
