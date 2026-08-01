"""Stand up and tear down the BIG-IP side of the L2 lab.

`lab.py` does this for XC; this is its BIG-IP twin, and it closes the two gaps that one has:

- **an explicit inverse.** `lab-create` has no `lab-rm`, so every XC lab it ever made is still
  there. Something that creates infrastructure on demand and cannot remove it is a leak with a
  friendly interface.
- **an audit record.** `docs/AUDIT.md` says out loud that `lab-create` mutates a tenant and writes
  nothing, so the trail cannot show it. Here, creating and removing a tenant is recorded like any
  other mutating action, through the same centrally-stamped `audit.record`.

Both halves keep `lab.py`'s shape otherwise: idempotent by existence, clean-slate, and every name
derived from one `--name` so a lab is one word to create and the same word to remove.

**The guard is the AS3 tenant, which is what makes this safe to hand a command.** An AS3 tenant is a
hard partition — objects live under `/<tenant>/` and a tenant-scoped DELETE cannot reach outside it —
so it is the BIG-IP analogue of the XC namespace, and `VPCOPILOT_PROTECTED_BIGIP_TENANTS` is the
analogue of `VPCOPILOT_PROTECTED_LBS`. `/Common` is protected unconditionally: it is where the
appliance's own configuration lives, and no override should be able to delete it.
"""
from __future__ import annotations

import os
import re
from typing import Callable

from . import audit
from .bigip import BigIP

PROTECTED_ENV = "VPCOPILOT_PROTECTED_BIGIP_TENANTS"
# `Common` always, plus anything the operator names. Unlike `VPCOPILOT_PROTECTED_LBS`, whose default
# is a demo LB an operator may legitimately want to clear, this default is structural: /Common holds
# the appliance's own config, so removing it is never what someone meant.
_ALWAYS_PROTECTED = {"Common"}
# An AS3 tenant is a BIG-IP object name: letters, digits, `_` and `-`, not starting with a digit.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class LabRefused(RuntimeError):
    """A policy decision: the tool declined because the operator asked for something it refuses.

    Deliberately distinct from `BigIPError` (also a `RuntimeError`) so a surface can tell "we
    declined" from "we could not reach the appliance". Both used to render as `refused:` and as
    HTTP 409 — so a dropped tunnel, which is the most likely failure of a command whose management
    path is an SSM port-forward, looked exactly like the unoverridable `/Common` guard. A CI gate
    has to respond oppositely to the two: a refusal means fix the request, a transport failure means
    retry. Found by adversarial review.
    """


def protected_tenants() -> set[str]:
    named = {s.strip() for s in os.environ.get(PROTECTED_ENV, "").split(",") if s.strip()}
    return _ALWAYS_PROTECTED | named


def validate_tenant(tenant: str) -> str:
    """A tenant name must be a plain AS3 identifier, and this runs BEFORE the protected check.

    The `/Common` refusal is only worth as much as the parsing in front of it. Without this,
    `Common ` (trailing space), `./Common` or a percent-encoded variant are all names that are not
    literally `"Common"` and would sail past a set-membership test, while AS3 may well resolve them
    to the tenant the guard exists to protect. A name carrying `/` is the sharp one: it would sit in
    `DELETE /mgmt/shared/appsvcs/declare/<tenant>` and address a different path segment.

    AS3's own rule is that a tenant is a BIG-IP object name: letters, digits, `_` and `-`, not
    starting with a digit. Anything else is refused rather than normalized — quietly "fixing" a
    name would mean acting on a tenant the operator did not type.
    """
    name = (tenant or "").strip()
    if not name:
        raise LabRefused("tenant name is required")
    if name != tenant:
        raise LabRefused(
            f"tenant name {tenant!r} has leading or trailing whitespace — refusing rather than "
            f"trimming it, because {name!r} may not be the tenant you meant.")
    if not _NAME_RE.match(name):
        raise LabRefused(
            f"invalid tenant name {name!r}: a tenant is letters, digits, '_' or '-', not starting "
            f"with a digit. Names carrying '/', '.' or whitespace are refused.")
    return name


def guard_tenant(tenant: str, *, allow_protected: bool, dry_run: bool) -> None:
    """The one protected-tenant guardrail every mutating path here shares (`engine.guard_lb`).

    `Common` is refused even with `allow_protected`, and even on a dry run. Every other guard in
    this project lets an override through because the operator may know something the tool does not;
    there is nothing to know here. A dry run that "previews" deleting the appliance's own
    configuration is a preview of an outage, and the flag exists for the tenants an operator
    deliberately protected, not for the one the appliance cannot function without.
    """
    tenant = validate_tenant(tenant)
    # Case-insensitive throughout: BIG-IP resolves `common` and `Common` to the same object, so a
    # check that only rejected the exact string would wave the lower-case spelling through to the
    # very tenant this guard exists to protect.
    lowered = tenant.lower()
    if lowered in {t.lower() for t in _ALWAYS_PROTECTED}:
        raise LabRefused(
            f"refusing to touch BIG-IP tenant '{tenant}': it holds the appliance's own "
            f"configuration. This is not overridable — create your lab in its own tenant."
        )
    if lowered in {t.lower() for t in protected_tenants()} and not allow_protected and not dry_run:
        raise LabRefused(
            f"refusing to mutate protected BIG-IP tenant '{tenant}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-tenant) or edit ${PROTECTED_ENV} to override."
        )


def declaration(tenant: str, app: str, origin_host: str, origin_port: int,
                virtual_address: str, virtual_port: int = 80) -> dict:
    """The AS3 declaration for a clean-slate lab: an HTTP virtual server in front of one origin.

    Clean-slate in the same sense as `lab._clean_slate` — **no WAF policy is attached**. The point of
    the lab is to watch the copilot attach one and watch the exploit stop working; shipping a policy
    here would mean the band-aid was already on before anyone applied it, which is exactly the
    "looks applied and is not" confusion G2's canary exists to prevent.
    """
    return {
        "class": "AS3",
        "action": "deploy",
        "persist": True,
        "declaration": {
            "class": "ADC",
            "schemaVersion": "3.0.0",
            "id": f"vpcopilot-{tenant}",
            "label": f"vpcopilot lab: {app}",
            tenant: {
                "class": "Tenant",
                app: {
                    "class": "Application",
                    "template": "http",
                    "serviceMain": {
                        "class": "Service_HTTP",
                        "virtualAddresses": [virtual_address],
                        "virtualPort": virtual_port,
                        "pool": "lab_pool",
                    },
                    "lab_pool": {
                        "class": "Pool",
                        "monitors": ["http"],
                        "members": [{"servicePort": origin_port,
                                     "serverAddresses": [origin_host]}],
                    },
                },
            },
        },
    }


def _split_origin(origin: str, default_port: int = 8080) -> tuple[str, int]:
    """`host:port`, refusing rather than crashing on a port that is not a number.

    `int()` raises `ValueError`, which is not a `RuntimeError`, so it escaped the surfaces' handlers
    entirely: the CLI printed a traceback exposing this function's body and the console answered a
    bare 500, where every other bad input on that endpoint gets a message.
    """
    host, _, port_s = origin.partition(":")
    if not host.strip():
        raise LabRefused(f"invalid origin {origin!r}: expected host or host:port")
    if not port_s:
        return host, default_port
    try:
        port = int(port_s)
    except ValueError:
        raise LabRefused(
            f"invalid origin {origin!r}: port {port_s!r} is not a number (expected host:port, "
            f"e.g. 10.30.10.22:8080)") from None
    if not 1 <= port <= 65535:
        raise LabRefused(f"invalid origin {origin!r}: port {port} is outside 1-65535")
    return host, port


def create(tenant: str, origin: str, virtual_address: str, *, app: str = "lab",
           virtual_port: int = 80, allow_protected: bool = False, dry_run: bool = False,
           out_dir: str = "out", client: BigIP | None = None, log: Callable = print) -> dict:
    """Create (or converge) the lab tenant. Idempotent by existence, like `lab.create_lab`."""
    guard_tenant(tenant, allow_protected=allow_protected, dry_run=dry_run)
    bip = client or BigIP()
    host, port = _split_origin(origin)

    existing = bip.tenants()
    if tenant in existing and not dry_run:
        # Converge rather than refuse: re-running with a changed origin should move the pool member,
        # which is what "idempotent by existence" means in lab.py — it is not "do nothing if a name
        # is taken".
        log(f"tenant {tenant} already exists — re-deploying to converge it")

    decl = declaration(tenant, app, host, port, virtual_address, virtual_port)
    res = bip.deploy(decl, dry_run=dry_run)
    results = res.get("results") or [{}]
    code = results[0].get("code")
    message = results[0].get("message", "")

    if dry_run:
        # AS3 answers a dry run with what it WOULD change, so the preview is the appliance's own
        # answer rather than this code's guess about it. Nothing is written and nothing is audited:
        # a dry run changed nothing, so there is nothing to answer for (docs/AUDIT.md).
        log(f"[dry-run] tenant {tenant}: AS3 reports {code} {message}")
        return {"tenant": tenant, "dry_run": True, "code": code, "message": message,
                "url": f"http://{virtual_address}", "audited": False}

    audit.record(out_dir, "bigip_lab_create", tenant=tenant, app=app,
                 origin=f"{host}:{port}", virtual_address=virtual_address,
                 virtual_port=virtual_port, code=code, message=message,
                 existed=tenant in existing)
    log(f"tenant {tenant}: {code} {message} — http://{virtual_address} -> {host}:{port}")
    return {"tenant": tenant, "app": app, "origin": f"{host}:{port}",
            "url": f"http://{virtual_address}", "code": code, "message": message,
            "existed": tenant in existing, "audited": True}


def remove(tenant: str, *, allow_protected: bool = False, dry_run: bool = False,
           out_dir: str = "out", client: BigIP | None = None, log: Callable = print) -> dict:
    """The explicit inverse `lab.py` never had.

    Scoped to one tenant by URL, so it cannot reach another one — the blast-radius boundary that
    made AS3 the right interface for this.
    """
    guard_tenant(tenant, allow_protected=allow_protected, dry_run=dry_run)
    bip = client or BigIP()

    if tenant not in bip.tenants():
        # Absent is reported, never invented as success: "there was nothing to remove" and "we
        # removed it" are different facts, and only one of them means the appliance changed.
        log(f"tenant {tenant} is not on this appliance — nothing to remove")
        return {"tenant": tenant, "removed": False, "reason": "not present", "audited": False}

    if dry_run:
        log(f"[dry-run] would remove tenant {tenant} and everything under it")
        return {"tenant": tenant, "removed": False, "dry_run": True, "audited": False}

    res = bip.delete_tenant(tenant)
    results = res.get("results") or [{}]
    code = results[0].get("code")
    message = results[0].get("message", "")
    audit.record(out_dir, "bigip_lab_remove", tenant=tenant, code=code, message=message)
    log(f"removed tenant {tenant}: {code} {message}")
    return {"tenant": tenant, "removed": True, "code": code, "message": message, "audited": True}


def status(*, client: BigIP | None = None) -> dict:
    """What is on the appliance right now — the read both surfaces show before anyone mutates.

    Reports `as3` separately from reachability because they are different failures: an appliance
    that answers but has no AS3 installed is the state the PAYG images ship in, and it needs a
    different fix from one that cannot be reached at all.
    """
    # Every branch returns the SAME key set — a degraded answer that silently omitted `protected`
    # rendered as a blank list on the CLI, which reads as "nothing is protected" rather than "we
    # could not get that far".
    base = {"configured": False, "reachable": False, "as3": None, "as3_installed": None,
            "tenants": [], "protected": sorted(protected_tenants()), "reason": ""}
    if not (os.environ.get("BIGIP_URL") or "").strip():
        return {**base, "reason": "BIGIP_URL not set"}
    try:
        # INSIDE the try: `BigIP.__init__` raises when BIGIP_PASSWORD is unset, and a URL with no
        # password is the ordinary half-configured state — the Setup page manages the three keys as
        # separate fields and only sends the ones that were filled in. A readout that crashes on
        # partial configuration is the one thing it must not do, since answering is its whole job.
        bip = client or BigIP()
        info = bip.info()
    except Exception as e:  # noqa: BLE001
        # Three different failures with three different fixes, and they must not render alike:
        # 401 is a wrong password, 404 on the AS3 path is an appliance that answers fine but has no
        # AS3 installed (the state every PAYG image ships in — this lab hit it), and no status at
        # all is a transport failure. Reporting them all as "unreachable" sent an operator hunting
        # a network problem when the fix was a package install or a password.
        st = getattr(e, "status", None)
        if st == 404:
            return {**base, "configured": True, "reachable": True, "as3_installed": False,
                    "reason": "the appliance answered, but AS3 is not installed on it — "
                              "install the f5-appsvcs iControl LX package"}
        if st in (401, 403):
            return {**base, "configured": True, "reachable": True,
                    "reason": f"the appliance answered {st} — check BIGIP_USER / BIGIP_PASSWORD"}
        return {**base, "configured": True, "reason": str(e)[:200]}
    try:
        tenants = bip.tenants()
    except Exception as e:  # noqa: BLE001
        # Reachable, AS3 answered, but the tenant list did not — e.g. AS3's documented
        # "configuration operation in progress" 503, the window right after a create. `tenants` is
        # empty here because it is UNKNOWN, and `reason` is what distinguishes that from an
        # appliance that genuinely has none.
        return {**base, "configured": True, "reachable": True, "as3": info.get("version"),
                "reason": str(e)[:200]}
    return {**base, "configured": True, "reachable": True, "as3": info.get("version"),
            "as3_installed": True, "tenants": tenants}
