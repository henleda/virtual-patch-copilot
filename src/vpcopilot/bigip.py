"""BIG-IP AS3 client. Thin REST over httpx, the same shape as `xc.py`.

AS3 rather than iControl REST, decided in L2: `GET /declare` is the snapshot `ApplyContext.load()`
takes, `"action": "dry-run"` is a real self-test, one POST is the whole attach, and a tenant-scoped
`DELETE` gives the same hard blast-radius boundary an XC namespace gives. iControl needs four to six
calls where AS3 needs one, with partial-failure states in between and no dry run.

**Reachability is the operator's problem, deliberately.** This takes a URL and does not care how it
resolves. In the reference lab the appliance's management interface is not published — it is reached
through an SSM port-forward from the origin host — so `BIGIP_URL` points at the near end of whatever
tunnel the operator opened. Baking the tunnel in here would make the tool specific to one topology
and would tempt someone into opening a management port to the internet instead.
"""
from __future__ import annotations

import os
import re
from urllib.parse import quote

import httpx

AS3_PATH = "/mgmt/shared/appsvcs/declare"
INFO_PATH = "/mgmt/shared/appsvcs/info"
# Enforced at this layer too, not only in `bigip_lab.validate_tenant`: this is the one call that
# interpolates a caller-supplied string into a URL path.
_SAFE_TENANT = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class BigIPError(RuntimeError):
    """Carries the HTTP status when there was one, so a caller can tell apart failures that need
    completely different fixes: 401 is a wrong password, 404 on the AS3 path is an appliance with no
    AS3 installed (the state every PAYG image ships in), and no status at all is a transport failure
    — a dropped tunnel or an unreachable box. Rendering all three as "unreachable" sent an operator
    looking for a network problem when the fix was a package install or a password."""

    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


def _env(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise BigIPError(f"{key} not set — add it to .env")
    return v


def configured() -> bool:
    """Whether an appliance is configured at all — distinct from whether it answers. Lets a surface
    say "no BIG-IP configured" instead of surfacing a connection error for a lab nobody set up."""
    return bool((os.environ.get("BIGIP_URL") or "").strip())


class BigIP:
    def __init__(self, base_url=None, user=None, password=None, timeout=60, verify=False):
        self.base = (base_url or _env("BIGIP_URL")).rstrip("/")
        self.user = user or os.environ.get("BIGIP_USER", "admin")
        self.password = password or _env("BIGIP_PASSWORD")
        # A lab appliance presents its own self-signed certificate and there is no CA to pin it to.
        # `verify` is a parameter rather than a hardcoded False so a deployment that DOES have a
        # trusted cert is not forced to turn verification off.
        self._c = httpx.Client(timeout=timeout, verify=verify,
                               auth=(self.user, self.password),
                               headers={"Content-Type": "application/json"})

    def _redact(self, s: str) -> str:
        """Never let the admin password reach a log, an error string or a traceback (`xc._redact`)."""
        return s.replace(self.password, "***REDACTED***") if self.password else s

    def _req(self, method: str, path: str, **kw):
        try:
            r = self._c.request(method, f"{self.base}{path}", **kw)
        except httpx.HTTPError as e:
            raise BigIPError(self._redact(f"{method} {path} -> {type(e).__name__}: {e}")) from None
        if r.status_code >= 400:
            raise BigIPError(self._redact(f"{method} {path} -> {r.status_code}: {r.text[:400]}"),
                             status=r.status_code)
        return r

    # ---------------------------------------------------------------- reads

    def info(self) -> dict:
        """AS3 version. The cheapest proof the extension is installed AND answering — it is an
        iControl LX package, absent from the PAYG images, so "the appliance is up" and "AS3 is
        usable" are genuinely different facts."""
        return self._req("GET", INFO_PATH).json()

    def get_declaration(self) -> dict:
        """The whole current declaration — the snapshot every mutation is compared against.

        A BIG-IP with no AS3 tenants answers 204 with an empty body rather than an empty object, so
        that is normalized here; letting `.json()` raise on it would make "nothing deployed yet"
        indistinguishable from a broken appliance."""
        r = self._req("GET", AS3_PATH)
        if r.status_code == 204 or not r.content:
            return {}
        return r.json()

    def tenants(self) -> list[str]:
        """Tenant names in the current declaration. AS3 mixes its own bookkeeping keys in beside the
        tenants, so a tenant is identified by `class == Tenant` rather than by "not a key I know"."""
        decl = self.get_declaration()
        body = decl.get("declaration", decl) or {}
        return sorted(k for k, v in body.items() if isinstance(v, dict) and v.get("class") == "Tenant")

    # ---------------------------------------------------------------- writes

    def _checked(self, r) -> dict:
        """Raise on an AS3 failure that arrived inside a successful HTTP response.

        Measured against the real appliance, AS3 reports failure two different ways and only one of
        them is an HTTP error:

        - a **schema/validation** failure answers `HTTP 422` with a TOP-LEVEL `{code, errors,
          message}` and **no `results` array at all** — so a caller reading `results[0]` gets
          `None` and renders "AS3: None None" as though it had worked;
        - a **per-tenant** failure answers **HTTP 200** with the bad code inside
          `results[].code`, which sails straight past any status-code check.

        Both are treated as errors here, at the client, so no caller can forget: a lab that reports
        success and deployed nothing is the "looks applied and is not" failure this project keeps
        finding, arriving one layer below the policy.
        """
        body = r.json()
        top = body.get("code")
        if isinstance(top, int) and top >= 400:
            errs = "; ".join(str(e) for e in (body.get("errors") or []))[:300]
            raise BigIPError(self._redact(
                f"AS3 rejected the declaration ({top}): {body.get('message', '')} {errs}".strip()))
        bad = [x for x in (body.get("results") or [])
               if isinstance(x.get("code"), int) and x["code"] >= 400]
        if bad:
            detail = "; ".join(f"{x.get('tenant', '?')}: {x['code']} {x.get('message', '')}"
                               for x in bad)[:300]
            raise BigIPError(self._redact(f"AS3 reported a failure per tenant: {detail}"))
        return body

    def deploy(self, declaration: dict, *, dry_run: bool = False) -> dict:
        """POST a declaration. `dry_run` uses AS3's own `action: dry-run`, so the appliance itself
        reports what it would change — not a guess this code makes about it."""
        body = dict(declaration)
        if dry_run:
            body["action"] = "dry-run"
        return self._checked(self._req("POST", AS3_PATH, json=body))

    def delete_tenant(self, tenant: str) -> dict:
        """Remove exactly one tenant. Scoped by URL rather than by posting a declaration with the
        tenant omitted, because `updateMode: complete` on a whole-declaration POST would delete
        every OTHER tenant on the appliance as a side effect of removing this one.

        The name is validated by `bigip_lab.guard_tenant` before it reaches here, and refused again
        at this layer — this is the one call that interpolates a caller-supplied string into a URL,
        so it does not rely on a guard one module up.

        The encoding is real defence in depth: `quote(..., safe='')` percent-encodes a separator and
        `httpx` sends it that way — `URL.raw_path` is `…/declare/a%2Fb` on the wire. (`URL.path` is
        the percent-*decoded* convenience property and shows `…/declare/a/b`; reading it is how an
        earlier version of this comment came to claim, wrongly, that httpx normalizes the encoding
        away.) What the encoding cannot decide is whether the *appliance* re-splits the decoded
        path, so the name is refused outright rather than trusted to survive a round trip."""
        if not _SAFE_TENANT.match(tenant or ""):
            raise BigIPError(
                f"refusing to DELETE with tenant name {tenant!r}: a tenant is letters, digits, "
                f"'_' or '-'. A name carrying a separator would address a different endpoint.")
        return self._checked(self._req("DELETE", f"{AS3_PATH}/{quote(tenant, safe='')}"))
