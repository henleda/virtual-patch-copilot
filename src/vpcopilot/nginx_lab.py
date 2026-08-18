"""Stand up and tear down the NGINX side of the L2 lab — the `bigip_lab.py` twin.

`bigip_lab.create` builds an AS3 tenant (an HTTP virtual server in front of one origin, no WAF); this
builds the copilot-owned NGINX vhost: a `server`/`location` that reverse-proxies to the origin and
`include`s the copilot's managed-policy dir. That dir starts EMPTY — the clean slate — and
`nginx_apply` drops a per-finding `app_protect_policy_file` include into it. No band-aid ships from
here, the same discipline as the BIG-IP clean-slate declaration.

**The guard is the server name.** The copilot only ever writes files named `vpcopilot-` and only into
its own `vpcopilot-active` include dir, so it structurally cannot edit a user's config; `guard_site`
is the policy check on top of that. `VPCOPILOT_PROTECTED_NGINX_SITES` is the analogue of
`VPCOPILOT_PROTECTED_BIGIP_TENANTS`, and the nginx catch-all `_` is protected unconditionally — a
server that matches every request is the closest analogue of BIG-IP's `/Common`.
"""
from __future__ import annotations

import os
import re
from typing import Callable

from . import audit
from .nginx import Nginx

PROTECTED_ENV = "VPCOPILOT_PROTECTED_NGINX_SITES"
_ALWAYS_PROTECTED = {"_"}   # the nginx catch-all server_name — matches everything (the /Common analogue)
# A server_name is a hostname-ish token: letters, digits, dot, hyphen, underscore. A name carrying a
# '/' or whitespace is refused, never normalised — the same stance bigip_lab takes on tenant names,
# and here it also keeps the value safe to interpolate into a filename.
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
POLICY_PREFIX = "vpcopilot-"
ACTIVE_SUBDIR = "vpcopilot-active"


class LabRefused(RuntimeError):
    """A policy decision — the tool declined what was asked. Distinct from `NginxError` (unreachable /
    a bad config) so a surface can tell 'we declined' (fix the request) from 'we could not reach the
    box' (retry) — the same split `bigip_lab.LabRefused` draws against `BigIPError`."""


def protected_sites() -> set[str]:
    named = {s.strip() for s in os.environ.get(PROTECTED_ENV, "").split(",") if s.strip()}
    return _ALWAYS_PROTECTED | named


def validate_site(server: str) -> str:
    """A server name must be a plain hostname token, checked BEFORE the protected test — a name with
    whitespace or a '/' could both slip a set-membership guard and, since it lands in a filename,
    escape the copilot's `vpcopilot-` include dir."""
    name = (server or "").strip()
    if not name:
        raise LabRefused("server name is required")
    if name != server:
        raise LabRefused(
            f"server name {server!r} has leading or trailing whitespace — refusing rather than "
            f"trimming it, because {name!r} may not be the server you meant.")
    if not _NAME_RE.match(name):
        raise LabRefused(
            f"invalid server name {name!r}: a server_name is letters, digits, '.', '-' or '_'. "
            f"Names carrying '/' or whitespace are refused.")
    return name


def guard_site(server: str, *, allow_protected: bool, dry_run: bool) -> None:
    """The protected-server guardrail every mutating path here shares (`bigip_lab.guard_tenant`).

    The catch-all `_` is refused even with `allow_protected` and even on a dry run — a server that
    fronts every request is where a mistake reaches the whole box, so it is not overridable. Any other
    protected server is overridable, because the operator may know something the tool does not."""
    server = validate_site(server)
    if server in _ALWAYS_PROTECTED:
        raise LabRefused(
            f"refusing to touch the nginx catch-all server '{server}': it fronts every request on the "
            f"box. This is not overridable — give the copilot its own named server.")
    if server in protected_sites() and not allow_protected and not dry_run:
        raise LabRefused(
            f"refusing to mutate protected server '{server}'. Pass allow_protected=True "
            f"(CLI: --allow-protected-site) or edit ${PROTECTED_ENV} to override.")


def _vhost(server: str, location: str, origin: str, listen: int) -> str:
    """The copilot-owned vhost: a reverse proxy to `origin` whose `location` includes the managed
    dir. `listen … default_server` so a validation curl by IP still routes here; the empty managed
    dir means App Protect is OFF until `nginx_apply` drops a policy in — the clean slate."""
    return ("# vpcopilot-managed\n"
            f"upstream vpcopilot_origin {{ server {origin}; }}\n"
            f"server {{\n"
            f"    listen {listen} default_server;\n"
            f"    server_name {server};\n"
            f"    location {location} {{\n"
            f"        include /etc/nginx/conf.d/{ACTIVE_SUBDIR}/*.conf;\n"
            f"        proxy_pass http://vpcopilot_origin;\n"
            f"        proxy_set_header Host $host;\n"
            f"        proxy_set_header X-Real-IP $remote_addr;\n"
            f"    }}\n"
            f"}}\n")


def _vhost_path(nx: Nginx, server: str) -> str:
    return f"{nx.include_dir}/{POLICY_PREFIX}{server}.conf"


def create(server: str, origin: str, *, location: str = "/", listen: int = 80,
           allow_protected: bool = False, dry_run: bool = False, out_dir: str = "out",
           client: Nginx | None = None, log: Callable = print) -> dict:
    """Create (or converge) the copilot's lab vhost. Idempotent by existence — re-running with a new
    origin re-writes the vhost, the `bigip_lab.create` 'converge, don't refuse' stance."""
    guard_site(server, allow_protected=allow_protected, dry_run=dry_run)
    server = validate_site(server)
    nx = client or Nginx()
    vhost_path = _vhost_path(nx, server)
    vhost = _vhost(server, location, origin, listen)

    if dry_run:
        # Stage the vhost + the empty managed dir, `nginx -t`, then roll the staging back — the
        # AS3-dry-run analogue: the box's own `nginx -t` is the preview, and nothing is audited.
        nx.ensure_dir(f"{nx.include_dir}/{ACTIVE_SUBDIR}")
        nx.put_file(vhost_path, vhost)
        try:
            nx.test_config()
            ok, msg = True, "nginx -t ok"
        except Exception as e:  # noqa: BLE001
            ok, msg = False, str(e)
        nx.remove_file(vhost_path)
        log(f"[dry-run] site {server}: {msg}")
        return {"server": server, "dry_run": True, "ok": ok, "message": msg,
                "url": f"http://{server}", "audited": False}

    nx.ensure_dir(f"{nx.include_dir}/{ACTIVE_SUBDIR}")
    nx.put_file(vhost_path, vhost)
    nx.test_config()
    nx.reload()
    audit.record(out_dir, "nginx_lab_create", server=server, location=location, origin=origin,
                 listen=listen)
    log(f"site {server}: created — {location} -> {origin}")
    return {"server": server, "location": location, "origin": origin,
            "url": f"http://{server}", "audited": True}


def remove(server: str, *, allow_protected: bool = False, dry_run: bool = False,
           out_dir: str = "out", client: Nginx | None = None, log: Callable = print) -> dict:
    """The explicit inverse: remove the copilot's vhost + managed dir. Only our `vpcopilot-` files are
    touched, so a user's own config on the box is never disturbed."""
    guard_site(server, allow_protected=allow_protected, dry_run=dry_run)
    server = validate_site(server)
    nx = client or Nginx()
    vhost_path = _vhost_path(nx, server)
    if dry_run:
        log(f"[dry-run] would remove the copilot vhost for {server}")
        return {"server": server, "removed": False, "dry_run": True, "audited": False}
    nx.remove_file(vhost_path)
    nx.remove_file(f"{nx.include_dir}/{ACTIVE_SUBDIR}")  # rm -f on a dir is a no-op; the includes are files
    nx.reload()
    audit.record(out_dir, "nginx_lab_remove", server=server)
    log(f"removed the copilot vhost for {server}")
    return {"server": server, "removed": True, "audited": True}


def status(*, client: Nginx | None = None) -> dict:
    """What the box looks like right now — reachability and whether the App Protect module is loaded,
    reported separately (the `bigip_lab.status` split: 'answers' ≠ 'WAF usable')."""
    base = {"configured": False, "reachable": False, "app_protect": None,
            "protected": sorted(protected_sites()), "reason": ""}
    from .nginx import configured
    if not configured():
        return {**base, "reason": "NGINX_SSH_HOST not set"}
    try:
        nx = client or Nginx()
        if not nx.reachable():
            return {**base, "configured": True, "reason": "the box did not answer over SSH — "
                    "check NGINX_SSH_HOST/PORT/KEY and that the tunnel is open"}
        cfg = nx.get_config()
    except Exception as e:  # noqa: BLE001
        return {**base, "configured": True, "reason": str(e)[:200]}
    return {**base, "configured": True, "reachable": True,
            "app_protect": "ngx_http_app_protect_module" in cfg,
            "version": nx.version()}
