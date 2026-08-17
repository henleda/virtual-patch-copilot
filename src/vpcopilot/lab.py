"""Stand up a clean-slate XC test LB for an arbitrary app origin.

Generalizes the vpcopilot-lab recipe: create an origin pool -> the app (host:port), then a
CLEAN-SLATE HTTP LB (WAF off, no policies, all controls disabled) at `domain`, cloning the
proven pool + LB templates so every required XC field is present. Returns the DNS records to
add (A -> the shared VIP + the ACME challenge CNAME) — same flow as vpcopilot-lab. The copilot
then scans the app's repo and applies/validates band-aids against `https://<domain>`."""
from __future__ import annotations

import copy
import ipaddress
import os
import time
from typing import Callable

from .bigip_lab import LabRefused
from .xc import XC

# clean-slate: every security control OFF so the copilot applies from scratch
_STATUS_FIELDS = ("host_name", "auto_cert_info", "cert_state", "dns_info", "internet_vip_info",
                  "state", "downstream_tls_certificate_expiration_timestamps")

# The objects cloned to build a lab. CONFIG, not constants — they used to be hardcoded defaults
# naming this operator's own tenant (`nimbus-bigip-pool`, `nimbus-www`), which had three costs:
# the command only worked on a tenant that happened to contain objects by those names; the CLI
# exposed no way to override them; and `nimbus-www` was simultaneously the default source template
# here and the default PROTECTED object in `engine.protected_lbs()` — the one load balancer the
# tool refuses to mutate was the one it read to build every lab.
#
# Cloning itself stays: copying a known-good object guarantees every required XC field is present,
# where composing a spec from scratch discovers a missing one at PUT time. Only the names moved to
# config, so the same values keep the same behaviour on this tenant while the tool stops assuming
# them anywhere else.
POOL_TEMPLATE_ENV = "VPCOPILOT_LAB_POOL_TEMPLATE"
LB_TEMPLATE_ENV = "VPCOPILOT_LAB_LB_TEMPLATE"
DEFAULT_POOL_TEMPLATE = "nimbus-bigip-pool"
DEFAULT_LB_TEMPLATE = "nimbus-www"


def pool_template_default() -> str:
    return os.environ.get(POOL_TEMPLATE_ENV, "").strip() or DEFAULT_POOL_TEMPLATE


def lb_template_default() -> str:
    return os.environ.get(LB_TEMPLATE_ENV, "").strip() or DEFAULT_LB_TEMPLATE


def _origin_server(host: str) -> dict:
    try:
        ipaddress.ip_address(host)
        return {"public_ip": {"ip": host}, "labels": {}}
    except ValueError:
        return {"public_name": {"dns_name": host}, "labels": {}}


def _split_origin(origin: str, default_port: int) -> tuple[str, int]:
    """`host:port` / `[ipv6]:port` -> `(host, port)`, refusing rather than crashing on a bad port.

    Mirrors `bigip_lab._split_origin`: a bare `int(port)` raises `ValueError`, which is not the
    `RuntimeError` the surfaces catch, so a typo'd port (`5OOO`) escaped `lab-create` as a traceback
    exposing this body. Bracketed IPv6 is split on the `]` so the colons inside the address are not
    read as the port separator."""
    origin = origin.strip()
    if origin.startswith("["):                       # [2001:db8::1] or [2001:db8::1]:5000
        host, _, rest = origin[1:].partition("]")
        port_s = rest[1:] if rest.startswith(":") else ""
    else:
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


def _clean_slate(spec: dict) -> None:
    spec.pop("app_firewall", None); spec["disable_waf"] = {}
    for k in ("active_service_policies", "service_policies_from_namespace"):
        spec.pop(k, None)
    spec["no_service_policies"] = {}
    spec.pop("bot_defense", None); spec["disable_bot_defense"] = {}
    spec.pop("rate_limit", None); spec["disable_rate_limit"] = {}
    spec.pop("enable_malicious_user_detection", None); spec["disable_malicious_user_detection"] = {}
    spec.pop("api_specification", None); spec.pop("api_definition", None); spec["disable_api_definition"] = {}
    spec["data_guard_rules"] = []
    # drop any origin-auth request header (that's the Nimbus/BIG-IP template's, not ours)
    mo = spec.get("more_option") or {}
    mo.pop("request_headers_to_add", None)
    for k in _STATUS_FIELDS:
        spec.pop(k, None)


def _template(fetch: Callable, name: str, kind: str, env: str, flag: str) -> dict:
    """Read a template object, and when it is not there say what to set rather than surfacing a 404.

    This is the failure every tenant but the one these defaults were written for will hit first, so
    it names the remedy: which object was looked for, and the two ways to point it somewhere else."""
    try:
        return fetch(name)
    except Exception as e:  # noqa: BLE001 — XCError, but the client raises its own type
        raise RuntimeError(
            f"no {kind} named {name!r} in this namespace to clone as the lab template ({e}). "
            f"`lab-create` builds a lab by copying a known-good {kind} so every required XC field "
            f"is present. Point it at one of yours with {flag}, or set ${env}."
        ) from None


def create_lab(domain: str, origin: str, *, name: str | None = None, origin_tls: bool = False,
               pool_template: str | None = None, lb_template: str | None = None,
               poll: bool = True, log: Callable = print) -> dict:
    """`pool_template`/`lb_template` default to `$VPCOPILOT_LAB_POOL_TEMPLATE` /
    `$VPCOPILOT_LAB_LB_TEMPLATE`, falling back to the objects this operator's tenant happens to
    carry. Passing them explicitly still wins, so every existing call is unchanged."""
    pool_template = pool_template or pool_template_default()
    lb_template = lb_template or lb_template_default()
    xc = XC()
    host, port = _split_origin(origin, 443 if origin_tls else 80)
    base = name or domain.split(".")[0]
    pool_name, lb_name = f"{base}-pool", f"{base}-lab"

    # 1) origin pool -> the app (clone a working pool for all required fields, then swap origin)
    if xc.origin_pool_exists(pool_name):
        log(f"origin pool {pool_name} already exists")
    else:
        pspec = copy.deepcopy(_template(xc.get_origin_pool, pool_template, "origin pool",
                                        POOL_TEMPLATE_ENV, "--pool-template")["spec"])
        pspec["origin_servers"] = [_origin_server(host)]
        pspec["port"] = port
        pspec.pop("use_tls", None); pspec.pop("no_tls", None)
        if origin_tls:
            pspec["use_tls"] = {"skip_server_verification": {}, "tls_config": {"default_security": {}},
                                "no_mtls": {}, "default_session_key_caching": {}}
        else:
            pspec["no_tls"] = {}
        xc.create_origin_pool({"metadata": {"name": pool_name, "namespace": xc.ns}, "spec": pspec})
        log(f"created origin pool {pool_name} -> {host}:{port} ({'https' if origin_tls else 'http'})")

    # 2) clean-slate HTTP LB at `domain` (clone the known-good LB, swap pool + domain, strip security)
    if xc.lb_exists(lb_name):
        log(f"LB {lb_name} already exists")
    else:
        spec = copy.deepcopy(_template(xc.get_lb, lb_template, "load balancer",
                                       LB_TEMPLATE_ENV, "--lb-template")["spec"])
        spec["domains"] = [domain]
        spec["default_route_pools"] = [{"pool": {"name": pool_name, "namespace": xc.ns},
                                        "weight": 1, "priority": 1}]
        _clean_slate(spec)
        xc.create_lb({"metadata": {"name": lb_name, "namespace": xc.ns,
                                   "description": f"vpcopilot test LB for {domain}"}, "spec": spec})
        log(f"created clean-slate LB {lb_name} for {domain}")

    # 3) DNS records to add (A -> shared VIP, ACME challenge CNAME) — poll for the auto-cert record
    dns = {"a": None, "acme": None}
    for _ in range(6 if poll else 1):
        s = xc.get_lb(lb_name)["spec"]
        vip = next((d.get("ip_address") for d in s.get("dns_info", []) if d.get("ip_address")), None)
        dns["a"] = {"type": "A", "name": domain, "value": vip}
        recs = (s.get("auto_cert_info", {}) or {}).get("dns_records") or []
        if recs:
            r = recs[0]
            dns["acme"] = {"type": r.get("type"), "name": r.get("name"), "value": r.get("value")}
            break
        if poll:
            time.sleep(8)
    return {"domain": domain, "lb": lb_name, "pool": pool_name, "origin": f"{host}:{port}",
            "url": f"https://{domain}", "dns_records": dns}
