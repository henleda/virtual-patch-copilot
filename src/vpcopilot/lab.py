"""Stand up a clean-slate XC test LB for an arbitrary app origin.

Generalizes the vpcopilot-lab recipe: create an origin pool -> the app (host:port), then a
CLEAN-SLATE HTTP LB (WAF off, no policies, all controls disabled) at `domain`, cloning the
proven pool + LB templates so every required XC field is present. Returns the DNS records to
add (A -> the shared VIP + the ACME challenge CNAME) — same flow as vpcopilot-lab. The copilot
then scans the app's repo and applies/validates band-aids against `https://<domain>`."""
from __future__ import annotations

import copy
import ipaddress
import time
from typing import Callable

from .xc import XC

# clean-slate: every security control OFF so the copilot applies from scratch
_STATUS_FIELDS = ("host_name", "auto_cert_info", "cert_state", "dns_info", "internet_vip_info",
                  "state", "downstream_tls_certificate_expiration_timestamps")


def _origin_server(host: str) -> dict:
    try:
        ipaddress.ip_address(host)
        return {"public_ip": {"ip": host}, "labels": {}}
    except ValueError:
        return {"public_name": {"dns_name": host}, "labels": {}}


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


def create_lab(domain: str, origin: str, *, name: str | None = None, origin_tls: bool = False,
               pool_template: str = "nimbus-bigip-pool", lb_template: str = "nimbus-www",
               poll: bool = True, log: Callable = print) -> dict:
    xc = XC()
    host, _, port_s = origin.partition(":")
    port = int(port_s) if port_s else (443 if origin_tls else 80)
    base = name or domain.split(".")[0]
    pool_name, lb_name = f"{base}-pool", f"{base}-lab"

    # 1) origin pool -> the app (clone a working pool for all required fields, then swap origin)
    if xc.origin_pool_exists(pool_name):
        log(f"origin pool {pool_name} already exists")
    else:
        pspec = copy.deepcopy(xc.get_origin_pool(pool_template)["spec"])
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
        spec = copy.deepcopy(xc.get_lb(lb_template)["spec"])
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
