"""F5 Distributed Cloud config-API client. Thin REST over httpx.

The agents never call this — only the deterministic orchestrator does, behind the human
gate. Read methods are safe; write methods (create/put/delete) mutate live XC state and
are only invoked by the gated apply flow with snapshot + rollback."""
from __future__ import annotations

import json
import os

import httpx


class XCError(RuntimeError):
    pass


def _env(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise XCError(f"{key} not set — add it to .env")
    return v


class XC:
    def __init__(self, base_url=None, token=None, namespace=None, timeout=30):
        self.base = (base_url or _env("XC_API_URL")).rstrip("/")
        self.token = token or _env("XC_API_TOKEN")
        self.ns = namespace or os.environ.get("XC_NAMESPACE", "default")
        self._c = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"APIToken {self.token}",
                "Content-Type": "application/json",
            },
        )

    def _req(self, method: str, path: str, **kw):
        r = self._c.request(method, f"{self.base}{path}", **kw)
        if r.status_code >= 400:
            raise XCError(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
        return r.json() if r.content else {}

    # --- service policies ---
    def list_service_policies(self) -> dict:
        return self._req("GET", f"/config/namespaces/{self.ns}/service_policys")

    def get_service_policy(self, name: str) -> dict:
        return self._req("GET", f"/config/namespaces/{self.ns}/service_policys/{name}")

    def service_policy_exists(self, name: str) -> bool:
        try:
            self.get_service_policy(name)
            return True
        except XCError:
            return False

    def create_service_policy(self, spec: dict) -> dict:
        return self._req("POST", f"/config/namespaces/{self.ns}/service_policys", json=spec)

    def delete_service_policy(self, name: str) -> dict:
        return self._req("DELETE", f"/config/namespaces/{self.ns}/service_policys/{name}")

    # --- http load balancer ---
    def get_lb(self, name: str) -> dict:
        return self._req("GET", f"/config/namespaces/{self.ns}/http_loadbalancers/{name}")

    def put_lb(self, name: str, obj: dict) -> dict:
        return self._req("PUT", f"/config/namespaces/{self.ns}/http_loadbalancers/{name}", json=obj)

    def create_lb(self, obj: dict) -> dict:
        return self._req("POST", f"/config/namespaces/{self.ns}/http_loadbalancers", json=obj)

    # --- app firewall (WAF) ---
    def get_app_firewall(self, name: str) -> dict:
        return self._req("GET", f"/config/namespaces/{self.ns}/app_firewalls/{name}")

    def create_app_firewall(self, obj: dict) -> dict:
        return self._req("POST", f"/config/namespaces/{self.ns}/app_firewalls", json=obj)

    def app_firewall_exists(self, name: str) -> bool:
        try:
            self.get_app_firewall(name)
            return True
        except XCError:
            return False

    # --- api definition ---
    def get_api_definition(self, name: str) -> dict:
        return self._req("GET", f"/config/namespaces/{self.ns}/api_definitions/{name}")

    def create_api_definition(self, obj: dict) -> dict:
        return self._req("POST", f"/config/namespaces/{self.ns}/api_definitions", json=obj)

    def delete_api_definition(self, name: str) -> dict:
        return self._req("DELETE", f"/config/namespaces/{self.ns}/api_definitions/{name}")

    def api_definition_exists(self, name: str) -> bool:
        try:
            self.get_api_definition(name)
            return True
        except XCError:
            return False

    def put_swagger(self, name: str, openapi: dict, version: str = "v1") -> str:
        """Upload an OpenAPI/swagger doc to the object store; return its versioned URL."""
        path = f"/object_store/namespaces/{self.ns}/stored_objects/swagger/{name}"
        r = self._c.put(f"{self.base}{path}", json={
            "metadata": {"name": name, "namespace": self.ns, "version": version},
            "string_value": json.dumps(openapi)})
        if r.status_code >= 400:
            raise XCError(f"put_swagger {name} -> {r.status_code}: {r.text[:300]}")
        return r.json()["metadata"]["url"]
