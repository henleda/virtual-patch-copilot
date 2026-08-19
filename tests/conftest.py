"""D1 (pulled forward for Phase 3): in-memory fakes so the SafeApply engine and control handlers
can be tested without a real XC tenant, network, or wall-clock waits.

FakeXC models just enough of the XC config API: an LB whose spec is a mutable dict, plus the
service-policy / app-firewall / api-definition object stores. It records every put_lb so tests can
assert the exact attach → validate → rollback sequence.
"""
from __future__ import annotations

import copy

import pytest


class FakeXC:
    def __init__(self, lb_spec=None, namespace="test-ns", tenant="test-tenant"):
        self.ns = namespace
        self.tenant = tenant
        self.lb = {"metadata": {"name": "lab", "namespace": namespace},
                   "system_metadata": {"tenant": tenant},
                   "spec": copy.deepcopy(lb_spec or {"no_service_policies": {}})}
        self.service_policies: dict[str, dict] = {}
        self.app_firewalls: dict[str, dict] = {"nimbus-waf": {"spec": {"blocking": {}}}}
        self.api_definitions: dict[str, dict] = {}
        self.swaggers: dict[str, dict] = {}
        self.user_identifications: dict[str, dict] = {}
        self.put_lb_calls: list[dict] = []       # every spec PUT, in order
        self.fail_put_lb = False                  # flip on to simulate an XC write failure

    # ---- LB ----
    def get_lb(self, name):
        return copy.deepcopy(self.lb)

    def put_lb(self, name, obj):
        if self.fail_put_lb:
            raise RuntimeError("simulated XC PUT failure")
        self.lb["spec"] = copy.deepcopy(obj["spec"])
        self.put_lb_calls.append(copy.deepcopy(obj["spec"]))
        return self.lb

    # ---- service policies ----
    def list_service_policies(self):
        return {"items": [{"name": n} for n in self.service_policies]}

    def service_policy_exists(self, name):
        return name in self.service_policies

    def get_service_policy(self, name):
        if name not in self.service_policies:      # the real client raises XCError on a 404
            raise RuntimeError(f"GET service_policy {name} -> 404")
        return copy.deepcopy(self.service_policies[name])

    def create_service_policy(self, obj):
        self.service_policies[obj["metadata"]["name"]] = copy.deepcopy(obj)
        return obj

    def put_service_policy(self, name, obj):
        self.service_policies[name] = copy.deepcopy(obj)
        return obj

    def delete_service_policy(self, name):
        return self.service_policies.pop(name, None)

    # ---- app firewall ----
    def app_firewall_exists(self, name):
        return name in self.app_firewalls

    def get_app_firewall(self, name):
        return copy.deepcopy(self.app_firewalls[name])

    def create_app_firewall(self, obj):
        self.app_firewalls[obj["metadata"]["name"]] = copy.deepcopy(obj)
        return obj

    # ---- api definition / swagger ----
    def api_definition_exists(self, name):
        return name in self.api_definitions

    def create_api_definition(self, obj):
        self.api_definitions[obj["metadata"]["name"]] = copy.deepcopy(obj)
        return obj

    def delete_api_definition(self, name):
        self.api_definitions.pop(name, None)

    def put_swagger(self, name, openapi, version="v1"):
        self.swaggers[name] = copy.deepcopy(openapi)
        return f"string:///{name}"

    # ---- user identification ----
    def user_identification_exists(self, name):
        return name in self.user_identifications

    def get_user_identification(self, name):
        return copy.deepcopy(self.user_identifications[name])

    def create_user_identification(self, obj):
        self.user_identifications[obj["metadata"]["name"]] = copy.deepcopy(obj)
        return obj


class FakeBigIP:
    """In-memory BIG-IP appliance for the AS3 apply/lab paths — the BIG-IP twin of FakeXC.

    Holds an ADC body (tenant name → Tenant object), answers `get_declaration()` with it, and applies
    a `deploy()` as a *selective* update (replace exactly the posted tenant), so a test can assert the
    end state after attach → validate → rollback. `dry_run` records without mutating. Records every
    call so a test can assert the exact deploy sequence.
    """
    def __init__(self, declaration=None, as3_version="3.56.0"):
        self.as3_version = as3_version
        self._adc: dict = copy.deepcopy(declaration or {})   # {tenant_name: Tenant obj}
        self.deployed: list[dict] = []
        self.dry_runs: list[dict] = []
        self.deleted: list[str] = []

    def info(self):
        return {"version": self.as3_version}

    def get_declaration(self):
        if not self._adc:
            return {}   # a BIG-IP with no AS3 tenants answers empty (the real client normalizes 204→{})
        return {"class": "ADC", "schemaVersion": "3.0.0", **copy.deepcopy(self._adc)}

    def tenants(self):
        return sorted(k for k, v in self._adc.items() if isinstance(v, dict) and v.get("class") == "Tenant")

    def deploy(self, declaration, *, dry_run=False):
        if dry_run:
            self.dry_runs.append(copy.deepcopy(declaration))
            return {"results": [{"code": 200, "message": "success", "dryRun": True}]}
        self.deployed.append(copy.deepcopy(declaration))
        for k, v in declaration.get("declaration", {}).items():
            if isinstance(v, dict) and v.get("class") == "Tenant":
                self._adc[k] = copy.deepcopy(v)   # selective: this tenant only
        return {"results": [{"code": 200, "message": "success"}]}

    def delete_tenant(self, tenant):
        self.deleted.append(tenant)
        self._adc.pop(tenant, None)
        return {"results": [{"code": 200, "message": "success"}]}


class FakeHarness:
    """A Harness whose agents return canned typed objects, keyed by role. No LLM calls."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls: list[tuple] = []

    def run(self, role, system, user, schema, **overrides):
        self.calls.append((role, system, user))
        r = self.responses.get(role)
        return r(system, user) if callable(r) else r

    def warmup(self):
        pass  # no registry to warm for the fake


# The live suite's fixtures. Re-exported here because pytest only auto-discovers fixtures from a
# conftest — a fixture defined in an ordinary module is invisible, which is how the first live run
# failed with "fixture 'evidence' not found" despite the helper being imported.
from tests.live import evidence  # noqa: E402,F401


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Stash each phase's report on the item so a fixture teardown can tell a test that RAN from one
    that skipped. Without it the `evidence` vacuity check fired on skipped live tests and turned a
    clean skip into an ERROR — the exact outcome the live suite is required not to produce."""
    outcome = yield
    setattr(item, f"_vpc_rep_{outcome.get_result().when}", outcome.get_result())


@pytest.fixture(autouse=True)
def _no_audit_sink(monkeypatch):
    """J3: the audit sink is configured by environment, and `audit.record` runs in most of this
    suite. A developer or CI box with `VPCOPILOT_AUDIT_SINK` exported would therefore ship the
    suite's ~270 *fabricated* audit records — apply_waf, retire, rollback_failed — to a real
    collector, where they are indistinguishable from records of real changes to a load balancer.
    Measured at 267 datagrams on one full run.

    Documenting "unset it before running the tests" would be a guard that depends on someone
    remembering. This is the structural version, and it also keeps the "no network in tests"
    invariant true regardless of the shell the suite is launched from. Tests that exercise the sink
    set the variable themselves; a test-level `monkeypatch.setenv` runs after this and wins."""
    for var in ("VPCOPILOT_AUDIT_SINK", "VPCOPILOT_AUDIT_SINK_TOKEN"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def _isolated_inventory(tmp_path_factory, monkeypatch):
    """The global live-band-aid inventory (`inventory.py`) defaults to the cwd. In the repo that would
    make every test that applies a band-aid write a shared `./inventory.json` — cross-contaminating
    tests and dirtying the tree. Point it at a fresh per-test temp dir so each test starts with an
    empty inventory. A test that asserts inventory contents sets `VPCOPILOT_INVENTORY_DIR` itself (it
    runs after this autouse fixture and wins), or reads the dir this provides."""
    monkeypatch.setenv("VPCOPILOT_INVENTORY_DIR", str(tmp_path_factory.mktemp("inv")))


@pytest.fixture
def fake_xc():
    return FakeXC()


@pytest.fixture
def fake_bigip():
    """A FakeBigIP pre-seeded with a clean-slate tenant/app (as `bigip-lab create` would leave it),
    so an apply path finds a tenant to attach a band-aid to."""
    from vpcopilot import bigip_lab
    decl = bigip_lab.declaration("vpcopilot_lab", "lab", "10.0.0.5", 8080, "10.0.0.190")["declaration"]
    adc = {k: v for k, v in decl.items() if isinstance(v, dict) and v.get("class") == "Tenant"}
    return FakeBigIP(declaration=adc)


@pytest.fixture
def noop_sleep():
    return lambda *_a, **_k: None


@pytest.fixture(autouse=True)
def _reset_console_scan_state():
    """The console's `_scan` dict is MODULE state shared by every test that posts to /api/scan.

    `POST /api/scan` now claims `state="running"` synchronously, under a lock, before spawning the
    worker — that is what closed the double-scan race. The consequence is that any test which stubs
    `_run_scan` (several do, to avoid running a real pipeline) leaves the flag set, so the next such
    test gets a 409 and fails for a reason that has nothing to do with it. Four tests across four
    files broke exactly this way, every one of them passing in isolation.

    Resetting it here fixes the class rather than the four instances, and keeps the guarantee that a
    test's outcome does not depend on what ran before it.
    """
    yield
    try:
        from vpcopilot.console import app as _console
        _console._scan.update(state="idle", log=[], summary=None, error=None)
    except Exception:  # noqa: BLE001 — the console is optional for most of the suite
        pass
