from vpcopilot.lab import _clean_slate, _origin_server


def test_origin_server_ip_vs_dns():
    assert _origin_server("16.59.6.127") == {"public_ip": {"ip": "16.59.6.127"}, "labels": {}}
    assert _origin_server("app.example.com") == {"public_name": {"dns_name": "app.example.com"}, "labels": {}}


def test_clean_slate_disables_all_controls_and_strips_status():
    spec = {"app_firewall": {"x": 1}, "active_service_policies": {"p": []}, "bot_defense": {},
            "rate_limit": {}, "enable_malicious_user_detection": {}, "api_specification": {},
            "api_definition": {}, "data_guard_rules": [{"r": 1}], "host_name": "z", "cert_state": "x",
            "more_option": {"request_headers_to_add": [{"name": "X-Nimbus-Origin"}]}}
    _clean_slate(spec)
    for on, off in [("app_firewall", "disable_waf"), ("bot_defense", "disable_bot_defense"),
                    ("rate_limit", "disable_rate_limit"),
                    ("enable_malicious_user_detection", "disable_malicious_user_detection")]:
        assert on not in spec and spec[off] == {}
    assert "active_service_policies" not in spec and spec["no_service_policies"] == {}
    assert spec["disable_api_definition"] == {} and "api_specification" not in spec
    assert spec["data_guard_rules"] == []
    assert "host_name" not in spec and "cert_state" not in spec
    assert not spec["more_option"].get("request_headers_to_add")


# ================= the lab templates are configuration, not constants =================
class _FakeXC:
    """Records which objects were READ as templates, and what was created from them.

    `create_lab` re-reads the LB it just created to pull the DNS records out, so `read` holds the
    two TEMPLATE reads first and the readback after — assertions look at `read[:2]`."""
    ns = "test-ns"

    def __init__(self, have=("nimbus-bigip-pool", "nimbus-www", "mine-pool", "mine-lb")):
        self.have = set(have)
        self.read: list[str] = []
        self.created: list[str] = []

    def _get(self, name):
        self.read.append(name)
        if name not in self.have:
            raise RuntimeError(f"GET {name} -> 404")
        return {"spec": {"origin_servers": [], "port": 80, "domains": ["x"], "loadbalancer_type": {}}}

    get_origin_pool = _get
    get_lb = _get

    def origin_pool_exists(self, n):
        return False

    def lb_exists(self, n):
        return False

    def create_origin_pool(self, obj):
        self.created.append(obj["metadata"]["name"])

    def create_lb(self, obj):
        self.created.append(obj["metadata"]["name"])
        self.have.add(obj["metadata"]["name"])      # it exists now, and gets read back
        return obj


def _run(monkeypatch, fake, **kw):
    from vpcopilot import lab
    monkeypatch.setattr(lab, "XC", lambda *a, **k: fake)
    return lab.create_lab("app.example.com", "10.0.0.1:8080", poll=False,
                          log=lambda m: None, **kw)


def test_the_defaults_are_unchanged_so_this_tenant_behaves_identically(monkeypatch):
    """No regression. The two names moved into config; they did not change value, so an existing
    `lab-create` on this operator's tenant clones exactly what it always did."""
    from vpcopilot import lab
    for var in (lab.POOL_TEMPLATE_ENV, lab.LB_TEMPLATE_ENV):
        monkeypatch.delenv(var, raising=False)
    assert lab.pool_template_default() == "nimbus-bigip-pool"
    assert lab.lb_template_default() == "nimbus-www"

    fake = _FakeXC()
    _run(monkeypatch, fake)
    assert fake.read[:2] == ["nimbus-bigip-pool", "nimbus-www"]


def test_the_environment_can_point_the_lab_at_another_tenants_objects(monkeypatch):
    """The actual coupling cost this fixes: `lab-create` only worked on a tenant that happened to
    contain objects named `nimbus-bigip-pool` and `nimbus-www`."""
    from vpcopilot import lab
    monkeypatch.setenv(lab.POOL_TEMPLATE_ENV, "mine-pool")
    monkeypatch.setenv(lab.LB_TEMPLATE_ENV, "mine-lb")
    fake = _FakeXC()
    _run(monkeypatch, fake)
    assert fake.read[:2] == ["mine-pool", "mine-lb"]


def test_an_explicit_argument_beats_the_environment(monkeypatch):
    from vpcopilot import lab
    monkeypatch.setenv(lab.POOL_TEMPLATE_ENV, "env-pool")
    monkeypatch.setenv(lab.LB_TEMPLATE_ENV, "env-lb")
    fake = _FakeXC(have=("mine-pool", "mine-lb"))
    _run(monkeypatch, fake, pool_template="mine-pool", lb_template="mine-lb")
    assert fake.read[:2] == ["mine-pool", "mine-lb"]


def test_an_empty_environment_value_falls_back_rather_than_asking_for_an_object_named_nothing(monkeypatch):
    from vpcopilot import lab
    monkeypatch.setenv(lab.POOL_TEMPLATE_ENV, "   ")
    monkeypatch.setenv(lab.LB_TEMPLATE_ENV, "")
    assert lab.pool_template_default() == "nimbus-bigip-pool"
    assert lab.lb_template_default() == "nimbus-www"


def test_a_missing_template_names_the_remedy_instead_of_surfacing_a_404(monkeypatch):
    """This is the first failure any other tenant hits, so it has to say what to set."""
    import pytest

    from vpcopilot import lab
    monkeypatch.setenv(lab.POOL_TEMPLATE_ENV, "not-here")
    fake = _FakeXC()
    with pytest.raises(RuntimeError) as e:
        _run(monkeypatch, fake)
    msg = str(e.value)
    assert "not-here" in msg
    assert "--pool-template" in msg and lab.POOL_TEMPLATE_ENV in msg
    assert "clone" in msg                       # says WHY a template is needed at all


def test_the_templates_are_only_ever_read_never_written(monkeypatch):
    """`nimbus-www` is simultaneously the default template here and the default PROTECTED object in
    `engine.protected_lbs()`. That is safe only because the template is read, deep-copied, and the
    copy is what gets created."""
    fake = _FakeXC()
    _run(monkeypatch, fake)
    assert fake.read[:2] == ["nimbus-bigip-pool", "nimbus-www"]
    assert "nimbus-www" not in fake.created and "nimbus-bigip-pool" not in fake.created
    assert fake.created == ["app-pool", "app-lab"]


def test_the_cli_exposes_both_templates(monkeypatch):
    """They existed on the module function but no flag reached them, so from the command line they
    were effectively hardcoded."""
    import inspect

    from vpcopilot import cli
    params = inspect.signature(cli.lab_create).parameters
    assert "pool_template" in params and "lb_template" in params
    src = inspect.getsource(cli.lab_create)
    assert "--pool-template" in src and "--lb-template" in src
    assert "pool_template=pool_template" in src and "lb_template=lb_template" in src
