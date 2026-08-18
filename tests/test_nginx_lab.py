"""nginx_lab — the guard + the copilot vhost. Offline, with a fake Nginx client."""
from __future__ import annotations

import pytest

from vpcopilot import audit
from vpcopilot.nginx_lab import LabRefused, create, guard_site, remove, status, validate_site


class FakeNginx:
    def __init__(self, cfg=""):
        self.files: dict[str, str] = {}
        self.dirs: set[str] = set()
        self.reloads = 0
        self.tests = 0
        self._cfg = cfg
        self.include_dir = "/etc/nginx/conf.d"
        self.policy_dir = "/etc/app_protect/conf"

    def put_file(self, path, content):
        self.files[path] = content

    def remove_file(self, path):
        self.files.pop(path, None)

    def ensure_dir(self, path):
        self.dirs.add(path)

    def test_config(self):
        self.tests += 1
        return "ok"

    def reload(self):
        self.reloads += 1

    def get_config(self):
        return self._cfg

    def reachable(self):
        return True

    def version(self):
        return "nginx/1.29.8 (nginx-plus-r37.0.4)"


# ---------------------------------------------------------------- the guard

def test_the_catch_all_server_is_refused_unconditionally():
    """`_` fronts every request — the /Common analogue — so even an override cannot touch it."""
    for kw in ({"allow_protected": True, "dry_run": False}, {"allow_protected": False, "dry_run": True}):
        with pytest.raises(LabRefused, match="catch-all"):
            guard_site("_", **kw)


def test_a_protected_site_is_refused_but_overridable(monkeypatch):
    monkeypatch.setenv("VPCOPILOT_PROTECTED_NGINX_SITES", "prod.example.com")
    with pytest.raises(LabRefused, match="protected server"):
        guard_site("prod.example.com", allow_protected=False, dry_run=False)
    guard_site("prod.example.com", allow_protected=True, dry_run=False)   # override works
    guard_site("vpcopilot.lab", allow_protected=False, dry_run=False)     # an unprotected name is fine


@pytest.mark.parametrize("bad", ["", "  vpcopilot.lab", "a/b", "has space"])
def test_a_name_with_whitespace_or_a_slash_is_refused_not_normalised(bad):
    with pytest.raises(LabRefused):
        validate_site(bad)


# ---------------------------------------------------------------- create / remove

def test_create_writes_the_vhost_ensures_the_managed_dir_and_reloads(tmp_path):
    nx = FakeNginx()
    r = create("vpcopilot.lab", "10.30.10.22:8080", out_dir=str(tmp_path), client=nx)
    assert r["audited"] is True
    vhost = nx.files["/etc/nginx/conf.d/vpcopilot-vpcopilot.lab.conf"]
    assert "server_name vpcopilot.lab;" in vhost
    assert "include /etc/nginx/conf.d/vpcopilot-active/*.conf;" in vhost   # the managed glob
    assert "proxy_pass http://vpcopilot_origin;" in vhost
    assert "/etc/nginx/conf.d/vpcopilot-active" in nx.dirs                 # empty = clean slate
    assert nx.tests >= 1 and nx.reloads == 1
    assert any(a["action"] == "nginx_lab_create" for a in audit.load(str(tmp_path)))


def test_create_dry_run_stages_and_rolls_back_without_auditing(tmp_path):
    nx = FakeNginx()
    r = create("vpcopilot.lab", "10.30.10.22:8080", dry_run=True, out_dir=str(tmp_path), client=nx)
    assert r["dry_run"] is True and r["ok"] is True and r["audited"] is False
    assert nx.files == {}                 # staged vhost was rolled back
    assert nx.reloads == 0                # nothing reloaded
    assert audit.load(str(tmp_path)) == []


def test_remove_drops_only_the_copilot_vhost_and_reloads(tmp_path):
    nx = FakeNginx()
    nx.files["/etc/nginx/conf.d/vpcopilot-vpcopilot.lab.conf"] = "server {}"
    nx.files["/etc/nginx/conf.d/user-own.conf"] = "server {}"
    r = remove("vpcopilot.lab", out_dir=str(tmp_path), client=nx)
    assert r["removed"] is True and nx.reloads == 1
    assert "/etc/nginx/conf.d/user-own.conf" in nx.files      # untouched
    assert "/etc/nginx/conf.d/vpcopilot-vpcopilot.lab.conf" not in nx.files


def test_status_reports_app_protect_from_the_config(monkeypatch):
    monkeypatch.setenv("NGINX_SSH_HOST", "127.0.0.1")
    nx = FakeNginx(cfg="load_module modules/ngx_http_app_protect_module.so;")
    s = status(client=nx)
    assert s["configured"] and s["reachable"] and s["app_protect"] is True


def test_status_without_a_host_is_configured_false(monkeypatch):
    monkeypatch.delenv("NGINX_SSH_HOST", raising=False)
    s = status(client=FakeNginx())
    assert s["configured"] is False and "NGINX_SSH_HOST" in s["reason"]
