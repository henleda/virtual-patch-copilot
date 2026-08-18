"""The Nginx SSH transport client — offline, with subprocess.run mocked. The real box is proven in
the Phase-1 spike; here we pin the command construction, the honest `nginx -t` gate, and redaction."""
from __future__ import annotations

import types

import pytest

from vpcopilot import nginx
from vpcopilot.nginx import Nginx, NginxError, configured


def _fake_run(rc=0, out=b"", err=b""):
    """A subprocess.run stand-in that records the calls and returns a fixed result."""
    calls = []

    def run(argv, input=None, capture_output=False, timeout=None):
        calls.append({"argv": argv, "input": input})
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)
    return run, calls


def _client(monkeypatch, **env):
    base = {"NGINX_SSH_HOST": "127.0.0.1", "NGINX_SSH_PORT": "2223", "NGINX_SSH_USER": "ubuntu",
            "NGINX_SSH_KEY": "/k/id.pem"}
    base.update(env)
    for k in ("NGINX_SSH_HOST", "NGINX_SSH_PORT", "NGINX_SSH_USER", "NGINX_SSH_KEY",
              "NGINX_SSH_PASSWORD", "NGINX_RELOAD_CMD", "NGINX_POLICY_DIR", "NGINX_INCLUDE_DIR",
              "NGINX_SSH_STRICT"):
        monkeypatch.delenv(k, raising=False)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    return Nginx()


def test_configured_reflects_the_host_env(monkeypatch):
    monkeypatch.delenv("NGINX_SSH_HOST", raising=False)
    assert configured() is False
    monkeypatch.setenv("NGINX_SSH_HOST", "box")
    assert configured() is True


def test_ssh_argv_carries_port_key_and_target(monkeypatch):
    nx = _client(monkeypatch)
    argv = nx._ssh_argv()
    assert "-p" in argv and "2223" in argv
    assert "-i" in argv and "/k/id.pem" in argv
    assert argv[-1] == "ubuntu@127.0.0.1"
    assert "BatchMode=yes" in argv          # never hang on an interactive prompt


def test_put_file_creates_the_parent_and_writes_the_body(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch)
    nx.put_file("/etc/app_protect/conf/vpcopilot-f1.json", '{"a":1}')
    remote = calls[-1]["argv"][-1]
    assert "mkdir -p /etc/app_protect/conf" in remote          # parent created first
    assert "tee /etc/app_protect/conf/vpcopilot-f1.json >/dev/null" in remote
    assert calls[-1]["input"] == b'{"a":1}'                    # body on stdin


def test_reload_uses_the_configured_command(monkeypatch):
    run, calls = _fake_run()
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch, NGINX_RELOAD_CMD="sudo systemctl reload nginx")
    nx.reload()
    assert calls[-1]["argv"][-1] == "sudo systemctl reload nginx"


def test_test_config_raises_on_a_bad_config(monkeypatch):
    run, _ = _fake_run(rc=1, err=b"nginx: [emerg] unknown directive")
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch)
    with pytest.raises(NginxError, match="nginx -t failed"):
        nx.test_config()


def test_a_transport_failure_is_an_nginx_error_not_a_traceback(monkeypatch):
    def boom(*a, **k):
        raise OSError("no ssh binary")
    monkeypatch.setattr(nginx.subprocess, "run", boom)
    nx = _client(monkeypatch)
    with pytest.raises(NginxError, match="ssh 127.0.0.1:2223"):
        nx.get_config()  # get_config swallows non-zero rc but a transport OSError still raises


def test_a_remote_path_with_a_dotdot_segment_is_refused(monkeypatch):
    """The `..` backstop under nginx_apply's finding-id check — a path that could escape the policy
    dir never reaches a `sudo tee`/`sudo rm` on the box."""
    run, calls = _fake_run()
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch)
    for op in (lambda: nx.put_file("/etc/app_protect/conf/vpcopilot-../../../etc/passwd", "x"),
               lambda: nx.remove_file("/etc/nginx/conf.d/vpcopilot-active/../../nginx.conf"),
               lambda: nx.remove_dir("/etc/nginx/../..")):
        with pytest.raises(NginxError, match="'\\.\\.' segment"):
            op()
    assert calls == []                     # nothing ran on the box


def test_remove_dir_refuses_a_non_vpcopilot_directory(monkeypatch):
    run, _ = _fake_run()
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch)
    with pytest.raises(NginxError, match="non-vpcopilot"):
        nx.remove_dir("/etc/nginx/conf.d")           # not a vpcopilot- dir → never rm -rf'd


def test_get_config_raises_on_a_failed_nginx_T(monkeypatch):
    """`nginx -T` always prints the config, so an empty result means the command FAILED — surfaced as
    an error, not masked as an empty config (which would let a drift check misfire)."""
    run, _ = _fake_run(rc=1, err=b"sudo: a password is required")
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch)
    with pytest.raises(NginxError, match="nginx -T failed"):
        nx.get_config()


def test_ssh_host_key_defaults_to_accept_new_and_is_overridable(monkeypatch):
    nx = _client(monkeypatch)                        # NGINX_SSH_STRICT unset
    argv = " ".join(nx._ssh_argv())
    assert "StrictHostKeyChecking=accept-new" in argv       # TOFU, not blindly 'no'
    assert "UserKnownHostsFile=/dev/null" not in argv       # accept-new pins against real known_hosts
    nx2 = _client(monkeypatch, NGINX_SSH_STRICT="no")
    argv2 = " ".join(nx2._ssh_argv())
    assert "StrictHostKeyChecking=no" in argv2 and "UserKnownHostsFile=/dev/null" in argv2


def test_password_is_redacted_from_errors(monkeypatch):
    run, _ = _fake_run(rc=1, err=b"failed for s3cr3t")
    monkeypatch.setattr(nginx.subprocess, "run", run)
    nx = _client(monkeypatch, NGINX_SSH_PASSWORD="s3cr3t", NGINX_SSH_KEY="")
    with pytest.raises(NginxError) as ei:
        nx._run("whoami")
    assert "s3cr3t" not in str(ei.value) and "REDACTED" in str(ei.value)
