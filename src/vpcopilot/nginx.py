"""NGINX + App Protect transport over SSH — the L2 analogue of `bigip.py`.

Where the BIG-IP client speaks AS3 REST to an appliance, this one runs `nginx -t` and a graceful
reload over SSH on a box that already has App Protect installed. The band-aid is a policy file plus a
copilot-owned managed `include`; a reload is the whole attach.

**Reachability is the operator's problem, deliberately** (`bigip.py`'s stance): `NGINX_SSH_HOST`
points at the near end of whatever tunnel the operator opened — in the reference lab, an SSM
port-forward to the box's SSH. Baking the tunnel in here would tie the tool to one topology and would
tempt someone into opening SSH to the internet instead.

Transport is the stdlib `ssh`/`scp` binaries via `subprocess` — no new dependency, and it inherits
the operator's own SSH agent/known-hosts posture rather than reimplementing a client.
"""
from __future__ import annotations

import os
import shlex
import subprocess


class NginxError(RuntimeError):
    """A transport or `nginx -t` failure — the box unreachable, or refusing a config. Distinct from an
    emit decline (a control with no NAP band-aid), which is a normal answer, not an error."""


def _env(key: str) -> str:
    v = os.environ.get(key)
    if not v:
        raise NginxError(f"{key} not set — add it to .env")
    return v


def configured() -> bool:
    """Whether a box is configured at all — distinct from whether it answers (`bigip.configured`)."""
    return bool((os.environ.get("NGINX_SSH_HOST") or "").strip())


def _guard_path(path: str) -> str:
    """Refuse a remote path with a `..` segment — a backstop under the finding-id validation in
    nginx_apply, so a value that slipped through can never `..`-escape the policy/include dir into a
    root-owned write or delete."""
    if ".." in (path or "").split("/"):
        raise NginxError(f"refusing a remote path with a '..' segment: {path!r}")
    return path


class Nginx:
    def __init__(self, host=None, port=None, user=None, key=None, password=None,
                 reload_cmd=None, policy_dir=None, include_dir=None, timeout=60):
        self.host = host or _env("NGINX_SSH_HOST")
        self.port = str(port or os.environ.get("NGINX_SSH_PORT", "22"))
        self.user = user or os.environ.get("NGINX_SSH_USER", "ubuntu")
        self.key = key or os.environ.get("NGINX_SSH_KEY") or None
        self.password = password or os.environ.get("NGINX_SSH_PASSWORD") or None
        self.reload_cmd = reload_cmd or os.environ.get("NGINX_RELOAD_CMD", "sudo nginx -s reload")
        self.policy_dir = (policy_dir or os.environ.get("NGINX_POLICY_DIR", "/etc/app_protect/conf")).rstrip("/")
        self.include_dir = (include_dir or os.environ.get("NGINX_INCLUDE_DIR", "/etc/nginx/conf.d")).rstrip("/")
        # Host-key policy: TOFU by default (accept-new pins the box's key on first use and ABORTS on a
        # later mismatch — so a MITM on the policy-push / root-command channel is caught, not silently
        # trusted). An operator whose reachability is a rotating tunnel endpoint (e.g. one SSM
        # port-forward reused for different boxes) can set NGINX_SSH_STRICT=no; NGINX_SSH_STRICT=yes
        # requires the key to be pre-known. Never a hardcoded "no".
        self.strict = os.environ.get("NGINX_SSH_STRICT", "accept-new")
        self.timeout = timeout

    def _redact(self, s: str) -> str:
        """Never let an SSH password reach a log/error/traceback (`bigip._redact`)."""
        return s.replace(self.password, "***REDACTED***") if self.password else s

    def _ssh_argv(self) -> list[str]:
        argv = ["ssh", "-p", self.port, "-o", "BatchMode=yes",
                "-o", f"StrictHostKeyChecking={self.strict}", "-o", "LogLevel=ERROR",
                "-o", f"ConnectTimeout={min(self.timeout, 30)}"]
        # Only the explicit "no" mode discards known_hosts; accept-new/yes pin against the operator's
        # real known_hosts so a first-use key is remembered and a later change aborts.
        if self.strict == "no":
            argv += ["-o", "UserKnownHostsFile=/dev/null"]
        if self.key:
            argv += ["-i", self.key]
        argv.append(f"{self.user}@{self.host}")
        return argv

    def _run(self, remote_cmd: str, *, stdin: bytes | None = None, check: bool = True):
        """Run one command on the box; returns (stdout, stderr, rc). Raises NginxError on a transport
        failure, or on a non-zero rc when `check`."""
        argv = self._ssh_argv() + [remote_cmd]
        try:
            p = subprocess.run(argv, input=stdin, capture_output=True, timeout=self.timeout + 60)
        except (subprocess.TimeoutExpired, OSError) as e:
            raise NginxError(self._redact(f"ssh {self.host}:{self.port} -> {type(e).__name__}: {e}")) from None
        out, err = p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
        if check and p.returncode != 0:
            raise NginxError(self._redact(
                f"remote command failed (rc={p.returncode}): {(err or out).strip()[:400]}"))
        return out, err, p.returncode

    # ---------------------------------------------------------------- reads

    def reachable(self) -> bool:
        """Does the box answer at all — the 'is it up' read, distinct from 'is one configured'."""
        try:
            self._run("true")
            return True
        except NginxError:
            return False

    def version(self) -> str:
        """`nginx -v` — the cheapest proof NGINX is installed and answering."""
        out, err, _ = self._run("nginx -v", check=False)
        return (err or out).strip()

    def get_config(self) -> str:
        """`nginx -T` — the full expanded config, the snapshot every mutation is compared against
        (the `BigIP.get_declaration` analogue). Raises on a non-zero rc rather than returning `""`:
        `nginx -T` always prints the config, so an empty result means the command FAILED (e.g. sudo
        wanted a password) — masking that as 'empty config' would let a drift check silently misfire."""
        out, err, rc = self._run("sudo nginx -T", check=False)
        if rc != 0:
            raise NginxError(f"nginx -T failed (rc={rc}): {(err or out).strip()[:400]}")
        return out

    def read_file(self, path: str) -> str | None:
        """The file's content, or None if it does not exist — used to preserve an existing vhost
        across a dry-run (`nginx_lab.create`)."""
        _guard_path(path)
        out, _, rc = self._run(f"sudo cat {shlex.quote(path)} 2>/dev/null", check=False)
        return out if rc == 0 else None

    # ---------------------------------------------------------------- writes

    def put_file(self, path: str, content: str) -> None:
        """Write a file on the box (the policy/include dirs need sudo). `tee` rather than scp so one
        SSH invocation both creates the parent and writes the body."""
        _guard_path(path)
        self._run(f"sudo mkdir -p {shlex.quote(os.path.dirname(path))} && "
                  f"sudo tee {shlex.quote(path)} >/dev/null", stdin=content.encode())

    def remove_file(self, path: str) -> None:
        """Idempotent remove of ONE file — an absent file is a no-op (so a detach a prior pass already
        did is harmless)."""
        _guard_path(path)
        self._run(f"sudo rm -f {shlex.quote(path)}")

    def remove_dir(self, path: str) -> None:
        """Recursively remove a copilot-owned directory. Guarded twice — no `..` segment, and the
        basename must be a `vpcopilot-` dir — so a bad path can never `rm -rf` an operator's tree."""
        _guard_path(path)
        if not os.path.basename(path).startswith("vpcopilot-"):
            raise NginxError(f"refusing to recursively remove a non-vpcopilot directory: {path!r}")
        self._run(f"sudo rm -rf {shlex.quote(path)}")

    def ensure_dir(self, path: str) -> None:
        """`mkdir -p` — used for the copilot-owned managed-include dir, whose empty state is the lab's
        clean slate (nginx tolerates a glob `include` that matches nothing)."""
        _guard_path(path)
        self._run(f"sudo mkdir -p {shlex.quote(path)}")

    def test_config(self) -> str:
        """`nginx -t` — the honest failure gate (`BigIP._checked` analogue): never reload a config the
        box itself rejects. Raises NginxError with the box's own message on a bad config."""
        out, err, rc = self._run("sudo nginx -t", check=False)
        if rc != 0:
            raise NginxError(f"nginx -t failed: {(err or out).strip()[:500]}")
        return (out or err).strip()

    def reload(self) -> None:
        """Graceful reload via `NGINX_RELOAD_CMD`. `nginx -T`/`-t` prove the config *references* the
        policy; only the live exploit probe proves the enforcer actually loaded it — see
        docs/design/nginx-app-protect-apply.md §5."""
        self._run(self.reload_cmd)
