"""J3 — optional off-box sink for the audit trail.

`audit.log` is written by the same process that makes the change, to a local file, so anyone who
can write the out dir can edit it (`docs/AUDIT.md`, honest limits). Shipping each entry to a
collector as it is written is the cheap half of the answer: the copy leaves the box immediately,
so altering the local log afterwards no longer alters the only record.

Three transports, chosen by the scheme of one variable, `VPCOPILOT_AUDIT_SINK`:

    https://collector.example.com/ingest   POST the entry as the request body
    syslog://10.0.0.9:514                  RFC 3164 datagram over UDP
    syslog:///var/run/syslog               …or to a local unix datagram socket
    stdout                                 one JSON line on stdout, for a log-scraping runtime
    off                                    deliberately disabled (distinct from never configured)

Four properties are the whole point, and each is pinned by a test:

- **The local log stays authoritative.** The line is written to disk *first* and the sink is handed
  the exact same string, so the two cannot disagree about what happened. If the local write fails,
  nothing is delivered — an off-box event with no local counterpart would be unreconcilable.
- **It never fails the run it observes.** Every path returns a status string; nothing raises. A
  sink hangs off `audit.record`, which is called on the rollback-failed path, so a sink that could
  raise would turn "the LB may be left changed" into an unrecorded event.
- **A dead collector costs one warning and one timeout, not one per entry.** After a failure the
  sink goes quiet for `COOLDOWN_S` rather than paying the timeout again on the next record — an
  apply writes several entries and a hung collector would otherwise stall it for their sum.
- **Misconfigured never renders as clean.** An unparseable value is reported as invalid and warns;
  it is not silently equivalent to having no sink at all.

Deliberately NOT here: a delivery record written back into `audit.log`. The sink lives inside
`audit.record`, so recording its own outcome would recurse, and an entry-count-changing side effect
is the bug J4's no-op check exists to prevent. Delivery outcome is reported by `vpcopilot
audit-sink` and `GET /api/audit-sink` instead.
"""
from __future__ import annotations

import errno
import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

from . import __version__, runmeta

SINK_ENV = "VPCOPILOT_AUDIT_SINK"
TOKEN_ENV = "VPCOPILOT_AUDIT_SINK_TOKEN"

TIMEOUT_S = 5           # an audit sink sits on the critical path of an apply, unlike reconcile's
COOLDOWN_S = 60.0       # escalation webhook (10s) which runs at the end of a pass
SYSLOG_PORT = 514
SYSLOG_PRI = 134        # local0.info — facility 16 * 8 + severity 6

# Injected rather than called directly, so tests can drive the cooldown without sleeping (the
# house convention for clocks — cf. reconcile's `now`/`sleep` parameters).
_now = time.monotonic
_localtime = time.localtime

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_state: dict = {"attempted": 0, "delivered": 0, "failed": 0, "suppressed": 0,
                "last_error": "", "warned": False, "quiet_until": 0.0}
# The console runs each apply on its own daemon thread and they share this module, so the counters
# are read-modify-written concurrently. Only the bookkeeping is guarded — never the socket call, or
# one hung collector would serialize every other thread's audit write behind it. (`ledger._LOCK` is
# the in-repo precedent for a threading lock around shared state.)
_LOCK = threading.Lock()


def reset_state() -> None:
    """Forget delivery counters and the one-warning latch. For tests only — a surface that wanted
    a fresh answer used to call this, which silently destroyed a long-lived console's record of
    earlier failures."""
    with _LOCK:
        _state.update(attempted=0, delivered=0, failed=0, suppressed=0,
                      last_error="", warned=False, quiet_until=0.0)


def _claim_warning() -> bool:
    """Check-and-set under the lock, so "log one warning" stays one warning when two console
    threads fail at the same moment."""
    with _LOCK:
        if _state["warned"]:
            return False
        _state["warned"] = True
        return True


def _warn(msg: str) -> None:
    """One line to stderr — never stdout.

    `audit.record` takes no log callable and adding one would land it in `**detail` and be
    serialized into the entry. stderr is the only stream that is unconditionally safe: the MCP
    server repoints `sys.stdout` at stderr for its lifetime, but a warning that *relies* on that
    swap would corrupt the protocol stream anywhere the swap is not in force."""
    try:
        sys.stderr.write(msg + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001 — a closed stderr must not break an audit write
        pass


def redact(target: str, kind: str | None) -> str:
    """What a surface may print. A webhook URL routinely carries the credential in its *path*
    (Slack, Teams, a Splunk HEC token), so only the origin is ever shown — the same reason
    `reconcile.notify` logs `type(e).__name__` and never `str(e)`.

    Rebuilt from `hostname`/`port`, deliberately NOT from `netloc`: `urlsplit` puts userinfo in
    netloc, so `https://user:pass@host/x` would otherwise print the password on the CLI panel, the
    Setup page and the API response."""
    if kind in ("http", "https"):
        u = urlsplit(target)
        host = u.hostname or ""
        try:
            port = f":{u.port}" if u.port else ""
        except ValueError:
            port = ""
        auth = "…@" if (u.username or u.password) else ""
        tail = "/…" if (u.path.strip("/") or u.query) else ""
        return f"{u.scheme}://{auth}{host}{port}{tail}"
    return target


def configure() -> dict:
    """Read the sink configuration from the environment, every time.

    Deliberately not cached: `POST /api/config` writes `.env` and reloads it into `os.environ` in
    the running console, so a module-level constant would leave the Setup page lying until relaunch.

    Returns `{configured, kind, target, redacted, reason}`. `kind` is None when nothing usable was
    configured; `reason` says which of the three cases that is — unset, deliberately `off`, or a
    value that could not be parsed."""
    raw = (os.environ.get(SINK_ENV) or "").strip()
    if not raw:
        return {"configured": False, "kind": None, "target": "", "redacted": "",
                "reason": "no sink configured"}
    if raw.lower() in ("off", "none", "disabled"):
        # A value, not an empty box: the console's .env writer drops falsy updates, so clearing the
        # field cannot unset a key. Without an explicit off, a sink turned on from the Setup page
        # could never be turned off from it.
        return {"configured": False, "kind": None, "target": "", "redacted": "",
                "reason": "explicitly disabled"}
    if raw.lower() in ("stdout", "stdout:", "stdout://"):
        return {"configured": True, "kind": "stdout", "target": "stdout", "redacted": "stdout",
                "reason": ""}

    try:
        u = urlsplit(raw)
    except ValueError as e:
        # `urlsplit` RAISES on some malformed values — a dropped bracket in an IPv6 host
        # (`https://[2001:db8::1/x`), a netloc that fails NFKC validation. Unguarded, that
        # propagated out of `status()` into a CLI traceback and a console 500, while `emit`'s bare
        # except swallowed it with no warning at all: the one input shape that produced *silence*
        # on the apply path was the shape this module exists to make loud.
        return {"configured": True, "kind": None, "target": raw, "redacted": "(unparseable)",
                "reason": f"sink value could not be parsed as a URL ({e})"}
    scheme = u.scheme.lower()
    if scheme in ("http", "https"):
        if not u.netloc:
            return {"configured": True, "kind": None, "target": raw, "redacted": f"{scheme}://…",
                    "reason": f"{scheme} sink has no host"}
        return {"configured": True, "kind": scheme, "target": raw,
                "redacted": redact(raw, scheme), "reason": ""}
    if scheme == "syslog":
        if u.netloc:
            host = u.hostname or ""
            if not host:
                return {"configured": True, "kind": None, "target": raw, "redacted": raw,
                        "reason": "syslog sink has no host"}
            try:
                port = u.port or SYSLOG_PORT
            except ValueError:
                return {"configured": True, "kind": None, "target": raw, "redacted": raw,
                        "reason": "syslog sink has an invalid port"}
            return {"configured": True, "kind": "syslog-udp", "target": raw,
                    "redacted": f"syslog://{host}:{port}", "reason": "",
                    "host": host, "port": port}
        if u.path:
            return {"configured": True, "kind": "syslog-unix", "target": raw,
                    "redacted": f"syslog://{u.path}", "reason": "", "path": u.path}
        return {"configured": True, "kind": None, "target": raw, "redacted": raw,
                "reason": "syslog sink names neither a host nor a socket path"}

    got = scheme or "no scheme"
    return {"configured": True, "kind": None, "target": raw, "redacted": raw.split("://")[0][:40],
            "reason": f"unsupported sink ({got}) — expected https://, http://, syslog://, stdout or off"}


# ---------------------------------------------------------------- transports


def _syslog_frame(payload: str, *, pid: int) -> bytes:
    """RFC 3164: `<PRI>MMM DD HH:MM:SS HOSTNAME TAG[pid]: MSG`, day space-padded.

    The header timestamp is local time because the RFC says so; it is the *transport's* clock. The
    authoritative one is `ts` inside the JSON, which is UTC — stated here because a reader
    comparing the two will otherwise think one of them is wrong."""
    t = _localtime()
    stamp = f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    # Whitespace of any kind would split the header into the wrong fields; a receiver would then
    # read part of the hostname as the tag. `json.dumps` already escapes newlines inside `payload`,
    # so the message itself is structurally single-line.
    host = "".join(c for c in (runmeta.host() or "-").split(".")[0] if not c.isspace())[:255] or "-"
    return f"<{SYSLOG_PRI}>{stamp} {host} vpcopilot[{pid}]: {payload}".encode("utf-8", "replace")


def _oversize_envelope(entry: dict, size: int) -> str:
    """What goes out when the full entry will not fit in one datagram.

    Measured: a macOS `/var/run/syslog` unix socket has `SO_SNDBUF` 2048 and refuses anything
    larger with EMSGSIZE; UDP walls at ~9216. The entries that overflow are the *interesting* ones
    — a `drift_detected` carries a full field-level diff — so dropping them would lose exactly the
    records worth shipping, and silence would be indistinguishable from a quiet day. This is a
    valid JSON object that says an entry happened, identifies it, and says it did not fit."""
    def _short(v):
        # The envelope exists because the entry did not fit, so it must not be able to overflow in
        # turn: every field it borrows from the entry is bounded.
        return v if not isinstance(v, str) else v[:120]

    return json.dumps({
        "ts": _short(entry.get("ts")), "action": _short(entry.get("action")),
        "run_id": _short(entry.get("run_id")), "actor": _short(entry.get("actor")),
        "host": _short(entry.get("host")), "tool_version": _short(entry.get("tool_version")),
        "finding_id": _short(entry.get("finding_id")), "lb": _short(entry.get("lb")),
        "audit_sink_oversize": True, "bytes": size,
        "note": "entry too large for one syslog datagram — the full record is in the run's audit.log",
    })


def _send_syslog(cfg: dict, line: str, entry: dict) -> None:
    """One datagram, with a second attempt carrying the reduced envelope on EMSGSIZE.

    The limit is never hardcoded: it differs by platform (2048 on a macOS unix socket, far larger
    on a Linux `/dev/log`) and by socket buffer, so the kernel is asked rather than guessed — it
    answers by refusing the write, which is the one signal that is right everywhere."""
    unix = cfg["kind"] == "syslog-unix"
    if unix:
        fam, dest = socket.AF_UNIX, cfg["path"]
    else:
        # Resolved rather than assumed AF_INET: a `syslog://[fe80::1]:514` collector is perfectly
        # legal and an AF_INET socket cannot reach it at all — the sink would read as configured
        # and deliver nothing, for ever.
        fam, _, _, _, dest = socket.getaddrinfo(
            cfg["host"], cfg["port"], type=socket.SOCK_DGRAM)[0]
    pid = os.getpid()
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.settimeout(TIMEOUT_S)
        frame = _syslog_frame(line, pid=pid)
        try:
            s.sendto(frame, dest)
        except OSError as e:
            if e.errno != errno.EMSGSIZE:
                raise
            s.sendto(_syslog_frame(_oversize_envelope(entry, len(line.encode())), pid=pid), dest)
    finally:
        s.close()


def _send_http(cfg: dict, line: str) -> None:
    # Function-local, matching `reconcile.notify` — the tests monkeypatch `httpx.Client`, which
    # only works while the attribute is resolved at call time.
    import httpx
    headers = {"content-type": "application/json"}
    token = (os.environ.get(TOKEN_ENV) or "").strip()
    if token:
        headers["authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=TIMEOUT_S) as c:
        # `content=` sends the exact bytes that were appended to audit.log. Re-encoding the parsed
        # dict would let key order or float formatting drift between the two copies.
        r = c.post(cfg["target"], content=line.encode(), headers=headers)
    if 300 <= r.status_code < 400:
        # httpx does not follow redirects by default, so the body was never re-sent — treating a
        # 3xx as success meant a moved ingest path (or a proxy bouncing to an SSO page) swallowed
        # the entire audit stream while every surface read "delivered N/N".
        #
        # Refused rather than followed, deliberately: this request carries the bearer token, and
        # chasing a Location to a host the operator did not configure is how a credential ends up
        # somewhere it was never meant to go. Point the sink at the final URL instead.
        raise OSError(f"HTTP {r.status_code} redirect — point the sink at the final URL")
    if r.status_code >= 400:
        raise OSError(f"HTTP {r.status_code}")


def _send_stdout(line: str) -> None:
    """`sys.stdout` is resolved here, not bound at import, so the MCP server's stdout swap applies
    and a scraped-stdout sink cannot corrupt the protocol stream."""
    out = sys.stdout
    if out is None:
        raise OSError("no stdout")
    out.write(line + "\n")
    out.flush()


# ---------------------------------------------------------------- the hook


def emit(line: str, entry: dict, *, force: bool = False) -> str:
    """Deliver one already-written audit line. Returns a status; never raises.

    `skipped` no sink · `invalid` configured but unusable · `suppressed` inside the post-failure
    cooldown · `sent` · `sent-unconfirmed` (UDP, which cannot answer) · `failed`.

    `force` bypasses the cooldown and is used only by `check(send=True)`: an operator asking
    "is it working now" must not be answered with a suppression from a minute ago."""
    try:
        cfg = configure()
    except Exception:  # noqa: BLE001 — configuration parsing must not break an audit write either
        return "invalid"
    if not cfg["configured"]:
        return "skipped"
    if cfg["kind"] is None:
        with _LOCK:
            _state["last_error"] = cfg["reason"]
        if _claim_warning():
            _warn(f"⚠ audit sink not usable: {cfg['reason']} — nothing is being shipped off-box; "
                  f"the local audit.log is unaffected (check it with `vpcopilot audit-sink`)")
        return "invalid"

    now = _now()
    with _LOCK:
        if not force and now < _state["quiet_until"]:
            _state["suppressed"] += 1
            return "suppressed"
        _state["attempted"] += 1

    try:
        if cfg["kind"] == "stdout":
            _send_stdout(line)
        elif cfg["kind"] in ("http", "https"):
            _send_http(cfg, line)
        else:
            _send_syslog(cfg, line, entry)
    except Exception as e:  # noqa: BLE001 — every transport failure is the same answer
        with _LOCK:
            _state["failed"] += 1
            # Never `str(e)`: an httpx error message can carry the URL, and a URL can carry a token.
            _state["last_error"] = type(e).__name__
            _state["quiet_until"] = now + COOLDOWN_S
        if _claim_warning():
            _warn(f"⚠ audit sink delivery failed ({type(e).__name__}) — the entry is still in the "
                  f"run's audit.log, which is authoritative; further failures are counted silently "
                  f"(see `vpcopilot audit-sink`)")
        return "failed"
    with _LOCK:
        _state["delivered"] += 1
        if force:
            # A test event that landed is proof the collector is back, so stop suppressing.
            _state["quiet_until"] = 0.0
    # UDP is fire-and-forget: a datagram to a port with nothing bound succeeds at the send call, so
    # "sent" here means "handed to the kernel", not "delivered". Saying plainly that it could not be
    # confirmed is the J2 `present-unverified` precedent — reporting "I cannot check this" the same
    # way as "this worked" would destroy the distinction that matters most. The unix-socket and HTTP
    # transports do get an answer from the other end, so they report `sent` unqualified.
    return "sent-unconfirmed" if cfg["kind"] == "syslog-udp" else "sent"


def status() -> dict:
    """Configuration plus what this process has actually delivered. The counters are per-process:
    a one-shot CLI run reports its own apply, while a long-lived console or MCP session accumulates.
    A CLI run that failed said so on stderr; there is nowhere else for it to have been recorded."""
    cfg = configure()
    return {
        "configured": cfg["configured"], "kind": cfg["kind"], "target": cfg["redacted"],
        "usable": bool(cfg["configured"] and cfg["kind"]), "reason": cfg["reason"],
        "token_set": bool((os.environ.get(TOKEN_ENV) or "").strip()),
        "attempted": _state["attempted"], "delivered": _state["delivered"],
        "failed": _state["failed"], "suppressed": _state["suppressed"],
        "last_error": _state["last_error"],
    }


def test_payload() -> str:
    """A test event is deliberately NOT shaped like an audit entry: it carries `kind` where a real
    entry carries `action`, so a collector alerting on actions cannot be tripped by a connectivity
    check, and it says in-band that it is not evidence of anything."""
    return json.dumps({
        "kind": "vpcopilot-audit-sink-test", "ts": runmeta.utc_now(),
        "actor": runmeta.actor(), "host": runmeta.host(), "tool_version": __version__,
        "note": "connectivity test from `vpcopilot audit-sink --send` — not an audit record, "
                "and not written to any audit.log",
    })


def check(*, send: bool = False) -> dict:
    """Answer "is the sink configured, is it usable, and does a delivery land" without touching a
    run directory. Read-only with respect to the audit trail: the test event is never written to
    `audit.log`, so asking the question does not add to the evidence."""
    st = status()
    if not send or not st["usable"]:
        st["delivery"] = "not attempted" if st["usable"] else "not attempted (no usable sink)"
        return st
    payload = test_payload()
    # `force`, deliberately not `reset_state()`: clearing the counters would destroy a long-lived
    # console's record of earlier failures as a side effect of asking whether the sink works now.
    outcome = emit(payload, json.loads(payload), force=True)
    st = status()
    st["delivery"] = outcome
    return st
