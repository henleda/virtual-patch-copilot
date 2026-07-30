"""J3 — the off-box audit event sink.

Offline throughout: every transport is faked. The syslog tests speak to a real socket object but
one this file owns, so nothing leaves the process, and the HTTP tests monkeypatch `httpx.Client`
the way `test_reconcile.py` does — which works only because `audit_sink` imports httpx inside the
function that uses it.

The class of bug this file exists to pin is one shape: a sink that is configured and silently not
delivering, rendering exactly like a box with no sink at all."""
from __future__ import annotations

import errno
import json
import socket

import pytest

from vpcopilot import audit, audit_sink


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No global env isolation exists in conftest, so a developer with the variable exported in
    their shell would otherwise run the whole suite against their own collector."""
    monkeypatch.delenv(audit_sink.SINK_ENV, raising=False)
    monkeypatch.delenv(audit_sink.TOKEN_ENV, raising=False)
    audit_sink.reset_state()
    yield
    audit_sink.reset_state()


def _fake_httpx(monkeypatch, *, status=200, boom=None):
    sent = {}

    class C:
        def __init__(self, **kw):
            sent["timeout"] = kw.get("timeout")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, content=None, headers=None):
            if boom:
                raise boom
            sent.update(url=url, content=content, headers=headers)
            return type("R", (), {"status_code": status})()

    import httpx
    if boom and not isinstance(boom, Exception):
        monkeypatch.setattr(httpx, "Client", boom)
    else:
        monkeypatch.setattr(httpx, "Client", C)
    return sent


# ---------------------------------------------------------------- configuration


@pytest.mark.parametrize("raw,kind,reason_bit", [
    ("https://c.test/ingest", "https", ""),
    ("http://c.test/ingest", "http", ""),
    ("syslog://10.0.0.9:514", "syslog-udp", ""),
    ("syslog://10.0.0.9", "syslog-udp", ""),
    ("syslog:///var/run/syslog", "syslog-unix", ""),
    ("stdout", "stdout", ""),
    ("STDOUT", "stdout", ""),
    ("  https://c.test/x  ", "https", ""),
])
def test_every_documented_sink_spelling_parses(monkeypatch, raw, kind, reason_bit):
    monkeypatch.setenv(audit_sink.SINK_ENV, raw)
    cfg = audit_sink.configure()
    assert cfg["configured"] and cfg["kind"] == kind


@pytest.mark.parametrize("raw", ["ftp://c.test", "wat", "https://", "syslog://", "syslog://:notaport"])
def test_an_unparseable_sink_is_invalid_not_absent(monkeypatch, raw):
    """The distinction the whole feature turns on: "we are not shipping anything" must not read the
    same as "nothing is configured". An invalid value is `configured` with no usable kind."""
    monkeypatch.setenv(audit_sink.SINK_ENV, raw)
    cfg = audit_sink.configure()
    assert cfg["configured"] is True and cfg["kind"] is None and cfg["reason"]


@pytest.mark.parametrize("raw", [
    "https://[2001:db8::5:8088/ingest",   # dropped bracket — the typo the IPv6 syntax invites
    "syslog://[fe80::1",
    "https://ho℀st/x",               # netloc that fails NFKC validation
])
def test_a_url_that_urlsplit_itself_rejects_is_reported_not_raised(tmp_path, monkeypatch, capsys, raw):
    """Found by adversarial review. `urlsplit` RAISES on these, and unguarded that propagated out of
    status() into a CLI traceback and a console 500 — while emit's bare except swallowed it with no
    warning at all. The one input shape that produced silence on the apply path was the shape this
    module exists to make loud."""
    monkeypatch.setenv(audit_sink.SINK_ENV, raw)
    cfg = audit_sink.configure()                      # must not raise
    assert cfg["configured"] is True and cfg["kind"] is None and "could not be parsed" in cfg["reason"]
    assert audit_sink.status()["usable"] is False     # …and neither must the surfaces' entry point
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert len(audit.load(str(tmp_path))) == 1
    assert "audit sink not usable" in capsys.readouterr().err   # it is loud, like every other bad value
    assert raw not in audit_sink.status()["target"]             # and the unparseable value is not echoed


@pytest.mark.parametrize("raw", ["off", "OFF", "none", "disabled"])
def test_off_is_a_value_because_a_blank_field_cannot_clear_a_key(monkeypatch, raw):
    """`console._write_env` drops falsy updates and the UI skips empty inputs, so clearing the box
    cannot unset the variable. Without an explicit off, a sink enabled from the Setup page could
    never be disabled from it."""
    monkeypatch.setenv(audit_sink.SINK_ENV, raw)
    cfg = audit_sink.configure()
    assert cfg["configured"] is False and cfg["kind"] is None
    assert cfg["reason"] == "explicitly disabled"      # …and distinguishable from never-set
    monkeypatch.delenv(audit_sink.SINK_ENV)
    assert audit_sink.configure()["reason"] == "no sink configured"


def test_configuration_is_read_every_call_not_cached(monkeypatch):
    """POST /api/config writes .env and reloads it into os.environ of the RUNNING console. A
    module-level constant would leave the Setup page lying until relaunch."""
    assert audit_sink.configure()["kind"] is None
    monkeypatch.setenv(audit_sink.SINK_ENV, "stdout")
    assert audit_sink.configure()["kind"] == "stdout"


def test_a_webhook_url_never_renders_its_path(monkeypatch):
    """Slack/Teams/Splunk-HEC style webhooks carry the credential in the path. Only the origin is
    ever shown — the same reason `reconcile.notify` logs the exception type and never its message."""
    secret = "https://hooks.test/services/T000/B000/XXXXSECRETXXXX"
    monkeypatch.setenv(audit_sink.SINK_ENV, secret)
    for surface in (audit_sink.configure()["redacted"], audit_sink.status()["target"],
                    audit_sink.check()["target"]):
        assert "XXXXSECRETXXXX" not in surface and surface == "https://hooks.test/…"


def test_a_bare_origin_is_shown_whole(monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://collector.test")
    assert audit_sink.configure()["redacted"] == "https://collector.test"


def test_a_password_in_the_url_is_never_rendered_on_any_surface(monkeypatch):
    """`urlsplit` puts userinfo in `netloc`, so redacting from netloc would print the password on
    the CLI panel, the Setup page and the API response. Rebuilt from hostname/port instead."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://svc:hunter2@collector.test:8443/ingest")
    red = audit_sink.configure()["redacted"]
    assert "hunter2" not in red and "svc" not in red
    assert red == "https://…@collector.test:8443/…"
    assert "hunter2" not in json.dumps(audit_sink.status())


def test_an_ipv6_collector_is_reachable(tmp_path, monkeypatch):
    """A hardcoded AF_INET socket cannot reach `syslog://[::1]:514` at all — the sink would read as
    configured and deliver nothing, for ever. The family is resolved, not assumed."""
    rx = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        rx.bind(("::1", 0))
    except OSError:
        pytest.skip("no IPv6 loopback on this box")
    rx.settimeout(2.0)
    try:
        monkeypatch.setenv(audit_sink.SINK_ENV, f"syslog://[::1]:{rx.getsockname()[1]}")
        audit.record(str(tmp_path), "apply_waf", lb="lab", finding_id="v6")
        payload = rx.recv(65535).decode().partition(": ")[2]
    finally:
        rx.close()
    assert json.loads(payload)["finding_id"] == "v6"


# ---------------------------------------------------------------- fail-soft


def test_a_dead_collector_never_fails_an_apply_and_warns_exactly_once(tmp_path, monkeypatch, capsys):
    """The acceptance criterion. `audit.record` is called on the rollback-failed path, so a sink
    that could raise would turn "the LB may be left changed" into an unrecorded event."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    _fake_httpx(monkeypatch, boom=lambda **k: (_ for _ in ()).throw(ConnectionError("refused")))
    out = str(tmp_path)
    for i in range(4):
        audit.record(out, "rollback_failed", finding_id=f"f{i}", lb="lab")
    assert len(audit.load(out)) == 4                       # every entry still on disk
    err = capsys.readouterr().err
    assert err.count("audit sink delivery failed") == 1    # one warning, not four
    assert "ConnectionError" in err


def test_the_warning_goes_to_stderr_never_stdout(tmp_path, monkeypatch, capsys):
    """`mcp.serve()` repoints sys.stdout at stderr, but a warning that RELIED on that swap would
    corrupt the protocol stream anywhere the swap is not in force."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    _fake_httpx(monkeypatch, boom=lambda **k: (_ for _ in ()).throw(ConnectionError("refused")))
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    cap = capsys.readouterr()
    assert cap.out == "" and "audit sink delivery failed" in cap.err


def test_a_failing_sink_never_leaks_the_url_or_the_error_message(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://hooks.test/services/SECRETPATH")
    _fake_httpx(monkeypatch, boom=lambda **k: (_ for _ in ()).throw(ConnectionError("connecting to https://hooks.test/services/SECRETPATH")))
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    err = capsys.readouterr().err
    assert "SECRETPATH" not in err and "hooks.test" not in err
    assert audit_sink.status()["last_error"] == "ConnectionError"


def test_an_http_error_status_is_a_failure_not_a_delivery(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    _fake_httpx(monkeypatch, status=503)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    st = audit_sink.status()
    assert st["delivered"] == 0 and st["failed"] == 1 and st["last_error"] == "OSError"


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_is_a_failure_because_the_body_was_never_re_sent(tmp_path, monkeypatch, status):
    """Found by adversarial review, reproduced against a real 302 server. httpx does not follow
    redirects by default, so a moved ingest path — or a proxy bouncing to an SSO page — swallowed
    the whole audit stream while every surface read `delivered N/N`.

    It is refused rather than followed on purpose: the request carries the bearer token, and
    chasing a Location to a host the operator never configured is how a credential travels."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    _fake_httpx(monkeypatch, status=status)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    st = audit_sink.status()
    assert st["delivered"] == 0 and st["failed"] == 1


def test_udp_reports_sent_unconfirmed_because_it_cannot_be_acknowledged(tmp_path, monkeypatch):
    """A datagram to a port with nothing bound succeeds at the send call, so "sent" over UDP means
    "handed to the kernel". Painting that the same green as an answered POST would destroy the
    distinction that matters most — the J2 `present-unverified` precedent."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "syslog://127.0.0.1:9")   # discard port, nothing bound
    assert audit_sink.check(send=True)["delivery"] == "sent-unconfirmed"
    # …while a transport that DOES get an answer from the other end is unqualified.
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    _fake_httpx(monkeypatch)
    assert audit_sink.check(send=True)["delivery"] == "sent"


def test_both_surfaces_distinguish_unconfirmed_from_delivered():
    """A guard that lives on one surface is not a guard — and this one is a wording guard."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    html = (root / "src/vpcopilot/console/static/index.html").read_text()
    cli = (root / "src/vpcopilot/cli.py").read_text()
    assert "sent-unconfirmed" in html and "sent, unconfirmed" in html
    assert "sent-unconfirmed" in cli and "UDP cannot acknowledge" in cli


def test_an_invalid_sink_warns_once_and_delivers_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(audit_sink.SINK_ENV, "ftp://nope.test")
    for _ in range(3):
        audit.record(str(tmp_path), "apply_waf", lb="lab")
    err = capsys.readouterr().err
    assert err.count("audit sink not usable") == 1 and "unsupported sink" in err
    assert audit_sink.status()["attempted"] == 0        # nothing was ever tried


def test_a_dead_collector_is_paid_for_once_not_once_per_entry(tmp_path, monkeypatch):
    """A hung collector at a 5s timeout, times the several entries one apply writes, is a stall the
    acceptance ("never fails an apply") does not name but would certainly be. After a failure the
    sink goes quiet for a cooldown instead of paying the timeout again."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    calls = []
    _fake_httpx(monkeypatch, boom=lambda **k: (calls.append(1), (_ for _ in ()).throw(ConnectionError("x")))[1])
    clock = [1000.0]
    monkeypatch.setattr(audit_sink, "_now", lambda: clock[0])
    out = str(tmp_path)
    for _ in range(5):
        audit.record(out, "apply_waf", lb="lab")
    assert len(calls) == 1 and audit_sink.status()["suppressed"] == 4

    clock[0] += audit_sink.COOLDOWN_S + 1               # cooldown expires -> it tries again
    audit.record(out, "apply_waf", lb="lab")
    assert len(calls) == 2


def test_delivery_resumes_after_the_collector_comes_back(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    state = {"up": False}

    class C:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, url, content=None, headers=None):
            if not state["up"]:
                raise ConnectionError("refused")
            return type("R", (), {"status_code": 200})()

    import httpx
    monkeypatch.setattr(httpx, "Client", lambda **k: C())
    clock = [1000.0]
    monkeypatch.setattr(audit_sink, "_now", lambda: clock[0])
    out = str(tmp_path)
    audit.record(out, "apply_waf", lb="lab")
    assert audit_sink.status()["failed"] == 1
    state["up"] = True
    clock[0] += audit_sink.COOLDOWN_S + 1
    audit.record(out, "apply_waf", lb="lab")
    assert audit_sink.status()["delivered"] == 1


# ---------------------------------------------------------------- the local log stays authoritative


def test_the_shipped_copy_is_byte_identical_to_the_line_on_disk(tmp_path, monkeypatch):
    """Serialized once and handed to both destinations. Re-encoding the parsed dict would let key
    order or float formatting drift between the evidence and the copy of it."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    sent = _fake_httpx(monkeypatch)
    out = str(tmp_path)
    audit.record(out, "apply_service_policy", finding_id="neg-pay-001", lb="lab", passed=True)
    on_disk = (tmp_path / "audit.log").read_text().splitlines()[0]
    assert sent["content"] == on_disk.encode()
    assert json.loads(sent["content"])["finding_id"] == "neg-pay-001"


def test_nothing_is_delivered_when_the_local_write_fails(tmp_path, monkeypatch):
    """The local log is authoritative, so an off-box event with no local counterpart must not
    exist — it could never be reconciled against the run it belongs to."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    sent = _fake_httpx(monkeypatch)
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert sent == {}


def test_a_sink_changes_nothing_about_the_entry_itself(tmp_path, monkeypatch):
    """No new key, no reordering, no envelope: the exporter, the golden expectations and
    `export --verify` all read this file."""
    out = str(tmp_path)
    audit.record(out, "apply_waf", lb="lab", finding_id="f1")
    without = (tmp_path / "audit.log").read_text()
    (tmp_path / "audit.log").unlink()
    monkeypatch.setenv(audit_sink.SINK_ENV, "stdout")
    audit.record(out, "apply_waf", lb="lab", finding_id="f1")
    a, b = json.loads(without), json.loads((tmp_path / "audit.log").read_text())
    assert list(a) == list(b) and {k: a[k] for k in a if k != "ts"} == {k: b[k] for k in b if k != "ts"}


def test_the_sink_never_writes_an_audit_record_of_its_own(tmp_path, monkeypatch):
    """A delivery record inside `audit.record` would recurse, and an entry-count-changing side
    effect is the bug J4's no-op check exists to prevent."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    _fake_httpx(monkeypatch, boom=lambda **k: (_ for _ in ()).throw(ConnectionError("x")))
    out = str(tmp_path)
    audit.record(out, "apply_waf", lb="lab")
    assert len(audit.load(out)) == 1
    assert audit.load(out)[0]["action"] == "apply_waf"


def test_identity_still_cannot_be_forged_with_a_sink_configured(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    sent = _fake_httpx(monkeypatch)
    audit.record(str(tmp_path), "apply_waf", lb="lab", actor="someone-else", run_id="deadbeef")
    shipped = json.loads(sent["content"])
    assert shipped["actor"] != "someone-else" and shipped["run_id"] != "deadbeef"


# ---------------------------------------------------------------- transports


def test_the_http_sink_sends_json_with_the_bearer_token_when_set(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/ingest")
    monkeypatch.setenv(audit_sink.TOKEN_ENV, "s3cr3t")
    sent = _fake_httpx(monkeypatch)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert sent["url"] == "https://c.test/ingest"
    assert sent["headers"]["content-type"] == "application/json"
    assert sent["headers"]["authorization"] == "Bearer s3cr3t"
    assert sent["timeout"] == audit_sink.TIMEOUT_S


def test_the_http_sink_sends_no_auth_header_when_no_token_is_set(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/ingest")
    sent = _fake_httpx(monkeypatch)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert "authorization" not in sent["headers"]


def test_the_stdout_sink_writes_one_json_line_resolved_at_call_time(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(audit_sink.SINK_ENV, "stdout")
    audit.record(str(tmp_path), "apply_waf", lb="lab", finding_id="f1")
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1 and json.loads(out[0])["finding_id"] == "f1"


def test_a_stdout_sink_cannot_corrupt_the_mcp_protocol_stream(tmp_path, monkeypatch):
    """K1 points `sys.stdout` at stderr for the server's lifetime precisely so a stray write beneath
    it cannot land on the message stream. That guarantee has to cover this new writer, which is
    only true because the sink resolves `sys.stdout` when it writes rather than at import."""
    import io
    import sys as _sys

    from vpcopilot import mcp
    monkeypatch.setenv(audit_sink.SINK_ENV, "stdout")
    frames, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(_sys, "stderr", err)
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n"
    mcp.serve(io.StringIO(req), frames, enable_writes=False, swap_stdout=True)
    audit_sink.reset_state()

    # Now emit while the swap is in force, exactly as a write tool would.
    saved = _sys.stdout
    _sys.stdout = _sys.stderr
    try:
        audit.record(str(tmp_path), "apply_waf", lb="lab")
    finally:
        _sys.stdout = saved
    assert "apply_waf" in err.getvalue()          # the event landed on stderr…
    assert "apply_waf" not in frames.getvalue()   # …and never on the protocol stream
    assert json.loads(frames.getvalue().strip())["id"] == 1


def _udp_listener():
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(2.0)
    return rx, rx.getsockname()[1]


def test_the_syslog_sink_emits_a_wellformed_rfc3164_frame(tmp_path, monkeypatch):
    rx, port = _udp_listener()
    try:
        monkeypatch.setenv(audit_sink.SINK_ENV, f"syslog://127.0.0.1:{port}")
        audit.record(str(tmp_path), "apply_service_policy", lb="lab", finding_id="f1")
        frame = rx.recvfrom(65535)[0].decode()
    finally:
        rx.close()
    assert frame.startswith(f"<{audit_sink.SYSLOG_PRI}>")
    head, _, payload = frame.partition(": ")
    assert "vpcopilot[" in head
    assert json.loads(payload)["finding_id"] == "f1"    # the JSON survives the framing intact


def test_an_oversize_entry_degrades_to_an_envelope_that_says_so(tmp_path, monkeypatch):
    """Measured on macOS: a `/var/run/syslog` unix socket has SO_SNDBUF 2048 and refuses anything
    larger with EMSGSIZE; UDP walls around 9216. The entries that overflow are the interesting ones
    — `drift_detected` carries a whole field-level diff — so dropping them would lose exactly the
    records worth shipping. The kernel sets the limit; nothing here hardcodes one."""
    rx, port = _udp_listener()
    try:
        monkeypatch.setenv(audit_sink.SINK_ENV, f"syslog://127.0.0.1:{port}")
        real = socket.socket

        class Refusing:
            def __init__(self, *a, **k):
                self._s = real(*a, **k)
                self._first = True

            def sendto(self, data, dest):
                if self._first:                 # the kernel's answer to a too-large datagram
                    self._first = False
                    raise OSError(errno.EMSGSIZE, "Message too long")
                return self._s.sendto(data, dest)

            def __getattr__(self, n):
                return getattr(self._s, n)

        monkeypatch.setattr(audit_sink.socket, "socket", Refusing)
        audit.record(str(tmp_path), "drift_detected", lb="lab", finding_id="f1",
                     changes={"k%d" % i: "v" * 80 for i in range(40)})
        payload = rx.recvfrom(65535)[0].decode().partition(": ")[2]
    finally:
        rx.close()
    env = json.loads(payload)                    # valid JSON, not a truncated fragment
    assert env["audit_sink_oversize"] is True and env["action"] == "drift_detected"
    assert env["finding_id"] == "f1" and env["bytes"] > 1024
    assert "audit.log" in env["note"]
    assert audit_sink.status()["delivered"] == 1  # …and it counts as delivered, not as a failure


def test_an_oversize_entry_that_still_will_not_fit_is_a_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(audit_sink.SINK_ENV, "syslog://127.0.0.1:9")

    class AlwaysRefusing:
        def __init__(self, *a, **k): pass
        def settimeout(self, t): pass
        def close(self): pass
        def sendto(self, data, dest): raise OSError(errno.EMSGSIZE, "Message too long")

    monkeypatch.setattr(audit_sink.socket, "socket", AlwaysRefusing)
    audit.record(str(tmp_path), "apply_waf", lb="lab")
    assert audit_sink.status()["failed"] == 1
    assert "audit sink delivery failed" in capsys.readouterr().err


def test_the_unix_syslog_transport_reaches_a_real_socket(tmp_path, monkeypatch):
    """The `syslog:///var/run/syslog` shape, against a socket this test owns rather than the box's
    syslogd — same code path, nothing leaves the process."""
    import shutil
    import tempfile
    # NOT tmp_path: sun_path is capped at ~104 bytes and pytest's per-test directory blows it.
    short = tempfile.mkdtemp(prefix="vpcs")
    sock_path = f"{short}/s"
    rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    rx.bind(sock_path)
    rx.settimeout(2.0)
    try:
        monkeypatch.setenv(audit_sink.SINK_ENV, f"syslog://{sock_path}")
        assert audit_sink.configure()["kind"] == "syslog-unix"
        audit.record(str(tmp_path), "retire", lb="lab", finding_id="f1")
        payload = rx.recv(65535).decode().partition(": ")[2]
    finally:
        rx.close()
        shutil.rmtree(short, ignore_errors=True)
    assert json.loads(payload)["action"] == "retire"


# ---------------------------------------------------------------- the check surface


def test_check_reports_configuration_without_touching_the_network(monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")

    def boom(**k):
        raise AssertionError("check() must not deliver without --send")
    import httpx
    monkeypatch.setattr(httpx, "Client", boom)
    st = audit_sink.check()
    assert st["usable"] and st["kind"] == "https" and st["delivery"] == "not attempted"


def test_check_send_delivers_a_test_event_that_is_not_an_audit_record(tmp_path, monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    sent = _fake_httpx(monkeypatch)
    st = audit_sink.check(send=True)
    assert st["delivery"] == "sent"
    body = json.loads(sent["content"])
    assert body["kind"] == "vpcopilot-audit-sink-test" and "action" not in body
    assert "not an audit record" in body["note"]
    assert not (tmp_path / "audit.log").exists()      # asking the question adds no evidence


def test_check_send_reports_a_dead_collector_rather_than_a_clean_bill(monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    _fake_httpx(monkeypatch, boom=lambda **k: (_ for _ in ()).throw(ConnectionError("x")))
    st = audit_sink.check(send=True)
    assert st["delivery"] == "failed" and st["last_error"] == "ConnectionError"


def test_check_send_is_not_silenced_by_an_earlier_failures_cooldown(monkeypatch):
    """The check exists to answer "is it working NOW". Reporting `suppressed` because an unrelated
    entry failed a minute ago would be the tool declining to look."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    audit_sink._state.update(quiet_until=audit_sink._now() + 999, failed=1, warned=True)
    _fake_httpx(monkeypatch)
    assert audit_sink.check(send=True)["delivery"] == "sent"


def test_check_send_does_not_erase_the_record_of_earlier_failures(monkeypatch):
    """A long-lived console accumulates delivery history. Answering "does it work now" by wiping
    the counters would destroy the evidence that it had been failing — the operator would click a
    button to diagnose a problem and delete the symptom."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    audit_sink._state.update(failed=7, attempted=9, delivered=2, last_error="ConnectError",
                             quiet_until=audit_sink._now() + 999, warned=True)
    _fake_httpx(monkeypatch)
    st = audit_sink.check(send=True)
    assert st["delivery"] == "sent"
    assert st["failed"] == 7 and st["delivered"] == 3 and st["attempted"] == 10


def test_a_successful_test_event_re_arms_a_suppressed_sink(monkeypatch):
    """Proving the collector is back is a reason to stop suppressing: otherwise the operator sees
    "sent" and the next real audit entry is still silently dropped for the rest of the cooldown."""
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    audit_sink._state.update(quiet_until=audit_sink._now() + 999)
    _fake_httpx(monkeypatch)
    audit_sink.check(send=True)
    assert audit_sink._state["quiet_until"] == 0.0


def test_one_warning_survives_concurrent_failures_from_console_threads(tmp_path, monkeypatch, capsys):
    """The console runs each apply on its own daemon thread against this shared module. Without a
    check-and-set the "log one warning" guarantee degrades to "log one warning per racing thread"."""
    import threading
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://down.test/x")
    gate = threading.Barrier(8)

    class C:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def post(self, *a, **k):
            gate.wait(timeout=5)          # every thread fails at the same instant
            raise ConnectionError("refused")

    import httpx
    monkeypatch.setattr(httpx, "Client", lambda **k: C())
    monkeypatch.setattr(audit_sink, "_now", lambda: 1000.0)   # nobody is suppressed by a cooldown
    ts = [threading.Thread(target=audit.record, args=(str(tmp_path), "apply_waf"), kwargs={"lb": "lab"})
          for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert capsys.readouterr().err.count("audit sink delivery failed") == 1
    assert len(audit.load(str(tmp_path))) == 8        # …and every entry still reached disk


def test_check_on_an_unusable_sink_says_so_and_sends_nothing(monkeypatch):
    monkeypatch.setenv(audit_sink.SINK_ENV, "ftp://nope.test")
    st = audit_sink.check(send=True)
    assert st["configured"] and not st["usable"] and "no usable sink" in st["delivery"]


# ---------------------------------------------------------------- surfaces


def test_the_sink_keys_are_on_the_setup_page_and_the_token_is_secret():
    """The acceptance names the ⚙ Setup page, which renders exactly MANAGED_KEYS."""
    from vpcopilot.console import app
    assert audit_sink.SINK_ENV in app.MANAGED_KEYS
    assert audit_sink.TOKEN_ENV in app.MANAGED_KEYS
    assert audit_sink.TOKEN_ENV in app.SECRET_KEYS      # a bearer token is never echoed back
    assert audit_sink.SINK_ENV not in app.SECRET_KEYS   # …the URL is, so the page can show it


def test_the_console_endpoint_and_the_cli_call_the_same_module_function(monkeypatch):
    """One module function, two surfaces — a guard or a readout that lives on one is neither."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setenv(audit_sink.SINK_ENV, "stdout")
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    c = TestClient(A.app)
    got = c.get("/api/audit-sink").json()
    assert got["kind"] == "stdout" and got["usable"] is True
    assert got == {k: v for k, v in audit_sink.status().items()}


def test_the_console_status_endpoint_sends_nothing(monkeypatch):
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))

    def boom(**k):
        raise AssertionError("GET /api/audit-sink must not reach the network — the page polls it")
    import httpx
    monkeypatch.setattr(httpx, "Client", boom)
    assert TestClient(A.app).get("/api/audit-sink").status_code == 200


def test_the_console_post_can_deliver_a_test_event(monkeypatch):
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setenv(audit_sink.SINK_ENV, "https://c.test/x")
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    sent = _fake_httpx(monkeypatch)
    r = TestClient(A.app).post("/api/audit-sink", json={"send": True}).json()
    assert r["delivery"] == "sent" and json.loads(sent["content"])["kind"] == "vpcopilot-audit-sink-test"


def test_the_setup_page_actually_calls_the_endpoint():
    """A surface nothing calls is not a surface (the I1 precedent)."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1]
            / "src/vpcopilot/console/static/index.html").read_text()
    assert "/api/audit-sink" in html and "sinkStatus" in html and "checkSink(" in html


def test_every_css_class_the_console_uses_to_mark_a_failure_is_actually_defined():
    """Found live while validating J3, and it was already broken: `class="bad"` marks a failure in
    the H2 dependency preview (a manifest that would not parse, a package OSV could not be asked
    about) and the class was defined NOWHERE, so all of it rendered as ordinary text. A warning
    styled like body copy is the same defect that preview exists to prevent."""
    import re
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1]
            / "src/vpcopilot/console/static/index.html").read_text()
    used = set(re.findall(r'class="([a-z-]+)"', html)) & {"bad", "band", "nob", "muted", "sub", "mono"}
    for cls in sorted(used):
        assert re.search(rf"\.{cls}\s*{{", html), f'.{cls} is used in markup but never defined in CSS'


def test_the_suite_cannot_ship_fabricated_audit_records_to_a_real_collector():
    """Found by adversarial review: with `VPCOPILOT_AUDIT_SINK` exported in the shell, a full run
    shipped **267 datagrams** of invented records — apply_waf, retire, rollback_failed — to the
    developer's real collector, where they are indistinguishable from records of real changes.
    Documenting "unset it first" is a guard that depends on remembering; conftest clears it."""
    from pathlib import Path
    conftest = (Path(__file__).resolve().parents[1] / "tests/conftest.py").read_text()
    assert "autouse=True" in conftest and audit_sink.SINK_ENV in conftest
    # The fixture is autouse, so by the time this test body runs the variable is already gone
    # whatever the launching shell had in it.
    assert audit_sink.configure()["configured"] is False


def test_the_cli_command_exists_and_is_kebab_case():
    from vpcopilot import cli
    names = {c.name for c in cli.app.registered_commands}
    assert "audit-sink" in names


def test_the_documented_limit_is_actually_written_down():
    """This project states its limits rather than leaving them to be discovered (the J1/J4
    precedent). A sink is a copy, not a second source of truth, and the doc has to say so."""
    from pathlib import Path
    txt = (Path(__file__).resolve().parents[1] / "docs/AUDIT.md").read_text()
    assert "VPCOPILOT_AUDIT_SINK" in txt
    assert "authoritative" in txt and "best-effort" in txt
