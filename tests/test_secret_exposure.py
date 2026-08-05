"""Credentials reaching a surface they must never reach.

From the 2026-08-04 deep-dive review plus one found while walking the console. The shared shape:
redaction existed and was applied to the OBVIOUS carriers — headers, bodies, declared secret keys —
and skipped one that is just as credential-bearing in practice.

Every assertion here uses a realistic secret shape. A test that asserts a password is absent from a
string that never contained it proves nothing, and one of these tests was exactly that until it was
rewritten (see tests/test_bigip_lab.py).
"""
from __future__ import annotations

import os
import pathlib
import tempfile

import pytest


# ---------------------------------------------------------------- recorded traffic


def test_a_secret_in_the_query_string_is_redacted_like_one_in_the_body():
    """Headers and bodies were cleaned; the QUERY STRING was not. `?api_key=sk-live-…` and
    `?access_token=…` therefore shipped verbatim into simulation.json, the console API, the MCP
    tool output and the SIGNED EVIDENCE BUNDLE — the artifact whose whole purpose is to be handed
    to someone else.

    `REDACT_BODY_KEYS` already named `api_key` and `access_token`: the module knew they were
    secrets and simply never applied the rule to the query."""
    from vpcopilot.traffic import _record
    rec = _record(method="GET", source="har", ts="", status=200, headers={}, body=None,
                  url_or_path="/api/pay?api_key=sk-live-SECRET123&access_token=tok-ABC&id=7")
    blob = repr(rec.query)
    assert "sk-live-SECRET123" not in blob and "tok-ABC" not in blob, f"secret survived: {blob}"
    assert rec.query.get("id") == ["7"], "a non-secret parameter must be preserved untouched"


def test_the_redacted_parameter_keeps_its_shape():
    """Replaced, not dropped — exactly as in a body. A policy matcher is judged against the shape
    of the request, so a query parameter that vanishes changes what is being tested."""
    from vpcopilot.traffic import _record
    rec = _record(method="GET", source="har", ts="", status=200, headers={}, body=None,
                  url_or_path="/x?api_key=a&api_key=b")
    assert list(rec.query) == ["api_key"], "the key must survive"
    assert rec.query["api_key"] == ["[redacted]", "[redacted]"], "both values, both redacted"


def test_a_query_secret_is_counted_so_the_sample_is_not_reported_clean():
    """The compounding failure. The redaction counter never saw the query, so a sample whose ONLY
    secrets were in query strings reported zero redactions — affirmatively describing itself as
    clean. "We did not check this" rendering as "this is clean", which is the failure mode this
    project exists to avoid."""
    from vpcopilot.traffic import _record
    counts: dict = {}
    _record(method="GET", source="har", ts="", status=200, headers={}, body=None,
            url_or_path="/x?api_key=sk-live-SECRET", counts=counts)
    assert counts.get("api_key") == 1, f"the query secret was not counted: {counts}"


def test_every_traffic_source_inherits_the_fix():
    """HAR, XC tenant logs, JSONL and probe records all build through `_record`, so the redaction
    is applied once rather than four times. Pinned, because a fifth source added later that builds
    a RequestRecord directly would silently skip it."""
    import inspect

    from vpcopilot import traffic
    src = inspect.getsource(traffic)
    assert src.count("RequestRecord(") == 1, \
        "a RequestRecord is built outside _record — that path skips query redaction"
    assert "_clean_query(query, counts)" in src


# ---------------------------------------------------------------- the audit sink URL


@pytest.fixture
def env_file(monkeypatch):
    """A real .env, because the console reads the file rather than the process environment."""
    d = pathlib.Path(tempfile.mkdtemp())
    path = d / ".env"
    path.write_text("")
    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", path)
    return path


SINK = "https://hec:hunter2SECRET@splunk.example.com:8088/services/collector/TOK-ABC"


def test_the_console_does_not_hand_back_the_sink_url_in_full(env_file):
    """A sink URL routinely carries credentials in the URL ITSELF: basic auth, and the Splunk-HEC
    shape `…/services/collector/<token>`. `audit_sink.redact` exists for this and every other
    surface used it; `/api/config` returned the raw string."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    env_file.write_text(f"VPCOPILOT_AUDIT_SINK={SINK}\n")
    got = TestClient(A.app).get("/api/config").json()["VPCOPILOT_AUDIT_SINK"]
    assert "hunter2SECRET" not in got["value"], "the basic-auth password was returned in full"
    assert "TOK-ABC" not in got["value"], "the HEC token was returned in full"
    assert got["set"] is True and "splunk.example.com" in got["value"], \
        "it must still say WHICH sink is configured — a blank is not the fix"


def test_saving_the_redacted_value_back_does_not_destroy_the_real_sink(env_file):
    """The regression the redaction nearly introduced. The settings form posts every non-empty
    field, so showing `https://…@host/…` in an editable input meant one Save wrote the ellipsis
    into .env — silently breaking the one component whose failure mode is "no record of anything".

    Guarded on the SERVER, not just by leaving the field empty: the endpoint is reachable
    directly, and a guard that lives only in the page is not a guard."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    env_file.write_text(f"VPCOPILOT_AUDIT_SINK={SINK}\n")
    client = TestClient(A.app)
    shown = client.get("/api/config").json()["VPCOPILOT_AUDIT_SINK"]["value"]
    client.post("/api/config", json={"updates": {"VPCOPILOT_AUDIT_SINK": shown}})
    assert SINK in env_file.read_text(), "saving the redacted display value destroyed the sink"


def test_a_real_change_to_the_sink_still_saves(env_file):
    """The fix must not make the field read-only — an operator has to be able to change it."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    env_file.write_text(f"VPCOPILOT_AUDIT_SINK={SINK}\n")
    TestClient(A.app).post("/api/config",
                           json={"updates": {"VPCOPILOT_AUDIT_SINK": "syslog://logs.example:514"}})
    assert "syslog://logs.example:514" in env_file.read_text()


# ---------------------------------------------------------------- configured-where


def test_a_credential_from_the_environment_does_not_read_as_unset(env_file, monkeypatch):
    """Found while walking the GUI: Setup reported `BIGIP_URL (unset)` directly above a panel that
    was talking to the appliance over that URL — two panels on one screen contradicting each other
    about whether a fact was established.

    Not cosmetic. An operator who believes it is unset sets it; this page writes .env; the process
    keeps using the environment value that still wins — so the change reads as applied and is not,
    on a security-relevant credential."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setenv("BIGIP_URL", "https://127.0.0.1:18443")
    got = TestClient(A.app).get("/api/config").json()
    assert got["BIGIP_URL"]["set"] is True, "a live credential rendered as unset"
    assert got["BIGIP_URL"]["source"] == "environment"
    assert got["GITHUB_TOKEN"]["set"] is False and got["GITHUB_TOKEN"]["source"] == "", \
        "a genuinely unset key must still read as unset — three states, not one"


def test_the_env_file_wins_in_the_report_when_both_are_set(env_file, monkeypatch):
    """`load_dotenv(override=True)` means .env wins at runtime, so the page must say .env."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    env_file.write_text("BIGIP_USER=from-file\n")
    monkeypatch.setenv("BIGIP_USER", "from-environ")
    got = TestClient(A.app).get("/api/config").json()["BIGIP_USER"]
    assert got["source"] == "env-file" and got["value"] == "from-file"


def test_the_console_page_renders_the_third_state():
    """A distinction the API makes and the page throws away is not a fix."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "src/vpcopilot/console/static/index.html").read_text()
    assert "set in environment" in src, "the page still shows only set/unset"
    assert "still wins until the console is restarted" in src, \
        "it must warn that saving .env will not take effect while the env var is set"


def test_no_managed_key_is_left_out_of_the_three_state_report():
    """Every key the page manages goes through the same logic — a per-key exception is how the
    original defect survived."""
    from vpcopilot.console.app import MANAGED_KEYS, get_config
    os.environ.pop("VPCOPILOT_NOTHING", None)
    got = get_config()
    assert set(got) == set(MANAGED_KEYS)
    assert all("source" in v for v in got.values())
