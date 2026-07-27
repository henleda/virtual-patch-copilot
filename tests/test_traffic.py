"""G2 — traffic ingestion. Records come from a HAR export, a JSONL sample, or XC access logs, and
are normalized to one `RequestRecord` shape. Redaction runs at INGEST because the redacted sample
ships in the evidence bundle: a value that is never parsed into a record can never leak."""
import json

import pytest

from vpcopilot import traffic

HAR = {"log": {"entries": [
    {"startedDateTime": "2026-07-27T10:00:00Z",
     "request": {"method": "POST", "url": "https://app.example.com/api/pay?ref=abc&ref=def",
                 "headers": [{"name": "Content-Type", "value": "application/json"},
                             {"name": "Authorization", "value": "Bearer sk-live-SECRET"},
                             {"name": "User-Agent", "value": "curl/8.1"}],
                 "postData": {"mimeType": "application/json", "text": '{"amount": -5, "to": "x"}'}},
     "response": {"status": 200}},
    {"request": {"method": "GET", "url": "https://app.example.com/health", "headers": []},
     "response": {"status": 200}},
]}}

XC_LOGS = [
    {"method": "GET", "req_path": "/api/accounts?id=7", "rsp_code": 200, "user_agent": "node",
     "time": "2026-07-27T15:21:37.178Z", "src_ip": "3.21.170.57",
     "req_headers": '{"accept":"*/*","cookie":"session=abc123"}',
     "vh_name": "ves-io-http-loadbalancer-nimbus-www"},
    {"method": "POST", "req_path": "/api/pay", "rsp_code": 403, "user_agent": "curl/8",
     "time": "2026-07-27T15:22:00.000Z", "req_headers": "{}",
     "vh_name": "ves-io-http-loadbalancer-other-lb"},
]


# ---- HAR ----
def test_har_maps_method_path_query_and_body():
    recs, _ = traffic.from_har(HAR)
    assert len(recs) == 2
    r = recs[0]
    assert r.method == "POST" and r.path == "/api/pay"
    assert r.query == {"ref": ["abc", "def"]}          # repeated params keep both values
    assert r.json_body == {"amount": -5, "to": "x"}    # HAR carries bodies; XC logs do not
    assert r.user_agent == "curl/8.1" and r.ts == "2026-07-27T10:00:00Z"
    assert r.status == 200 and r.source == "har"


def test_har_entry_without_body_or_headers_still_parses():
    assert traffic.from_har(HAR)[0][1].path == "/health"


# ---- XC access logs ----
def test_xc_log_maps_the_real_field_names():
    recs, _ = traffic.from_xc_logs(XC_LOGS)
    r = recs[0]
    assert r.method == "GET" and r.path == "/api/accounts" and r.query == {"id": ["7"]}
    assert r.status == 200 and r.user_agent == "node" and r.source == "xc"
    assert r.json_body is None                          # XC captures no request body


def test_xc_log_headers_arrive_as_a_json_string():
    assert traffic.from_xc_logs(XC_LOGS)[0][0].headers.get("accept") == "*/*"


def test_xc_logs_filter_by_lb_via_vh_name():
    recs, _ = traffic.from_xc_logs(XC_LOGS, lb="nimbus-www")
    assert len(recs) == 1 and recs[0].path == "/api/accounts"


# ---- redaction: a correctness requirement, because the sample is distributed ----
def test_authorization_and_cookie_are_stripped_at_ingest():
    recs, red = traffic.from_har(HAR)
    assert "Authorization" not in recs[0].headers and "authorization" not in recs[0].headers
    assert "sk-live-SECRET" not in json.dumps(recs[0].model_dump())
    assert red.get("authorization") == 1


def test_cookie_stripped_from_xc_records_too():
    recs, red = traffic.from_xc_logs(XC_LOGS)
    assert "cookie" not in {k.lower() for k in recs[0].headers}
    assert red.get("cookie") == 1


def test_secret_looking_body_fields_are_redacted_not_dropped():
    har = {"log": {"entries": [{"request": {
        "method": "POST", "url": "https://x/api/login", "headers": [],
        "postData": {"mimeType": "application/json",
                     "text": '{"username": "jo", "password": "hunter2", "token": "t-1"}'}}}]}}
    r, red = traffic.from_har(har)
    body = r[0].json_body
    assert body["username"] == "jo"                     # shape preserved so matchers still work
    assert body["password"] == traffic.REDACTED and body["token"] == traffic.REDACTED
    assert red.get("password") == 1 and red.get("token") == 1


def test_extra_redact_patterns_are_configurable():
    har = {"log": {"entries": [{"request": {
        "method": "GET", "url": "https://x/a", "headers": [{"name": "X-Trace", "value": "abc"}]}}]}}
    recs, _ = traffic.from_har(har, redact_headers=("x-trace",))
    assert "X-Trace" not in recs[0].headers


def test_src_ip_is_not_carried_into_the_record():
    """The bundle ships the sample; a client IP is personal data and nothing in G2 needs it."""
    assert "3.21.170.57" not in json.dumps([r.model_dump() for r in traffic.from_xc_logs(XC_LOGS)[0]])


# ---- robustness: a malformed line must never kill a replay ----
def test_malformed_records_are_counted_not_raised(tmp_path):
    p = tmp_path / "s.jsonl"
    p.write_text('{"method":"GET","path":"/ok"}\nnot json at all\n{"no_path":true}\n')
    recs, red = traffic.from_jsonl(p.read_text())
    assert len(recs) == 1 and recs[0].path == "/ok"
    assert red.get("_skipped") == 2


def test_load_dispatches_on_extension(tmp_path):
    (tmp_path / "t.har").write_text(json.dumps(HAR))
    (tmp_path / "t.jsonl").write_text('{"method":"GET","path":"/a"}\n')
    assert len(traffic.load(str(tmp_path / "t.har"))[0]) == 2
    assert len(traffic.load(str(tmp_path / "t.jsonl"))[0]) == 1
    with pytest.raises(ValueError):
        traffic.load(str(tmp_path / "t.txt"))


def test_empty_source_is_empty_not_an_error():
    assert traffic.from_har({"log": {"entries": []}}) == ([], {})
    assert traffic.from_jsonl("") == ([], {})


def test_record_round_trips_through_a_probe_request_shape():
    """A finding's own exploit is a valid record — that is what makes the acceptance testable
    without inventing a second fixture for the exploit side."""
    rec = traffic.from_probe_request({"method": "POST", "path": "/api/pay",
                                      "json_body": {"amount": -1}}, source="probe")
    assert rec.method == "POST" and rec.path == "/api/pay" and rec.json_body == {"amount": -1}


def test_the_committed_nimbus_sample_ingests_and_holds_one_exploit():
    """G2's acceptance leans on this fixture: one negative-amount transfer among legitimate ones."""
    from pathlib import Path
    recs, red = traffic.load(str(Path(__file__).parent.parent / "bench/fixtures/traffic/nimbus-sample.jsonl"))
    assert len(recs) == 200 and red.get("_skipped") is None
    neg = [r for r in recs if r.json_body and (r.json_body.get("amount") or 0) < 0]
    pays = [r for r in recs if r.path == "/api/pay"]
    assert len(neg) == 1 and len(pays) == 61      # exactly one exploit, 60 legitimate transfers
