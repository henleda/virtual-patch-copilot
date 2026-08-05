"""G2 — turn recorded traffic into `RequestRecord`s a candidate band-aid can be replayed against.

Three sources, one shape: a HAR export, a JSONL sample, or XC access logs. A HAR carries request
bodies; **XC access logs do not**, which is why a `body_matcher` policy cannot be judged from
tenant logs alone — `SimulationResult.bodies_available` says so out loud rather than letting a
would-block count quietly mean less than it looks.

Redaction runs here, at ingest, and not at export. The redacted sample ships inside the evidence
bundle, so a secret that is never parsed into a record can never leak from one; a filter applied
later would only cover the paths someone remembered to route through it. Every ingest returns
`(records, redaction_counts)` and the counts reach `simulation.json`, because a redaction you
cannot see is a redaction you cannot trust.

Read-only: nothing here contacts XC, and nothing mutates the source it reads."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .schemas import RequestRecord

REDACTED = "[redacted]"

# Stripped from headers entirely — the name alone is not sensitive, the value always is.
REDACT_HEADERS = ("authorization", "cookie", "set-cookie", "proxy-authorization",
                  "x-api-key", "x-auth-token", "api-key")
# Replaced (not dropped) in a JSON body: the key must survive so an `additionalProperties:false`
# or a required-field matcher still sees the same document shape.
REDACT_BODY_KEYS = ("password", "passwd", "secret", "token", "access_token", "refresh_token",
                    "api_key", "apikey", "authorization", "ssn", "card", "card_number", "cvv", "pan")


def _split(url_or_path: str) -> tuple[str, dict]:
    """`/a/b?x=1&x=2` -> (`/a/b`, {'x': ['1','2']}). Accepts a full URL or a bare path."""
    parts = urlsplit(url_or_path or "")
    return (parts.path or "/"), parse_qs(parts.query, keep_blank_values=True)


def _clean_headers(headers: dict, extra: tuple, counts: dict) -> dict:
    out = {}
    drop = tuple(h.lower() for h in REDACT_HEADERS) + tuple(h.lower() for h in extra)
    for k, v in (headers or {}).items():
        if str(k).lower() in drop:
            counts[str(k).lower()] = counts.get(str(k).lower(), 0) + 1
            continue
        out[k] = v
    return out


def _clean_query(query: dict, counts: dict) -> dict:
    """Redact secret-looking QUERY parameters, by the same key list the body already uses.

    Headers and bodies were cleaned; the query string was not — so a sample carrying
    `?api_key=sk-live-…` or `?access_token=…` shipped the credential VERBATIM into
    simulation.json, the console API, the MCP tool output and the signed evidence bundle. Worse,
    the redaction counter never saw it, so the run affirmatively reported the sample as clean:
    "we did not check this" rendering as "this is clean", on the artifact meant to be shareable.

    Values are replaced rather than dropped, exactly as in a body: a policy matcher is judged
    against the shape of the request, and a query parameter that vanishes changes that shape.
    """
    out: dict = {}
    for k, vals in (query or {}).items():
        if str(k).lower() in REDACT_BODY_KEYS:
            counts[str(k).lower()] = counts.get(str(k).lower(), 0) + len(vals or [""])
            out[k] = ["[redacted]" for _ in (vals or [""])]
        else:
            out[k] = vals
    return out


def _clean_body(body, counts: dict):
    """Replace secret-looking values in place, keeping every key — the document shape is what a
    schema or body matcher is judged against."""
    if isinstance(body, dict):
        out = {}
        for k, v in body.items():
            if str(k).lower() in REDACT_BODY_KEYS and not isinstance(v, (dict, list)):
                counts[str(k).lower()] = counts.get(str(k).lower(), 0) + 1
                out[k] = REDACTED
            else:
                out[k] = _clean_body(v, counts)
        return out
    if isinstance(body, list):
        return [_clean_body(v, counts) for v in body]
    return body


def _record(*, method, url_or_path, headers, body, ts, status, source,
            redact_headers=(), counts=None) -> RequestRecord:
    counts = counts if counts is not None else {}
    path, query = _split(url_or_path)
    query = _clean_query(query, counts)
    hdrs = _clean_headers(headers, redact_headers, counts)
    ua = next((v for k, v in hdrs.items() if str(k).lower() == "user-agent"), "")
    return RequestRecord(method=(method or "GET").upper(), path=path, query=query, headers=hdrs,
                         json_body=_clean_body(body, counts) if isinstance(body, (dict, list)) else None,
                         ts=ts, status=status, user_agent=ua, source=source)


# ---------------- sources ----------------
def from_har(har: dict, *, redact_headers=()) -> tuple[list[RequestRecord], dict]:
    counts: dict = {}
    out = []
    for e in ((har or {}).get("log") or {}).get("entries") or []:
        req = e.get("request") or {}
        hdrs = {h.get("name"): h.get("value") for h in (req.get("headers") or []) if h.get("name")}
        body = None
        post = req.get("postData") or {}
        if "json" in (post.get("mimeType") or "") and post.get("text"):
            try:
                body = json.loads(post["text"])
            except json.JSONDecodeError:
                body = None
        out.append(_record(method=req.get("method"), url_or_path=req.get("url"), headers=hdrs,
                           body=body, ts=e.get("startedDateTime"),
                           status=(e.get("response") or {}).get("status"), source="har",
                           redact_headers=redact_headers, counts=counts))
    return out, counts


def from_xc_logs(logs: list, *, lb: str | None = None, redact_headers=()) -> tuple[list[RequestRecord], dict]:
    """Map XC access-log records. `vh_name` is `ves-io-http-loadbalancer-<lb>`, so a run can be
    scoped to the LB it cares about. `src_ip` is deliberately NOT carried into the record: the
    sample is distributed in the evidence bundle and nothing in G2 needs a client address."""
    counts: dict = {}
    out = []
    for raw in logs or []:
        rec = raw
        if isinstance(rec, str):
            try:
                rec = json.loads(rec)
            except json.JSONDecodeError:
                counts["_skipped"] = counts.get("_skipped", 0) + 1
                continue
        if lb and not str(rec.get("vh_name", "")).endswith(f"-{lb}"):
            continue
        hdrs = rec.get("req_headers") or {}
        if isinstance(hdrs, str):
            try:
                hdrs = json.loads(hdrs)
            except json.JSONDecodeError:
                hdrs = {}
        if rec.get("user_agent") and not any(k.lower() == "user-agent" for k in hdrs):
            hdrs["User-Agent"] = rec["user_agent"]
        out.append(_record(method=rec.get("method"), url_or_path=rec.get("req_path") or rec.get("original_path"),
                           headers=hdrs, body=None, ts=rec.get("time") or rec.get("@timestamp"),
                           status=rec.get("rsp_code"), source="xc",
                           redact_headers=redact_headers, counts=counts))
    return out, counts


def from_jsonl(text: str, *, redact_headers=()) -> tuple[list[RequestRecord], dict]:
    """One JSON object per line, already in `RequestRecord` shape (what `--logs` usually gets).
    A malformed line is counted and skipped — one bad line must never kill a replay."""
    counts: dict = {}
    out = []
    for ln in (text or "").splitlines():
        if not ln.strip():
            continue
        try:
            d = json.loads(ln)
            out.append(_record(method=d.get("method"), url_or_path=d.get("path") or d["path"],
                               headers=d.get("headers") or {}, body=d.get("json_body"),
                               ts=d.get("ts"), status=d.get("status"), source=d.get("source") or "jsonl",
                               redact_headers=redact_headers, counts=counts))
        except (json.JSONDecodeError, KeyError, TypeError):
            counts["_skipped"] = counts.get("_skipped", 0) + 1
    return out, counts


def from_probe_request(pr: dict, *, source: str = "probe") -> RequestRecord:
    """A finding's own exploit/legit request is a valid record — `ProbeRequest` is the shape
    `RequestRecord` was modelled on, so the acceptance case needs no second fixture."""
    counts: dict = {}
    return _record(method=pr.get("method"), url_or_path=pr.get("path"), headers=pr.get("headers") or {},
                   body=pr.get("json_body"), ts=None, status=None, source=source, counts=counts)


def load(path: str, *, redact_headers=()) -> tuple[list[RequestRecord], dict]:
    """Dispatch on extension: `.har` / `.json` (HAR) or `.jsonl` / `.ndjson`."""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix not in (".har", ".json", ".jsonl", ".ndjson"):  # checked BEFORE reading, so an
        raise ValueError(                                     # unsupported type says so plainly
            f"unsupported traffic file '{p.suffix}' — use .har, .json, .jsonl or .ndjson")
    text = p.read_text()
    if suffix in (".har", ".json"):
        return from_har(json.loads(text), redact_headers=redact_headers)
    return from_jsonl(text, redact_headers=redact_headers)
