"""OSV.dev client — the advisory facts, fetched by code and never invented by a model.

OSV was chosen over NVD and bare GHSA because it needs no credentials (so `scan --cve` stays "safe
to run anywhere", like the rest of scan), spans ecosystems on one schema, and carries the **fixed
version** — which is the whole of H1's "recommend the fixed version rather than drafting a patch to
vendor code".

Three things the real API does that a reading of the schema does not prepare you for. All three
were found by querying it, and each one silently degrades the answer if unhandled:

1. **Querying by CVE id often returns the GIT-range record.** `CVE-2024-23334` resolves to an entry
   whose only `affected` block is a `GIT` range: no package, no ecosystem, and `fixed` values that
   are 40-character commit SHAs. The clean `PyPI/aiohttp fixed=3.9.2` lives on its **aliases**
   (`GHSA-5h86-8mv2-jq9f`, `PYSEC-2024-24`). So this follows aliases and merges. Without that,
   "upgrade to 24a6d64966d99182e95f5d3a29541ef2fec397ad" is what the operator gets told.
2. **`fixed` is not always a version.** Same cause. A value that looks like a commit is not offered
   as an upgrade target — it is recorded as evidence and the recommendation says so.
3. **`summary` is frequently empty** (`CVE-2021-41773`, `CVE-2022-22965`), and for OS-level CVEs
   there is no package at all — only `database_specific.cpe`. The prose in `details` is the real
   payload, and it is what the resolve agent reasons over.

Read-only and cached on disk: an advisory is immutable enough for a run, and a demo should not
depend on the network being up.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Callable

API = "https://api.osv.dev/v1/vulns"
CACHE_ENV = "VPCOPILOT_ADVISORY_CACHE"
TIMEOUT = 20

# A 40- (or 7+) character hex string in a `fixed` event is a commit, not something anyone can
# `pip install`. Offering it as an upgrade target is worse than admitting there isn't one.
_COMMITISH = re.compile(r"^[0-9a-f]{7,40}$")
_ADVISORY_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|"
                          r"PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$", re.I)


def valid_id(advisory_id: str) -> bool:
    return bool(_ADVISORY_ID.match((advisory_id or "").strip()))


def _cache_dir() -> Path | None:
    raw = (os.environ.get(CACHE_ENV) or "").strip()
    return Path(raw) if raw else None


def _cached(advisory_id: str) -> dict | None:
    d = _cache_dir()
    if not d:
        return None
    p = d / f"{advisory_id}.json"
    try:
        return json.loads(p.read_text()) if p.is_file() else None
    except (OSError, json.JSONDecodeError):
        return None


def _store(advisory_id: str, obj: dict) -> None:
    d = _cache_dir()
    if not d:
        return
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{advisory_id}.json").write_text(json.dumps(obj, indent=2))
    except OSError:
        pass


def fetch(advisory_id: str, *, log: Callable = print) -> dict:
    """One raw OSV record. Cache first, then the API."""
    advisory_id = (advisory_id or "").strip()
    hit = _cached(advisory_id)
    if hit is not None:
        return hit
    import httpx
    r = httpx.get(f"{API}/{advisory_id}", timeout=TIMEOUT)
    if r.status_code == 404:
        raise RuntimeError(f"no advisory '{advisory_id}' in OSV.dev — check the id "
                           "(CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx, PYSEC-YYYY-NN)")
    if r.status_code != 200:
        raise RuntimeError(f"OSV.dev returned {r.status_code} for '{advisory_id}': {r.text[:200]}")
    obj = r.json()
    _store(advisory_id, obj)
    return obj


def _affected_rows(obj: dict) -> list[dict]:
    """Flatten `affected[].ranges[]` into rows that say what is broken and what fixes it.

    `versioned` marks a row whose `fixed` is something a human can install, as opposed to a commit
    SHA from a GIT range. `database_specific.extracted_events` carries real version strings for some
    GIT ranges (`CVE-2021-41773` → `introduced=2.4.49`), so it is read as a fallback identity even
    when the events themselves are commits."""
    rows = []
    for a in obj.get("affected") or []:
        pkg = a.get("package") or {}
        cpe = ((a.get("database_specific") or {}).get("cpe")
               or ((a.get("ranges") or [{}])[0].get("database_specific") or {}).get("cpe") or "")
        for rng in a.get("ranges") or []:
            events = rng.get("events") or []
            extracted = (rng.get("database_specific") or {}).get("extracted_events") or []
            fixed = [e["fixed"] for e in events if e.get("fixed")]
            intro = [e["introduced"] for e in events if e.get("introduced")]
            last = [e["last_affected"] for e in events if e.get("last_affected")]
            versioned = [f for f in fixed if not _COMMITISH.match(str(f))]
            rows.append({
                "ecosystem": pkg.get("ecosystem") or "",
                "package": pkg.get("name") or "",
                "cpe": cpe,
                "range_type": rng.get("type") or "",
                "introduced": intro,
                "fixed": fixed,
                "last_affected": last,
                "fixed_versions": versioned,
                "versioned": bool(versioned),
                "extracted": [f"{k}={v}" for e in extracted for k, v in e.items()],
            })
        if not (a.get("ranges") or []):     # some records list bare versions with no range
            vs = a.get("versions") or []
            rows.append({"ecosystem": pkg.get("ecosystem") or "", "package": pkg.get("name") or "",
                         "cpe": cpe, "range_type": "", "introduced": [], "fixed": [],
                         "last_affected": vs[-1:], "fixed_versions": [], "versioned": False,
                         "extracted": []})
    return rows


def _first_sentence(text: str) -> str:
    t = " ".join((text or "").split())
    m = re.search(r"^(.{20,180}?[.!?])(\s|$)", t)
    return (m.group(1) if m else t[:160]).strip()


def resolve(advisory_id: str, *, follow_aliases: bool = True, log: Callable = print) -> dict:
    """A normalized advisory: the requested record, enriched from its aliases when the requested one
    has no installable fixed version.

    This is the function that makes "recommend the fixed version" true rather than nearly true —
    see the module docstring for what querying a CVE id alone actually returns."""
    if not valid_id(advisory_id):
        raise RuntimeError(f"'{advisory_id}' is not an advisory id — expected CVE-YYYY-NNNNN, "
                           "GHSA-xxxx-xxxx-xxxx, PYSEC-YYYY-NN, GO-YYYY-NNNN or RUSTSEC-YYYY-NNNN")
    obj = fetch(advisory_id, log=log)
    rows = _affected_rows(obj)
    consulted = [obj.get("id") or advisory_id]

    if follow_aliases and not any(r["versioned"] for r in rows):
        for alias in (obj.get("aliases") or [])[:4]:
            if not valid_id(alias):
                continue
            try:
                alt = fetch(alias, log=log)
            except Exception as e:  # noqa: BLE001 — enrichment is best-effort, never fatal
                log(f"  ⚠ could not read alias {alias}: {e}")
                continue
            alt_rows = _affected_rows(alt)
            consulted.append(alias)
            if any(r["versioned"] for r in alt_rows):
                log(f"  {advisory_id} carries no installable fixed version; {alias} does "
                    f"({', '.join(sorted({v for r in alt_rows for v in r['fixed_versions']}))})")
                rows = alt_rows + rows
                break

    sev = next((s.get("score") for s in obj.get("severity") or [] if s.get("score")), "")
    details = obj.get("details") or ""
    return {
        "id": obj.get("id") or advisory_id,
        "aliases": obj.get("aliases") or [],
        "consulted": consulted,
        "summary": obj.get("summary") or _first_sentence(details),
        "details": details[:4000],
        "cwe_ids": (obj.get("database_specific") or {}).get("cwe_ids") or [],
        "cvss": sev,
        "published": obj.get("published") or "",
        "affected": rows,
        "references": [r.get("url") for r in (obj.get("references") or [])][:12],
    }


def severity_from_cvss(cvss: str) -> str:
    """CVSS vector → the project's four-level Severity. Absent scores are `medium`, never
    `critical` — an unknown severity must not jump the queue ahead of a measured one."""
    m = re.search(r"CVSS:3\.[01]/(.+)", cvss or "")
    if not m:
        return "medium"
    parts = dict(p.split(":", 1) for p in m.group(1).split("/") if ":" in p)
    # Approximate the base score from the impact/exploitability metrics that dominate it. This is a
    # bucketing, not a CVSS implementation — OSV rarely publishes the numeric score.
    high_impact = sum(1 for k in ("C", "I", "A") if parts.get(k) == "H")
    net = parts.get("AV") == "N"
    easy = parts.get("AC") == "L" and parts.get("PR") == "N" and parts.get("UI") == "N"
    if net and easy and high_impact >= 2:
        return "critical"
    if net and (high_impact >= 1 or easy):
        return "high"
    if high_impact >= 1:
        return "medium"
    return "low"


def upgrade_target(advisory: dict) -> dict:
    """The single best "upgrade to X" recommendation, or an honest statement that OSV has none.

    Prefers a row with an installable version. A GIT-only advisory yields `fixed_version: ""` and a
    note carrying the commit — because telling an operator to "upgrade to
    24a6d64966d99182e95f5d3a29541ef2fec397ad" is not a recommendation."""
    rows = advisory.get("affected") or []
    best = next((r for r in rows if r["versioned"]), None)
    if best:
        return {"package": best["package"], "ecosystem": best["ecosystem"],
                "fixed_version": sorted(best["fixed_versions"])[0],
                "vulnerable_range": ", ".join(best["introduced"]) or "see advisory", "note": ""}
    any_row = rows[0] if rows else {}
    commits = [f for r in rows for f in r.get("fixed", [])]
    note = ("OSV records the fix as a source commit, not a released version"
            if commits else "OSV lists no fixed version for this advisory")
    # A GIT range's `introduced` is a commit SHA, which tells an operator nothing about which
    # release they are running. `database_specific.extracted_events` carries the human versions
    # for exactly that case (CVE-2021-41773 → introduced=2.4.49), so prefer it.
    introduced = [v for v in (any_row.get("introduced") or []) if not _COMMITISH.match(str(v))]
    return {"package": any_row.get("package") or any_row.get("cpe", ""),
            "ecosystem": any_row.get("ecosystem", ""), "fixed_version": "",
            "vulnerable_range": ", ".join(introduced) or ", ".join(any_row.get("extracted") or [])
            or "see advisory",
            "note": f"{note}: {', '.join(commits[:2])}" if commits else note}
