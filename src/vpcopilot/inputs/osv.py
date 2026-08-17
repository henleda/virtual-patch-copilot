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

H2 asks a different question — *what is wrong with the packages I have installed* — and measuring
that against the live API on 2026-07-29 surfaced three more, all of which only bite at volume:

4. **`querybatch` returns ids, not advisories.** One request covers 400 coordinates in 3.4s and its
   ids match `/v1/query` exactly, so it is a faithful *discovery* pass — but the bodies are not in
   it, and fetching each id would be one request per advisory (70 for `aiohttp 3.9.1` alone) where
   `/v1/query` returns all of them for a coordinate in one. Batch to find the hits, query the hits.
   One bad ecosystem also fails the **whole** batch with HTTP 400, so entries are validated first.
5. **Records are roughly two-to-one with advisories.** OSV publishes a GHSA *and* a PYSEC entry for
   most Python advisories, cross-linked by `aliases` — 70 records for `aiohttp 3.9.1` are 35
   advisories. Collapsing them is correctness, not thrift: the duplicate carries a different id, so
   nothing downstream would recognise it as one.
6. **CVSS v4 is now the majority.** 43 of those 70 severity scores are `CVSS_V4` against 32
   `CVSS_V3`, and 38 records carry a v4 vector and nothing else — every one of which a v3-only
   parser buckets as `medium` whatever it says. See `severity_from_cvss`.

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
QUERY_API = "https://api.osv.dev/v1/query"
BATCH_API = "https://api.osv.dev/v1/querybatch"
CACHE_ENV = "VPCOPILOT_ADVISORY_CACHE"
TIMEOUT = 20
BATCH_TIMEOUT = 90
BATCH_CHUNK = 250       # 400 in one request answered in 3.4s live; 250 keeps a chunk well inside it

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


# CVSS v4 renamed the vulnerable-system impact metrics. Mapping them onto the v3 names means ONE
# bucketing rule serves both vectors and the two can never drift apart.
_CVSS4_ALIAS = {"VC": "C", "VI": "I", "VA": "A"}


def severity_from_cvss(cvss: str) -> str:
    """CVSS vector → the project's four-level Severity. Absent scores are `medium`, never
    `critical` — an unknown severity must not jump the queue ahead of a measured one.

    **v4 is not optional any more.** H1 only ever met v3 vectors, so the v3-only regex looked
    complete. Measured against live OSV on 2026-07-29, `aiohttp 3.9.1` returns 70 advisories
    carrying 43 CVSS_V4 scores against 32 CVSS_V3, and **38 of the 70 records publish a v4 vector
    and nothing else** — every one of which fell through to the `medium` default regardless of what
    it actually said, including `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H` (an unauthenticated remote
    denial of service). One CVE at a time that is a cosmetic mislabel; H2 filters hundreds of
    advisories on this value, so it decides what gets resolved at all."""
    m = re.search(r"CVSS:(3\.[01]|4\.0)/(.+)", cvss or "")
    if not m:
        return "medium"
    parts = dict(p.split(":", 1) for p in m.group(2).split("/") if ":" in p)
    if m.group(1) == "4.0":
        parts = {_CVSS4_ALIAS.get(k, k): v for k, v in parts.items()}
    # Approximate the base score from the impact/exploitability metrics that dominate it. This is a
    # bucketing, not a CVSS implementation — OSV rarely publishes the numeric score.
    high_impact = sum(1 for k in ("C", "I", "A") if parts.get(k) == "H")
    net = parts.get("AV") == "N"
    # v4 splits v3's single AC into AC (complexity) and AT (attack requirements). A v3 vector has no
    # AT, so defaulting it to "N" leaves every v3 verdict byte-identical to before.
    easy = (parts.get("AC") == "L" and parts.get("PR") == "N" and parts.get("UI") == "N"
            and parts.get("AT", "N") == "N")
    if net and easy and high_impact >= 2:
        return "critical"
    if net and (high_impact >= 1 or easy):
        return "high"
    if high_impact >= 1:
        return "medium"
    return "low"


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_VTOKEN = re.compile(r"(\d+|[a-zA-Z]+)")


def _version_key(v: str) -> list:
    """A loose, ecosystem-agnostic ordering key.

    PyPI, npm and Maven each have their own version algebra and none of the three agrees with the
    others; `packaging` implements PEP 440 only and raises on Maven's `2.0-beta9` or `1.2.1.2-jre17`.
    Rather than pull in three comparators to answer one question — *is this fix newer than what I
    have* — split into digit and letter runs and order those. Digits compare numerically (so
    `1.10.0 > 1.9.2`, which a string sort gets backwards) and a letter run sorts BELOW a bare number
    at the same position, so `2.0-beta9 < 2.0`."""
    return [(1, int(t), "") if t.isdigit() else (0, 0, t.lower()) for t in _VTOKEN.findall(str(v))]


def comparable(v: str) -> bool:
    """A version with no digits in it cannot be ordered against anything meaningfully."""
    return any(t.isdigit() for t in _VTOKEN.findall(str(v or "")))


def version_gt(a: str, b: str) -> bool:
    """`a > b` under `_version_key`, padding the shorter with release-level zeros so a longer
    version is not automatically greater — `2.0-beta9` must not outrank `2.0`."""
    ka, kb = _version_key(a), _version_key(b)
    pad = (1, 0, "")
    for x, y in zip(ka + [pad] * (len(kb) - len(ka)), kb + [pad] * (len(ka) - len(kb)),
                    strict=True):
        if x != y:
            return x > y
    return False


# --------------------------------------------------------------------------- H2: package queries
def _coord_key(pkg: dict) -> str:
    return f"{pkg['ecosystem']}/{pkg['name']}@{pkg['version']}"


def _fallback(pkgs: list[dict], out: dict[str, list[str]], log: Callable) -> None:
    """Ask about each coordinate individually, and never let one failure end the run.

    `query_package` raises on any non-200 and lets httpx transport errors through. Unguarded, a
    single 429 here propagated out of `query_batch`, out of `deps.survey` — whose own per-package
    loop IS guarded — and out of `resolve_manifests`, which `pipeline` does not wrap. So the
    fallback that exists so a batch failure never loses a chunk became the thing that lost the
    whole scan, including the repo half of a `--manifest` run alongside a repo. The causes of a
    batch failure (OSV down, network cut, rate limiting) are exactly the causes that make these
    retries fail too, and the fallback issues up to `BATCH_CHUNK` sequential requests, which is
    the traffic pattern most likely to draw a 429 in the first place.

    A coordinate we could not ask about is left OUT of `out` and stamped on the package dict, so
    `deps.survey` reports it as unchecked. It must never read as "no advisories"."""
    for p in pkgs:
        try:
            out[_coord_key(p)] = [v.get("id") for v in query_package(p, log=log) if v.get("id")]
        except Exception as e:  # noqa: BLE001 — one coordinate's failure is not the manifest's
            log(f"  ⚠ could not check {_coord_key(p)}: {e} — reported as unchecked, not clean")
            p["error"] = str(e)
            out.pop(_coord_key(p), None)


def query_batch(packages: list[dict], *, log: Callable = print) -> dict[str, list[str]]:
    """`POST /v1/querybatch` — which of these coordinates has any advisory at all.

    **The batch endpoint returns ids and `modified` timestamps only, never the advisory bodies.**
    That is not in the shape of the response you would guess from `/v1/query`, and it inverts the
    obvious design: fetching each id would cost one request per *advisory* (70 for `aiohttp 3.9.1`
    alone), where `/v1/query` returns every full record for a coordinate in a single round trip.
    So batch is used for exactly what it is good at — one request that says which packages are worth
    asking about — and the bodies come from `query_package` for the hits only. On a 100-package
    manifest with 15 vulnerable that is 16 requests rather than 100.

    Measured live 2026-07-29: 400 queries answered in 3.4s, and the ids returned are identical to
    `/v1/query` for the same coordinate across five packages, so nothing is truncated."""
    import httpx
    out: dict[str, list[str]] = {}
    # One invalid ecosystem fails the ENTIRE batch with HTTP 400 ("error in query at index 1"), so
    # anything OSV would reject is dropped here rather than being allowed to cost every other
    # package in the manifest its answer.
    usable = [p for p in packages if p.get("ecosystem") in _KNOWN_ECOSYSTEMS and p.get("version")]
    for p in packages:
        if p not in usable:
            out[_coord_key(p)] = []
    for i in range(0, len(usable), BATCH_CHUNK):
        chunk = usable[i:i + BATCH_CHUNK]
        body = {"queries": [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                             "version": p["version"]} for p in chunk]}
        try:
            r = httpx.post(BATCH_API, json=body, timeout=BATCH_TIMEOUT)
            r.raise_for_status()
            results = r.json().get("results") or []
        except Exception as e:  # noqa: BLE001
            # Degrade to per-package queries rather than losing the chunk: batch is an optimisation,
            # and reporting "no advisories" because a request failed is the one answer that must
            # never be produced by an error.
            log(f"  ⚠ OSV batch query failed ({e}) — falling back to one query per package")
            _fallback(chunk, out, log)
            continue
        # `results` is positionally aligned with `queries`; a short list means OSV changed
        # its contract, and pairing the wrong package with the wrong answer is the worst outcome.
        for p, res in zip(chunk, results, strict=False):
            out[_coord_key(p)] = [v.get("id") for v in (res.get("vulns") or []) if v.get("id")]
        # `strict=False` above deliberately refuses to mispair, but that leaves the unanswered tail
        # with no entry at all — and the caller reads a missing key as "no advisories"
        # (`hits.get(key)` is None, so the package never reaches `vulnerable`). A short 200 would
        # therefore report packages as CLEAN that OSV never answered for. Ask about those
        # individually instead: slower, and the only answer that is not a guess.
        unanswered = [p for p in chunk if _coord_key(p) not in out]
        if unanswered:
            log(f"  ⚠ OSV batch answered {len(results)} of {len(chunk)} coordinate(s) — "
                f"querying the remaining {len(unanswered)} individually rather than reading "
                "them as clean")
            _fallback(unanswered, out, log)
    return out


def query_package(pkg: dict, *, log: Callable = print) -> list[dict]:
    """`POST /v1/query` — every full advisory record for one exact coordinate.

    The version is sent because OSV does the range matching; asking without one returns the union
    over all versions (87 for aiohttp against 70 for `3.9.1`). It is never sent unvalidated — see
    `inputs/manifest.py` for why a version string OSV cannot parse is more dangerous than no version
    at all."""
    import httpx
    r = httpx.post(QUERY_API, json={"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
                                    "version": pkg["version"]}, timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f"OSV.dev returned {r.status_code} for "
                           f"{_coord_key(pkg)}: {r.text[:200]}")
    vulns = r.json().get("vulns") or []
    for v in vulns:                      # share H1's cache: an advisory body is an advisory body
        if v.get("id"):
            _store(v["id"], v)
    return vulns


_KNOWN_ECOSYSTEMS = {"PyPI", "npm", "Maven", "Go", "crates.io", "RubyGems", "Packagist",
                     "NuGet", "Hex", "Debian", "Alpine", "Ubuntu"}


def alias_groups(records: list[dict]) -> list[list[dict]]:
    """Collapse records that are the same advisory under different ids.

    Not an optimisation — a correctness requirement. Live, `aiohttp 3.9.1` returns **70 records that
    are 35 advisories**: OSV publishes a GHSA and a PYSEC entry for every one, cross-linked by
    `aliases`. Without this, H2 would resolve each advisory twice, pay two model calls for it, and
    emit two band-aids for one hole — and the duplicate would not look like a duplicate, because the
    two records carry different ids.

    Union-find over `aliases`. `related` is deliberately NOT followed: it links advisories that are
    *about* each other rather than identical, and merging on it would collapse distinct
    vulnerabilities into one."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for rec in records:
        rid = rec.get("id") or ""
        if not rid:
            continue
        find(rid)
        for al in rec.get("aliases") or []:
            union(rid, al)
    groups: dict[str, list[dict]] = {}
    for rec in records:
        if rec.get("id"):
            groups.setdefault(find(rec["id"]), []).append(rec)
    return list(groups.values())


def preferred_record(group: list[dict]) -> dict:
    """The record to reason over, from a set describing one advisory.

    Prefers the one carrying the most usable facts rather than a fixed id-prefix order: a CVE record
    is often a GIT range with commit SHAs while its GHSA alias carries the installable version
    (H1's finding), but which id holds the prose varies by advisory."""
    def score(r: dict) -> tuple:
        rows = _affected_rows(r)
        return (any(x["versioned"] for x in rows), bool(r.get("severity")),
                bool(r.get("summary")), len(r.get("details") or ""),
                (r.get("database_specific") or {}).get("cwe_ids") is not None)
    return sorted(group, key=score, reverse=True)[0]


def normalize_record(rec: dict, group: list[dict] | None = None) -> dict:
    """A raw OSV record → the same shape `resolve()` returns, without any network access.

    H2 already holds the full bodies from `query_package`, so re-fetching by id to reuse `resolve()`
    would be one request per advisory for data already in memory. The `affected` rows are merged
    across the whole alias group, because that is exactly where H1 found the installable version to
    live when the record you asked for did not have one."""
    group = group or [rec]
    rows: list[dict] = []
    for r in sorted(group, key=lambda r: r is not rec):     # the preferred record's rows first
        rows += _affected_rows(r)
    sev = ""
    for r in group:                                        # prefer any scored vector over none
        sev = next((s.get("score") for s in r.get("severity") or [] if s.get("score")), "") or sev
        if sev:
            break
    details = rec.get("details") or ""
    cwes: list[str] = []
    for r in group:
        cwes += (r.get("database_specific") or {}).get("cwe_ids") or []
    return {
        "id": rec.get("id") or "",
        "aliases": sorted(({a for r in group for a in (r.get("aliases") or [])}
                           | {r.get("id") for r in group if r.get("id")}) - {rec.get("id")}),
        "consulted": [r.get("id") for r in group if r.get("id")],
        "summary": rec.get("summary") or _first_sentence(details),
        "details": details[:4000],
        "cwe_ids": list(dict.fromkeys(cwes)),
        "cvss": sev,
        "published": rec.get("published") or "",
        "withdrawn": rec.get("withdrawn") or "",
        "affected": rows,
        "references": [r.get("url") for r in (rec.get("references") or [])][:12],
    }


def upgrade_target_for(advisory: dict, package: str, ecosystem: str, installed: str) -> dict:
    """The upgrade to recommend to someone running `package @ installed` — **not** the advisory's
    lowest fixed version, and **not** some other package's.

    `upgrade_target()` — H1's version, kept unchanged for the single-CVE path — answers a different
    question: *what does this advisory fix*, with no installed coordinate to relate it to. It takes
    the first `affected` row carrying a version, whatever package that row names and whichever
    maintenance branch it describes. H1 asks about one advisory at a time and shows the package
    beside the version, so a reader can see the mismatch. H2 turns the answer into a per-package
    recommendation, where two things go wrong:

    1. **The wrong package — reproduced live, 2026-07-29.** 10 of 145 advisories sampled list
       several packages. For Log4Shell (`GHSA-jfh8-c2jp-5v3q`), a manifest pinning
       `org.ops4j.pax.logging:pax-logging-log4j2 1.10.0` is told to upgrade to **2.15.0**, which is
       `log4j-core`'s fix and not a version pax-logging has ever published. Its own fix is `1.10.8`.
       Same shape on `GHSA-p6mc-m468-83gw`: `lodash` is fixed at `4.17.19`, `lodash-es` at
       `4.17.20`, and `lodash.pick` **not at all** (`last_affected 4.4.0`), so a manifest holding
       `lodash.pick` gets sent to install a version that does not exist for it.
    2. **The wrong branch.** Selection ignores the installed version entirely, so which of an
       advisory's maintenance branches you are told about is decided by OSV's document order.
       Log4Shell publishes `2.13.0→2.15.0`, `2.0-beta9→2.3.1` and `2.4→2.12.2` for one package; the
       live record happens to list the first of those first, so `2.14.1` currently gets the right
       answer by luck. Nothing in the OSV schema promises that order, and the failure it permits is
       recommending `2.3.1` to someone running `2.14.1` — a downgrade, presented as the fix.

    So: filter to the rows for THIS package, then take the smallest published fix strictly greater
    than what is installed. Where nothing published is newer, say that instead of naming the closest
    number — a version that would not fix anything is worse than admitting there is no upgrade."""
    rows = [r for r in (advisory.get("affected") or [])
            if r.get("package") and _same_package(r["package"], package, r.get("ecosystem", ""), ecosystem)]
    base = {"package": package, "ecosystem": ecosystem, "installed": installed,
            "fixed_version": "", "vulnerable_range": "", "note": ""}
    if not rows:
        # The advisory reached us because OSV matched this coordinate, so silence here means the
        # affected block is shaped in a way this cannot read — report it rather than guessing.
        base["note"] = (f"{advisory.get('id', 'advisory')} matched {ecosystem}/{package} but "
                        "publishes no version range for it")
        return base
    fixes = sorted({f for r in rows for f in r.get("fixed_versions") or []}, key=_version_key)
    intro = [v for r in rows for v in r.get("introduced") or [] if not _COMMITISH.match(str(v))]
    base["vulnerable_range"] = ", ".join(dict.fromkeys(intro)) or "see advisory"
    if not comparable(installed):
        base["note"] = (f"cannot order '{installed}' against the published fixes "
                        f"({', '.join(fixes) or 'none'}) — pick one by hand")
        return base
    higher = [f for f in fixes if comparable(f) and version_gt(f, installed)]
    if higher:
        base["fixed_version"] = higher[0]
        return base
    commits = [f for r in rows for f in r.get("fixed", [])]
    if fixes:
        base["note"] = (f"every published fix ({', '.join(fixes)}) is at or below the installed "
                        f"{installed} — the fix for this branch is not released, or {installed} "
                        "predates the affected line")
    elif commits:
        base["note"] = ("OSV records the fix as a source commit, not a released version: "
                        + ", ".join(commits[:2]))
    else:
        base["note"] = f"OSV lists no fixed version for {ecosystem}/{package}"
    return base


def _same_package(row_name: str, want: str, row_eco: str, want_eco: str) -> bool:
    if want_eco and row_eco and row_eco != want_eco:
        return False
    if row_name == want:
        return True
    if (row_eco or want_eco) == "PyPI":     # PEP 503: Flask_Login and flask-login are one package
        return re.sub(r"[-_.]+", "-", row_name).lower() == re.sub(r"[-_.]+", "-", want).lower()
    return False


def upgrade_target(advisory: dict) -> dict:
    """The single best "upgrade to X" recommendation, or an honest statement that OSV has none.

    Prefers a row with an installable version. A GIT-only advisory yields `fixed_version: ""` and a
    note carrying the commit — because telling an operator to "upgrade to
    24a6d64966d99182e95f5d3a29541ef2fec397ad" is not a recommendation."""
    rows = advisory.get("affected") or []
    best = next((r for r in rows if r["versioned"]), None)
    if best:
        return {"package": best["package"], "ecosystem": best["ecosystem"],
                "fixed_version": sorted(best["fixed_versions"], key=_version_key)[0],
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
