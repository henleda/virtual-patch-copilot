"""H1 — the CVE/advisory input path. Offline: OSV is faked, the resolve agent is faked.

The live behaviours these fakes encode were all observed against the real api.osv.dev — see the
docstrings. Three of them are not guessable from the OSV schema and each one silently degrades the
answer if unhandled."""
import json

import pytest

from vpcopilot.inputs import osv

_REAL_FETCH = osv.fetch      # captured at import, before the autouse fake replaces it

# Shapes taken verbatim from real api.osv.dev responses.
LODASH = {"id": "GHSA-jf85-cpcp-j695", "aliases": ["CVE-2019-10744"],
          "summary": "Prototype Pollution in lodash", "details": "lodash before 4.17.12 …",
          "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
          "database_specific": {"cwe_ids": ["CWE-1321"]},
          "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                                 {"fixed": "4.17.12"}]}]}],
          "references": [{"url": "https://example.test/a", "type": "ADVISORY"}]}

# CVE-2024-23334: querying by CVE id returns a GIT-range record with NO package and commit-SHA
# "fixed" values. The installable 3.9.2 only exists on the GHSA alias.
AIOHTTP_CVE = {"id": "CVE-2024-23334", "aliases": ["GHSA-5h86-8mv2-jq9f", "PYSEC-2024-24"],
               "summary": "aiohttp.web.static(follow_symlinks=True) is vulnerable to directory traversal",
               "details": "When 'follow_symlinks' is set to True there is no validation …",
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
               "database_specific": {"cwe_ids": ["CWE-22"]},
               "affected": [{"ranges": [{"type": "GIT", "repo": "https://github.com/aio-libs/aiohttp",
                                         "events": [{"introduced": "0"},
                                                    {"fixed": "24a6d64966d99182e95f5d3a29541ef2fec397ad"}]}]}],
               "references": []}
AIOHTTP_GHSA = {"id": "GHSA-5h86-8mv2-jq9f", "aliases": ["CVE-2024-23334"], "summary": "aiohttp traversal",
                "details": "…", "severity": [], "database_specific": {"cwe_ids": ["CWE-22"]},
                "affected": [{"package": {"ecosystem": "PyPI", "name": "aiohttp"},
                              "ranges": [{"type": "ECOSYSTEM",
                                          "events": [{"introduced": "1.0.5"}, {"fixed": "3.9.2"}]}]}],
                "references": []}
# CVE-2021-41773: an OS-level CVE — no package at all, no fixed version, versions only in
# database_specific.extracted_events.
HTTPD = {"id": "CVE-2021-41773", "aliases": ["BIT-apache-2021-41773"], "summary": "",
         "details": "A flaw was found in a change made to path normalization in Apache HTTP "
                    "Server 2.4.49. An attacker could use a path traversal attack.",
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
         "database_specific": {},
         "affected": [{"ranges": [{"type": "GIT", "events": [{"introduced": "bbacd798"},
                                                             {"last_affected": "bbacd798"}],
                                   "database_specific": {"cpe": "cpe:2.3:a:apache:http_server:2.4.49",
                                                         "extracted_events": [{"introduced": "2.4.49"}]}}]}],
         "references": []}

RECORDS = {r["id"]: r for r in (LODASH, AIOHTTP_CVE, AIOHTTP_GHSA, HTTPD)}


@pytest.fixture(autouse=True)
def _fake_osv(monkeypatch):
    def fetch(advisory_id, *, log=print):
        if advisory_id not in RECORDS:
            raise RuntimeError(f"no advisory '{advisory_id}' in OSV.dev")
        return RECORDS[advisory_id]
    monkeypatch.setattr(osv, "fetch", fetch)


# ---- the three things the real API does that the schema does not prepare you for ----
def test_a_cve_id_resolves_through_its_alias_to_an_installable_version():
    """Observed live: `CVE-2024-23334` alone yields a GIT range whose only `fixed` value is
    24a6d64966d99182e95f5d3a29541ef2fec397ad. Telling an operator to "upgrade to" that is not a
    recommendation. The real 3.9.2 lives on the GHSA alias, so resolve follows aliases."""
    a = osv.resolve("CVE-2024-23334", log=lambda m: None)
    t = osv.upgrade_target(a)
    assert t["fixed_version"] == "3.9.2"
    assert t["package"] == "aiohttp" and t["ecosystem"] == "PyPI"
    assert a["consulted"] == ["CVE-2024-23334", "GHSA-5h86-8mv2-jq9f"]


def test_a_commit_sha_is_never_offered_as_an_upgrade_target():
    """The mirror of the above: with no alias to rescue it, the honest answer is that OSV has no
    installable version — not a 40-character hex string."""
    a = osv.resolve("CVE-2024-23334", follow_aliases=False, log=lambda m: None)
    t = osv.upgrade_target(a)
    assert t["fixed_version"] == ""
    assert "source commit" in t["note"] and "24a6d649" in t["note"]


def test_an_advisory_with_no_package_still_resolves():
    """OS-level CVEs have no ecosystem package at all — identity falls back to the CPE, and the
    affected version lives in database_specific.extracted_events."""
    a = osv.resolve("CVE-2021-41773", log=lambda m: None)
    t = osv.upgrade_target(a)
    assert t["fixed_version"] == "" and "no fixed version" in t["note"]
    assert "apache" in t["package"]
    assert "2.4.49" in t["vulnerable_range"]


def test_an_empty_summary_falls_back_to_the_first_sentence_of_details():
    """`summary` is empty on many CVE records; `details` is where the prose actually lives."""
    a = osv.resolve("CVE-2021-41773", log=lambda m: None)
    assert a["summary"].startswith("A flaw was found") and a["summary"].endswith(".")


def test_the_clean_case_needs_no_alias_hop():
    a = osv.resolve("GHSA-jf85-cpcp-j695", log=lambda m: None)
    assert osv.upgrade_target(a)["fixed_version"] == "4.17.12"
    assert a["consulted"] == ["GHSA-jf85-cpcp-j695"]


# ---- ids and severity ----
@pytest.mark.parametrize("vid,ok", [
    ("CVE-2024-23334", True), ("GHSA-5h86-8mv2-jq9f", True), ("PYSEC-2024-24", True),
    ("GO-2024-1234", True), ("RUSTSEC-2021-0001", True),
    ("", False), ("not-an-id", False), ("CVE-24-1", False), ("../../etc/passwd", False),
])
def test_advisory_ids_are_validated(vid, ok):
    assert osv.valid_id(vid) is ok


def test_a_bad_id_is_refused_before_any_request(monkeypatch):
    monkeypatch.setattr(osv, "fetch", lambda *a, **k: pytest.fail("must not fetch"))
    with pytest.raises(RuntimeError, match="not an advisory id"):
        osv.resolve("'; DROP TABLE", log=lambda m: None)


def test_an_unknown_advisory_says_so():
    with pytest.raises(RuntimeError, match="no advisory"):
        osv.resolve("CVE-1999-0001", log=lambda m: None)


@pytest.mark.parametrize("vector,expect", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "medium"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "low"),
    ("", "medium"),          # unknown is never critical — it must not jump the queue
    ("garbage", "medium"),
])
def test_severity_buckets(vector, expect):
    assert osv.severity_from_cvss(vector) == expect


# ---- the cache ----
def test_the_cache_is_used_and_written(tmp_path, monkeypatch):
    monkeypatch.setenv(osv.CACHE_ENV, str(tmp_path))
    monkeypatch.setattr(osv, "fetch", _REAL_FETCH)   # undo the autouse fake for this one
    calls = []

    class R:
        status_code = 200
        def json(self): return LODASH
    import httpx
    monkeypatch.setattr(httpx, "get", lambda url, **k: calls.append(url) or R())
    osv.fetch("GHSA-jf85-cpcp-j695")
    osv.fetch("GHSA-jf85-cpcp-j695")
    assert len(calls) == 1                                   # second call served from disk
    assert json.loads((tmp_path / "GHSA-jf85-cpcp-j695.json").read_text())["id"] == LODASH["id"]


# ---- the finding + decision + remediation the pipeline consumes ----
class FakeProfile:
    def __init__(self, observable=True, **kw):
        from vpcopilot.schemas import Severity, VulnClass
        self.network_observable = observable
        self.reason = kw.get("reason", "the advisory names the request path")
        self.vuln_class = VulnClass("other")
        self.severity = Severity("high")
        self.title = kw.get("title", "t")
        self.description = "d"
        self.exploit_sketch = kw.get("sketch", "GET /static/../../etc/passwd")
        self.paths = kw.get("paths", ["/static/../../etc/passwd"])
        self.http_methods = ["GET"]
        self.parameters, self.headers, self.example_requests, self.caveats = [], [], [], []
        self.confidence = 0.8


def _resolve(monkeypatch, advisory_id, profile):
    from vpcopilot.agents import resolve as ra
    from vpcopilot.inputs.cve import resolve_advisory
    monkeypatch.setattr(ra, "run", lambda h, a: profile)
    return resolve_advisory(None, advisory_id, log=lambda m: None)


def test_an_observable_advisory_becomes_a_finding_that_triage_can_route(monkeypatch):
    r = _resolve(monkeypatch, "CVE-2024-23334", FakeProfile())
    f = r["finding"]
    assert f.id == "CVE-2024-23334" and f.source == "osv:CVE-2024-23334"
    assert f.file == "" and f.line == 0 and f.code_snippet == ""   # there is no source
    assert f.endpoint == "/static/../../etc/passwd" and f.http_method == "GET"
    assert f.severity.value == "high"
    assert r["decision"] is None                                    # triage runs normally


def test_the_cwe_picks_the_vuln_class_before_the_agent_does(monkeypatch):
    """CWE-1321 is prototype pollution → mass_assignment. Deterministic where the advisory tells
    us; the agent only guesses when it does not."""
    r = _resolve(monkeypatch, "GHSA-jf85-cpcp-j695", FakeProfile())
    assert r["finding"].vuln_class.value == "mass_assignment"


def test_a_non_observable_advisory_routes_to_no_bandaid_in_code(monkeypatch):
    """The acceptance requires this, so it is decided in code rather than asked of triage — a hard
    requirement must not depend on a model honouring a prompt."""
    r = _resolve(monkeypatch, "CVE-2024-23334",
                 FakeProfile(observable=False, reason="exploitation needs a local file."))
    d = r["decision"]
    assert d is not None and d.no_bandaid is True and d.bandaids == []
    assert "local file" in d.residual_risk
    assert "3.9.2" in d.residual_risk               # and it points at the real fix
    assert r["finding"].exploit_sketch.startswith("no network-observable exploitation pattern")


def test_the_cure_is_a_version_bump_never_a_patch(monkeypatch):
    r = _resolve(monkeypatch, "CVE-2024-23334", FakeProfile())
    rem = r["remediation"]
    assert rem.kind == "dependency_upgrade"
    assert rem.fixed_version == "3.9.2" and rem.package == "aiohttp"
    assert rem.patched_content == "" and rem.diff == "" and rem.file == ""
    assert "3.9.2" in rem.summary and "upstream" in rem.pr_body


def test_an_advisory_with_no_fix_says_so_rather_than_inventing_one(monkeypatch):
    r = _resolve(monkeypatch, "CVE-2021-41773", FakeProfile())
    rem = r["remediation"]
    assert rem.fixed_version == "" and "no fixed version" in rem.summary.lower()
    assert "No installable fixed version" in rem.pr_body


def test_a_declining_agent_cannot_smuggle_paths_through(monkeypatch):
    """The prompt forbids it, but a model that says "cannot be observed" and lists paths anyway
    must not have those paths reach generate."""
    from vpcopilot.agents import resolve as ra
    from vpcopilot.harness import Harness   # noqa: F401 — only for the type
    prof = FakeProfile(observable=False, paths=["/admin"])
    monkeypatch.setattr(ra.Harness, "run", lambda self, *a, **k: prof, raising=False)

    class H:
        def run(self, *a, **k): return prof
    out = ra.run(H(), {"id": "CVE-2024-23334"})
    assert out.paths == [] and out.http_methods == []


# ---- the pipeline entry, correlation identity, and the PR decline ----
def test_the_pipeline_refuses_a_missing_or_conflicting_input():
    """repo and --cve are alternatives; --spec is additive (H3) and may accompany a repo."""
    from vpcopilot.pipeline import run_pipeline
    with pytest.raises(ValueError, match="pass a repo path"):
        run_pipeline()
    with pytest.raises(ValueError, match="cannot be combined"):
        run_pipeline("/some/repo", advisory="CVE-2024-23334")
    with pytest.raises(ValueError, match="cannot be combined"):
        run_pipeline(advisory="CVE-2024-23334", spec_path="/some/spec.yaml")


def test_a_file_less_finding_gets_its_own_coverage_key():
    """Before this, `endpoint_of("")` returned "" so every advisory's service_policy collapsed onto
    the single key `service_policy:` and all but the first were logged "already covered" — silently
    generating no band-aid at all."""
    from vpcopilot.correlate import coverage_key
    a = coverage_key("service_policy", "", identity="osv:CVE-2024-23334")
    b = coverage_key("service_policy", "", identity="osv:CVE-2019-10744")
    assert a != b
    # and the repo path is untouched
    assert coverage_key("service_policy", "app/api/pay/route.js") == "service_policy:pay"
    assert coverage_key("waf", "", identity="x") == "waf"        # LB-wide is still LB-wide


def test_identity_is_used_verbatim_not_through_endpoint_of():
    """`endpoint_of` returns the second-to-last segment — right for a repo path, wrong for a URL,
    where /api/pay and /api/login would both collapse to `api`."""
    from vpcopilot.correlate import coverage_key
    assert coverage_key("service_policy", "", identity="/api/pay") != \
           coverage_key("service_policy", "", identity="/api/login")


def test_two_advisories_of_one_class_do_not_dedup_into_each_other():
    """The dedup key was (file, class, endpoint or Lline) — ("", cls, "L0") for every advisory."""
    from vpcopilot.pipeline import _dedup_findings
    from vpcopilot.schemas import Finding

    def f(fid):
        return Finding(id=fid, title=fid, vuln_class="other", severity="high", description="d",
                       exploit_sketch="e", source=f"osv:{fid}")
    kept = _dedup_findings([f("CVE-1"), f("CVE-2")], lambda m: None, {})
    assert {k.id for k in kept} == {"CVE-1", "CVE-2"}


def test_pr_declines_a_dependency_upgrade_without_touching_github(monkeypatch):
    from vpcopilot import pr
    monkeypatch.setattr(pr, "_resolve_token", lambda *a: pytest.fail("must not need a token"))
    res = pr.open_pr({"finding_id": "CVE-2024-23334", "kind": "dependency_upgrade",
                      "package": "aiohttp", "ecosystem": "PyPI", "fixed_version": "3.9.2",
                      "vulnerable_range": "1.0.5", "summary": "s", "pr_title": "t", "pr_body": "b"},
                     "acme/app", log=lambda m: None)
    assert res["mode"] == "advisory" and res["fixed_version"] == "3.9.2"
    assert "upgrade aiohttp to 3.9.2" in res["recommendation"]


def test_a_code_fix_with_no_patch_still_raises():
    """The advisory branch must not become a way for a broken code fix to pass silently."""
    from vpcopilot import pr
    with pytest.raises(RuntimeError, match="no patched_content"):
        pr.open_pr({"finding_id": "f1", "file": "a.js", "patched_content": "",
                    "pr_title": "t", "pr_body": "b"}, "acme/app", log=lambda m: None)


def test_a_dry_run_can_now_report_a_missing_patch_instead_of_raising():
    """The check used to sit above the dry-run branch, so --dry-run raised identically to a live
    run and could preview nothing."""
    from vpcopilot import pr
    res = pr.open_pr({"finding_id": "f1", "file": "a.js", "patched_content": "",
                      "pr_title": "t", "pr_body": "b"}, "acme/app", dry_run=True,
                     log=lambda m: None)
    assert res["mode"] == "dry_run" and res["has_patch"] is False


def test_the_resolve_agent_is_registered_everywhere_it_has_to_be():
    """Four sites, not the three the roadmap names — bench_model.py is the fourth, and an agent
    missing from it is absent from every benchmark's model map."""
    from vpcopilot.bench_model import AGENTS
    from vpcopilot.config import AGENT_NAMES
    from vpcopilot.console.app import AGENT_ROLES
    assert "resolve" in AGENT_NAMES and "resolve" in AGENTS and "resolve" in AGENT_ROLES
    assert "resolve" in (__import__("pathlib").Path("src/vpcopilot/report.py").read_text())


def test_every_shipped_config_names_the_resolve_agent():
    """An agent absent from agents.yaml silently falls back to the defaults model, and run.json
    then records that as fact."""
    import pathlib

    from vpcopilot.config import load_config
    for cfg in sorted(pathlib.Path("config").glob("agents*.yaml")):
        assert load_config(str(cfg)).for_agent("resolve").model, cfg


def test_the_console_scan_surface_accepts_an_advisory():
    """One module function, two surfaces — a CVE has to be reachable from the console too, and the
    both/neither rule has to hold across the wire."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    c = TestClient(A.app)
    assert c.post("/api/scan", json={"repo": "", "cve": ""}).status_code == 400
    assert c.post("/api/scan", json={"repo": "/x", "cve": "CVE-2024-23334"}).status_code == 400
    html = (__import__("pathlib").Path(A.__file__).parent / "static" / "index.html").read_text()
    assert 'id="scanCve"' in html and "cve," in html
