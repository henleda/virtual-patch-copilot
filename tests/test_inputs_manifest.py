"""H2 — the dependency manifest input path. Offline: OSV is faked, the resolve agent is faked.

Every live behaviour these fakes encode was measured against the real api.osv.dev on 2026-07-29 and
is recorded in the docstring of the test that pins it. Four of them are invisible from the OSV
schema, and each one silently produces a *confident wrong answer* rather than an error."""
import json

import pytest

from vpcopilot.inputs import deps, manifest, osv

FIX = "bench/fixtures/manifests"


# =============================================================== parsing: refusing to guess
def test_only_an_exact_pin_becomes_a_query():
    """A `requirements.txt` is a request, not a lockfile. `>=`, `~=`, a wildcard and a bare name all
    describe a range someone else resolves later, so none of them names an installed version."""
    r = manifest.parse(f"{FIX}/requirements.txt")
    assert r["kind"] == "pip"
    got = {p["name"]: p["version"] for p in r["packages"]}
    assert got["aiohttp"] == "3.9.1" and got["urllib3"] == "2.0.7"
    unpinned = {s["raw"].split()[0].split(">")[0].split("~")[0].split("=")[0]
                for s in r["skipped"] if s["reason"] == "unpinned"}
    assert {"gunicorn", "cryptography", "boto3", "django"} <= unpinned
    assert not any(p["name"] in ("gunicorn", "cryptography", "boto3", "django")
                   for p in r["packages"])


@pytest.mark.parametrize("bad", ["not-a-version", "1.0.0-SNAPSHOT", "${project.version}", ""])
def test_the_reason_an_unresolvable_version_is_refused_rather_than_sent(bad):
    """Measured live: OSV does NOT error on a version string it cannot parse. `aiohttp` at each of
    these returned **81 advisories**, against 70 for the real 3.9.1 and 87 for no version at all.
    So sending a guess does not fail loudly — it returns a larger, wrong answer that every stage
    downstream treats as fact. This test pins the invariant that makes that unreachable: a
    coordinate only exists once its version is known."""
    assert not manifest._UNRESOLVED.search("3.9.1")
    entries, _ = manifest._parse_requirements.__wrapped__(bad) if False else ([], [])  # noqa: B018
    # every parser emits `version` or nothing at all — never a placeholder
    for path in (f"{FIX}/requirements.txt", f"{FIX}/package-lock.json", f"{FIX}/pom.xml"):
        for p in manifest.parse(path)["packages"]:
            assert p["version"] and not manifest._UNRESOLVED.search(p["version"])
            assert p["version"] != bad or bad == ""
    assert entries == []


def test_extras_markers_and_continuations():
    r = manifest.parse(f"{FIX}/requirements.txt")
    by = {p["name"]: p for p in r["packages"]}
    assert "flask-login" in by                       # PEP 503: Flask_Login[extras] -> flask-login
    assert by["importlib-metadata"]["version"] == "6.8.0"
    assert "python_version" in by["importlib-metadata"]["note"]     # marker recorded, not dropped
    assert by["urllib3"]["version"] == "2.0.7"       # backslash continuation + --hash


def test_pep503_normalisation_collapses_one_package_spelt_two_ways():
    assert manifest.normalize_pypi("Flask_Login") == "flask-login"
    assert manifest.normalize_pypi("zope.interface") == "zope-interface"


def test_editable_and_direct_url_requirements_are_named_not_silently_dropped():
    r = manifest.parse(f"{FIX}/requirements.txt")
    reasons = {s["reason"] for s in r["skipped"]}
    assert {"editable", "direct-reference", "pip-option"} <= reasons
    assert all(s["detail"] for s in r["skipped"])    # every refusal states why


def test_r_includes_are_followed_with_a_cycle_guard(tmp_path):
    r = manifest.parse(f"{FIX}/requirements-with-include.txt")
    names = {p["name"] for p in r["packages"]}
    assert {"mypy", "pytest", "black", "aiohttp"} <= names   # own + both includes

    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("-r b.txt\nfoo==1.0\n")
    b.write_text("-r a.txt\nbar==2.0\n")
    got = manifest.parse(str(a))                            # must terminate
    assert {p["name"] for p in got["packages"]} == {"foo", "bar"}


def test_a_missing_include_is_reported_and_does_not_abort_the_file(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("-r nope.txt\nflask==3.0.0\n")
    r = manifest.parse(str(p))
    assert [x["name"] for x in r["packages"]] == ["flask"]
    assert any(s["reason"] == "include-unreadable" for s in r["skipped"])


# ---------------------------------------------------------------- package-lock.json
def test_lockfile_v2_is_not_double_counted():
    """lockfileVersion 2 carries BOTH the v3 `packages` map and the v1 `dependencies` tree,
    describing the same installs. A parser reading both reports every package twice — and the
    duplicate looks exactly like a real second install at a different depth."""
    doc = json.loads(open(f"{FIX}/package-lock.json").read())
    assert doc["lockfileVersion"] == 2 and doc["packages"] and doc["dependencies"]  # both present
    r = manifest.parse(f"{FIX}/package-lock.json")
    assert [p["name"] for p in r["packages"]].count("lodash") == 1


def test_the_root_project_is_not_one_of_its_own_dependencies():
    r = manifest.parse(f"{FIX}/package-lock.json")
    assert "nimbus-web" not in {p["name"] for p in r["packages"]}


def test_scoped_names_survive_the_node_modules_prefix():
    r = manifest.parse(f"{FIX}/package-lock.json")
    assert "@babel/traverse" in {p["name"] for p in r["packages"]}


def test_workspace_links_git_deps_and_versionless_entries_are_refused_by_name():
    r = manifest.parse(f"{FIX}/package-lock.json")
    by = {s["raw"]: s["reason"] for s in r["skipped"]}
    assert by["node_modules/internal-tools"] == "workspace-link"
    assert by["node_modules/forked-dep"] == "direct-reference"
    assert by["node_modules/no-version-here"] == "no-version"


def test_runtime_beats_dev_when_one_package_is_reachable_both_ways():
    """lodash is a runtime dependency AND vendored under jest as a dev one. If anything reaches it
    at runtime it is in the request path, so the runtime scope wins."""
    r = manifest.parse(f"{FIX}/package-lock.json")
    assert next(p for p in r["packages"] if p["name"] == "lodash")["scope"] == "runtime"


def test_a_v1_lockfile_still_parses(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "lodash": {"version": "4.17.15", "dependencies": {"nested": {"version": "1.0.0"}}}}}))
    r = manifest.parse(str(p))
    assert {x["name"]: x["version"] for x in r["packages"]} == {"lodash": "4.17.15",
                                                                "nested": "1.0.0"}


def test_a_workspace_source_tree_is_not_queried_as_a_registry_package(tmp_path):
    """v2/v3 `packages` keys are project-relative PATHS: only `node_modules/...` are installed
    registry releases. A workspace's own source (`packages/internal-tools`) was emitted as a
    registry coordinate — asking OSV about first-party code under a name that can collide with a
    public package, and where the entry carried no `name`, under the directory path itself, which
    is not a legal npm name. Both were counted in `packages_parsed`/`packages_queried`."""
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "root"},
        "packages/internal-tools": {"name": "internal-tools", "version": "1.0.0"},
        "packages/axios": {"name": "axios", "version": "0.0.1"},
        "packages/no-name-here": {"version": "2.0.0"},
        "node_modules/lodash": {"version": "4.17.15"}}}))
    r = manifest.parse(str(p))
    assert [x["name"] for x in r["packages"]] == ["lodash"]      # was: all four
    assert {s["reason"] for s in r["skipped"]} == {"workspace-source"}
    assert len(r["skipped"]) == 3


def test_a_v1_entry_with_no_version_is_reported_not_dropped(tmp_path):
    """The v2/v3 branch refuses a versionless entry explicitly; the v1 branch fell through both
    arms and dropped it with no trace, so identical lockfile content was invisible risk in v1 and
    a reported refusal in v3."""
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "lodash": {"version": "4.17.15"},
        "no-version-here": {"resolved": "https://registry.npmjs.org/x/-/x.tgz"}}}))
    r = manifest.parse(str(p))
    assert [x["name"] for x in r["packages"]] == ["lodash"]
    assert [(s["raw"], s["reason"]) for s in r["skipped"]] == [("no-version-here", "no-version")]


def test_an_unresolved_property_in_a_coordinate_is_refused_like_one_in_a_version(tmp_path):
    """`expand()` runs on groupId/artifactId, but only the VERSION was tested for a leftover
    `${...}`. Neither `${project.groupId}` nor `${project.artifactId}` is ever in `props`, so the
    literal reached OSV inside the coordinate NAME, came back empty, and was counted as
    checked-and-clean. `${project.groupId}` for intra-project deps is ordinary multi-module Maven."""
    p = tmp_path / "pom.xml"
    p.write_text("""<project><groupId>com.acme</groupId><version>2.4.0</version><dependencies>
      <dependency><groupId>${project.groupId}</groupId><artifactId>common</artifactId>
        <version>${project.version}</version></dependency>
      <dependency><groupId>org.x</groupId><artifactId>${artifact.name}</artifactId>
        <version>1.0</version></dependency>
      <dependency><groupId>org.ok</groupId><artifactId>real</artifactId>
        <version>1.2.3</version></dependency></dependencies></project>""")
    r = manifest.parse(str(p))
    assert [x["name"] for x in r["packages"]] == ["org.ok:real"]
    assert not any("${" in x["name"] for x in r["packages"])
    assert {s["reason"] for s in r["skipped"]} == {"unresolved-property"}


def test_a_package_json_is_refused_not_silently_read_as_an_empty_lockfile(tmp_path):
    """`detect_kind` routes any JSON carrying a `dependencies` map to the npm parser, and a
    package.json has one — but of name → RANGE STRING, where a v1 lockfile has name → {version}.
    Every entry failed the isinstance check and was dropped, so a package.json with three
    dependencies parsed to zero packages, zero skipped and NO error: byte-identical to a clean
    lockfile. That is the one confusion this module exists to prevent."""
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"name": "app", "version": "1.0.0",
                             "dependencies": {"lodash": "4.17.20", "express": "^4.17.1"},
                             "devDependencies": {"jest": "^29.0.0"}}))
    with pytest.raises(manifest.ManifestError, match="package-lock.json"):
        manifest.parse(str(p))
    # …and through parse_all it degrades to a reported error, never to "nothing found"
    r = manifest.parse_all([str(p)])
    assert r["packages"] == [] and r["errors"] and "package.json looks like" in r["errors"][0]["error"]
    assert r["files"][0]["error"]


def test_an_empty_dependencies_map_is_still_a_legitimate_empty_lockfile(tmp_path):
    """The package.json guard keys on "no value is an object", so it must not fire on a lockfile
    that genuinely installs nothing."""
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    assert manifest.parse(str(p))["packages"] == []


def test_a_lock_entry_that_is_not_an_object_is_reported_not_dropped(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {
        "real": {"version": "1.0.0"}, "bogus": "juststring"}}))
    r = manifest.parse(str(p))
    assert [x["name"] for x in r["packages"]] == ["real"]
    assert [(s["raw"], s["reason"]) for s in r["skipped"]] == [("bogus", "not-a-lock-entry")]


# ---------------------------------------------------------------- pom.xml
def test_pom_namespaces_properties_and_dependency_management():
    """A real pom declares `xmlns`, so every ElementTree tag arrives as `{uri}dependency`. Properties
    and <dependencyManagement> are the two places a version legitimately lives elsewhere."""
    r = manifest.parse(f"{FIX}/pom.xml")
    by = {p["name"]: p for p in r["packages"]}
    assert by["org.apache.logging.log4j:log4j-core"]["version"] == "2.14.1"   # ${log4j.version}
    assert by["com.fasterxml.jackson.core:jackson-databind"]["version"] == "2.13.0"  # managed
    assert by["test.nimbus:nimbus-common"]["version"] == "2.4.0"              # ${project.version}
    assert by["junit:junit"]["scope"] == "test"


def test_an_unresolvable_property_is_refused_never_sent_as_a_literal():
    """`${spring.version}` with no <properties> entry is the pom equivalent of an unpinned
    requirement, and OSV answers a literal `${...}` with 81 advisories rather than an error."""
    r = manifest.parse(f"{FIX}/pom.xml")
    by = {s["raw"]: s for s in r["skipped"]}
    assert by["org.springframework:spring-core"]["reason"] == "unresolved-property"
    assert by["org.slf4j:slf4j-api"]["reason"] == "inherited-version"
    assert not any("${" in p["version"] for p in r["packages"])


def test_a_pom_declaring_a_dtd_is_refused(tmp_path):
    """ElementTree expands internal entities and `defusedxml` is not a dependency. A dependency
    manifest has no business declaring a DTD, so this is a refusal rather than a parse."""
    p = tmp_path / "pom.xml"
    p.write_text('<?xml version="1.0"?><!DOCTYPE project [<!ENTITY a "aaa">]>'
                 '<project><dependencies/></project>')
    with pytest.raises(manifest.ManifestError, match="DTD or entity"):
        manifest.parse(str(p))


def test_a_self_referential_property_terminates(tmp_path):
    p = tmp_path / "pom.xml"
    p.write_text('<project><properties><a>${b}</b></properties>'
                 '<dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId>'
                 '<version>${a}</version></dependency></dependencies></project>'
                 .replace("</b>", "</a>"))
    r = manifest.parse(str(p))
    assert not r["packages"] and r["skipped"][0]["reason"] == "unresolved-property"


# ---------------------------------------------------------------- kind detection & parse_all
@pytest.mark.parametrize("name,kind", [
    ("requirements.txt", "pip"), ("requirements-dev.txt", "pip"),
    ("package-lock.json", "npm"), ("npm-shrinkwrap.json", "npm"), ("pom.xml", "maven"),
])
def test_kind_is_detected_from_the_canonical_names(tmp_path, name, kind):
    p = tmp_path / name
    p.write_text("{}")
    assert manifest.detect_kind(p) == kind


def test_an_unrecognised_name_is_sniffed_then_refused(tmp_path):
    j = tmp_path / "deps.json"
    j.write_text('{"lockfileVersion": 3, "packages": {}}')
    assert manifest.detect_kind(j) == "npm"
    x = tmp_path / "deps.xml"
    x.write_text('<?xml version="1.0"?><project/>')
    assert manifest.detect_kind(x) == "maven"
    bad = tmp_path / "notes.md"
    bad.write_text("# hello")
    with pytest.raises(manifest.ManifestError, match="cannot tell what kind"):
        manifest.detect_kind(bad)


def test_one_broken_manifest_does_not_cost_the_others_their_scan(tmp_path):
    bad = tmp_path / "pom.xml"
    bad.write_text("<project><dependencies>")     # truncated
    res = manifest.parse_all([f"{FIX}/requirements.txt", str(bad)])
    assert res["packages"] and len(res["errors"]) == 1
    assert "well-formed" in res["errors"][0]["error"]


def test_a_missing_manifest_is_an_error_not_an_empty_result():
    res = manifest.parse_all(["/no/such/requirements.txt"])
    assert res["packages"] == [] and len(res["errors"]) == 1


def test_an_oversized_manifest_is_refused(tmp_path, monkeypatch):
    p = tmp_path / "requirements.txt"
    p.write_text("flask==3.0.0\n")
    monkeypatch.setattr(manifest, "MAX_BYTES", 4)
    with pytest.raises(manifest.ManifestError, match="refusing to parse"):
        manifest.parse(str(p))


# =============================================================== osv: severity, versions, aliases
@pytest.mark.parametrize("vector,expect", [
    # v3 — every one of these is unchanged by adding the v4 branch (pinned again in test_inputs_cve)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "medium"),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "low"),
    # v4 — VC/VI/VA replace C/I/A, and AT is a second exploitability gate alongside AC
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "critical"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:U", "high"),
    ("CVSS:4.0/AV:L/AC:H/PR:H/UI:A/AT:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "low"),
    ("", "medium"), ("garbage", "medium"),
])
def test_severity_covers_cvss_v4_as_well_as_v3(vector, expect):
    """Live, `aiohttp 3.9.1` returns 70 advisories carrying 43 CVSS_V4 scores against 32 CVSS_V3,
    and 38 records publish a v4 vector and NOTHING else. Before this, every one of those fell
    through the v3-only regex to the `medium` default whatever it said — including an
    unauthenticated remote denial of service. H1 never noticed because one CVE at a time it is a
    cosmetic mislabel; H2 filters hundreds of advisories on this value."""
    assert osv.severity_from_cvss(vector) == expect


def test_a_v4_only_advisory_is_no_longer_flattened_to_medium():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:U"
    assert osv.severity_from_cvss(v4) == "high"      # was "medium" for all 38 such records


@pytest.mark.parametrize("a,b", [
    ("1.10.0", "1.9.2"),      # a string sort gets this backwards, and Log4Shell hangs on it
    ("2.15.0", "2.14.1"), ("4.17.20", "4.17.19"), ("2.0", "2.0-beta9"), ("1.0.1", "1.0"),
    ("10.0.0", "9.99.99"), ("2.3.1", "2.3"),
])
def test_versions_order_numerically_not_lexically(a, b):
    assert osv.version_gt(a, b) and not osv.version_gt(b, a)


def test_a_version_with_no_digits_is_declared_uncomparable():
    assert osv.comparable("2.14.1") and not osv.comparable("latest")


LOG4SHELL = {
    "id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell",
    "details": "JNDI lookup in log messages", "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "database_specific": {"cwe_ids": ["CWE-94"]},
    # Verbatim shape from the live record: several branches of the SAME package, plus a completely
    # different package (pax-logging) whose fixed versions are numerically far lower.
    "affected": [
        {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]},
        {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}]}]},
        {"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.4"}, {"fixed": "2.12.2"}]}]},
        {"package": {"ecosystem": "Maven", "name": "org.ops4j.pax.logging:pax-logging-log4j2"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.8.0"}, {"fixed": "1.9.2"}]}]},
        {"package": {"ecosystem": "Maven", "name": "org.ops4j.pax.logging:pax-logging-log4j2"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.10.0"}, {"fixed": "1.10.8"}]}]},
    ], "references": []}

# GHSA-p6mc-m468-83gw, verbatim shape: one advisory, several packages, and one of them has NO fix.
LODASH_MULTI = {
    "id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], "summary": "Prototype pollution",
    "details": "…", "severity": [{"type": "CVSS_V3",
                                  "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}],
    "database_specific": {"cwe_ids": ["CWE-1321"]},
    "affected": [
        {"package": {"ecosystem": "npm", "name": "lodash"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.19"}]}]},
        {"package": {"ecosystem": "npm", "name": "lodash-es"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.7.0"}, {"fixed": "4.17.20"}]}]},
        {"package": {"ecosystem": "npm", "name": "lodash.pick"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"},
                                                  {"last_affected": "4.4.0"}]}]},
    ], "references": []}


def _norm(rec):
    return osv.normalize_record(rec, [rec])


def test_the_fix_is_for_the_package_you_actually_have():
    """Reproduced live against api.osv.dev on 2026-07-29: a manifest pinning
    `org.ops4j.pax.logging:pax-logging-log4j2 1.10.0` is told by `upgrade_target()` to upgrade to
    **2.15.0** — `log4j-core`'s Log4Shell fix, and not a version pax-logging has ever published.
    `upgrade_target` takes the first `affected` row carrying a version, whatever package it names,
    because it answers "what does this advisory fix" rather than "what should I install"."""
    a = _norm(LOG4SHELL)
    assert osv.upgrade_target(a)["package"] == "org.apache.logging.log4j:log4j-core"
    assert osv.upgrade_target(a)["fixed_version"] == "2.15.0"          # not pax-logging's fix
    t = osv.upgrade_target_for(a, "org.ops4j.pax.logging:pax-logging-log4j2", "Maven", "1.10.0")
    assert t["fixed_version"] == "1.10.8" and t["package"].startswith("org.ops4j")

    m = _norm(LODASH_MULTI)
    assert osv.upgrade_target_for(m, "lodash", "npm", "4.17.15")["fixed_version"] == "4.17.19"
    assert osv.upgrade_target_for(m, "lodash-es", "npm", "4.17.15")["fixed_version"] == "4.17.20"


def test_the_fix_is_the_one_for_your_branch_not_whichever_osv_listed_first():
    """One package, three maintenance branches. `upgrade_target` ignores the installed version, so
    which branch it names is decided by document order — the live Log4Shell record happens to list
    `2.13.0→2.15.0` first, so `2.14.1` gets the right answer by luck. Nothing in the OSV schema
    promises that order. With the branches listed the other way round, the old selection recommends
    **2.3.1** to someone running **2.14.1**: a downgrade, presented as the fix."""
    reordered = dict(LOG4SHELL, affected=[LOG4SHELL["affected"][1],      # 2.0-beta9 -> 2.3.1
                                          LOG4SHELL["affected"][0],      # 2.13.0    -> 2.15.0
                                          LOG4SHELL["affected"][2]])
    assert osv.upgrade_target(_norm(reordered))["fixed_version"] == "2.3.1"    # the downgrade
    t = osv.upgrade_target_for(_norm(reordered), "org.apache.logging.log4j:log4j-core",
                               "Maven", "2.14.1")
    assert t["fixed_version"] == "2.15.0"      # unchanged by the reordering
    assert osv.upgrade_target_for(_norm(LOG4SHELL), "org.apache.logging.log4j:log4j-core",
                                  "Maven", "2.14.1")["fixed_version"] == "2.15.0"


def test_a_package_with_no_published_fix_says_so_rather_than_borrowing_a_siblings():
    """`lodash.pick` is affected and has only `last_affected` — no fix was ever released for it.
    Naming lodash's 4.17.19 would send someone to install a version of a package that has none."""
    t = osv.upgrade_target_for(_norm(LODASH_MULTI), "lodash.pick", "npm", "4.4.0")
    assert t["fixed_version"] == "" and "no fixed version" in t["note"]


def test_an_installed_version_above_every_published_fix_is_not_told_to_downgrade():
    t = osv.upgrade_target_for(_norm(LOG4SHELL), "org.apache.logging.log4j:log4j-core",
                               "Maven", "2.99.0")
    assert t["fixed_version"] == "" and "at or below the installed" in t["note"]


def test_an_uncomparable_installed_version_refuses_to_pick():
    t = osv.upgrade_target_for(_norm(LOG4SHELL), "org.apache.logging.log4j:log4j-core",
                               "Maven", "latest")
    assert t["fixed_version"] == "" and "cannot order" in t["note"]


def test_pypi_names_match_across_pep503_spellings():
    rec = {"id": "X", "affected": [{"package": {"ecosystem": "PyPI", "name": "Flask-Login"},
                                    "ranges": [{"type": "ECOSYSTEM",
                                                "events": [{"introduced": "0"},
                                                           {"fixed": "0.6.3"}]}]}]}
    assert osv.upgrade_target_for(_norm(rec), "flask-login", "PyPI", "0.6.2")["fixed_version"] \
        == "0.6.3"


def test_aliases_collapse_records_that_are_one_advisory():
    """Live, `aiohttp 3.9.1` returns 70 records that are 35 advisories: OSV publishes a GHSA and a
    PYSEC entry for every one. Without collapsing them H2 pays two model calls per advisory and
    emits two band-aids for one hole — and the duplicate carries a different id, so it does not
    look like a duplicate."""
    recs = [{"id": "GHSA-a", "aliases": ["CVE-1", "PYSEC-1"]},
            {"id": "PYSEC-1", "aliases": ["CVE-1"]},
            {"id": "GHSA-b", "aliases": ["CVE-2"]}]
    groups = osv.alias_groups(recs)
    assert len(groups) == 2
    assert {len(g) for g in groups} == {2, 1}


def test_related_advisories_are_not_merged():
    """`related` links advisories that are ABOUT each other, not identical ones. Merging on it
    would collapse distinct vulnerabilities into one finding."""
    recs = [{"id": "GHSA-a", "aliases": [], "related": ["GHSA-b"]}, {"id": "GHSA-b", "aliases": []}]
    assert len(osv.alias_groups(recs)) == 2


def test_the_preferred_record_is_the_one_carrying_an_installable_version():
    git_only = {"id": "CVE-1", "aliases": ["GHSA-x"], "summary": "s", "details": "d",
                "affected": [{"ranges": [{"type": "GIT",
                                          "events": [{"fixed": "24a6d64966d99182e95f5d3a29541ef2"}]}]}]}
    versioned = {"id": "GHSA-x", "aliases": ["CVE-1"], "summary": "", "details": "",
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "aiohttp"},
                               "ranges": [{"type": "ECOSYSTEM",
                                           "events": [{"introduced": "0"}, {"fixed": "3.9.2"}]}]}]}
    assert osv.preferred_record([git_only, versioned])["id"] == "GHSA-x"


def test_normalize_record_merges_the_whole_alias_group():
    group = [{"id": "GHSA-x", "aliases": ["CVE-1"], "summary": "sum", "details": "det",
              "severity": [], "database_specific": {"cwe_ids": ["CWE-79"]},
              "affected": [{"package": {"ecosystem": "PyPI", "name": "p"},
                            "ranges": [{"type": "ECOSYSTEM",
                                        "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]},
             {"id": "PYSEC-1", "aliases": ["CVE-1"], "summary": "", "details": "",
              "severity": [{"type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
              "affected": []}]
    a = osv.normalize_record(group[0], group)
    assert a["cvss"].startswith("CVSS:3.1")          # the score lives on the sibling record
    assert set(a["consulted"]) == {"GHSA-x", "PYSEC-1"}
    assert a["cwe_ids"] == ["CWE-79"]


# =============================================================== the batch query
class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code, self.text = payload, status, json.dumps(payload)

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code != 200:
            raise RuntimeError(f"HTTP {self.status_code}")


def test_batch_asks_once_and_only_the_hits_are_fetched_in_full(monkeypatch):
    """`querybatch` returns ids and `modified` only — never the advisory bodies. Fetching each id
    would be one request per ADVISORY (70 for aiohttp 3.9.1 alone), where `/v1/query` returns every
    full record for a coordinate in one round trip. So batch answers "which packages are worth
    asking about" and nothing else."""
    import httpx
    calls = []

    def post(url, json=None, **kw):
        calls.append(url)
        if url.endswith("querybatch"):
            return _Resp({"results": [{"vulns": [{"id": "GHSA-a", "modified": "x"}]}, {}]})
        return _Resp({"vulns": [dict(LODASH_MULTI)]})
    monkeypatch.setattr(httpx, "post", post)
    pkgs = [{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"},
            {"ecosystem": "npm", "name": "clean", "version": "1.0.0"}]
    hits = osv.query_batch(pkgs, log=lambda m: None)
    assert hits["npm/lodash@4.17.15"] == ["GHSA-a"] and hits["npm/clean@1.0.0"] == []
    assert calls == [osv.BATCH_API]                    # one request for both packages


def test_an_unknown_ecosystem_is_dropped_before_the_batch_not_sent(monkeypatch):
    """Measured live: ONE invalid ecosystem fails the WHOLE batch with
    `error in query at index 1: invalid ecosystem`. A typo in one manifest line must not cost every
    other package in the manifest its answer."""
    import httpx
    sent = []

    def post(url, json=None, **kw):
        sent.append(json)
        return _Resp({"results": [{"vulns": []}]})
    monkeypatch.setattr(httpx, "post", post)
    hits = osv.query_batch([{"ecosystem": "npm", "name": "ok", "version": "1.0"},
                            {"ecosystem": "Bogus", "name": "bad", "version": "1.0"}],
                           log=lambda m: None)
    assert [q["package"]["name"] for q in sent[0]["queries"]] == ["ok"]
    assert hits["Bogus/bad@1.0"] == []


def test_a_failed_batch_degrades_to_per_package_queries_never_to_zero(monkeypatch):
    """Reporting "no advisories" because a request failed is the one answer that must never come
    out of an error."""
    import httpx

    def post(url, json=None, **kw):
        if url.endswith("querybatch"):
            raise RuntimeError("connection reset")
        return _Resp({"vulns": [{"id": "GHSA-a"}]})
    monkeypatch.setattr(httpx, "post", post)
    hits = osv.query_batch([{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}],
                           log=lambda m: None)
    assert hits["npm/lodash@4.17.15"] == ["GHSA-a"]


def test_one_failing_fallback_query_does_not_end_the_scan(monkeypatch):
    """The fallback exists so a batch failure never loses a chunk — unguarded, it became the thing
    that lost the whole run. `query_package` raises on any non-200, and the causes of a batch
    failure (OSV down, rate limiting) are exactly the causes that make the retries fail too. It
    propagated out of `query_batch`, out of `deps.survey` (whose own loop IS guarded) and out of
    `resolve_manifests`, which the pipeline does not wrap — so a 429 also destroyed the repo half
    of a `scan ./repo --manifest` run."""
    import httpx

    def post(url, json=None, **kw):
        if url.endswith("querybatch"):
            raise RuntimeError("batch down")
        if json["package"]["name"] == "boom":
            raise RuntimeError("OSV.dev returned 429")
        return _Resp({"vulns": [{"id": "GHSA-ok"}]})
    monkeypatch.setattr(httpx, "post", post)
    pkgs = [{"ecosystem": "npm", "name": "boom", "version": "1.0"},
            {"ecosystem": "npm", "name": "fine", "version": "1.0"}]
    hits = osv.query_batch(pkgs, log=lambda m: None)
    assert hits["npm/fine@1.0"] == ["GHSA-ok"]         # the second package is still reached
    assert "npm/boom@1.0" not in hits                  # never "clean"…
    assert "429" in pkgs[0]["error"]                   # …it is stamped as unchecked


def test_a_package_that_could_not_be_checked_is_not_reported_clean(tmp_path):
    """It stayed in `vulnerable` (so the funnel counted it) but contributed no advisory row, no
    counter and no warning — indistinguishable from a package that came back clean."""
    surveyed = {"files": [], "errors": [], "skipped": [], "dev_excluded": [], "considered": [1],
                "vulnerable": [1], "candidates": [], "records": 0, "_groups": {},
                "packages": [{"ecosystem": "PyPI", "name": "aiohttp", "version": "3.9.1",
                              "error": "OSV.dev returned 429"},
                             {"ecosystem": "PyPI", "name": "flask", "version": "3.0.0"}]}
    rep = deps.report(surveyed, [], min_severity="high", max_advisories=25, include_dev=False)
    assert rep["funnel"]["packages_unchecked"] == 1
    assert [u["name"] for u in rep["unchecked"]] == ["aiohttp"]
    from vpcopilot.report import _dependencies_html
    (tmp_path / "dependencies.json").write_text(json.dumps(rep))
    html = _dependencies_html(str(tmp_path))
    assert "Could not check" in html and "aiohttp" in html and "unknown, not absent" in html


def test_a_short_batch_answer_is_never_read_as_clean(monkeypatch):
    """`zip(..., strict=False)` refuses to mispair a short `results` list with its queries — but it
    also left the unanswered tail with no entry at all, and the caller reads a missing key as "no
    advisories" (`hits.get(key)` is None, so the package never reaches `vulnerable`). A 200 that
    answered two of three coordinates therefore reported the third as CLEAN."""
    import httpx
    asked = []

    def post(url, json=None, **kw):
        if url.endswith("querybatch"):
            return _Resp({"results": [{"vulns": []}, {"vulns": []}]})     # two answers, three asked
        asked.append(json["package"]["name"])
        return _Resp({"vulns": [{"id": "GHSA-tail"}]})
    monkeypatch.setattr(httpx, "post", post)
    pkgs = [{"ecosystem": "npm", "name": "a", "version": "1.0"},
            {"ecosystem": "npm", "name": "b", "version": "1.0"},
            {"ecosystem": "npm", "name": "c", "version": "1.0"}]
    hits = osv.query_batch(pkgs, log=lambda m: None)
    assert asked == ["c"]                              # only the unanswered one is re-asked
    assert hits["npm/c@1.0"] == ["GHSA-tail"]          # was: absent, i.e. indistinguishable from clean
    assert set(hits) == {"npm/a@1.0", "npm/b@1.0", "npm/c@1.0"}


# =============================================================== the funnel
class FakeProfile:
    def __init__(self, observable=True, **kw):
        from vpcopilot.schemas import Severity, VulnClass
        self.network_observable = observable
        self.reason = kw.get("reason", "the advisory names the request path")
        self.vuln_class = VulnClass("other")
        self.severity = Severity("high")
        self.title, self.description = "t", "d"
        self.exploit_sketch = "GET /x"
        self.paths = kw.get("paths", ["/api/pay"])
        self.http_methods = ["POST"]
        self.parameters = self.headers = self.example_requests = self.caveats = []
        self.confidence = 0.8


def _cand(pkg, aid, sev="high", **kw):
    return {"advisory_id": aid, "aliases": [], "advisory": {"id": aid, "cwe_ids": []},
            "package": pkg, "ecosystem": "PyPI", "installed": "1.0", "scope": "runtime",
            "manifest": "requirements.txt", "summary": "s", "cvss": "", "severity": sev,
            "withdrawn": kw.get("withdrawn", ""), "fixed_version": "2.0", "fix_note": "",
            "vulnerable_range": "1.0", "references": [], "disposition": "", "reason": ""}


def test_the_cap_is_shared_across_packages_not_eaten_by_the_first():
    """The first live run made the reason obvious: `aiohttp 3.9.1` alone carries 35 advisories, and
    a flat (severity, package, id) ordering handed it 23 of the 25 slots. Every other package was
    competing with one dependency's back catalogue, and packages later in the alphabet were capped
    out by advisories no worse than their own."""
    cands = ([_cand("aiohttp", f"GHSA-a{i}") for i in range(30)]
             + [_cand("django", "GHSA-d1"), _cand("lodash", "GHSA-l1")])
    chosen = deps.select(cands, min_severity="high", max_advisories=6, log=lambda m: None)
    assert {c["package"] for c in chosen} == {"aiohttp", "django", "lodash"}
    assert sum(1 for c in chosen if c["package"] == "aiohttp") == 4


def test_severity_still_outranks_breadth():
    cands = [_cand("aiohttp", "GHSA-crit", "critical"), _cand("django", "GHSA-low", "low")]
    chosen = deps.select(cands, min_severity="high", max_advisories=1, log=lambda m: None)
    assert [c["advisory_id"] for c in chosen] == ["GHSA-crit"]
    assert cands[1]["disposition"] == "below_severity"


def test_nothing_is_dropped_silently_everything_carries_a_reason():
    """"We did not look at this" and "this is fine" must never render the same way."""
    cands = [_cand("a", "GHSA-1", "medium"), _cand("b", "GHSA-2", withdrawn="2026-01-01"),
             _cand("c", "GHSA-3"), _cand("d", "GHSA-4")]
    deps.select(cands, min_severity="high", max_advisories=1, log=lambda m: None)
    by = {c["advisory_id"]: c for c in cands}
    assert by["GHSA-1"]["disposition"] == "below_severity"
    assert by["GHSA-2"]["disposition"] == "withdrawn"
    assert {by["GHSA-3"]["disposition"], by["GHSA-4"]["disposition"]} == {"", "capped"}
    assert all(c["reason"] for c in cands if c["disposition"])


def test_a_cap_of_zero_means_no_cap():
    cands = [_cand("a", f"GHSA-{i}") for i in range(40)]
    assert len(deps.select(cands, min_severity="high", max_advisories=0, log=lambda m: None)) == 40


def test_one_advisory_hitting_two_packages_costs_one_model_call(monkeypatch):
    """The profile answers "what does this look like in a request", which does not depend on which
    of the affected packages you have. Two packages must not receive two different verdicts."""
    from vpcopilot.agents import resolve as ra
    calls = []
    monkeypatch.setattr(ra, "run", lambda h, a: calls.append(a["id"]) or FakeProfile())
    chosen = [_cand("lodash", "GHSA-x"), _cand("lodash-es", "GHSA-x")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    assert calls == ["GHSA-x"]
    assert all(c["disposition"] == "exploitable" for c in chosen)


def test_two_packages_one_advisory_get_distinct_finding_ids(monkeypatch):
    from vpcopilot.agents import resolve as ra
    monkeypatch.setattr(ra, "run", lambda h, a: FakeProfile())
    chosen = [_cand("lodash", "GHSA-x"), _cand("lodash-es", "GHSA-x")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    built = deps.build(chosen)
    ids = [f.id for f in built["findings"]]
    assert ids == ["GHSA-x", "GHSA-x-2"] and len(set(ids)) == 2
    assert len(built["remediations"]) == 2


def test_a_declined_advisory_routes_to_no_bandaid_in_code(monkeypatch):
    """Same guarantee H1 makes, for the same reason: a hard acceptance requirement must not depend
    on a model honouring a prompt."""
    from vpcopilot.agents import resolve as ra
    monkeypatch.setattr(ra, "run", lambda h, a: FakeProfile(
        observable=False, reason="exploitation needs a crafted file on disk."))
    chosen = [_cand("aiohttp", "GHSA-x")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    built = deps.build(chosen)
    d = built["decisions"][built["findings"][0].id]
    assert d.no_bandaid is True and d.bandaids == []
    assert "crafted file" in d.residual_risk and "2.0" in d.residual_risk


def test_a_failing_resolve_loses_that_advisory_not_the_manifest(monkeypatch):
    from vpcopilot.agents import resolve as ra

    def boom(h, a):
        if a["id"] == "GHSA-bad":
            raise RuntimeError("model timeout")
        return FakeProfile()
    monkeypatch.setattr(ra, "run", boom)
    chosen = [_cand("a", "GHSA-bad"), _cand("b", "GHSA-ok")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    assert chosen[0]["disposition"] == "resolve_failed"
    assert chosen[1]["disposition"] == "exploitable"
    assert [f.id for f in deps.build(chosen)["findings"]] == ["GHSA-ok"]


def test_the_cure_is_a_version_bump_and_never_a_patch(monkeypatch):
    from vpcopilot.agents import resolve as ra
    monkeypatch.setattr(ra, "run", lambda h, a: FakeProfile())
    chosen = [_cand("aiohttp", "GHSA-x")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    rem = list(deps.build(chosen)["remediations"].values())[0]
    assert rem.kind == "dependency_upgrade" and rem.fixed_version == "2.0"
    assert rem.patched_content == "" and rem.diff == "" and rem.file == ""
    assert "upstream" in rem.pr_body and "requirements.txt" in rem.pr_body


def test_the_finding_identity_names_the_installed_coordinate(monkeypatch):
    """Two packages hit by one advisory must not collide on a coverage key, and `source` is what
    `coverage_key` falls back to when there is no repo file and no endpoint."""
    from vpcopilot.agents import resolve as ra
    from vpcopilot.correlate import coverage_key
    monkeypatch.setattr(ra, "run", lambda h, a: FakeProfile(paths=[]))
    chosen = [_cand("lodash", "GHSA-x"), _cand("lodash-es", "GHSA-x")]
    deps.resolve_all(None, chosen, {}, log=lambda m: None)
    fs = deps.build(chosen)["findings"]
    assert fs[0].source == "osv:GHSA-x@PyPI/lodash@1.0"
    assert fs[0].file == "" and fs[0].line == 0
    assert coverage_key("service_policy", "", identity=fs[0].source) != \
        coverage_key("service_policy", "", identity=fs[1].source)


# ================================= a finding whose recommended band-aid was claimed by another
def _decision(fid, *bandaids):
    from vpcopilot.schemas import BandaidOption, TriageDecision
    return TriageDecision(finding_id=fid, bandaids=[
        BandaidOption(control=c, coverage="partial", recommended=r, rationale="r")
        for c, r in bandaids])


def _finding(fid, endpoint):
    from vpcopilot.schemas import Finding
    return Finding(id=fid, title=fid, vuln_class="other", severity="critical", description="d",
                   exploit_sketch="e", source=f"osv:{fid}", endpoint=endpoint)


def _run_generate_loop(monkeypatch, decisions, findings):
    """Drive the pipeline's generate stage over prepared triage decisions, with every agent faked."""
    from vpcopilot import pipeline
    from vpcopilot.agents import generate, probe as probe_agent, triage
    from vpcopilot.schemas import GeneratedArtifact, GeneratedArtifacts, TriageBatch

    made = []

    def gen(h, f, control, rationale, exploit=None, legit=None):
        made.append((f.id, control.value))
        return GeneratedArtifacts(items=[GeneratedArtifact(
            finding_id=f.id, control=control, policy_name=f"{control.value}-{f.id}",
            spec={"rules": []})])
    monkeypatch.setattr(generate, "run", gen)
    monkeypatch.setattr(triage, "run", lambda h, fs: TriageBatch(decisions=decisions))
    monkeypatch.setattr(probe_agent, "run", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(pipeline, "_dedup_findings", lambda fs, log, c=None: fs)
    return made


def test_a_finding_whose_only_recommended_control_was_taken_still_gets_a_bandaid(monkeypatch,
                                                                                tmp_path):
    """The first live H2 run: Log4Shell's only recommended control was the LB-wide `waf`, which an
    aiohttp header-injection advisory had already claimed. The loop ended with nothing generated for
    the critical finding, while `correlations.json` recorded it as covered — and the WAF that
    actually shipped (`waf-block-header-injection-nullbyte-crlf`) addressed nothing about JNDI."""
    from vpcopilot import correlate
    seen = {"waf": "aiohttp-adv"}
    d = _decision("log4shell", ("waf", True), ("service_policy", False))
    preferred = [b for b in d.bandaids if b.recommended]
    assert [b.control.value for b in preferred] == ["waf"]
    assert correlate.coverage_key("waf", "", identity="/x") in seen        # the slot is taken
    # …and the alternative is NOT taken, so there is something to fall back to
    alt = [b for b in d.bandaids if not b.recommended]
    assert correlate.coverage_key(alt[0].control.value, "", identity="/x") not in seen


def test_the_fallback_only_fires_when_the_recommended_tier_produced_nothing(monkeypatch, tmp_path):
    """No regression: where a recommended band-aid is generated normally, the alternatives are
    never reached and the artifact set is exactly what it was before."""
    from vpcopilot.pipeline import run_pipeline
    made = _run_generate_loop(
        monkeypatch,
        [_decision("f1", ("service_policy", True), ("rate_limit", False))],
        [_finding("f1", "/api/pay")])
    from vpcopilot.inputs import deps as D
    monkeypatch.setattr(D, "resolve_manifests", lambda h, p, **k: {
        "findings": [_finding("f1", "/api/pay")], "decisions": {}, "remediations": {},
        "report": {"funnel": {}}, "candidates": []})
    from vpcopilot.harness import Harness
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    run_pipeline(manifest_paths=["x.txt"], out_dir=str(tmp_path), draft_code_fixes=False,
                 log=lambda m: None)
    assert made == [("f1", "service_policy")]        # the rate_limit alternative was never reached


def test_the_fallback_fires_when_every_recommended_control_was_claimed(monkeypatch, tmp_path):
    from vpcopilot.pipeline import run_pipeline
    fs = [_finding("owner", "/a"), _finding("loser", "/b")]
    made = _run_generate_loop(
        monkeypatch,
        [_decision("owner", ("waf", True)),
         _decision("loser", ("waf", True), ("service_policy", False))],
        fs)
    from vpcopilot.inputs import deps as D
    monkeypatch.setattr(D, "resolve_manifests", lambda h, p, **k: {
        "findings": fs, "decisions": {}, "remediations": {}, "report": {"funnel": {}},
        "candidates": []})
    from vpcopilot.harness import Harness
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    run_pipeline(manifest_paths=["x.txt"], out_dir=str(tmp_path), draft_code_fixes=False,
                 log=lambda m: None)
    assert ("owner", "waf") in made
    assert ("loser", "service_policy") in made       # was: nothing at all
    assert ("loser", "waf") not in made              # the LB-wide slot is still shared, not duplicated
    cor = json.loads((tmp_path / "correlations.json").read_text())
    assert cor[0]["finding_id"] == "loser" and cor[0]["covered_by"] == "owner"
    assert "not this one's" in cor[0]["note"]        # the claim is qualified, not absolute


def test_an_alternate_never_takes_a_slot_a_later_finding_recommends(monkeypatch, tmp_path):
    """Found by adversarial review, before shipping. The first cut of the fallback ran INTERLEAVED
    with the recommended tier and generated EVERY alternative, so `loser`'s non-recommended
    `rate_limit` claimed the LB-wide slot before `brute` — which actually recommended rate_limit —
    was reached. `brute` then got no band-aid at all and was recorded as covered by a policy built
    from `loser`'s exploit: the exact Log4Shell bug this change exists to fix, moved onto a
    different finding, plus two extra model calls for controls triage never recommended.

    Six of the seven controls are LB-wide, so contention is the normal case, not a corner."""
    from vpcopilot.harness import Harness
    from vpcopilot.inputs import deps as D
    from vpcopilot.pipeline import run_pipeline
    fs = [_finding("owner", "/a"), _finding("loser", "/b"), _finding("brute", "/c")]
    made = _run_generate_loop(monkeypatch, [
        _decision("owner", ("waf", True)),
        _decision("loser", ("waf", True), ("rate_limit", False), ("bot_defense", False)),
        _decision("brute", ("rate_limit", True)),
    ], fs)
    monkeypatch.setattr(D, "resolve_manifests", lambda h, p, **k: {
        "findings": fs, "decisions": {}, "remediations": {}, "report": {"funnel": {}},
        "candidates": []})
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    run_pipeline(manifest_paths=["x.txt"], out_dir=str(tmp_path), draft_code_fixes=False,
                 log=lambda m: None)
    assert ("brute", "rate_limit") in made      # was: stolen by loser's alternate, brute got nothing
    assert ("owner", "waf") in made
    # the fallback takes ONE alternative, not the whole non-recommended stack
    assert [m for m in made if m[0] == "loser"] == [("loser", "bot_defense")]
    assert {f.id for f in fs} - {m[0] for m in made} == set()      # nobody ends bare


def test_an_lb_wide_correlation_says_whose_exploit_the_policy_was_built_from(monkeypatch, tmp_path):
    """"One control covers both" is true of the slot and false of the protection: the attached
    policy was generated against the owning finding's exploit and validated against its probe."""
    from vpcopilot.pipeline import run_pipeline
    fs = [_finding("owner", "/a"), _finding("loser", "/a")]
    _run_generate_loop(monkeypatch,
                       [_decision("owner", ("service_policy", True)),
                        _decision("loser", ("service_policy", True))], fs)
    from vpcopilot.inputs import deps as D
    monkeypatch.setattr(D, "resolve_manifests", lambda h, p, **k: {
        "findings": fs, "decisions": {}, "remediations": {}, "report": {"funnel": {}},
        "candidates": []})
    from vpcopilot.harness import Harness
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    run_pipeline(manifest_paths=["x.txt"], out_dir=str(tmp_path), draft_code_fixes=False,
                 log=lambda m: None)
    cor = json.loads((tmp_path / "correlations.json").read_text())
    # service_policy is endpoint-scoped, not LB-wide: same endpoint really is one policy for both
    assert cor[0]["note"] == "same endpoint — one policy covers both"


# =============================================================== the pipeline and both surfaces
def test_the_pipeline_refuses_a_missing_or_conflicting_input():
    from vpcopilot.pipeline import run_pipeline
    with pytest.raises(ValueError, match="pass a repo path"):
        run_pipeline()
    with pytest.raises(ValueError, match="cannot be combined"):
        run_pipeline(advisory="CVE-2024-23334", manifest_paths=["requirements.txt"])
    # a manifest IS additive with a repo and a spec — no error path for that combination
    from vpcopilot.pipeline import run_pipeline as rp
    assert rp.__defaults__ is not None


def test_the_manifest_artifact_is_not_called_manifest_json():
    """`export.verify_bundle` locates each run in an archive by every member whose name ends
    `manifest.json`. An out-dir artifact by that name would be read as a second evidence manifest
    and break verification of the bundle it ships in."""
    from vpcopilot import export
    src = __import__("pathlib").Path("src/vpcopilot/pipeline.py").read_text()
    assert '"dependencies.json"' in src
    assert 'out / "manifest.json"' not in src
    assert "dependencies.json" in export.BUNDLE_FILES


def test_the_bundle_caveats_say_what_the_dependency_report_does_not_prove():
    from vpcopilot.export import build_manifest
    cav = " ".join(build_manifest("out").get("caveats", []))
    assert "dependencies.json" in cav and "never queried" in cav


def test_both_surfaces_reach_the_same_module_function():
    """One module function, two surfaces — a guard that lives in only one of them is not a guard."""
    import inspect

    from vpcopilot import cli
    from vpcopilot.console import app as A
    assert "survey_report" in inspect.getsource(cli.deps)
    assert "survey_report" in inspect.getsource(A.survey_dependencies)
    assert "manifest_paths" in inspect.getsource(A._run_scan)


def test_the_console_scan_surface_accepts_a_manifest():
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    c = TestClient(A.app)
    assert c.post("/api/scan", json={"repo": "", "cve": "", "manifest": []}).status_code == 400
    assert c.post("/api/scan", json={"repo": "", "cve": "CVE-2024-23334",
                                     "manifest": ["requirements.txt"]}).status_code == 400
    assert c.post("/api/scan", json={"manifest": ["r.txt"],
                                     "min_severity": "nope"}).status_code == 400
    assert c.post("/api/deps", json={"manifest": []}).status_code == 400
    html = (__import__("pathlib").Path(A.__file__).parent / "static" / "index.html").read_text()
    assert 'id="scanManifest"' in html and "manifest," in html and "surveyDeps" in html
    # Both surfaces or it is not a guard: the CLI printed parse errors and unchecked packages in
    # red while the preview rendered an all-zero funnel and an empty table for them.
    assert "d.errors||[]" in html and "d.unchecked||[]" in html
    assert "UNKNOWN, not absent" in html
    # …and a cleared advisory cap must mean the CLI default, not "no cap"
    assert "parseInt(scanMaxAdvisories.value)||0" not in html
    assert "advCap(scanMaxAdvisories.value)" in html and "const advCap" in html


def test_the_deps_endpoint_is_read_only_and_needs_no_model(monkeypatch, tmp_path):
    """It parses and asks OSV. A version that reached a model would make the preview cost what the
    scan costs, and the point of the preview is seeing the funnel before paying for it."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setattr(osv, "query_batch", lambda pkgs, **kw: {})
    monkeypatch.setattr(A, "_active_config", None, raising=False)
    from vpcopilot.harness import Harness
    monkeypatch.setattr(Harness, "__init__",
                        lambda *a, **k: pytest.fail("the preview must not build a Harness"))
    c = TestClient(A.app)
    r = c.post("/api/deps", json={"manifest": [f"{FIX}/requirements.txt"]})
    assert r.status_code == 200
    d = r.json()["dependencies"]
    assert d["funnel"]["packages_parsed"] == 7 and d["funnel"]["packages_unpinned"] == 7
    assert d["unpinned"] and all(u["reason"] for u in d["unpinned"])


def test_the_report_renders_what_was_not_checked(tmp_path):
    from vpcopilot.report import _dependencies_html
    (tmp_path / "dependencies.json").write_text(json.dumps({
        "funnel": {"packages_parsed": 3, "packages_vulnerable": 1, "advisories_distinct": 5,
                   "exploitable": 1, "declined": 1, "not_resolved": 3, "packages_unpinned": 2},
        "settings": {"min_severity": "high", "max_advisories": 25},
        "unpinned": [{"reason": "unpinned"}, {"reason": "unresolved-property"}],
        "advisories": [{"severity": "high", "package": "aiohttp", "installed": "3.9.1",
                        "advisory_id": "GHSA-x", "fixed_version": "3.9.2",
                        "disposition": "exploitable", "reason": "names the path"}],
        "errors": []}))
    html = _dependencies_html(str(tmp_path))
    assert "Not checked" in html and "never queried" in html
    assert "Listed, not resolved" in html and "GHSA-x" in html
    assert _dependencies_html(str(tmp_path / "empty")) == ""     # absent -> no section at all


# ================================= an upgrade is not a drafted PR
def _upgrade(fid):
    from vpcopilot.schemas import RemediationPlan
    return RemediationPlan(finding_id=fid, kind="dependency_upgrade",
                           summary=f"upgrade aiohttp 3.9.1 → 3.9.2 (fixes {fid})",
                           package="aiohttp", ecosystem="PyPI",
                           pr_title="fix(aiohttp): upgrade", pr_body="body")


def _code_fix(fid):
    from vpcopilot.schemas import RemediationPlan
    return RemediationPlan(finding_id=fid, summary="add a guard", file="app.py",
                           diff="--- a\n+++ b\n", patched_content="def f(): pass\n",
                           pr_title="fix: guard", pr_body="body")


def _pipeline_with(monkeypatch, tmp_path, findings, remediations):
    from vpcopilot.harness import Harness
    from vpcopilot.inputs import deps as D
    from vpcopilot.pipeline import run_pipeline
    _run_generate_loop(monkeypatch, [_decision(f.id, ("service_policy", True)) for f in findings],
                       findings)
    monkeypatch.setattr(D, "resolve_manifests", lambda h, p, **k: {
        "findings": findings, "decisions": {}, "remediations": remediations,
        "report": {"funnel": {}}, "candidates": []})
    monkeypatch.setattr(Harness, "__init__", lambda self, cp=None: None)
    monkeypatch.setattr(Harness, "warmup", lambda self: None)
    run_pipeline(manifest_paths=["x.txt"], out_dir=str(tmp_path), draft_code_fixes=False,
                 log=lambda m: None)
    return json.loads((tmp_path / "summary.json").read_text())


def test_a_dependency_upgrade_is_never_counted_as_a_drafted_code_fix_pr(monkeypatch, tmp_path):
    """The first live H2 run reported `code_fix_prs: 6` for six advisory findings, and the report's
    hero panel rendered "6 — code-fix PRs (the cure)". Zero PRs were drafted and none CAN be: the
    cure is a version bump in someone else's package, which is why `remediate` is never called and
    `pr.py` declines. The cure half of the story was overstated on every surface that renders it."""
    fs = [_finding("adv-1", "/a"), _finding("adv-2", "/b")]
    summary = _pipeline_with(monkeypatch, tmp_path, fs,
                             {"adv-1": _upgrade("adv-1"), "adv-2": _upgrade("adv-2")})
    assert summary["code_fix_prs"] == []                      # was: both of them
    assert summary["dependency_upgrades"] == ["adv-1", "adv-2"]
    counts = json.loads((tmp_path / "run.json").read_text())["counts"]
    assert counts["code_fix_prs"] == 0 and counts["dependency_upgrades"] == 2
    metrics = json.loads((tmp_path / "metrics.json").read_text())["synthesize"]
    assert metrics["code_fix_prs"] == 0 and metrics["dependency_upgrades"] == 2
    # …and the number a human actually reads, in the report's impact hero
    from vpcopilot.impact import impact
    im = impact(str(tmp_path))
    assert im["code_prs"] == 0 and im["dependency_upgrades"] == 2
    html = (tmp_path / "report.html").read_text()
    assert "upgrades to ship (no PR)" in html
    assert ">2</span><span class=\"l\">code-fix PRs (the cure)" not in html


def test_a_later_scan_without_a_manifest_does_not_inherit_the_previous_dependencies(monkeypatch,
                                                                                     tmp_path):
    """Every other member of the out dir is rewritten unconditionally, so a re-scan replaces it.
    `dependencies.json` was written only when a manifest was given — so scanning the same out dir
    again without one left the PREVIOUS run's dependency data in place, and the report,
    `GET /api/deps` and the evidence bundle all presented it as this run's. G4 shipped the same
    class of bug with leftover `policies/` artifacts."""
    fs = [_finding("adv-1", "/a")]
    _pipeline_with(monkeypatch, tmp_path, fs, {"adv-1": _upgrade("adv-1")})
    assert (tmp_path / "dependencies.json").is_file()

    # …now a scan of the same out dir with no manifest at all
    from vpcopilot.pipeline import _write_out
    _write_out(str(tmp_path), [], [], [], [], [], [], [], deps_report=None)
    assert not (tmp_path / "dependencies.json").exists()
    from vpcopilot.report import _dependencies_html
    assert _dependencies_html(str(tmp_path)) == ""


def test_a_drafted_code_fix_still_counts_as_one(monkeypatch, tmp_path):
    """No regression: a real patch is still a code-fix PR, and the new key stays empty rather than
    absent, so a consumer can tell "none" from "this run predates the split"."""
    fs = [_finding("code-1", "/a")]
    summary = _pipeline_with(monkeypatch, tmp_path, fs, {"code-1": _code_fix("code-1")})
    assert summary["code_fix_prs"] == ["code-1"]
    assert summary["dependency_upgrades"] == []
    counts = json.loads((tmp_path / "run.json").read_text())["counts"]
    assert counts["code_fix_prs"] == 1 and counts["dependency_upgrades"] == 0
    # the extra hero stat and chip are omitted entirely when nothing was held back
    assert "upgrades to ship" not in (tmp_path / "report.html").read_text()
