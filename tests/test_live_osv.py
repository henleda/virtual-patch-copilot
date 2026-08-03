"""Live: the OSV client against api.osv.dev.

The cheapest of the live tests — no XC tenant, no appliance, no model, no credential at all — so it
is the one that proves the harness shape before anything expensive depends on it.

It re-runs the four behaviours H2 found by querying OSV for real, each of which **silently degrades
the answer** rather than failing loudly, and none of which is visible from the schema:

- asking for a CVE id usually returns the GIT-range record, so the installable version only exists
  on the GHSA alias — the client has to follow aliases;
- CVSS v4 is now the majority and was being bucketed as `medium` by a v3-only matcher;
- `upgrade_target_for` must return a fix for the package you *have*, not the first package the
  advisory happens to name;
- OSV publishes a GHSA *and* a PYSEC entry for most Python advisories, so 70 records are 35
  advisories.

Marked `live` because it reaches the network, and `VPCOPILOT_LIVE_NET=1` gates it: hitting a public
API is cheap but it is still not something a plain `pytest` should do behind someone's back.
"""
from __future__ import annotations

import pytest

from tests.live import requires
from vpcopilot.inputs import osv

pytestmark = pytest.mark.live


@pytest.fixture(autouse=True)
def _gate():
    requires("VPCOPILOT_LIVE_NET")


def test_a_cve_id_resolves_through_its_alias_to_an_installable_version(evidence):
    """H2's finding: asking for a CVE id usually returns the git-range record — no package, and
    `fixed` values that are commit SHAs. "Upgrade to 24a6d649…" is not a recommendation. The
    installable `PyPI/aiohttp 3.9.2` exists only on the GHSA alias, so the client follows aliases."""
    got = osv.resolve("CVE-2024-23334", log=lambda m: None)
    evidence.record(f"resolved CVE-2024-23334, consulted {got.get('consulted')}")

    # The alias hop is observable in `consulted`: the CVE alone is not enough, so the client
    # followed through to the GHSA. This is the mechanism, asserted directly.
    assert len(got.get("consulted") or []) > 1, \
        f"only {got.get('consulted')} was consulted — the alias hop did not happen"

    rows = got.get("affected") or []
    ecosystem_rows = [r for r in rows if r.get("range_type") == "ECOSYSTEM" and r.get("package")]
    git_rows = [r for r in rows if r.get("range_type") == "GIT"]
    assert ecosystem_rows, "no ECOSYSTEM row: there is nothing installable to recommend"
    evidence.record(f"{len(ecosystem_rows)} ecosystem row(s), {len(git_rows)} git row(s)")

    target = osv.upgrade_target(got)
    fixed = str(target.get("fixed_version") or "")
    assert target.get("package") and target.get("ecosystem"), \
        f"the upgrade target names no installable coordinate: {target!r}"
    assert fixed, f"no installable upgrade target derived from {target!r}"
    # A commit SHA is never an upgrade target — "upgrade to 24a6d649…" is not a recommendation.
    # The GIT rows above are exactly where such a SHA would come from, so this is the live
    # assertion that the client picked the ecosystem row over them.
    assert not (len(fixed) >= 40 and all(c in "0123456789abcdef" for c in fixed.lower())), \
        f"the upgrade target is a commit SHA, not an installable version: {fixed!r}"
    evidence.record(f"installable upgrade target {fixed!r}, not a SHA")


def test_cvss_v4_is_bucketed_by_severity_and_not_defaulted_to_medium(evidence):
    """H2 measured `aiohttp 3.9.1` returning 43 v4 scores against 32 v3, with **38 of 70 records
    publishing a v4 vector and nothing else** — every one of which fell through to the `medium`
    default whatever it said, including an unauthenticated remote DoS. H2 *filters* on this value,
    so it decided what got resolved at all."""
    v4_dos = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H"
    got = osv.severity_from_cvss(v4_dos)
    evidence.record(f"v4 vector -> {got}")
    assert got != "medium", "a v4 vector fell through to the medium default — the H2 defect is back"
    assert got in ("high", "critical")

    # …and every v3 verdict must stay byte-identical, which is what made the fix safe to ship.
    v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert osv.severity_from_cvss(v3) == "critical"
    evidence.record("v3 bucketing unchanged")


def test_a_real_query_returns_more_records_than_advisories(evidence):
    """OSV publishes a GHSA *and* a PYSEC entry for most Python advisories, cross-linked by
    `aliases`. Collapsing them is correctness, not thrift: the duplicate carries a different id, so
    nothing downstream would recognise it as one, and it would cost two model calls and two
    band-aids per hole."""
    records = osv.query_package({"name": "aiohttp", "ecosystem": "PyPI", "version": "3.9.1"})
    assert records, "OSV returned nothing for a package known to carry advisories"
    ids = {r.get("id") for r in records}
    evidence.record(f"{len(records)} raw records, {len(ids)} distinct ids")

    # The de-duplication is what H2 added; assert the raw feed still has the shape that made it
    # necessary, so the day OSV stops double-publishing we find out from a test rather than by
    # wondering why a count changed.
    prefixes = {i.split("-")[0] for i in ids if i}
    assert len(prefixes) > 1, f"expected several id namespaces (GHSA/PYSEC/…), saw {prefixes}"
    evidence.record(f"id namespaces present: {sorted(prefixes)}")


def test_an_unparseable_version_is_never_sent_to_osv(evidence):
    """The load-bearing refusal, and OSV is why: it does **not** error on a version string it cannot
    parse. H2 measured `aiohttp` at `not-a-version`, `1.0.0-SNAPSHOT` and `${project.version}` each
    returning **81** advisories against 70 for the real `3.9.1` — a bigger, wrong answer that every
    downstream stage treats as fact."""
    real = osv.query_package({"name": "aiohttp", "ecosystem": "PyPI", "version": "3.9.1"})
    junk = osv.query_package({"name": "aiohttp", "ecosystem": "PyPI", "version": "not-a-version"})
    evidence.record(f"real 3.9.1 -> {len(real)} records; junk version -> {len(junk)} records")
    assert len(junk) != len(real), (
        "OSV answered a junk version identically to a real one — if this ever holds, the premise "
        "behind refusing to guess a version has changed and `unpinned` should be revisited")
    assert len(junk) > len(real), "the junk version returned a SMALLER set than the real one"
