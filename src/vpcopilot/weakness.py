"""J5 — CWE and OWASP classification, derived by CODE.

Regulated buyers ask for the compensating-control story in CWE and OWASP terms. This stamps each
finding with them, and the whole design is about **not inventing** one.

**Four tiers, and the tier travels with the value** (`cwe_source`):

- **`advisory`** — OSV handed us `cwe_ids` for this advisory. That is a *fact*, not a
  classification, and it is emitted verbatim. Verified live: `CVE-2024-23334` → `CWE-22`,
  `GHSA-8r6j-v8pm-fqw3` → `CWE-94`.
- **`evidence`** — the recorded exploit/legit pair *proves* a numeric-bound violation, so `CWE-1284`
  is a fact about this finding rather than a guess about its class. See `classify_from_probe`.
- **`mapped`** — derived from `vuln_class` through the table below. A classification this tool made.
- **`""` (blank)** — no honest answer exists. Blank, with the reason available. This is the H2
  `unpinned` precedent: a guess that looks like an answer is worse than a gap.

**Why the advisory tier must win, and never be re-derived from `vuln_class`.** `inputs/cve.py`
deliberately collapses `CWE-77`, `CWE-78` and `CWE-94` into one `command_injection` class, and
`CWE-200`/`CWE-209`/`CWE-532` into `sensitive_data`. Going back the other way would stamp a
*specific* CWE the advisory never claimed — a fabricated fact of exactly the kind this project
exists to avoid. So where OSV spoke, we quote it.

**Why several classes map to nothing, checked against MITRE's own guidance** (each verified at
`cwe.mitre.org`, not assumed):

- `CWE-840` *Business Logic Errors* is **PROHIBITED** for mapping — *"This CWE ID must not be used
  to map to real-world vulnerabilities"* — because it is a Category, not a Weakness. It is the
  obvious choice for `business_logic`, and it is disallowed, so that class maps to **nothing**.
  That includes the flagship negative-amount finding.
- `CWE-200` and `CWE-287` are **DISCOURAGED** (an impact and a Class rather than root causes), so
  `sensitive_data` and `broken_auth` get nothing — the latter because MITRE offers two
  destinations when leaving CWE-287 and this class genuinely holds both.

**Why three classes get no OWASP API category.** Injection was **removed** from the API Security
Top 10 in 2023 and was *not* absorbed into API8 (Security Misconfiguration) — the API8 page never
mentions it. So `sqli`, `xss` and `command_injection` have no honest API category, and forcing them
into one would be a wrong answer dressed as a taxonomy. They are blank in the API axis; the Web
Top 10 covers them, and a Web column is a separate decision this item did not take.

Nothing here calls a model. The classification an auditor reads is code, per the project's
"agents reason, code acts".
"""
from __future__ import annotations

import re

# A CWE id and nothing else. Anything that does not match this is not quoted as a fact.
_CWE_ID = re.compile(r"CWE-\d+")

# vuln_class -> (cwe id, cwe title). ONLY weaknesses MITRE marks ALLOWED or ALLOWED-WITH-REVIEW for
# vulnerability mapping, and only where the class maps to exactly one of them. Verified 2026-08-04.
CLASS_CWE: dict[str, tuple[str, str]] = {
    "sqli": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"),
    "xss": ("CWE-79", "Improper Neutralization of Input During Web Page Generation"),
    "command_injection": ("CWE-77", "Improper Neutralization of Special Elements used in a Command"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "broken_object_authz": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "mass_assignment": ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined "
                                   "Object Attributes"),
    "rate_abuse": ("CWE-799", "Improper Control of Interaction Frequency"),
}

# Why the remaining classes are deliberately absent. Surfaced rather than left as silence, so
# "we did not classify this" never reads like "this has no weakness".
CWE_DECLINED: dict[str, str] = {
    "business_logic": (
        "CWE-840 (Business Logic Errors) is the obvious mapping and MITRE marks it PROHIBITED — it "
        "is a Category, not a Weakness, and must not be used to map real vulnerabilities. The class "
        "spans too many distinct weaknesses to name one honestly."),
    "sensitive_data": (
        "CWE-200 is DISCOURAGED for mapping (it describes an impact, not a root cause) and the class "
        "spans several distinct weaknesses — a leaked token, a PAN in a response and a secret in a "
        "log are not one CWE."),
    "broken_auth": (
        "CWE-287 is DISCOURAGED, and MITRE offers TWO destinations when leaving it — CWE-1390 (Weak "
        "Authentication) and CWE-306 (Missing Authentication) — because they are different "
        "weaknesses. This class holds both, plus response-discrepancy enumeration (CWE-204): a "
        "signup that leaks which emails exist is not 'weak authentication'. CWE-1390 is also "
        "ALLOWED-WITH-REVIEW, and the review it asks for is exactly this one."),
    "other": "the finding's class is 'other', so there is nothing to map from.",
}

# vuln_class -> OWASP API Security Top 10 (2023). The API list is primary: this tool reasons in
# endpoints, service policies and API schemas.
CLASS_OWASP_API: dict[str, tuple[str, str]] = {
    "broken_object_authz": ("API1:2023", "Broken Object Level Authorization"),
    "broken_auth": ("API2:2023", "Broken Authentication"),
    "mass_assignment": ("API3:2023", "Broken Object Property Level Authorization"),
    "sensitive_data": ("API3:2023", "Broken Object Property Level Authorization"),
    "rate_abuse": ("API4:2023", "Unrestricted Resource Consumption"),
    "ssrf": ("API7:2023", "Server Side Request Forgery"),
}

OWASP_DECLINED: dict[str, str] = {
    "sqli": "Injection was REMOVED from the API Security Top 10 in 2023 and not absorbed elsewhere",
    "xss": "Injection was REMOVED from the API Security Top 10 in 2023 and not absorbed elsewhere",
    "command_injection": (
        "Injection was REMOVED from the API Security Top 10 in 2023 and not absorbed elsewhere"),
    "business_logic": (
        "API6:2023 covers automated abuse of a legitimate business flow, which is not the same as a "
        "broken business invariant — mapping this class to it would be wrong"),
    "other": "the finding's class is 'other', so there is nothing to map from.",
}

# The advisory tier's ids are quoted, not looked up, so this is only for rendering a title when we
# happen to know one. An unknown id is still emitted — the id is the fact, the title is a courtesy.
CWE_TITLES: dict[str, str] = {cwe: title for cwe, title in CLASS_CWE.values()}
CWE_TITLES.update({
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-94": "Improper Control of Generation of Code",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
})


# A FOURTH tier, narrower than `mapped` and stronger: a weakness the recorded evidence establishes.
#
# `business_logic` maps to nothing at class level and that is correct — MITRE prohibits CWE-840 and
# the class genuinely spans unrelated weaknesses (a missing balance check and an unbounded amount
# are not one CWE). But L1's `emitters.derive_numeric_constraint` already decides, deterministically
# and from two recorded requests, whether a finding IS a numeric-bound violation. Where it says yes,
# CWE-1284 is a fact about that finding rather than a guess about its class.
#
# Deliberately narrow: only a numeric-bound flaw, only when the probe pair proves it. Everything
# else stays blank. This is a refinement of the `mapped` tier that the J5 decision did not
# anticipate — flagged in the roadmap so it can be rejected as scope creep without unpicking the
# rest.
EVIDENCE_CWE = ("CWE-1284", "Improper Validation of Specified Quantity in Input")


def classify_from_probe(vuln_class: str, probe: dict | None) -> dict | None:
    """CWE-1284 when the recorded exploit/legit pair establishes a numeric-bound violation.

    Returns None when the evidence does not support it — which is most of the time, and is the
    point: this tier only speaks when it can point at the two requests that prove it."""
    if (vuln_class or "") != "business_logic" or not probe:
        return None
    try:
        from .emitters import derive_numeric_constraint
    except Exception:  # noqa: BLE001 — a classification must never break a scan
        return None
    c = derive_numeric_constraint(probe.get("exploit") or {}, probe.get("legit") or {})
    if not c:
        return None
    return {"cwe": EVIDENCE_CWE[0], "cwe_title": EVIDENCE_CWE[1], "cwe_source": "evidence",
            "reason": (f"the recorded exploit sends {c['parameter']}={c['exploit_value']} where the "
                       f"legit request sends {c['legit_value']}, which establishes an unvalidated "
                       f"quantity rather than merely a 'business logic' label")}


def classify(vuln_class: str, advisory_cwe_ids: list[str] | None = None) -> dict:
    """Return `{cwe, cwe_title, cwe_source, owasp, owasp_title, reason}` for one finding.

    `advisory_cwe_ids` is OSV's own list when the finding came from an advisory (H1/H2). When
    present it wins outright — see the module docstring on why re-deriving would fabricate.
    """
    vc = (vuln_class or "").strip()
    # Validate the SHAPE, not just truthiness. `str(c).strip()` alone accepted `None` (→ the
    # fabricated id "NONE"), `123` (→ "123"), and — worst — a bare string instead of a list, which
    # iterates its CHARACTERS and stamped "C". Every one of those puts a confident wrong CWE into an
    # evidence bundle, which is the single thing this module must never do. The advisory tier is the
    # one that claims to state a FACT, so it is the one that has to be sure.
    raw = advisory_cwe_ids if isinstance(advisory_cwe_ids, (list, tuple, set)) else []
    ids = [c.upper().strip() for c in raw
           if isinstance(c, str) and _CWE_ID.fullmatch(c.upper().strip())]

    if ids:
        cwe, source = ids[0], "advisory"
        reason = ("the advisory named this weakness; it is quoted, not inferred"
                  if len(ids) == 1 else
                  f"the advisory named {len(ids)} weaknesses ({', '.join(ids)}); the first is "
                  f"quoted and the rest are recorded in the finding's advisory data")
    else:
        pair = CLASS_CWE.get(vc)
        cwe, source = (pair[0] if pair else ""), ("mapped" if pair else "")
        reason = "" if pair else CWE_DECLINED.get(vc, f"no CWE mapping is defined for class {vc!r}")

    api = CLASS_OWASP_API.get(vc)
    owasp, owasp_title = (api if api else ("", ""))
    if not api:
        why = OWASP_DECLINED.get(vc, f"no OWASP API category is defined for class {vc!r}")
        reason = f"{reason} · OWASP: {why}" if reason else f"OWASP: {why}"

    return {"cwe": cwe, "cwe_title": CWE_TITLES.get(cwe, ""), "cwe_source": source,
            "owasp": owasp, "owasp_title": owasp_title, "reason": reason}


def stamp(finding, advisory: dict | None = None, probe: dict | None = None) -> None:
    """Set `cwe` / `owasp` / `cwe_source` on a `Finding` in place.

    Called by the pipeline before `_write_out`, so `findings.json` carries the classification while
    the *discover* contract stays untouched — the agent is never asked for these, which is what
    keeps G4's four-provider recall scorecard from moving.

    Precedence: **advisory** (the record said so) → **evidence** (the probe pair proves it) →
    **mapped** (the class implies it) → blank. Each tier is more specific to *this* finding than
    the one after it.
    """
    vc = getattr(finding, "vuln_class", "") or ""
    got = classify(vc, (advisory or {}).get("cwe_ids"))
    if not got["cwe"]:
        ev = classify_from_probe(vc, probe)
        if ev:
            got = {**got, **ev}
    finding.cwe = got["cwe"]
    finding.owasp = got["owasp"]
    finding.cwe_source = got["cwe_source"]


def summary(findings: list[dict]) -> dict:
    """Counts for the report, including the ones that were NOT classified.

    `unclassified` is a first-class number rather than an absence: a report showing only the
    classified findings would overstate the coverage, which is the failure this whole item is
    supposed to avoid.

    And it is SPLIT, because "there is no honest mapping for this class" and "this finding never
    went through the stamp" are different facts and must never render the same way. Only the class
    table can tell them apart, so the split is computed here rather than asserted by the template:
      `declined`  — the class was considered and has a stated reason for carrying nothing.
      `unstamped` — the class WOULD map, so the blank means the finding predates J5 or reached the
                    report by a path that bypassed the pipeline. That is a defect, not a taxonomy
                    result, and the report says so.
    """
    by_owasp: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    unclassified = declined = unstamped = cwe_no_owasp = 0
    for f in findings:
        cwe, owasp = (f.get("cwe") or ""), (f.get("owasp") or "")
        if cwe:
            by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
        if owasp:
            by_owasp[owasp] = by_owasp.get(owasp, 0) + 1
        if not cwe and not owasp:
            unclassified += 1
            vc = f.get("vuln_class") or ""
            would = classify(vc)
            if would["cwe"] or would["owasp"]:
                unstamped += 1
            else:
                declined += 1
        if cwe and not owasp:
            cwe_no_owasp += 1
    return {"by_owasp": dict(sorted(by_owasp.items())), "by_cwe": dict(sorted(by_cwe.items())),
            "unclassified": unclassified, "declined": declined, "unstamped": unstamped,
            "cwe_no_owasp": cwe_no_owasp, "total": len(findings)}
