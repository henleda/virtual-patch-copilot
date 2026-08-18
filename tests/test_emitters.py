"""L1 — the declarative WAF policy emitter.

Offline throughout: the two vendored schemas (`tests/fixtures/waf-schemas/`) are read from disk, and
nothing here reaches an appliance. What the schemas can and cannot prove is stated in that
directory's PROVENANCE.md and pinned below — validation is a necessary check and a weak one, so
several tests assert on the exact emitted document rather than on a green validator.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vpcopilot import emitters

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "waf-schemas"

# The recorded pair the flagship constraint is derived from — the same shape probes.json carries.
PROBE = {
    "finding_id": "neg-transfer-001",
    "exploit": {"method": "POST", "path": "/api/transfer",
                "json_body": {"from": "LK-1001", "to": "LK-2001", "amount_cents": -50000}},
    "legit": {"method": "POST", "path": "/api/transfer",
              "json_body": {"from": "LK-1001", "to": "LK-1002", "amount_cents": 2500}},
}


def _validate(policy: dict, fixture: str) -> list[str]:
    from jsonschema import Draft7Validator
    schema = json.loads((FIXTURES / fixture).read_text())
    return sorted(f"{list(e.absolute_path)}: {e.message}" for e in Draft7Validator(schema).iter_errors(policy))


def _emit(**kw):
    return emitters.emit(target="bigip-awaf", control="service_policy",
                         policy_name="deny-negative-transfer", probe=PROBE, **kw)


# ---------------------------------------------------------------- the derivation


def test_the_constraint_is_derived_from_the_two_recorded_requests():
    """"Agents reason, code acts" applied to a number an operator acts on. The exploit sends -50000
    and the legit request sends 2500, so the field, its type and the bound between them are facts —
    not a model's opinion."""
    c = emitters.derive_numeric_constraint(PROBE["exploit"], PROBE["legit"])
    assert c == {"parameter": "amount_cents", "exploit_value": -50000, "legit_value": 2500,
                 "minimum": 0, "data_type": "decimal", "samples_were_whole": True,
                 "nested": False}


def test_a_field_that_merely_differs_is_not_mistaken_for_the_constraint():
    """An account id or a timestamp differs between the two requests too. Only a field the exploit
    drove NEGATIVE while the legit request kept non-negative describes this flaw."""
    c = emitters.derive_numeric_constraint(
        {"json_body": {"amount": -5, "account": 111, "ts": 1699}},
        {"json_body": {"amount": 5, "account": 222, "ts": 1700}})
    assert c["parameter"] == "amount"


@pytest.mark.parametrize("exploit,legit", [
    ({"amount": -5, "fee": -1}, {"amount": 5, "fee": 1}),      # two candidates — ambiguous
    ({"amount": 5}, {"amount": 10}),                            # neither is negative
    ({"amount": "abc"}, {"amount": 10}),                        # not numeric
    ({}, {}),                                                   # nothing recorded
    ({"ok": True}, {"ok": False}),                              # bool is not a numeric constraint
])
def test_it_refuses_to_guess_when_the_evidence_does_not_support_one_field(exploit, legit):
    """A policy built on the wrong parameter blocks nothing and looks applied — the G2 canary's
    failure mode. Returning None is the honest answer."""
    assert emitters.derive_numeric_constraint({"json_body": exploit}, {"json_body": legit}) is None


def test_an_ambiguous_pair_declines_with_a_reason_rather_than_emitting():
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="x",
                      probe={"exploit": {"json_body": {"a": -1, "b": -2}},
                             "legit": {"json_body": {"a": 1, "b": 2}}})
    assert r.supported is False and r.policy is None
    assert "refusing to guess" in r.reason


# ---------------------------------------------------------------- the four schema traps


def test_the_negative_rejection_comes_from_minimumValue_not_from_dataType():
    """TRAP 1. F5 defines `integer` as whole numbers only, so -500 IS an integer — a policy relying
    on dataType alone would import cleanly and block nothing."""
    p = _emit().policy["policy"]["parameters"][0]
    assert p["checkMinValue"] is True and p["minimumValue"] == 0


def test_the_data_type_is_never_narrowed_to_integer_from_whole_samples():
    """Found by adversarial review, and measured against this repo's OWN G2 traffic corpus: 30 of
    61 recorded legitimate `/api/pay` requests carry a fractional amount (17.5, 32.5, …). Inferring
    `integer` from two coincidentally-whole probe values would declare **49%** of known-good traffic
    illegal — 49× G2's own blast-radius threshold — while contributing NOTHING to the negative
    rejection, which comes entirely from `minimumValue`. Cost with no benefit."""
    assert _emit().policy["policy"]["parameters"][0]["dataType"] == "decimal"
    # …even though both recorded samples happen to be whole, which is recorded but not acted on.
    c = emitters.derive_numeric_constraint(PROBE["exploit"], PROBE["legit"])
    assert c["samples_were_whole"] is True and c["data_type"] == "decimal"
    # and the floor still enforces: checkMinValue is valid for `decimal` as well as `integer`.
    schema = json.loads((FIXTURES / "bigip-awaf-v17_1.json").read_text())
    props = schema["properties"]["policy"]["properties"]["parameters"]["oneOf"][0]["items"]["properties"]
    assert "decimal" in props["dataType"]["enum"]


def test_a_fractional_legit_value_still_yields_a_working_floor():
    """The case the corpus is full of: a legitimate amount of 17.50 must not be collateral."""
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="p",
                      probe={"exploit": {"path": "/p", "json_body": {"amount": -20.5}},
                             "legit": {"path": "/p", "json_body": {"amount": 17.5}}})
    p = r.policy["policy"]["parameters"][0]
    assert p["dataType"] == "decimal" and p["minimumValue"] == 0


def test_the_violation_is_armed_to_block_not_merely_alarm():
    """TRAP 2. Without block:true the constraint only ALARMS — the band-aid looks applied and lets
    the exploit through."""
    v = _emit().policy["policy"]["blocking-settings"]["violations"]
    numeric = [x for x in v if x["name"] == "VIOL_PARAMETER_NUMERIC_VALUE"]
    assert numeric and numeric[0]["block"] is True


def test_a_json_body_value_is_reached_through_a_json_profile():
    """TRAP 3. `parameterLocation` has no `json` value, so a body value is not addressable as a
    parameter directly — it becomes one only via a json-profile with handleJsonValuesAsParameters,
    attached through urls[].urlContentProfiles."""
    pol = _emit().policy["policy"]
    assert pol["json-profiles"][0]["handleJsonValuesAsParameters"] is True
    profile_name = pol["json-profiles"][0]["name"]
    attached = [c for c in pol["urls"][0]["urlContentProfiles"]
                if c.get("contentProfile", {}).get("name") == profile_name]
    assert attached and attached[0]["type"] == "json"
    # …and the schemas agree there is no `json` location to shortcut with.
    schema = json.loads((FIXTURES / "bigip-awaf-v17_1.json").read_text())
    params = schema["properties"]["policy"]["properties"]["parameters"]["oneOf"][0]
    enum = params["items"]["properties"]["parameterLocation"]["enum"]
    assert "json" not in enum and pol["parameters"][0]["parameterLocation"] in enum


def test_the_mandatory_default_url_content_profile_is_present_and_first():
    """TRAP 6, and only the appliance says so. ASM REFUSES a URL whose content-profile list omits
    the default `*:*` entry — "[fatal] Could not add the URL … The default URL Content Profile
    (*:*) is mandatory." Neither schema requires it, so this was invisible until a real import."""
    ucp = _emit().policy["policy"]["urls"][0]["urlContentProfiles"]
    assert ucp[0]["headerName"] == "*" and ucp[0]["headerValue"] == "*"
    assert ucp[0]["type"] == "do-nothing"


def test_the_url_protocol_matches_the_virtual_server_rather_than_being_hardcoded():
    """TRAP 5. The protocol is part of the URL's IDENTITY in ASM: an `https` entry does not match
    `http` traffic. Hardcoding https produced a policy that imported and matched nothing."""
    assert _emit(protocol="http").policy["policy"]["urls"][0]["protocol"] == "http"
    assert _emit(protocol="https").policy["policy"]["urls"][0]["protocol"] == "https"


def test_the_emitted_parameter_is_the_one_that_was_derived():
    """Found by adversarial review, and the sharpest of them: mutating the emitted parameter name to
    a constant survived the WHOLE suite. Nothing connected the derivation to the document, so the
    constraint could have been computed correctly and then written about a different field —
    a policy that validates, imports, and matches nothing."""
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="p",
                      probe={"exploit": {"path": "/p", "json_body": {"other": 1, "amount_cents": -5}},
                             "legit": {"path": "/p", "json_body": {"other": 2, "amount_cents": 5}}})
    assert r.derived_from["parameter"] == "amount_cents"
    assert r.policy["policy"]["parameters"][0]["name"] == r.derived_from["parameter"]
    assert r.policy["policy"]["parameters"][0]["minimumValue"] == r.derived_from["minimum"]


def test_the_url_entry_carries_the_exploits_own_path_and_method():
    """ASM identifies a URL by protocol + name + method — all three, per the vendored schema's own
    prose ("URL + Method"). TRAP 5 pinned only the protocol, so forcing the path to "/" or the
    method to GET survived the suite: a policy scoped to the wrong endpoint entirely."""
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="p",
                      probe={"exploit": {"method": "PUT", "path": "/api/v2/pay",
                                         "json_body": {"amount": -5}},
                             "legit": {"method": "PUT", "path": "/api/v2/pay",
                                       "json_body": {"amount": 5}}})
    u = r.policy["policy"]["urls"][0]
    assert u["name"] == "/api/v2/pay" and u["method"] == "PUT"
    # …and the default entry is still first, so the URL is acceptable to ASM (TRAP 6).
    assert u["urlContentProfiles"][0]["headerName"] == "*"


def test_the_json_profile_is_matched_on_the_json_content_type():
    """Mutating the header value to `text/plain` survived the suite: the json-profile would then
    never fire for a JSON body, the parameter would never be extracted, and the policy would import
    clean and block nothing — while every assertion about the profile still passed."""
    ucp = _emit().policy["policy"]["urls"][0]["urlContentProfiles"]
    json_entry = [c for c in ucp if c.get("type") == "json"][0]
    assert json_entry["headerName"] == "Content-Type"
    assert json_entry["headerValue"] == "application/json"


def test_the_policy_is_in_blocking_mode():
    """A policy in transparent mode observes and never blocks — the exact 'looks applied and is
    not' state G2's canary exists to catch."""
    assert _emit().policy["policy"]["enforcementMode"] == "blocking"


# ---------------------------------------------------------------- portability (the acceptance)


def test_the_emitted_policy_validates_against_the_bigip_schema():
    assert _validate(_emit().policy, "bigip-awaf-v17_1.json") == []


def test_the_same_policy_with_only_template_name_swapped_validates_against_nap():
    """L1's acceptance criterion, executed — and deliberately NOT vacuous.

    The emitter uses the BIG-IP template name, so the pre-swap object genuinely FAILS NAP (whose
    template.name is a single-value enum) and the swap proves something. Had it defaulted to the
    NGINX name, both schemas would pass and this test would certify nothing."""
    policy = _emit().policy
    before = _validate(policy, "nginx-app-protect-policy.json")
    assert before, "the pre-swap policy must FAIL NAP, or the swap proves nothing"
    assert any("template" in e and "POLICY_TEMPLATE_NGINX_BASE" in e for e in before)

    swapped = emitters.swap_target(policy, "nginx-app-protect")
    assert _validate(swapped, "nginx-app-protect-policy.json") == []

    # "the same policy object with only its template.name swapped" — assert the *only*.
    a, b = json.loads(json.dumps(policy)), json.loads(json.dumps(swapped))
    a["policy"]["template"]["name"] = b["policy"]["template"]["name"] = "<same>"
    assert a == b


def test_swapping_does_not_mutate_the_callers_policy():
    """"The same object" would be quietly false if the swap edited it in place."""
    policy = _emit().policy
    emitters.swap_target(policy, "nginx-app-protect")
    assert policy["policy"]["template"]["name"] == "POLICY_TEMPLATE_FUNDAMENTAL"


def test_schema_validation_is_known_to_be_weak_and_the_key_set_is_pinned_too():
    """Measured, not assumed: `additionalProperties` is absent from every object node in both
    schemas, so an invented section validates GREEN. The schema check alone therefore certifies
    almost nothing about the document — so the exact key set is pinned separately."""
    # Swap first, so the ONLY thing under test is the invented section — otherwise NAP rejects it
    # for the template name and the assertion would pass for the wrong reason.
    forged = emitters.swap_target(_emit().policy, "nginx-app-protect")
    forged["policy"]["totally-invented-section"] = {"nonsense": True}
    forged["policy"]["parmeters"] = []                     # …and a misspelling of a real section
    assert _validate(forged, "nginx-app-protect-policy.json") == [], \
        "if this ever fails, the schemas started closing objects — revisit PROVENANCE.md"

    assert set(_emit().policy["policy"]) == {
        "name", "template", "applicationLanguage", "enforcementMode",
        "blocking-settings", "json-profiles", "urls", "parameters"}


# ---------------------------------------------------------------- unsupported, and XC


@pytest.mark.parametrize("control", ["rate_limit", "malicious_user", "bot_defense"])
def test_a_control_with_no_declarative_equivalent_reports_unsupported_with_a_reason(control):
    """L1's third acceptance criterion. Emitting an empty or shaped-but-inert document here would
    be the failure this project exists to prevent."""
    r = emitters.emit(target="bigip-awaf", control=control, policy_name="x", probe=PROBE)
    assert r.supported is False
    assert r.policy is None                       # emits NOTHING, not an empty policy
    assert len(r.reason) > 40                     # a named reason, not a shrug
    assert control in emitters.UNSUPPORTED


@pytest.mark.parametrize("control", ["waf", "api_schema"])
def test_declarative_equivalents_not_built_decline_rather_than_emit_an_inert_policy(control):
    """These map to a declarative-WAF policy in principle, but this emitter does not implement them.
    They DECLINE (supported=False, no policy) with a named reason — the same discipline as the
    no-equivalent controls, for a different reason (built-or-buildable but declined, not impossible),
    so they are deliberately NOT in UNSUPPORTED."""
    r = emitters.emit(target="bigip-awaf", control=control, policy_name="x", probe=PROBE)
    assert r.supported is False
    assert r.policy is None                       # a shaped-but-inert document is the failure to avoid
    assert len(r.reason) > 40
    assert control not in emitters.UNSUPPORTED    # distinct from a control with NO equivalent at all


def test_waf_data_guard_emits_a_schema_valid_response_masking_policy():
    """The response-masking form (live-proven 2026-08-18). It derives NOTHING from the probe — the
    sensitive-data classes are fixed — so it emits with no exploit/legit pair, and the policy masks a
    PAN and an SSN on egress. Validated against the vendored AWAF schema, like the value form."""
    r = emitters.emit(target="bigip-awaf", control="waf_data_guard", policy_name="mask-profile-pii")
    assert r.supported is True and r.policy is not None
    dg = r.policy["policy"]["data-guard"]
    assert dg["enabled"] is True and dg["maskData"] is True          # masks, and masking is ON…
    assert dg["creditCardNumbers"] is True and dg["usSocialSecurityNumbers"] is True   # …PAN + SSN
    assert dg["enforcementMode"] == "ignore-urls-in-list"            # empty list = enforce on ALL urls
    # THE live-found trap: VIOL_DATA_GUARD must be alarm-only. block:true (the template default) makes
    # ASM REJECT the whole response instead of masking it — schema-valid, wrong behavior.
    viol = r.policy["policy"]["blocking-settings"]["violations"]
    dg_viol = [v for v in viol if v["name"] == "VIOL_DATA_GUARD"]
    assert dg_viol and dg_viol[0]["block"] is False and dg_viol[0]["alarm"] is True
    assert _validate(r.policy, "bigip-awaf-v17_1.json") == []        # schema-clean


def test_waf_attack_signatures_declined_because_asm_stages_them_verified_on_a_live_bigip():
    """The attack-signature `waf` form was built and tested against a live BIG-IP (v17.5, AS3 3.56):
    the policy imports and attaches in blocking mode, but ASM keeps freshly-imported signatures in
    STAGING (log-only) regardless of signatureStaging / placeSignaturesInStaging /
    enforcementReadinessPeriod=0 and a follow-up apply-policy task, so a SQLi it is meant to block
    reaches the app. Emitting it would be a band-aid that looks applied and blocks nothing. This test
    pins the decision AND its reason, so a future 'why not just emit signatures?' is answered in code."""
    r = emitters.emit(target="bigip-awaf", control="waf", policy_name="x", probe=PROBE)
    assert r.supported is False and r.policy is None
    assert "staging" in r.reason.lower() and "signature" in r.reason.lower()


def test_unsupported_is_never_expressible_as_an_empty_collection():
    """The reason `GeneratedArtifacts.items` already carries min_length=1: an empty collection is
    how a missing band-aid silently becomes an absent one."""
    from pydantic import ValidationError

    from vpcopilot.schemas import GeneratedArtifacts
    with pytest.raises(ValidationError):
        GeneratedArtifacts(items=[])
    r = emitters.emit(target="bigip-awaf", control="rate_limit", policy_name="x", probe=PROBE)
    assert r.supported is False and r.reason      # an explicit answer, not an absence


def test_the_xc_target_emits_the_generated_spec_unchanged():
    """XC is an emitter too, so the abstraction is proven by the backend that already works — and
    the XC path stays byte-identical, which is L1's fourth acceptance criterion."""
    spec = {"metadata": {"name": "deny-negative-pay-amount"}, "spec": {"algo": "FIRST_MATCH"}}
    r = emitters.emit(target="xc", control="service_policy", policy_name="p", spec=spec)
    assert r.supported is True and r.policy is spec


def test_the_xc_registry_is_untouched_by_this_module():
    """controls.py keeps the XC registry unchanged (acceptance criterion 4)."""
    from vpcopilot import controls
    assert set(controls.CONTROLS) == {"service_policy", "waf", "waf_data_guard", "api_schema",
                                      "rate_limit", "malicious_user", "bot_defense"}
    src = (Path(__file__).resolve().parents[1] / "src/vpcopilot/emitters.py").read_text()
    assert "controls." not in src and "import controls" not in src


def test_adding_a_target_touches_only_this_module():
    """Acceptance criterion 5, made testable: a target is a row in TARGETS and nothing else, so the
    emitter must not be keyed on a hardcoded list anywhere outside it."""
    assert set(emitters.TARGETS) == {"xc", "bigip-awaf", "nginx-app-protect"}
    results = emitters.emit_all(control="service_policy", policy_name="p",
                                spec={"x": 1}, probe=PROBE)
    assert {r.target for r in results} == set(emitters.TARGETS)


def test_an_unknown_target_is_an_error_not_a_silent_skip():
    with pytest.raises(emitters.EmitError, match="unknown target"):
        emitters.emit(target="nope", control="service_policy", policy_name="x", probe=PROBE)


def test_a_finding_with_no_recorded_pair_declines_rather_than_inventing_one():
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="x", probe={})
    assert r.supported is False and "no recorded pair" in r.reason


def test_a_nested_parameter_is_flagged_because_asm_naming_is_undocumented():
    """F5 documents no rule for how ASM names a parameter extracted from a NESTED JSON key. Getting
    it wrong yields a policy that validates and matches nothing, so it is surfaced rather than
    assumed — the roadmap's own open question, answered by declining to be silent."""
    r = emitters.emit(target="bigip-awaf", control="service_policy", policy_name="x",
                      probe={"exploit": {"path": "/p", "json_body": {"txn": {"amount": -5}}},
                             "legit": {"path": "/p", "json_body": {"txn": {"amount": 5}}}})
    assert r.supported is True and r.derived_from["nested"] is True
    assert "undocumented" in r.reason


# ---------------------------------------------------------------- the vendored schemas


def _run_dir(tmp_path, policy_name="deny-negative-pay-amount", probes=True, corrupt=False):
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies.json").write_text(json.dumps(
        [{"finding_id": "f1", "control": "service_policy", "policy_name": policy_name}]))
    (tmp_path / "policies" / f"service_policy.{policy_name}.json").write_text(
        "{ broken" if corrupt else json.dumps({"spec": {}}))
    if probes:
        (tmp_path / "probes.json").write_text(json.dumps([{**PROBE, "finding_id": "f1"}]))
    return tmp_path


def test_the_cli_survives_a_policy_name_the_model_chose(tmp_path):
    """Found by adversarial review. `policy_name` is a free string a MODEL picks — schemas.py calls
    it "kebab-case" but nothing validates it — and Rich parses markup inside table cells. A name
    carrying a closing tag raised MarkupError, printed a traceback and wrote NOTHING, after the
    constraint had derived correctly."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    d = _run_dir(tmp_path, policy_name="deny-[-close-]-thing")
    # The literal Rich crasher, kept out of the filename because a `/` is a separate defect
    # (below): patch the index alone so the name reaches the renderer verbatim.
    (d / "policies.json").write_text(json.dumps(
        [{"finding_id": "f1", "control": "service_policy", "policy_name": "deny-[/bogus]-thing"}]))
    res = CliRunner().invoke(cli.app, ["emit", "--out", str(d), "--target", "bigip-awaf"])
    assert "MarkupError" not in res.output and "Traceback" not in res.output
    assert list((d / "emitted").glob("*.json")), "the policy must still be written"


def test_a_policy_name_carrying_a_separator_cannot_escape_the_output_directory(tmp_path):
    """Found while writing the test above, which is the better find: `policy_name` is a model-chosen
    string interpolated into a FILENAME, so `../../etc/x` resolves outside `emitted/`. The K1
    precedent — a policy name reaching a path is refused, not trusted."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    d = _run_dir(tmp_path)
    (d / "policies.json").write_text(json.dumps(
        [{"finding_id": "f1", "control": "service_policy", "policy_name": "../../escaped"}]))
    res = CliRunner().invoke(cli.app, ["emit", "--out", str(d), "--target", "bigip-awaf"])
    assert res.exit_code == 0
    written = list((d / "emitted").glob("*.json"))
    assert written and all(p.parent == d / "emitted" for p in written)
    assert not (tmp_path.parent / "escaped.json").exists()
    assert ".." not in written[0].name


def test_the_cli_declines_a_corrupt_index_rather_than_tracebacking(tmp_path):
    """`policies.json` is rewritten by every scan and can be caught mid-write. An unreadable index
    means nothing can be established, which is a decline with a reason (the J4 precedent)."""
    from typer.testing import CliRunner

    from vpcopilot import cli
    d = _run_dir(tmp_path)
    (d / "policies.json").write_text("{ truncated")
    res = CliRunner().invoke(cli.app, ["emit", "--out", str(d), "--target", "bigip-awaf"])
    assert res.exit_code == 1 and "cannot read" in res.output
    assert "Traceback" not in res.output


def test_the_cli_emits_and_writes_the_policy(tmp_path):
    from typer.testing import CliRunner

    from vpcopilot import cli
    d = _run_dir(tmp_path)
    res = CliRunner().invoke(cli.app, ["emit", "--out", str(d), "--target", "bigip-awaf"])
    assert res.exit_code == 0
    written = json.loads((d / "emitted" / "bigip-awaf.deny-negative-pay-amount.json").read_text())
    assert written["policy"]["parameters"][0]["name"] == "amount_cents"


def test_the_console_endpoint_and_the_cli_emit_the_same_document(tmp_path, monkeypatch):
    """One module function, two surfaces."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    d = _run_dir(tmp_path)
    monkeypatch.setattr(A, "OUT", d)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    body = TestClient(A.app).post("/api/emit", json={"target": "bigip-awaf"}).json()
    assert body["emitted"] == 1
    direct = emitters.emit(target="bigip-awaf", control="service_policy",
                           policy_name="deny-negative-pay-amount",
                           probe={**PROBE, "finding_id": "f1"})
    assert body["results"][0]["policy"] == direct.policy


def test_the_console_declines_a_corrupt_index_with_a_reason_not_a_500(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    d = _run_dir(tmp_path)
    (d / "policies.json").write_text("{ truncated")
    monkeypatch.setattr(A, "OUT", d)
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    r = TestClient(A.app, raise_server_exceptions=False).post("/api/emit", json={"target": "bigip-awaf"})
    assert r.status_code == 400 and "cannot read" in r.json()["detail"]


def test_the_console_lists_targets_from_the_registry(monkeypatch):
    """Acceptance criterion 5 on this surface: the picker must not hardcode a list."""
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    monkeypatch.setattr(A, "ENV_PATH", A.Path("/nonexistent-vpcopilot-env"))
    keys = [t["key"] for t in TestClient(A.app).get("/api/emit-targets").json()["targets"]]
    assert keys == list(emitters.TARGETS)


def test_the_review_page_actually_calls_the_emit_endpoint():
    """A surface nothing calls is not a surface (the I1 precedent)."""
    html = (Path(__file__).resolve().parents[1]
            / "src/vpcopilot/console/static/index.html").read_text()
    assert "/api/emit" in html and "runEmit(" in html and "emitTarget" in html


def test_the_cli_command_is_registered():
    from vpcopilot import cli
    assert "emit" in {c.name or c.callback.__name__ for c in cli.app.registered_commands}


def test_the_vendored_schemas_are_the_ones_provenance_records():
    """They are regenerated per product release, so the digest IS the version. A silent swap would
    change what the acceptance criterion means."""
    import hashlib
    expected = {
        "nginx-app-protect-policy.json":
            "1d19733c3832b9315b7ecac523ee5b5e8acaa1413e36435fc76f85129ba4f459",
        "bigip-awaf-v17_1.json":
            "fa74948beb639827bc47266443d46ca94df62791901701a316f80740d1098c84",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == digest
        assert digest in (FIXTURES / "PROVENANCE.md").read_text()


def test_provenance_states_what_validation_does_not_prove():
    """The J1/J4 precedent: state the limit rather than leave it to be discovered."""
    txt = (FIXTURES / "PROVENANCE.md").read_text()
    assert "additionalProperties" in txt and "free string" in txt
