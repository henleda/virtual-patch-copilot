"""H3 — an OpenAPI spec as a discovery input. Offline: no model, no network.

The structural pass is deterministic on purpose, so it is tested directly; the agent's judgement
about which of those facts matter is not something a unit test can pin."""
import pytest

from vpcopilot.inputs import openapi as oa

SPEC = """
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /api/pay:
    post:
      security: []
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
              properties:
                amount: {type: number}
                memo: {type: string, maxLength: 100}
                page: {type: integer, minimum: 0, maximum: 500}
  /api/users/{id}:
    get:
      parameters: [{name: id, in: path, schema: {type: string, format: uuid}}]
      security: [{bearer: []}]
"""


def _write(tmp_path, text=SPEC, name="spec.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_operations_are_flattened_with_their_methods(tmp_path):
    ops = oa.operations(oa.load_spec(_write(tmp_path)))
    assert {(o["method"], o["path"]) for o in ops} == {
        ("POST", "/api/pay"), ("GET", "/api/users/{id}")}


def test_a_number_with_no_minimum_is_found_deterministically(tmp_path):
    """The acceptance case. Recall here must not depend on which model is configured."""
    issues = oa.weak_constraints(oa.load_spec(_write(tmp_path)))
    amt = [i for i in issues if i["field"] == "amount" and "minimum" in i["detail"]]
    assert amt and amt[0]["notable"] is True          # a money-ish name is ranked up
    assert amt[0]["where"] == "POST /api/pay"


def test_a_bounded_field_is_not_flagged(tmp_path):
    issues = oa.weak_constraints(oa.load_spec(_write(tmp_path)))
    assert not [i for i in issues if i["field"] == "page"]
    assert not [i for i in issues if i["field"] == "memo"]     # maxLength present
    assert not [i for i in issues if i["field"] == "id"]       # format present


def test_an_open_object_and_a_missing_security_are_both_reported(tmp_path):
    issues = oa.weak_constraints(oa.load_spec(_write(tmp_path)))
    kinds = {(i["kind"], i["where"]) for i in issues}
    assert ("open_object", "POST /api/pay") in kinds
    assert ("no_auth", "POST /api/pay") in kinds
    assert ("no_auth", "GET /api/users/{id}") not in kinds     # it declares bearer


def test_refs_are_followed(tmp_path):
    spec = """
openapi: 3.0.3
info: {title: t, version: "1"}
components:
  schemas:
    Xfer: {type: object, additionalProperties: false, properties: {amount: {type: number}}}
paths:
  /p:
    post:
      security: [{b: []}]
      requestBody: {content: {application/json: {schema: {$ref: '#/components/schemas/Xfer'}}}}
"""
    issues = oa.weak_constraints(oa.load_spec(_write(tmp_path, spec)))
    assert [i for i in issues if i["field"] == "amount"]


def test_a_cyclic_ref_does_not_hang(tmp_path):
    spec = """
openapi: 3.0.3
info: {title: t, version: "1"}
components: {schemas: {A: {$ref: '#/components/schemas/A'}}}
paths:
  /p: {post: {security: [{b: []}], requestBody: {content: {application/json: {schema: {$ref: '#/components/schemas/A'}}}}}}
"""
    assert oa.weak_constraints(oa.load_spec(_write(tmp_path, spec))) is not None


@pytest.mark.parametrize("text,msg", [
    ("just: a mapping", "no top-level"),
    ("openapi: 3.0.0\ninfo: {}", "declares no `paths`"),
    ("- not\n- a mapping", "not an OpenAPI document"),
])
def test_a_document_that_is_not_a_spec_says_so(tmp_path, text, msg):
    with pytest.raises(RuntimeError, match=msg):
        oa.load_spec(_write(tmp_path, text))


def test_a_missing_file_says_so():
    with pytest.raises(RuntimeError, match="no OpenAPI spec at"):
        oa.load_spec("/nope/nothing.yaml")


# ---- the orphan comparison ----
def test_orphans_compare_both_directions(tmp_path):
    o = oa.orphans(oa.load_spec(_write(tmp_path)), ["POST /api/pay", "GET /api/legacy"])
    assert o["matched"] == ["/api/pay"]
    assert o["spec_only"] == ["/api/users/{id}"]
    assert o["code_only"] == ["/api/legacy"]


@pytest.mark.parametrize("declared,served", [
    ("/users/{id}/pay", "/users/:id/pay"),
    ("/users/{userId}", "/users/[id]"),
    ("/API/Pay", "/api/pay"),
    ("/api/pay/", "/api/pay"),
])
def test_path_parameter_styles_are_treated_as_the_same_endpoint(tmp_path, declared, served):
    spec = f"openapi: 3.0.3\ninfo: {{title: t, version: '1'}}\npaths:\n  {declared}:\n    get: {{}}\n"
    o = oa.orphans(oa.load_spec(_write(tmp_path, spec)), [f"GET {served}"])
    assert o["matched"] and not o["spec_only"] and not o["code_only"]


def test_the_scan_input_carries_the_structural_findings_as_hints(tmp_path):
    """The agent gets the deterministic pass as context, so it judges rather than hunts."""
    name, text = oa.as_scan_input(_write(tmp_path))
    assert name == "spec.yaml"
    assert "OpenAPI SPECIFICATION, not source code" in text
    assert "unbounded_number" in text and "amount" in text
    assert "   1: " in text                    # and the spec itself, numbered


def test_the_spec_input_ranks_notable_fields_first(tmp_path):
    _, text = oa.as_scan_input(_write(tmp_path))
    hints = [ln for ln in text.splitlines() if ln.startswith("  - [")]
    assert "amount" in hints[0]


# ---- the pipeline wiring ----
def test_spec_findings_key_on_their_endpoint_not_the_spec_filename():
    """A spec is ONE file declaring MANY endpoints. Keying on the file made
    `endpoint_of("pay-api.yaml")` the same string for every finding, so all of them collapsed onto
    one service_policy coverage key and all but the first were logged "already covered" — silently
    generating no band-aid. Observed on a real spec scan."""
    from vpcopilot.correlate import coverage_key
    a = coverage_key("service_policy", "", identity="/api/v1/transfer")
    b = coverage_key("service_policy", "", identity="/api/v1/admin/reset")
    assert a != b
    # two findings on the SAME endpoint still share one band-aid, which is the point of B1
    assert coverage_key("service_policy", "", identity="/api/v1/transfer") == a


def test_a_spec_may_accompany_a_repo_but_not_an_advisory():
    from vpcopilot.pipeline import run_pipeline
    with pytest.raises(ValueError, match="cannot be combined"):
        run_pipeline(advisory="CVE-2024-23334", spec_path="/s.yaml")
    with pytest.raises(ValueError, match="pass a repo path"):
        run_pipeline()


def test_the_console_scan_surface_accepts_a_spec():
    from fastapi.testclient import TestClient

    from vpcopilot.console import app as A
    c = TestClient(A.app)
    assert c.post("/api/scan", json={"cve": "CVE-2024-23334", "spec": "/s.yaml"}).status_code == 400
    assert c.post("/api/scan", json={}).status_code == 400
    assert "spec" in A.ScanReq.model_fields
