"""H3 — an OpenAPI spec as a discovery input.

A4 goes one way: the operator hands over a schema and XC enforces it. This is the other direction —
read the spec and find the flaws *in* it. A spec is a security artifact whether anyone treats it as
one: it is where `amount` is declared with no lower bound, where a path takes an object id with no
authorization statement, where `additionalProperties` is left open so mass assignment is legal by
declaration. Those are findings before a line of code is read, and the spec is often the only thing
you have for a service you do not own.

Two halves, deliberately split:

* **Code** does the structural pass — a numeric field with no `minimum`, a string with no
  `maxLength`, an operation with no `security`, an object that accepts extra properties. These are
  facts about the document, they need no judgement, and deriving them deterministically means recall
  does not depend on which model is configured.
* **The agent** decides which of those facts matter, and writes the exploit sketch. "No `minimum` on
  `amount` in a transfer" is a business-logic hole; the same omission on `page` is nothing. That is
  the judgement call, and it is the only part a model should be making.

The **orphan** comparison is pure code and needs both inputs: an endpoint declared in the spec that
no route in the repo serves is either dead documentation or a shadow API, and a route the code
serves that the spec never mentions is what an api_schema band-aid would silently start blocking.
Neither is a vulnerability by itself; both are the kind of drift that produces one.
"""
from __future__ import annotations

import re

from pathlib import Path
from typing import Any

HTTP_VERBS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

# Fields whose name implies a value where "unbounded" is a real hazard rather than a nitpick. Used
# only to RANK the structural findings — the agent still decides what matters.
_MONEY_ISH = ("amount", "price", "total", "balance", "quantity", "qty", "count", "limit", "size")


def load_spec(path: str) -> dict:
    """Parse an OpenAPI/Swagger document. YAML or JSON — `yaml.safe_load` handles both."""
    p = Path(path)
    if not p.is_file():
        raise RuntimeError(f"no OpenAPI spec at {path}")
    import yaml
    try:
        data = yaml.safe_load(p.read_text(errors="replace"))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"could not parse {path} as YAML or JSON: {e}") from None
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} is not an OpenAPI document (top level is not a mapping)")
    if not (data.get("openapi") or data.get("swagger")):
        raise RuntimeError(f"{path} has no top-level `openapi`/`swagger` version — is it a spec?")
    if not isinstance(data.get("paths"), dict) or not data["paths"]:
        raise RuntimeError(f"{path} declares no `paths` — nothing to analyse")
    return data


def _resolve(spec: dict, node: Any, _depth: int = 0) -> Any:
    """Follow a local `$ref` one level at a time. Bounded: a spec with a cyclic ref is a real thing
    and must not hang a scan."""
    if _depth > 8 or not isinstance(node, dict):
        return node if isinstance(node, dict) else {}
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    cur: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict) or part not in cur:
            return {}
        cur = cur[part]
    return _resolve(spec, cur, _depth + 1)


def operations(spec: dict) -> list[dict]:
    """Every declared operation, flattened, with its parameters and request-body schema resolved."""
    base = (spec.get("basePath") or "").rstrip("/")
    out = []
    for raw_path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in HTTP_VERBS or not isinstance(op, dict):
                continue
            body = {}
            rb = _resolve(spec, op.get("requestBody") or {})
            content = rb.get("content")     # a malformed spec may write this as a list — coerce it
            for _ct, media in (content if isinstance(content, dict) else {}).items():
                body = _resolve(spec, (media or {}).get("schema") or {})
                break
            if not body and op.get("parameters") is None and "schema" in op:  # swagger 2 style
                body = _resolve(spec, op.get("schema") or {})
            out.append({
                "path": f"{base}{raw_path}" if base else raw_path,
                "method": method.upper(),
                "operation_id": op.get("operationId") or "",
                "summary": op.get("summary") or op.get("description") or "",
                "parameters": [_resolve(spec, p) for p in (list(shared) + list(op.get("parameters") or []))],
                "body_schema": body,
                "security": op.get("security", spec.get("security")),
            })
    return out


def _walk_properties(spec: dict, schema: dict, prefix: str = "", _depth: int = 0):
    """Yield `(dotted_name, subschema)` for every property, following $ref and arrays."""
    if _depth > 6:
        return
    schema = _resolve(spec, schema)
    props = schema.get("properties")       # a malformed spec may write this as a list — coerce it
    for name, sub in (props if isinstance(props, dict) else {}).items():
        sub = _resolve(spec, sub)
        dotted = f"{prefix}{name}"
        yield dotted, sub
        if sub.get("type") == "object" or sub.get("properties"):
            yield from _walk_properties(spec, sub, f"{dotted}.", _depth + 1)
        if sub.get("type") == "array":
            items = _resolve(spec, sub.get("items") or {})
            if items.get("properties"):
                yield from _walk_properties(spec, items, f"{dotted}[].", _depth + 1)


def weak_constraints(spec: dict) -> list[dict]:
    """The structural pass: what the document leaves unbounded or unstated.

    Deterministic on purpose. Recall here does not depend on which model is configured — the agent's
    job is to say which of these is worth a band-aid, not to find them."""
    issues = []
    for op in operations(spec):
        where = f"{op['method']} {op['path']}"
        if op["security"] is not None and op["security"] == []:
            issues.append({"kind": "no_auth", "where": where, "field": "",
                           "detail": "declares `security: []` — explicitly unauthenticated"})
        elif op["security"] is None:
            issues.append({"kind": "no_auth", "where": where, "field": "",
                           "detail": "no `security` declared and no global default"})
        for p in op["parameters"]:
            sch = _resolve(spec, p.get("schema") or p)
            issues += _field_issues(where, p.get("name") or "", sch, "parameter")
        body = op["body_schema"]
        if body:
            if body.get("additionalProperties") is True or (
                    body.get("type") == "object" and "additionalProperties" not in body):
                issues.append({"kind": "open_object", "where": where, "field": "(body)",
                               "detail": "the request body accepts undeclared properties — mass "
                                         "assignment is legal by declaration"})
            for name, sub in _walk_properties(spec, body):
                issues += _field_issues(where, name, sub, "body field")
    return issues


def _field_issues(where: str, name: str, sch: dict, kind: str) -> list[dict]:
    if not isinstance(sch, dict):
        return []
    t, out = sch.get("type"), []
    money = any(w in (name or "").lower() for w in _MONEY_ISH)
    if t in ("number", "integer"):
        if "minimum" not in sch and "exclusiveMinimum" not in sch:
            out.append({"kind": "unbounded_number", "where": where, "field": name,
                        "detail": f"{kind} `{name}` is a {t} with no `minimum`"
                                  + (" — a negative value is legal by declaration" if money else ""),
                        "notable": money})
        if "maximum" not in sch and "exclusiveMaximum" not in sch:
            out.append({"kind": "unbounded_number", "where": where, "field": name,
                        "detail": f"{kind} `{name}` is a {t} with no `maximum`", "notable": money})
    if t == "string" and "maxLength" not in sch and not sch.get("enum") and not sch.get("format"):
        out.append({"kind": "unbounded_string", "where": where, "field": name,
                    "detail": f"{kind} `{name}` is a string with no `maxLength`, `enum` or `format`",
                    "notable": False})
    if t == "array" and "maxItems" not in sch:
        out.append({"kind": "unbounded_array", "where": where, "field": name,
                    "detail": f"{kind} `{name}` is an array with no `maxItems`", "notable": False})
    return out


def _normalize(path: str) -> str:
    """`/users/{id}/pay` and `/users/:id/pay` and `/users/[id]/pay` are the same endpoint."""
    import re
    p = re.sub(r"\{[^}]*\}|\[[^\]]*\]|:[A-Za-z_][A-Za-z0-9_]*", "{}", path or "")
    return "/" + p.strip("/").lower()


# A quoted, absolute path inside a route-registration line: @app.route("/api/pay", …),
# path('/users/<uid>'), router.get(`/api/x`). Deliberately literal-only — a path built by
# concatenation is not evidence of what is served, and guessing at one would be worse than
# the gap it fills.
_QUOTED_PATH = re.compile(r"""['"`](/[^'"`\s]*)['"`]""")

def orphans(spec: dict, repo_routes: list[str]) -> dict:
    """Spec vs code, both directions. Pure comparison — no model, no network.

    `code_only`: served but undeclared — the one that bites, because an `api_schema` band-aid
    built from this spec would start rejecting those routes the moment it is applied. This is a
    PRESENCE claim and a source sweep can establish it.

    `spec_unverified`: declared, and the sweep did not find it in the source. Deliberately NOT
    called `spec_only` any more, and deliberately not phrased as "nothing serves this": that is an
    ABSENCE claim, and a line-wise sweep cannot establish absence. File-based routing
    (`app/api/pay/route.js`) declares a route with no line to match, and a dynamically mounted
    router never appears literally. The old key asserted the strong reading and was consumed as
    such — it raised a medium finding — so it is gone rather than left empty for someone to
    reach for again.

    `swept`: whether any route was extracted at all. A sweep that found nothing is not a spec
    whose endpoints are all unserved, and the two used to be indistinguishable."""
    declared = {_normalize(op["path"]): op["path"] for op in operations(spec)}
    served = {}
    for r in repo_routes or []:
        # Two shapes reach here and only one used to be handled:
        #   "GET POST /users/v1/register"                     <- an in-repo spec's paths
        #   '  app.py:2: @app.route("/api/pay", methods=[…])' <- a framework REGISTRATION line
        # The old code took the last whitespace token and kept it if it began with "/". A
        # registration line's last token is `methods=["POST"])`, so it kept NONE of them — meaning
        # `served` was populated only from an in-repo OpenAPI file and NEVER from code, in any
        # configuration. With no in-repo spec every declared endpoint became "declared but served
        # by no route", and with one the comparison was spec-vs-spec, so a genuinely served
        # undeclared route was reported nowhere. Verified against a 3-route Flask app.
        parts = r.split()
        path = parts[-1] if parts else ""
        if path.startswith("/"):
            served[_normalize(path)] = path
            continue
        for quoted in _QUOTED_PATH.findall(r):
            served[_normalize(quoted)] = quoted

    # `code_only` is a PRESENCE claim — "the sweep found this route in the source and the spec does
    # not declare it" — and a source sweep can establish presence. `spec_only` is an ABSENCE claim
    # — "nothing serves this" — and a line-wise sweep cannot establish that: file-based routing
    # (app/api/pay/route.js) declares a route with no line to grep, and dynamically mounted routers
    # never appear literally. So the unmatched declarations are returned as `spec_unverified`, NOT
    # as orphans, whenever the sweep is the only evidence. Publishing them as orphans is a
    # confident claim resting on evidence that cannot support it.
    unmatched = sorted(declared[k] for k in declared.keys() - served.keys())
    return {
        "spec_unverified": unmatched,
        "swept": bool(served),
        "code_only": sorted(served[k] for k in served.keys() - declared.keys()),
        "matched": sorted(declared[k] for k in declared.keys() & served.keys()),
    }


def as_scan_input(spec_path: str) -> tuple[str, str]:
    """The spec rendered for the `discover` agent: `(relative_name, numbered_text)`.

    Feeding it through `discover` rather than adding a fourth agent is deliberate — the spec is a
    file with content, discover's whole job is "read this and tell me what is wrong with it", and
    routing it through the existing stage means H3's findings verify, triage and generate exactly
    like a code finding with no new path to keep in step."""
    spec = load_spec(spec_path)
    issues = weak_constraints(spec)
    raw = Path(spec_path).read_text(errors="replace")
    lines = raw.splitlines()
    numbered = "\n".join(f"{i + 1:4}: {ln}" for i, ln in enumerate(lines[:1200]))
    hints = "\n".join(f"  - [{i['kind']}] {i['where']}  {i['detail']}"
                      for i in sorted(issues, key=lambda x: (not x.get("notable"), x["kind"]))[:60])
    header = (
        "# This is an OpenAPI SPECIFICATION, not source code. Report flaws IN THE CONTRACT: "
        "missing bounds on values that need them, operations with no authorization, bodies that "
        "accept undeclared properties, ids in paths with no ownership check.\n"
        "# A deterministic structural pass already found the following. Decide which are "
        "SECURITY-RELEVANT — an unbounded `page` is nothing, an unbounded `amount` on a transfer "
        "is a business-logic hole — and ignore the rest.\n"
        f"{hints}\n\n")
    return Path(spec_path).name, header + numbered
