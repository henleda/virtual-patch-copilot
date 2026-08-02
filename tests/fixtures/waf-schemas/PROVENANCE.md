# Vendored declarative WAF policy schemas

Tests run offline (`ROADMAP.md`: "No network in `tests/`"), so the schemas the L1 emitter validates
against are pinned here rather than fetched. Both are regenerated per product release, so the digest
is the version — re-download and re-record it deliberately, never silently.

| file | source | sha256 |
|---|---|---|
| `nginx-app-protect-policy.json` | `github.com/nginx/documentation` → `data/nap-waf/schema/policy.json` (BSD-2-Clause) | `1d19733c3832b9315b7ecac523ee5b5e8acaa1413e36435fc76f85129ba4f459` |
| `bigip-awaf-v17_1.json` | `clouddocs.f5.com/products/waf-declarative-policy/` → `schema_v17_1.json` | `fa74948beb639827bc47266443d46ca94df62791901701a316f80740d1098c84` |

Fetch them again with:

```sh
gh api -H "Accept: application/vnd.github.raw" \
  repos/nginx/documentation/contents/data/nap-waf/schema/policy.json > nginx-app-protect-policy.json
```

F5's own NAP documentation gives no download URL — it tells you to generate the schema on an
installed NAP host (`/opt/app_protect/bin/generate_json_schema.pl`), which needs the subscription
this project does not have. The docs repo is the offline route around that, and it is why the L1
acceptance criterion is checkable here at all.

**The BIG-IP URL embeds a Sphinx content hash** (`_downloads/b5dbc8ac…/`) that changes on every docs
rebuild, so it is a provenance citation, not a live fetch target.

## What validating against these does NOT prove

Measured, not assumed: **neither schema closes any object** — `additionalProperties` is absent from
all **127** NAP and **173** BIG-IP object nodes. An emitted policy carrying an invented section, a
misspelled key, or a BIG-IP-only section left in by accident validates **green** against both. And
`blocking-settings.violations[].name` is a **free string** in both (`VIOL_PARAMETER_NUMERIC_VALUE`
does not even appear in the BIG-IP schema), so a typo in the violation that arms the block is
invisible here too.

So schema validation is a necessary check and a weak one. What it genuinely establishes is the
**portability swap**: NAP constrains `template.name` to `enum: ["POLICY_TEMPLATE_NGINX_BASE"]` while
BIG-IP types it as an unconstrained string, so a policy carrying the BIG-IP template name **fails**
NAP until swapped. That asymmetry is the one thing the schemas can prove, and the tests assert the
pre-swap failure as well as the post-swap pass — otherwise the check would be vacuous.

The proof that the policy actually *blocks* is the live appliance (L2), not this.
