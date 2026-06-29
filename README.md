# virtual-patch-copilot

An agent pipeline that **finds application vulnerabilities, triages each to the right
F5 Distributed Cloud control (or to code), generates the virtual patch, and drafts the
real code fix** — so the exposure window between "AI found a vuln" and "the code fix
ships" collapses from weeks to minutes, with a human in the loop.

It is **model-independent**: every agent's model is chosen in `config/agents.yaml`, so
you run it on Claude, OpenAI, Gemini, or local Ollama models — per agent or globally —
with no code change.

> Status: **brain implemented** (read-only) — `discover → verify → triage → generate →
> remediate`. The deploy/apply step (push policies to XC on a live LB with snapshot +
> rollback + validation, and open code-fix PRs) and the ops console are the next
> increments. See `DESIGN.md`.

## How it works

```
repo ─▶ discover ─▶ verify ─▶ triage ─┬▶ generate (XC service policy / malicious-user)
        (find)    (refute)  (route)   └▶ remediate (real code fix → GitHub PR)
```

Triage routes each finding to: **service_policy** · **malicious_user** · **both** ·
**waf** (the AI WAF already handles injection) · **code_fix_only**. Virtual patches are
treated as **temporary band-aids**; every finding also gets a code-fix PR — the cure.

## Quickstart

```bash
pip install -e .            # or: pip install -e ".[dev,deploy]"
cp .env.example .env        # add your model provider key(s)
# edit config/agents.yaml to pick models per agent
vpcopilot scan /path/to/app-repo --out out
```

Outputs land in `out/`: `findings.json`, `triage.json`, `policies/*.json` (XC specs),
and `remediations/*.patch` + `*.pr.md` (code-fix PR drafts). No XC or GitHub writes
happen in `scan` — it's safe to run anywhere.

## Dogfood

The first target is the Nimbus Bank demo app (a deliberately vulnerable online bank).
Pointed at it, the pipeline should find the negative-amount transfer flaw, route it to
a service policy, generate the policy we proved live, and draft the `amount > 0` fix.
