# virtual-patch-copilot

An agent pipeline that **finds application vulnerabilities, mitigates each live with the right
F5 Distributed Cloud (XC) control, and drafts the real code fix** — so the exposure window
between "AI found a vuln" and "the code fix ships" collapses from weeks to minutes, with a human
in the loop and everything reversible.

The band-aid buys time; the PR is the cure. Every mitigated finding also gets a code-fix PR, and
the copilot **validates its own band-aid against the finding's real exploit** — refining until the
exploit is actually blocked — so it never claims a fix that doesn't work.

It is **model-independent**: every agent's model is chosen in `config/agents.yaml`, so you run it
on Claude, OpenAI, Gemini, or local Ollama — per agent or globally — with no code change.

## How it works

```
repo ─▶ discover ─▶ verify ─▶ triage ─▶ generate ─┬▶ apply  (XC band-aid: snapshot → self-test →
        (find)    (refute)  (route)   (XC config) │         attach → validate → refine → keep/rollback)
                                       remediate  └▶ open PR (the real code fix — the cure)
```

- **discover → verify** find candidates and adversarially refute the weak ones (calibrated,
  severity-weighted confidence gate; each distinct vuln reported once, with its effective endpoint).
- **triage** routes each finding to the strongest control: `service_policy` · `waf` ·
  `waf_data_guard` · `api_schema` · `malicious_user` · `bot_defense` · `rate_limit` — or
  code-only when no band-aid fits.
- **apply** creates/attaches the control to a live LB behind a human gate, then **validates it
  against the finding's own exploit** (a probe agent derives setup/exploit/legit requests). If the
  policy doesn't block, the **refiner** diagnoses and retries until it does — or gives up honestly
  ("code fix required"). A deterministic linter catches self-defeating policies before any live
  round-trip.
- **remediate** drafts the code cure as a GitHub PR. A **ledger** tracks every finding
  `found → mitigated → remediated → retired`, and **retire** detaches the band-aid once the cure
  merges.

Guardrails throughout: protected LBs/policies refuse mutation unless opted in; every apply
snapshots first and rolls back on failure.

## Try it in 2 minutes (no cloud, no keys)

```bash
pip install -e ".[console]"
python3 demo/build_demo_out.py            # curated dataset — the full story, offline
VPCOPILOT_OUT=demo/out vpcopilot console  # http://127.0.0.1:8787
```

Open `demo/out/report.html` directly for the shareable dashboard. See **[docs/DEMO.md](docs/DEMO.md)**
for the guided walkthrough (and the live, behind-XC path).

## Quickstart (live)

```bash
pip install -e ".[deploy,console,dev]"   # deploy=GitHub PRs, console=web UI, dev=tests
cp .env.example .env                      # model key(s) + XC creds + GITHUB_TOKEN
# edit config/agents.yaml to pick models per agent
vpcopilot console                         # scan, apply, PR, retire — all from the UI
#   or headless:
vpcopilot scan /path/to/app-repo --out out
```

`scan` writes `out/` (`findings.json`, `triage.json`, `policies/*.json`, code-fix PR drafts,
`report.html`) and performs **no** XC or GitHub writes — safe to run anywhere. Live changes happen
only in `apply` / `pr` / `retire`, behind the gate. Full command reference: **[docs/USAGE.md](docs/USAGE.md)**.

## The console

- **Dashboard** — a hero band (N exploitable → mitigated live in seconds vs. change-control days),
  the findings table (click a row to inspect exploit / code / band-aid / cure), and per-finding
  **Apply** / **Open PR** buttons that live-stream the refiner (before `200 through` → after
  `403 BLOCKED`, with a *self-healed in N attempts* badge).
- **Impact** — control-family coverage and the full gated action log.
- **Ledger** — the four-state track with a **Retire** button.
- **Workflow** — the per-agent model wiring (the model-independence proof).

## Docs

| File | What |
|---|---|
| [docs/DEMO.md](docs/DEMO.md) | 5-minute runbook (offline + live) |
| [docs/USAGE.md](docs/USAGE.md) | full CLI + console reference |
| [DESIGN.md](DESIGN.md) | architecture |
| [MODELS.md](MODELS.md) | cross-provider model notes |
| [docs/QUALITY_PLAN.md](docs/QUALITY_PLAN.md) | quality burn-down |
