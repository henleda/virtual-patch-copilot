# DEMO — virtual-patch-copilot in five minutes

Two ways to run it. **Path A** needs no cloud and no API keys — it tells the whole story from a
curated dataset, ideal for a laptop walkthrough or a screen recording. **Path B** is the live
end-to-end: a real app behind F5 Distributed Cloud (XC), a real exploit blocked in minutes.

The one-line story to keep in mind:

> A frontier model finds exploitable vulns. The code fix needs 20–30 days of change control.
> The copilot puts an **XC band-aid in front of the app in minutes** — exploit blocked, legit
> traffic untouched — and opens the **code-fix PR (the cure)** in the same pass. When the cure
> ships, it **retires** the band-aid. Every step is gated, validated, and reversible.

---

## Path A — the offline walkthrough (no XC, no keys)

```bash
pip install -e ".[console]"
python3 demo/build_demo_out.py          # writes a curated demo/out (crAPI-flavoured)
VPCOPILOT_OUT=demo/out vpcopilot console # http://127.0.0.1:8787
```

Walk the tabs top to bottom — the whole arc is already in the data:

1. **Dashboard → hero band.** "6 exploitable vulns → mitigated live in ~30s, vs a 25-day change
   window." Five XC control families are in play (service_policy, api_schema, waf, rate_limit,
   waf_data_guard). One finding ships code-only (no band-aid fits) — honesty, not theatre.
2. **Dashboard → findings.** Click any row to inspect the exploit, the vulnerable code, the
   generated band-aid, and the code cure. Note the SQLi row.
3. **Impact tab.** Control-family coverage + the full action log: the SQLi service policy shows
   **self-healed ×2** — the refiner's first policy didn't block, it diagnosed and retried until the
   exploit actually returned 403. Rate-limit shows the behavioral proof (25/30 requests 429'd).
4. **Ledger tab.** The four-state track: `found → mitigated → remediated → retired`. `crapi-sqli-001`
   is walked all the way to **retired** — its cure PR merged, so the band-aid was detached.
5. **Open HTML report ↗** (Dashboard action bar). The same hero + self-heal + model-independence
   chips + severity/coverage bars in one shareable, self-contained `report.html`.

The report also lives at `demo/out/report.html` — open it directly with no server.

---

## Path B — live, behind XC (the real thing)

Prereqs in `.env`: `XC_API_URL`, `XC_API_TOKEN`, `XC_NAMESPACE`, a model key (e.g.
`ANTHROPIC_API_KEY`), and a `GITHUB_TOKEN` for PRs. Optional: `XC_DASHBOARD_URL` for the
"XC security dashboard ↗" deep link; `CHANGE_CONTROL_DAYS` to match the customer's number.

```bash
vpcopilot console            # http://127.0.0.1:8787
```

1. **Run scan** (tab) against a vulnerable app repo (VAmPI / crAPI / Nimbus). Watch discover →
   verify → triage → generate → remediate stream live.
2. **Dashboard.** Turn OFF `dry-run`, turn ON `keep live`, and click **Apply service_policy** on a
   finding. The refiner streams in the row: attach → validate → (refine → retry)* → **before 200
   through → after 403 BLOCKED · legit ok**, with a *self-healed in N attempts* badge if it took
   more than one try. It never claims success unless the live exploit is actually blocked.
3. **XC security dashboard ↗** (hero band) — jump to the native WAF/API-Security telemetry to show
   the block landing in XC.
4. **Open PR** on the same finding to draft the real code fix against your repo.
5. **Ledger → Retire** once the cure merges — the band-aid is detached and the finding goes
   `retired`. The loop is closed.

Guardrails hold throughout: protected LBs (`VPCOPILOT_PROTECTED_LBS`, default `nimbus-www`) and
`nimbus-*` policies refuse mutation unless you explicitly opt in; every apply snapshots first and
rolls back on failure.

---

## Talking points

- **Band-aids, not cures.** Every mitigated finding also gets a code-fix PR. The band-aid buys the
  20–30 days; the PR is the fix. The ledger tracks both to `retired`.
- **Self-healing.** The copilot validates its own policy against the finding's real exploit and
  refines until it works — so it never ships a band-aid that doesn't block.
- **Model-independent.** Every agent's model is set per-agent in `config/agents.yaml` (Workflow /
  Model independence panels show it) — Claude, OpenAI, Gemini, or local Ollama, no code change.
- **Reversible + gated.** Snapshot → self-test → attach → validate → keep or rollback. A human
  approves every live change in the console.

## Screenshots

Captured from `demo/out` (Path A) and checked in under [`docs/images/`](images/) — they carry the
story on their own:

| Shot | File |
|---|---|
| Review — hero band + findings | [`2-review.png`](images/2-review.png) |
| Mitigate — per-finding live apply | [`3-mitigate.png`](images/3-mitigate.png) |
| Retire — four-state ledger (`crapi-sqli-001` at *retired*) | [`5-retire.png`](images/5-retire.png) |
| The shareable HTML report (self-heal ×2 + rate-limit proof) | [`report.png`](images/report.png) |

To regenerate them: `VPCOPILOT_OUT=demo/out vpcopilot console`, then screenshot the `#review`,
`#mitigate`, `#retire` steps and `demo/out/report.html`.
