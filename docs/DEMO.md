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

Walk the steps top to bottom — the whole arc is already in the data:

1. **② Review → hero band.** "6 exploitable vulns → mitigated live in ~30s, vs a 25-day change
   window." Five XC control families are in play (service_policy, api_schema, waf, rate_limit,
   waf_data_guard). One finding ships code-only (no band-aid fits) — honesty, not theatre.
2. **② Review → findings.** Click any row to inspect the exploit, the vulnerable code, the
   generated band-aid, and the code cure. Note the SQLi row.
3. **② Review → Open HTML report ↗** (one click, right there in the step — no hunting in Setup).
   The same story as a shareable, self-contained `report.html`: hero, severity/coverage bars,
   model-independence, and the band-aid impact table where the SQLi service policy shows
   **self-healed ×2** — the refiner's first policy didn't block, it diagnosed and retried until the
   exploit actually returned 403 — and rate-limit shows the behavioral proof (25/30 requests 429'd).
   **Download** grabs a stamped copy. It is rebuilt from the current out dir every time you open
   it, so it is never a stale file.
4. **⑥ Retire → ledger.** The four-state track: `found → mitigated → remediated → retired`.
   `crapi-sqli-001` is walked all the way to **retired** — its cure PR merged, so the band-aid was
   detached.
5. **⑥ Retire → audit trail.** *Every change made to a load balancer*, one row each: when (UTC) ·
   action · justified by (the finding + severity) · control (+ the XC object) · load balancer
   (+ namespace) · outcome (with the `200 allowed → 403 blocked` proof and a self-heal ×N badge) ·
   by. Filter it, expand `▸` for the raw JSON, then **Export evidence bundle (.zip)** — the
   normalized `audit.csv`, the raw `audit.log`, the exact XC configs pushed, the pre-change LB
   snapshots, and a manifest that SHA-256s every member. **All runs** does the same for every run
   dir on disk. The curated log is hand-built, so a couple of rows carry no finding or actor; a
   live apply (Path B) stamps both on every record. Detail: [AUDIT.md](AUDIT.md).

The report also lives at `demo/out/report.html` — open it directly with no server. The same bundle
is available from the CLI:

```bash
vpcopilot export --out demo/out          # -> demo/out/audit-bundle.zip
```

---

## Path B — live, behind XC (the real thing)

Prereqs in `.env`: `XC_API_URL`, `XC_API_TOKEN`, `XC_NAMESPACE`, a model key (e.g.
`ANTHROPIC_API_KEY`), and a `GITHUB_TOKEN` for PRs. Optional: `XC_DASHBOARD_URL` for the
"XC security dashboard ↗" deep link; `CHANGE_CONTROL_DAYS` to match the customer's number.

```bash
vpcopilot console            # http://127.0.0.1:8787
```

1. **① Scan** a vulnerable app repo (VAmPI / crAPI / Nimbus). Watch discover → verify → triage →
   generate → remediate stream live. The log box is scrollable and holds the **whole** transcript —
   scroll up mid-scan to re-read the discover output and it stays put; a **↓ follow** chip and a
   line counter appear until you scroll back to the bottom. Long scans no longer push the page down.
2. **② Review** the findings, and hit **Open HTML report ↗** if someone wants the artifact now.
3. **④ Mitigate.** With `dry-run` OFF and `keep live` ON (**Run settings** — the collapsible bar at the top of the Mitigate step), click
   **Mitigate service_policy ▶** on a finding. The refiner streams in the row: attach → validate →
   (refine → retry)* → **before 200 through → after 403 BLOCKED · legit ok**, with a *self-healed in
   N attempts* badge if it took more than one try. It never claims success unless the live exploit
   is actually blocked.
4. **XC security dashboard ↗** (hero band) — jump to the native WAF/API-Security telemetry to show
   the block landing in XC.
5. **⑤ Cure → Open PR** on the same finding to draft the real code fix against your repo.
6. **⑥ Retire** once the cure merges — the band-aid is detached and the finding goes `retired`. The
   loop is closed. Below the ledger, the **audit trail** now has a row per live change: which
   finding justified it, which LB and namespace it touched, whether it stuck, and who ran it
   (`VPCOPILOT_ACTOR`, else the OS user). **Export evidence bundle (.zip)** hands that to whoever
   asks why the load balancer changed — see [AUDIT.md](AUDIT.md).

Dry runs are deliberately *not* in the trail: nothing changed, so there is nothing to answer for.
The bundle is evidence for a human reviewer, not a compliance certification.

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
- **Auditable.** Every live change is recorded with the finding that justified it, the LB +
  namespace it touched, whether it stuck, and who ran it — exportable as a .zip with a SHA-256
  manifest ([AUDIT.md](AUDIT.md)). It is evidence for a human reviewer, not a compliance
  certification.

## Screenshots

Captured from `demo/out` (Path A) and checked in under [`docs/images/`](images/) — they carry the
story on their own:

| Shot | File |
|---|---|
| Scan — the target form and its scrollable run log | [`1-scan.png`](images/1-scan.png) |
| Review — hero band + findings + the HTML-report buttons | [`2-review.png`](images/2-review.png) |
| Simulate — blast radius of each candidate before it is applied | [`3-simulate.png`](images/3-simulate.png) |
| Mitigate — per-finding live apply | [`4-mitigate.png`](images/4-mitigate.png) |
| Retire — four-state ledger (`crapi-sqli-001` at *retired*) + the audit trail | [`6-retire.png`](images/6-retire.png) |
| The shareable HTML report (self-heal ×2 + rate-limit proof) | [`report.png`](images/report.png) |

To regenerate them: rebuild the dataset with `python3 demo/build_demo_out.py`, run
`VPCOPILOT_OUT=demo/out vpcopilot console`, then capture the `#scan`, `#review`, `#mitigate` and
`#simulate`, `#mitigate` and `#retire` steps plus `demo/out/report.html` at 1200px wide / 2× device pixel ratio.

Point the console at a **credential-free** `.env` when you do (`VPCOPILOT_ENV=…`): with XC creds
loaded, the hero band renders a deep link carrying your tenant hostname and namespace, and that
would ship in the image. `build_demo_out.py` curates `actor`/`host`/`out_dir` in the fixture for the
same reason — no real machine identity in a shared dataset.
