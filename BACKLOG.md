# Backlog — future iterations

Loose ideas, not yet scheduled. Anything with a shape clear enough to plan against moves to
`ROADMAP.md`; anything committed lives in `PLAN.md`. Each item lives in exactly one file.

- ~~**HTML results dashboard.**~~ ✅ **Done** — `report.py` writes a single self-contained
  `<out>/report.html` (inline CSS, no external assets, native `<details>`) at the end of every
  `run_pipeline`; `vpcopilot report` rebuilds it from any existing out dir. It carries the hero,
  at-a-glance severity/coverage bars, model independence, pipeline metrics, findings + band-aid
  coverage, the generated XC policies, the `found → mitigated → remediated → retired` ledger and
  the band-aid impact table. Reachable from ② Review and Setup — **Open HTML report ↗** (rebuilt
  from the current out dir on every request, so it is never stale) and **Download** for a stamped
  `vpcopilot-report-<run>-<UTC>.html`. Not included: the benchmark scorecard — that still lives
  only in the console's ⑦ Benchmark step. Original ask: a standalone, static, shareable export of
  a run for stakeholders. _(Requested 2026-07-01.)_
- ~~**Ops console admin panel (localhost).**~~ ✅ **Done** in the console MVP — the ⚙ Setup page
  reads/writes the local `.env` (XC creds + model API keys), redacting secrets.
- ~~**Benchmark: bonus-vuln handling.**~~ ✅ **Done** as `PLAN.md` **D1** — `bonus:` in
  `bench/answer_key.yaml`; `bench.py` credits `bonus_found` and reports only genuine `noise`.
- ~~**Benchmark: per-stage metrics.**~~ ✅ **Done** as `PLAN.md` **D2** — `run_pipeline` writes
  `metrics.json` with per-stage timing and `verify.{refuted, dropped_low_confidence, confirm_rate,
  avg_confidence}` (the false-positive filter rate), rendered as the report's **Pipeline metrics**
  panel. _Residue:_ `_dedup_findings` logs discovery duplicates but the count never reaches
  `metrics.json` — one counter, tracked in `ROADMAP.md` **G4**.
- ~~**Finding correlation as a first-class step.**~~ ✅ **Done** as `PLAN.md` **B1** —
  `correlate.py` `coverage_key` collapses LB-wide controls and keys `service_policy` per endpoint;
  the pipeline skips a band-aid an earlier finding already covers and writes `correlations.json`.

_The four evidence items — sign the bundle, `export --verify`, audit event sink, attribution
backfill — moved to `ROADMAP.md` **J1–J4**._
