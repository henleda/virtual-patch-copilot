# Backlog — future iterations

Ideas captured for later; not yet scheduled.

- **HTML results dashboard.** Have an agent generate a self-contained HTML dashboard of a
  run — findings, triage (band-aids + residual risk), generated XC configs, and code-fix
  PRs, plus the benchmark scorecard. A shareable artifact for stakeholders. NOTE: the
  interactive console dashboard now exists — this is the *standalone, static, shareable*
  export (a single self-contained .html file). _(Requested 2026-07-01.)_
- ~~**Ops console admin panel (localhost).**~~ ✅ **Done** in the console MVP — the Admin tab
  reads/writes the local `.env` (XC creds + model API keys), redacting secrets.
- **Benchmark: bonus-vuln handling.** Add a `bonus:` section to `bench/answer_key.yaml` so
  real findings beyond the core key are credited rather than lumped into "extras."
  Distinguish bonus real vulns from genuine noise.
- **Benchmark: per-stage metrics.** Track verify precision/recall (false-positive filter
  rate) and discovery duplicates, not just discovery + triage.
- **Finding correlation as a first-class step.** The model already remarks "band-aid for A
  covers B" — make it explicit so overlapping band-aids are deduped/linked in the output.
