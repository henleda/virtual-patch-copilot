# Backlog — future iterations

Ideas captured for later; not yet scheduled.

- **HTML results dashboard.** Have an agent generate a self-contained HTML dashboard of a
  run — findings, triage (band-aids + residual risk), generated XC configs, and code-fix
  PRs, plus the benchmark scorecard. A shareable artifact for stakeholders that complements
  the ops console. _(Requested 2026-07-01.)_
- **Ops console admin panel (localhost).** An admin interface in the console where the user
  enters their XC API token, tenant, and XC URL, plus model API key(s) for their chosen
  provider(s); it writes/updates the local `.env`. Runs on localhost, so writing `.env`
  locally is fine. Lowers setup friction for F5 customers. _(Requested 2026-07-01.)_
- **Benchmark: bonus-vuln handling.** Add a `bonus:` section to `bench/answer_key.yaml` so
  real findings beyond the core key are credited rather than lumped into "extras."
  Distinguish bonus real vulns from genuine noise.
- **Benchmark: per-stage metrics.** Track verify precision/recall (false-positive filter
  rate) and discovery duplicates, not just discovery + triage.
- **Finding correlation as a first-class step.** The model already remarks "band-aid for A
  covers B" — make it explicit so overlapping band-aids are deduped/linked in the output.
