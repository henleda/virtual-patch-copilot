# Backlog — future iterations

Ideas captured for later; not yet scheduled.

- ~~**HTML results dashboard.**~~ ✅ **Done** — `report.py` writes a single self-contained
  `<out>/report.html` (inline CSS, no external assets, native `<details>`) at the end of every
  `run_pipeline`; `vpcopilot report` rebuilds it from any existing out dir. It carries the hero,
  at-a-glance severity/coverage bars, model independence, pipeline metrics, findings + band-aid
  coverage, the generated XC policies, the `found → mitigated → remediated → retired` ledger and
  the band-aid impact table. Reachable from ② Review and Setup — **Open HTML report ↗** (rebuilt
  from the current out dir on every request, so it is never stale) and **Download** for a stamped
  `vpcopilot-report-<run>-<UTC>.html`. Not included: the benchmark scorecard — that still lives
  only in the console's ⑥ Benchmark step. Original ask: a standalone, static, shareable export of
  a run for stakeholders. _(Requested 2026-07-01.)_
- ~~**Ops console admin panel (localhost).**~~ ✅ **Done** in the console MVP — the Admin tab
  reads/writes the local `.env` (XC creds + model API keys), redacting secrets.
- **Benchmark: bonus-vuln handling.** Add a `bonus:` section to `bench/answer_key.yaml` so
  real findings beyond the core key are credited rather than lumped into "extras."
  Distinguish bonus real vulns from genuine noise.
- **Benchmark: per-stage metrics.** Track verify precision/recall (false-positive filter
  rate) and discovery duplicates, not just discovery + triage.
- **Finding correlation as a first-class step.** The model already remarks "band-aid for A
  covers B" — make it explicit so overlapping band-aids are deduped/linked in the output.
- **Sign the evidence bundle.** `manifest.json` SHA-256s every member, so tampering with a
  *member* is detectable — but nothing binds the manifest to a signer. A detached signature
  (sigstore or a plain GPG/minisign detached sig next to the manifest) would make a bundle
  attributable after it leaves the machine, not just internally consistent. _(Requested 2026-07-26.)_
- **`vpcopilot export --verify`.** The other half of the above: re-read a bundle, recompute each
  member's digest against the manifest, and print pass/fail. Cheap, and it means the reviewer
  doesn't have to trust the sender's word. _(Requested 2026-07-26.)_
- **Stream audit events to a SIEM.** `audit.record` is the single choke point every mutating path
  goes through — an optional sink (syslog / HTTP webhook / stdout JSON) would put the trail
  somewhere other than the box that made the change. Fail-soft: a dead collector must never fail
  an apply. _(Requested 2026-07-26.)_
- **Backfill attribution onto historic audit logs.** Entries written before identity was stamped
  in `audit.record` have no `run_id` / `actor`, and older `apply_*` entries no `finding_id`; the
  export leaves those cells blank rather than guessing. A one-shot `vpcopilot audit backfill`
  could fill only what is provably derivable (policy name → finding, via `policies.json`), mark
  the rest `unknown`, and record that it did so — a backfill that silently invents an actor is
  worse than a blank. _(Requested 2026-07-26.)_
