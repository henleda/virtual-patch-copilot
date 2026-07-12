# Discovery / triage baseline

The nightly `bench` job scores a scan against a labeled answer key (`bench.run_bench`) and **fails
if quality regresses below the thresholds here**. Bump these numbers only when a real improvement is
confirmed — never lower them to make a red build pass.

Scored metrics (see `src/vpcopilot/bench.py`):

| metric | meaning | floor |
|---|---|---|
| `discovery_recall` | fraction of known vulns in the key that were found + verified | **0.80** |
| `triage_accuracy` | fraction of found vulns routed to an acceptable control (or no_bandaid) | **0.80** |
| `noise` | verified findings not in the key or bonus list (lower is better) | **≤ 4** |

The gate reads these floors; the fixture/deterministic portion runs in the fast suite
(`tests/test_bench.py`) and the live portion (`-m bench`, real models against VAmPI/crAPI) runs in
the nightly workflow. Answer keys live alongside their target app (e.g. `bench/vampi.key.yaml`).
