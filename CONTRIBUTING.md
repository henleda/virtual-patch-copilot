# Contributing

Thanks for your interest in virtual-patch-copilot. Contributions — bug reports, fixes, new controls,
docs — are welcome.

## Dev setup

```bash
pip install -e ".[deploy,console,dev]"
```

Requires Python 3.10+. No API keys or cloud access are needed for the test suite (it runs entirely
against in-memory fakes).

## Before you open a PR

```bash
ruff check src tests                                  # lint
pytest -m "not live and not bench"                    # the fast suite (no network/model/tenant)
```

CI runs exactly this across Python 3.10–3.12 with a coverage floor. Tests marked `live` (real XC /
model / network) and `bench` (the discovery benchmark) are excluded from the fast suite and run in
the nightly job.

- Add or update tests for anything you change; prefer the `FakeXC` / `FakeHarness` fixtures in
  `tests/conftest.py` so tests stay offline and deterministic.
- Keep the safety spine intact — every live-mutating path must snapshot → self-test → validate →
  roll back on failure, and honor the protected-LB / protected-policy guardrails.
- New band-aid controls are added in one place: the `controls.py` registry (attach/detach, LB-wide,
  validation kind, refine strategy). Wire the handler through the engine, not a new bespoke function.
- Match the surrounding style; `ruff` enforces the important bits.

## Scope + safety

This is a dual-use security tool. Please only exercise it against systems you own or are explicitly
authorized to test. Contributions that add destructive capabilities, mass-targeting, or
detection-evasion for offensive use will not be accepted. See [SECURITY.md](SECURITY.md).

## License of contributions

By contributing, you agree that your contributions are licensed under the project's Apache-2.0
license (see [LICENSE](LICENSE)).
