"""Shared machinery for the `live` suite — the tests that hit a real tenant, appliance or API.

Every roadmap item so far was proven by hand: G2's canary, I1's origin probe, I2's `example-dev`
diff, H1/H2's OSV behaviour, K1's MCP handshake, K2's 76-second PR review, L1's "the balance did not
move". **Not one of those proofs is repeatable by anyone but the person who ran it.** The demo's
central claim is "we ran it for real" and nothing in the repository re-runs it. This is the fixture
layer that lets those proofs become tests.

Three properties, and the second is the one that makes the suite worth having rather than dangerous:

1. **Skip when the credential is absent** — a contributor without a tenant sees `skipped`, never
   `failed`. The reason names the missing variable so a skip is actionable, not mysterious.
2. **A skip must never be reachable by accident, and a pass must never be vacuous.** Both failure
   modes end the same way — a green suite that proved nothing — which is precisely what this whole
   project treats as the worst outcome. `requires()` raises rather than returning a flag, so a test
   body cannot fall through it; and `evidence()` makes a test declare what it actually observed, so
   a run that queried nothing fails instead of passing quietly.
3. **Restore what you mutate.** A live test that leaves a control attached has changed the tenant
   for everyone, and the next test's baseline with it.
"""
from __future__ import annotations

import os

import pytest


def requires(*env: str) -> dict[str, str]:
    """Skip unless every named variable is set and non-empty; return them.

    Raises `Skipped` rather than returning a boolean on purpose: a helper that returned
    `False` would let a test body continue past it and report a pass having done nothing, which is
    the exact shape of failure this suite exists to eliminate.
    """
    missing = [k for k in env if not (os.environ.get(k) or "").strip()]
    if missing:
        pytest.skip(f"live test needs {', '.join(missing)} — set it to run this against the real "
                    f"thing (absent is a skip, never a pass)")
    return {k: os.environ[k].strip() for k in env}


class Evidence:
    """What a live test actually observed. Forces the vacuity check to be explicit.

    A live test can pass by doing nothing: the API returns an empty list, the `for` body never
    runs, every assertion inside it is skipped, and the test is green. That is the J3 defect
    (fabricated records shipping unnoticed) and the K2 defect (a diff that scanned zero files
    reading as a clean bill of health) in test form. So a test records what it saw, and the fixture
    fails the test if it saw nothing.
    """

    def __init__(self) -> None:
        self.observations: list[str] = []

    def record(self, what: str) -> None:
        self.observations.append(what)

    def __len__(self) -> int:
        return len(self.observations)


def check_not_vacuous(ev: "Evidence") -> None:
    """The teardown assertion, as a plain function so it is testable without pytest machinery —
    and so the guard itself is covered by the ordinary offline suite."""
    assert len(ev) > 0, (
        "this live test recorded no observations — it passed without proving anything. "
        "Call `evidence.record(...)` for each fact the test actually established, or the run "
        "cannot be told apart from one where the API returned nothing.")


@pytest.fixture
def evidence(request):
    """Yields an `Evidence`; fails the test if it ran and recorded nothing.

    Deliberately a fixture rather than a convention, because a convention is what the next test
    forgets — the argument K1 made for swapping `sys.stdout` instead of asking every call site to
    pass `log=`.

    **"If it ran" is load-bearing.** A test that skipped for a missing credential recorded nothing
    *correctly*, and asserting on it turned a clean skip into an ERROR — which is precisely the
    outcome the backlog item forbids ("a contributor without a tenant sees skipped, never failed").
    The first credential-free run of this suite produced exactly that, in the harness written to
    prevent it. The call report is consulted so the check applies only to tests that actually ran.
    """
    ev = Evidence()
    yield ev
    rep = getattr(request.node, "_vpc_rep_call", None)
    if rep is None or rep.skipped or rep.failed:
        return          # skipped, or already failing for a reason of its own — do not pile on
    check_not_vacuous(ev)


def restoring(fn, *args, **kwargs):
    """Run a cleanup that must happen even if the test explodes, and say so loudly if it fails.

    A live test that mutates a real tenant and then fails mid-way must not leave the estate
    changed — the next test's baseline depends on it, and so does the operator's demo.
    """
    try:
        fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"CLEANUP FAILED — the tenant/appliance may be left mutated: "
                    f"{type(e).__name__}: {e}")
