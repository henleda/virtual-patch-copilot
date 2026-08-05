"""G2 — shadow simulation: what would this band-aid do to everything *else*?

The safety spine proves a policy blocks the finding's exploit and passes one legit request. It says
nothing about the other million requests a day, and that gap is why security teams leave controls in
monitor mode. This replays a recorded sample against each candidate **through a spare LB** and
reports the would-block set before anything reaches the human gate.

Replay runs on a real LB rather than an offline evaluator on purpose (roadmap G1, decided): XC's own
enforcement is the only oracle that cannot silently disagree with XC. `apply.py` does not send what
`generate` emits — `normalize_service_policy_spec` fills defaults that decide the verdict — so a
second implementation would have to track that forever, and a wrong "allow" would ship the outage
this feature exists to prevent.

Safety: the spare LB is snapshotted and restored in a `finally`, the same spine `apply` uses; a
replay failure is reported on the policy, never raised past the restore. Nothing here writes an
audit record — a rehearsal is not a change to answer for."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Callable

import httpx

from .engine import ApplyContext, guard_lb, safe_rollback
from .probe import _blocked
from .runmeta import utc_now
from .schemas import PolicySimulation, RequestRecord, SimulationResult
import os

from .traffic import from_probe_request
from .xc import XC

MAX_SAMPLES = 10          # blocked requests carried into the report, per policy
DEFAULT_THRESHOLD = 0.01  # 1% of the sample — override with --threshold / VPCOPILOT_SIM_THRESHOLD


def effective_threshold(explicit: float | None = None) -> float:
    """The blast-radius threshold, resolved in ONE place.

    This used to be a lookup each surface had to remember to perform. The CLI, the console and the
    refiner all remembered; the MCP server did not — so an operator who had tightened
    `VPCOPILOT_SIM_THRESHOLD` got the default silently applied to every simulation an agent ran,
    and the number they set was the number they believed was in force.

    A guard that each caller re-implements is a guard that holds in some callers. Making it a
    property of the module means a fifth consumer inherits it rather than reimplementing it.
    """
    if explicit is not None:
        return float(explicit)
    raw = os.environ.get("VPCOPILOT_SIM_THRESHOLD", "")
    if not raw.strip():
        return DEFAULT_THRESHOLD
    try:
        return float(raw)
    except ValueError:
        # Refusing to guess: a malformed override is not the default. Silently substituting the
        # default would apply a threshold the operator did not choose and never be told about.
        raise RuntimeError(
            f"VPCOPILOT_SIM_THRESHOLD is set to {raw!r}, which is not a number. Fix it or unset it "
            f"— falling back to the default would silently apply a threshold you did not choose."
        ) from None
_SP_ONEOF = ("no_service_policies", "active_service_policies", "service_policies_from_namespace")


def _fire(rec: RequestRecord, url: str) -> tuple[int, str]:
    """Replay one record. Module-level so tests can substitute a transport with no network."""
    r = httpx.request(rec.method, url.rstrip("/") + rec.path, params=rec.query or None,
                      headers=rec.headers or None, json=rec.json_body, timeout=15,
                      follow_redirects=False)
    return r.status_code, r.text


def _try_fire(rec: RequestRecord, url: str) -> tuple[int | None, str]:
    """Per-request error isolation. A replay is hundreds of live requests over a network; one
    reset connection or TLS hiccup must not discard the whole measurement. An errored request is
    counted separately and is NEITHER blocked nor allowed — guessing either way would bias the
    number this feature exists to report honestly. (Caught live: one transient SSL EOF aborted an
    entire policy's simulation.)"""
    try:
        return _fire(rec, url)
    except Exception:  # noqa: BLE001 — every transport failure is per-request, never fatal
        return None, ""


def sim_name(policy_name: str) -> str:
    """Simulation always runs against a throwaway object, never the operator's.

    Attaching by name alone is not enough: a candidate straight from a scan has no object in the
    tenant yet, and referencing a policy that does not exist breaks the LB's config outright
    (caught live — every replayed request failed in transit, not just the ones under the rule).
    Creating under our own name also guarantees we measure the artifact on disk rather than
    whatever an identically-named object happens to contain, and makes cleanup unambiguous:
    we created it, so we may delete it."""
    return f"{policy_name}-vpcsim"


def _create_sim_policy(xc, name: str, spec: dict, log: Callable) -> str:
    from .apply import PROTECTED_POLICIES, artifact_spec, normalize_service_policy_spec
    tmp = sim_name(name)
    if tmp in PROTECTED_POLICIES or name in PROTECTED_POLICIES:
        raise RuntimeError(f"refusing to simulate against protected policy '{name}'")
    body = {"metadata": {"name": tmp, "namespace": xc.ns},
            "spec": normalize_service_policy_spec(artifact_spec(spec))}
    if xc.service_policy_exists(tmp):
        xc.put_service_policy(tmp, body)     # a leftover from an interrupted run — replace it
    else:
        xc.create_service_policy(body)
    log(f"  created throwaway policy '{tmp}'")
    return tmp


def _attach(ctx: ApplyContext, xc, policy_name: str) -> None:
    spec = {k: v for k, v in ctx.spec.items() if k not in _SP_ONEOF}
    spec["active_service_policies"] = {"policies": [{"namespace": xc.ns, "name": policy_name}]}
    ctx.put(spec)


def _canary(out_dir: str, finding_id: str) -> RequestRecord | None:
    """The finding's own exploit, as a record — a request we KNOW the policy must block. Used to
    confirm enforcement is live before counting anything."""
    p = Path(out_dir) / "probes.json"
    if not finding_id or not p.exists():
        return None
    try:
        for pr in json.loads(p.read_text()):
            if pr.get("finding_id") == finding_id and pr.get("exploit"):
                return from_probe_request(pr["exploit"], source="probe")
    except (json.JSONDecodeError, TypeError):
        return None
    return None


def _await_enforcement(url: str, canary: RequestRecord | None, log: Callable, *,
                       wait_seconds: int, retries: int, sleep) -> bool:
    """XC config takes seconds to reach the edge. Replaying before then counts an unenforced
    policy as harmless — the failure mode that makes a blast-radius number a lie.

    With a canary (the finding's own exploit) we poll until it is actually blocked, so the count
    that follows is measured against a live policy. Without one, wait the same fixed interval the
    apply path uses and say so, because we cannot prove enforcement."""
    if canary is None:
        sleep(wait_seconds)
        log(f"  waited {wait_seconds}s for propagation (no probe for this finding — enforcement unconfirmed)")
        return False
    for i in range(1, retries + 1):
        sleep(wait_seconds)
        status, text = _try_fire(canary, url)
        if status is not None and _blocked(status, text):
            log(f"  enforcing after ~{i * wait_seconds}s (canary {canary.method} {canary.path} -> {status})")
            return True
    log(f"  ⚠ canary never blocked after {retries * wait_seconds}s — the policy may not be enforcing")
    return False


def _replay(records: list[RequestRecord], url: str,
            log: Callable) -> tuple[int, list[RequestRecord], int]:
    """Returns (evaluated, blocked, errored). `evaluated` excludes errored requests: a rate is only
    honest over requests that actually reached the edge."""
    blocked, errored = [], 0
    for rec in records:
        status, text = _try_fire(rec, url)
        if status is None:
            errored += 1
            continue
        if _blocked(status, text):
            blocked.append(rec)
    return len(records) - errored, blocked, errored


def _score(sim: PolicySimulation, total: int, blocked: list, errored: int, threshold: float) -> PolicySimulation:
    """Fill a verdict from a replay. Shared by the standalone run and the refiner's per-attempt
    check so the two can never drift on what "too broad" means."""
    sim.errored = errored
    sim.evaluated = total
    sim.would_block = len(blocked)
    sim.block_rate = round(len(blocked) / total, 4) if total else 0.0
    sim.threshold = threshold
    sim.samples = [b.model_dump(exclude={"headers"}) for b in blocked[:MAX_SAMPLES]]
    sim.top_paths = [list(x) for x in Counter(b.path for b in blocked).most_common(5)]
    sim.top_user_agents = [list(x) for x in
                           Counter(b.user_agent for b in blocked if b.user_agent).most_common(5)]
    if not total:
        sim.reason = ("nothing measured — every replayed request failed in transit, so this is "
                      "zero evidence, not a clean result")
    elif sim.block_rate > threshold:
        sim.blocked_promotion = True
        sim.reason = (f"would block {sim.would_block}/{total} recorded requests "
                      f"({sim.block_rate:.1%}), over the {threshold:.1%} threshold")
    return sim


def measure_attached(records: list[RequestRecord], url: str, *, policy_name: str = "",
                     finding_id: str = "", threshold: float = DEFAULT_THRESHOLD,
                     max_records: int | None = None, log: Callable = print) -> dict:
    """G3: blast radius of the policy that is ALREADY attached and validating.

    The refiner has just attached a candidate and confirmed it blocks the exploit, so there is no
    second attach, no second propagation wait, and no second LB — we measure the exact policy that
    just passed, where it passed. Returns a plain dict so it drops straight into the refine agent's
    result payload, the audit record and the apply result."""
    sample = records[:max_records] if max_records else records
    total, blocked, errored = _replay(sample, url, log)
    sim = _score(PolicySimulation(policy_name=policy_name, finding_id=finding_id), total, blocked,
                 errored, threshold)
    return sim.model_dump(exclude={"samples", "top_user_agents", "enforcement_confirmed", "error"})


def simulate_policies(candidates: list[dict], records: list[RequestRecord], *, lb: str, url: str,
                      out_dir: str = "out", threshold: float = DEFAULT_THRESHOLD,
                      max_records: int | None = None, source: str = "", window: str = "",
                      redacted: dict | None = None, keep_policy: bool = False,
                      wait_seconds: int = 6, retries: int = 8,
                      log: Callable = print) -> SimulationResult:
    """Replay `records` against each candidate on `lb`, one policy at a time.

    One at a time is deliberate: two candidates on the same LB share FIRST_MATCH ordering, so a
    batched run would measure something no single band-aid does."""
    xc = XC()
    guard_lb(lb, allow_protected=False, dry_run=False)
    sample = records[:max_records] if max_records else records
    bodies = not (sample and all(r.source == "xc" for r in sample))

    res = SimulationResult(
        ts=utc_now(), lb=lb, source=source, records=len(records), records_replayed=len(sample),
        window=window, redacted=dict(redacted or {}), bodies_available=bodies,
        caveats=[
            "A would-block count describes THIS sample only — a quiet window makes any policy look "
            "safe. The window and record count are stated above; read them together with the rate.",
            "Replay runs one policy at a time on a spare LB. Two candidates share FIRST_MATCH "
            "ordering, so a batched result would not describe either band-aid alone.",
        ])
    if not bodies:
        res.caveats.append(
            "Records came from XC access logs, which capture no request body — a `body_matcher` "
            "policy cannot be judged from them. Supply a HAR to exercise body predicates.")

    for cand in candidates:
        name = cand["policy_name"]
        sim = PolicySimulation(policy_name=name, control=cand.get("control", "service_policy"),
                               finding_id=cand.get("finding_id", ""), threshold=threshold)
        ctx = ApplyContext(xc=xc, lb=lb, out_dir=out_dir, log=log,
                           finding_id=cand.get("finding_id")).load()
        tmp = None
        try:
            ctx.self_test()
            tmp = _create_sim_policy(xc, name, cand.get("spec") or {}, log)
            _attach(ctx, xc, tmp)
            log(f"simulate: '{name}' attached to {lb} · waiting for the edge to enforce it")
            sim.enforcement_confirmed = _await_enforcement(
                url, _canary(out_dir, cand.get("finding_id", "")), log,
                wait_seconds=wait_seconds, retries=retries, sleep=ctx.sleep)
            log(f"  replaying {len(sample)} record(s)")
            total, blocked, errored = _replay(sample, url, log)
            if errored:
                log(f"  {errored} record(s) failed in transit — excluded from the rate")
            _score(sim, total, blocked, errored, threshold)
            log(f"  ⚠ {name}: {sim.reason}" if sim.blocked_promotion
                else f"  {name}: would block {sim.would_block}/{total}")
        except Exception as e:  # noqa: BLE001 — a replay failure is reported, never raised past restore
            sim.error = str(e)
            log(f"  ⚠ {name}: simulation failed — {e}")
        finally:
            if not keep_policy:
                safe_rollback(ctx, verify=lambda b: "active_service_policies" not in b)
                if tmp:  # we created it, so we clean it up — detach first, then delete
                    try:
                        xc.delete_service_policy(tmp)
                        log(f"  deleted throwaway policy '{tmp}'")
                    except Exception as e:  # noqa: BLE001
                        log(f"  ⚠ could not delete '{tmp}': {e}")
        res.policies.append(sim)
    if any(p.errored for p in res.policies):
        res.caveats.append(
            "Some replayed requests failed in transit and are excluded from the rate — the "
            "`errored` count says how many. A rate over a shrunken sample is weaker evidence.")
    if any(not p.enforcement_confirmed and not p.error for p in res.policies):
        res.caveats.append(
            "Enforcement could not be CONFIRMED for at least one policy (no probe to use as a "
            "canary). A would-block count measured before the edge picks up the config reads as "
            "harmless — treat an unconfirmed 0% as unmeasured, not as safe.")
    return res


def candidates_from_out(out_dir: str, policy: str | None = None) -> list[dict]:
    """The scan's generated service policies, from the `policies.json` index. Only `service_policy`
    is replayable today: the other six controls are parameterized by the engine rather than matched
    per request, so there is no per-request verdict to count."""
    out = Path(out_dir)
    idx = out / "policies.json"
    if not idx.exists():
        return []
    cands = []
    for a in json.loads(idx.read_text()):
        if a.get("control") != "service_policy":
            continue
        if policy and a.get("policy_name") != policy:
            continue
        art = out / "policies" / f"service_policy.{a['policy_name']}.json"
        if not art.exists():
            continue
        cands.append({"policy_name": a["policy_name"], "control": "service_policy",
                      "finding_id": a.get("finding_id", ""), "spec": json.loads(art.read_text())})
    return cands


def write_result(out_dir: str, res: SimulationResult) -> str:
    """Write `simulation.json`, PRESERVING any policy this run did not measure.

    A narrower replay used to erase the wider one. `simulate --policy B` filters the candidates to B
    and this function overwrote the artifact wholesale, so a policy A that an earlier run had flagged
    `blocked_promotion` lost its flag — and `promotion_block`, the pre-apply blast-radius gate, went
    quiet for it. An operator who simulated everything, saw A flagged, then re-simulated only B would
    find A applying with no warning at all: a guard erased as a side effect of measuring something
    else, which is the shape of I1's "a band-aid could vouch for its own removal".

    So entries absent from this run are carried forward and stamped `carried_from` with the timestamp
    of the run that did measure them. The gate keeps firing, and nothing pretends the number is fresh.
    """
    p = Path(out_dir) / "simulation.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = res.model_dump()
    prev = load_result(out_dir)
    if prev:
        fresh = {pol.get("policy_name") for pol in payload.get("policies") or []}
        carried = []
        for pol in prev.get("policies") or []:
            if pol.get("policy_name") in fresh:
                continue
            pol = {**pol, "carried_from": pol.get("carried_from") or prev.get("ts", "")}
            carried.append(pol)
        if carried:
            payload["policies"] = (payload.get("policies") or []) + carried
            payload["caveats"] = (payload.get("caveats") or []) + [
                f"{len(carried)} policy result(s) carried forward from an earlier replay and NOT "
                f"measured by this one ({', '.join(c['policy_name'] for c in carried)}) — each "
                "carries `carried_from`. They are preserved so the pre-apply blast-radius gate does "
                "not go quiet for a policy this narrower run did not look at."]
    p.write_text(json.dumps(payload, indent=2))
    return str(p)


def load_result(out_dir: str) -> dict:
    p = Path(out_dir) / "simulation.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}


def promotion_block(out_dir: str, policy_name: str) -> dict | None:
    """The gate check: has this policy been simulated and found too broad?

    Returns None when there is no simulation for it — G2 adds a warning, **not** a prerequisite.
    An operator who never runs `simulate` sees exactly the behaviour they see today."""
    for p in load_result(out_dir).get("policies") or []:
        if p.get("policy_name") == policy_name and p.get("blocked_promotion"):
            return p
    return None


def promotion_gate(out_dir: str, policy_name: str | None, *, allow_overbroad: bool = False,
                   dry_run: bool = False, finding_id: str | None = None, lb: str | None = None,
                   log: Callable = print) -> None:
    """Enforce the G2 blast-radius decision. Raises unless the override is explicit.

    **K1 moved this out of the console and into the module, and that is a behaviour change worth
    stating.** `promotion_block` shipped with exactly one production caller — `console/app.py` — so
    the guard the roadmap describes existed on one of two surfaces: `vpcopilot apply --from-scan`
    would happily attach an over-broad policy that the console refuses, and the `--allow-overbroad`
    flag ROADMAP.md claims never existed. That is the same shape as I1's `--force-probe`, whose guard
    lived only in the CLI and left the console able to mass-replay every destructive exploit. A guard
    in one surface is not a guard, and K1 could not honestly claim its write tools "route through the
    same gate as the CLI and console" while the two disagreed about what the gate was.

    Still a warn-with-audited-override, never a machine veto (the G2/I2 precedent): exceeding the
    threshold requires `--allow-overbroad`, and taking the override writes a `simulate_override`
    audit record naming the rate, the threshold and the actor. Silent when nothing was simulated —
    G2 adds a check, not a prerequisite."""
    if dry_run or not policy_name:
        return
    over = promotion_block(out_dir, policy_name)
    if over is None:
        return
    if not allow_overbroad:
        raise RuntimeError(
            f"simulation says this policy {over.get('reason')}. Re-run with 'allow overbroad' "
            f"(CLI: --allow-overbroad) to apply it anyway."
        )
    log(f"⚠ overbroad override: {over.get('reason')}")
    from .audit import record
    record(out_dir, "simulate_override", finding_id=finding_id, policy=policy_name, lb=lb,
           block_rate=over.get("block_rate"), threshold=over.get("threshold"),
           reason=over.get("reason"))
