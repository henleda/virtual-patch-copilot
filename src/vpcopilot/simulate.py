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
from .traffic import from_probe_request
from .xc import XC

MAX_SAMPLES = 10          # blocked requests carried into the report, per policy
DEFAULT_THRESHOLD = 0.01  # 1% of the sample — override with --threshold / VPCOPILOT_SIM_THRESHOLD
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
            sim.errored = errored
            if errored:
                log(f"  {errored} record(s) failed in transit — excluded from the rate")
            sim.evaluated = total
            sim.would_block = len(blocked)
            sim.block_rate = round(len(blocked) / total, 4) if total else 0.0
            sim.samples = [b.model_dump(exclude={"headers"}) for b in blocked[:MAX_SAMPLES]]
            sim.top_paths = [list(x) for x in Counter(b.path for b in blocked).most_common(5)]
            sim.top_user_agents = [list(x) for x in
                                   Counter(b.user_agent for b in blocked if b.user_agent).most_common(5)]
            if not total:
                sim.reason = ("nothing measured — every replayed request failed in transit, so this "
                              "is zero evidence, not a clean result")
            if total and sim.block_rate > threshold:
                sim.blocked_promotion = True
                sim.reason = (f"would block {sim.would_block}/{total} recorded requests "
                              f"({sim.block_rate:.1%}), over the {threshold:.1%} threshold")
                log(f"  ⚠ {name}: {sim.reason}")
            else:
                log(f"  {name}: would block {sim.would_block}/{total}")
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
    p = Path(out_dir) / "simulation.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(res.model_dump(), indent=2))
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
