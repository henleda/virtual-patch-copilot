"""I2 — drift and conflict detection: what is on the LB *now*, versus what the last run left,
versus what is about to be pushed.

`ApplyContext.load()` already writes a per-LB timestamped snapshot before every change. That makes
the "what did we leave behind" half free; this turns it into a comparison you can run on its own,
and a guard the apply path can consult **before** it touches anything.

Three questions, answered separately because they fail differently:

1. **live vs last snapshot** — has someone hand-edited the LB in the XC console since we last
   applied? Reported as a field-level diff, because "the LB changed" is useless and
   `rate_limit.requests: 100 -> 5` is not.
2. **live vs proposed** — is what we are about to push already there?
3. **displacement and shadowing** — what does applying cost, and will the new policy actually fire?

The roadmap wrote (3) as "an earlier ALLOW on an already-attached policy shadows the new DENY".
Running it against a live LB showed that cannot happen: both attach paths REPLACE the oneof with
exactly one policy —

    new_spec["active_service_policies"] = {"policies": [{"namespace": ..., "name": policy_name}]}

— so this tool never leaves two service policies attached, and there is no earlier policy to be
shadowed by. Chasing the criterion as written produced a confident false positive on a real LB.

What is real, and what replaced it:

* **displacement** — that same replacement silently DETACHES whatever was attached. On a live LB
  that is a loss of protection nothing was reporting. Warned and audited, never refused: replacing
  the previous band-aid is the normal flow, and refusing would break every second apply.
* **shadowing, in its only true scope** — an ALLOW *inside the policy being applied* that matches
  the exploit before its DENY does. `lint_service_policy` already walks exactly that, so this reuses
  it rather than re-deriving it.

Read-only, always: no PUT, no snapshot written, no run artifact touched. A drift check that
mutated the thing it inspects would be worthless as a pre-flight."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable

from .apply import rule_matches
from .controls import CONTROLS, detach_control


def save_snapshot(out_dir: str, lb: str, lb_obj: dict) -> str:
    """Write a snapshot in the same place and shape `ApplyContext.load()` does — so a drift check
    has something to compare against even on a run that has not applied anything yet."""
    snaps = Path(out_dir, "snapshots")
    snaps.mkdir(parents=True, exist_ok=True)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    p = snaps / f"{lb}-{ts}.json"
    p.write_text(json.dumps(lb_obj, indent=2))
    return str(p)


def latest_snapshot(out_dir: str, lb: str) -> Path | None:
    """The newest snapshot for THIS lb. Names sort lexically because the timestamp is
    `%Y%m%dT%H%M%S`; `lb_snapshot.json` is deliberately ignored — it is overwritten by whichever
    LB was applied last and cannot be attributed."""
    snaps = Path(out_dir, "snapshots")
    if not snaps.is_dir():
        return None
    files = sorted(snaps.glob(f"{lb}-*.json"))
    return files[-1] if files else None


def diff_specs(was: dict, now: dict, *, _prefix: str = "") -> list[dict]:
    """Field-level differences as dotted paths. `[{path, was, now}]`, sorted, with a whole subtree
    reported at the point it appears or disappears rather than exploded leaf by leaf."""
    out: list[dict] = []
    for key in sorted(set(was) | set(now)):
        path = f"{_prefix}{key}"
        a, b = was.get(key), now.get(key)
        if a == b:
            continue
        if isinstance(a, dict) and isinstance(b, dict):
            out.extend(diff_specs(a, b, _prefix=f"{path}."))
        else:
            out.append({"path": path, "was": a, "now": b})
    return out


def _attached_service_policies(spec: dict) -> list[dict]:
    return ((spec.get("active_service_policies") or {}).get("policies") or [])


def _control_present(spec: dict, control: str) -> bool:
    """Is this control attached at all? Derived by inverting `detach_control`, so the registry stays
    the single source of truth for what "attached" means and this cannot drift from what rollback
    and retire do.

    The test is what detach **removed**, not merely what it changed. Every detach also *writes* an
    explicit disable marker (`no_service_policies`, `disable_waf`, …), so "the spec changed" is true
    even for an LB that never had the control — an empty spec would report every control as
    attached. Only a key that was already present and that detach then dropped or emptied means the
    control was really there."""
    if control not in CONTROLS:
        return False
    probe = copy.deepcopy(spec)
    detach_control(probe, control)
    return any(k not in probe or probe[k] != spec[k] for k in spec)


def check(lb: str, *, out_dir: str = "out", control: str | None = None,
          policy_name: str | None = None, exploit: dict | None = None, spec: dict | None = None,
          xc=None, log: Callable = print) -> dict:
    """Compare live / last-snapshot / proposed. Never mutates anything."""
    if xc is None:
        from .xc import XC
        xc = XC()
    lb_obj = xc.get_lb(lb)
    live = lb_obj.get("spec", {}) or {}

    snap_path = latest_snapshot(out_dir, lb)
    changes: list[dict] = []
    if snap_path:
        try:
            was = (json.loads(snap_path.read_text()).get("spec") or {})
            changes = diff_specs(was, live)
        except json.JSONDecodeError:
            changes = []
    report = {
        "lb": lb,
        "namespace": getattr(xc, "ns", ""),
        "live_vs_snapshot": {
            "snapshot": str(snap_path) if snap_path else None,
            "drifted": bool(changes),
            "changes": changes,
        },
        "attached": sorted(c for c in CONTROLS if _control_present(live, c)),
        "proposed": {"control": control, "policy_name": policy_name,
                     "no_change": False, "already_attached": False, "note": ""},
        "displaces": [],
        "conflicts": [],
        "conflicts_checked": False,
        "warnings": [],
        "ok_to_apply": True,
    }

    if control:
        present = _control_present(live, control)
        report["proposed"]["already_attached"] = present
        if control == "service_policy" and policy_name:
            # The proposed end state is exact — this policy name attached — so "unchanged" is a
            # fact, not an inference, and skipping is safe.
            names = [p.get("name") for p in _attached_service_policies(live)]
            report["proposed"]["no_change"] = names == [policy_name]
            if present and not report["proposed"]["no_change"]:
                report["proposed"]["note"] = f"a different service policy is attached: {names}"
        elif present:
            # Presence is NOT parameter equality: a rate_limit already on at 100/MINUTE would read
            # as unchanged while you push 5/MINUTE. Silently skipping a real change is worse than
            # re-applying an identical one, so this reports and never claims no_change.
            report["proposed"]["note"] = (
                f"{control} is already attached, but its parameters are not compared — "
                "re-applying will push the new values")

    if control == "service_policy" and not report["proposed"]["no_change"]:
        # What this apply COSTS. Attaching replaces the oneof wholesale, so every currently
        # attached policy other than the one being applied is about to be detached.
        for ref in _attached_service_policies(live):
            name = ref.get("name")
            if not name or name == policy_name:
                continue
            entry = {"policy": name, "denies": 0, "rules": 0, "protects_exploit": False}
            try:
                obj = xc.get_service_policy(name)
            except Exception as e:  # noqa: BLE001 — a policy we cannot read is a warning, not a crash
                report["warnings"].append(f"could not read attached policy '{name}': {e}")
                entry["unreadable"] = True
                report["displaces"].append(entry)
                continue
            rules = ((obj.get("spec") or obj).get("rule_list") or {}).get("rules") or []
            entry["rules"] = len(rules)
            entry["denies"] = sum(1 for r in rules if (r.get("spec") or {}).get("action") == "DENY")
            if exploit:
                for rule in rules:   # FIRST_MATCH: the first matching rule decides this policy
                    rs = rule.get("spec") or {}
                    if rule_matches(rs, exploit):
                        entry["protects_exploit"] = rs.get("action") == "DENY"
                        break
            report["displaces"].append(entry)

    if control == "service_policy" and spec is not None and exploit:
        # Shadowing in its only true scope: inside the policy being applied. Reuses the A9 linter
        # so drift and the linter can never disagree about what FIRST_MATCH means.
        from .apply import lint_service_policy
        report["conflicts_checked"] = True
        for issue in lint_service_policy(spec, exploit):
            if "ALLOW rule matches the exploit" in issue:
                report["conflicts"].append({"policy": policy_name, "kind": "shadowed_deny",
                                            "reason": issue})

    report["ok_to_apply"] = not report["conflicts"]
    return report


def summarize(report: dict) -> str:
    """One line per finding, for a log sink or a CLI that already has a table."""
    lines = []
    lvs = report["live_vs_snapshot"]
    if lvs["drifted"]:
        lines.append(f"drift: {len(lvs['changes'])} field(s) changed on {report['lb']} since "
                     f"{Path(lvs['snapshot']).name if lvs['snapshot'] else 'the last snapshot'}")
    for c in lvs["changes"]:
        lines.append(f"  {c['path']}: {json.dumps(c['was'])} -> {json.dumps(c['now'])}")
    if report["proposed"]["no_change"]:
        lines.append(f"no_change: {report['proposed']['policy_name']} is already the attached policy")
    elif report["proposed"]["note"]:
        lines.append(f"note: {report['proposed']['note']}")
    for c in report["conflicts"]:
        lines.append(f"conflict: {c['reason']}")
    for w in report["warnings"]:
        lines.append(f"⚠ {w}")
    return "\n".join(lines) or f"no drift on {report['lb']}"


def preflight(lb: str, policy_name: str, *, out_dir: str, exploit: dict | None = None,
              spec: dict | None = None, refine: bool = False, force: bool = False,
              xc=None, log: Callable = print) -> dict | None:
    """The pre-apply gate, in ONE place because both apply paths need it — `apply_from_scan` and
    `refine_apply_service_policy`, the latter being the default for the CLI's `--from-scan` and the
    console's Mitigate button. Two copies of a safety check is one copy that eventually stops
    matching.

    Returns the drift report when the caller should short-circuit with `no_change`, or None to
    proceed. Raises only when applying would provably accomplish nothing.

    `refine=True` downgrades the shadowed-DENY refusal to a warning: correcting rule order is
    precisely what the refine loop exists to do, and refusing there would break the default path
    to protect it from a problem it already fixes.

    Every outcome that changes what happens is audited — the refusal, the override, the skip, and
    the detachment. A guard whose decisions are invisible cannot be reviewed after the fact."""
    from .audit import record as _audit
    rep = check(lb, out_dir=out_dir, control="service_policy", policy_name=policy_name,
                exploit=exploit, spec=spec, xc=xc, log=log)
    lvs = rep["live_vs_snapshot"]
    if lvs["drifted"]:
        log(f"  ⚠ drift: {len(lvs['changes'])} field(s) on {lb} changed since the last apply — "
            "someone edited it outside this tool")
        for c in lvs["changes"][:6]:
            log(f"      {c['path']}: {json.dumps(c['was'])[:60]} -> {json.dumps(c['now'])[:60]}")
        _audit(out_dir, "drift_detected", lb=lb, policy=policy_name,
               snapshot=lvs["snapshot"], changes=lvs["changes"])
    for w in rep["warnings"]:
        log(f"  ⚠ {w}")

    for d in rep["displaces"]:
        # Not a veto — replacing the previous band-aid IS the normal flow. But it is a live loss of
        # protection, so it is said out loud and written down rather than happening quietly.
        detail = (f"{d['rules']} rule(s), {d['denies']} DENY" if not d.get("unreadable")
                  else "contents unreadable")
        log(f"  ⚠ applying will DETACH '{d['policy']}' ({detail})")
        if d["protects_exploit"]:
            log(f"      — and '{d['policy']}' is currently what blocks this exploit")
        _audit(out_dir, "policy_displaced", lb=lb, policy=policy_name, displaced=d["policy"],
               denies=d["denies"], rules=d["rules"], protects_exploit=d["protects_exploit"])

    if rep["conflicts"]:
        first = rep["conflicts"][0]
        log(f"  ⚠ conflict: {first['reason']}")
        if refine:
            log("      — refine will reorder it at apply; continuing")
        elif not force:
            _audit(out_dir, "drift_block", lb=lb, policy=policy_name, conflicts=rep["conflicts"])
            raise RuntimeError(f"refusing to apply '{policy_name}': {first['reason']}. "
                               "Pass force=True (CLI --force, console “apply anyway”) to apply it "
                               "regardless.")
        else:
            _audit(out_dir, "drift_override", lb=lb, policy=policy_name, conflicts=rep["conflicts"])
            log("  ⚠ forced: applying past the conflict — the DENY may never fire")

    if rep["proposed"]["no_change"] and not force:
        log(f"no_change — '{policy_name}' is already the attached service policy on {lb}; "
            "nothing to push")
        _audit(out_dir, "apply_skipped_no_change", lb=lb, policy=policy_name)
        return rep
    if rep["proposed"]["note"]:
        log(f"  note: {rep['proposed']['note']}")
    return None
