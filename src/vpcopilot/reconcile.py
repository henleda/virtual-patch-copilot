"""I1 — patch expiry and the reconcile loop: the thing that stops a band-aid outliving its cure.

`apply` puts a temporary control on a load balancer. `retire` takes it off once the code fix
merges. Between those two someone has to *notice* — that the cure landed, that it actually worked,
or that neither happened and the "temporary" patch is now a month old. That noticing is this
module, and it is meant to run unattended.

Three branches, decided per finding:

| the cure PR | the exploit, fired at ORIGIN | outcome |
|---|---|---|
| merged | no longer reproduces | **retire** — the fix is real, take the band-aid off |
| merged | still reproduces | **fix_ineffective** — hold the band-aid, say so loudly |
| not merged, past TTL | not fired | **escalate** — hold the band-aid, notify |

**Why the probe must hit the origin, not the load balancer.** With the band-aid live, firing at
the LB proves nothing: a blocked exploit means the band-aid works, which is what we already knew,
and says nothing about whether the code was fixed. The only way to ask "is the bug gone?" while
leaving the patch in place is to go around the patch. So reconcile fires at an operator-declared
origin URL and never at the LB.

**Why not detach, fire, and re-attach instead.** It was the obvious alternative and it is worse in
every dimension that matters here. It turns an evidence-gathering pass into a mutating one, on a
schedule, at 03:00, with nobody watching the window in which the vulnerability is live and
unprotected. Six of the seven controls are LB-wide, so detaching to test one finding drops
protection for every other finding on that LB. And `ApplyContext.load()` writes a snapshot on
every call, so a nightly pass would repoint `drift.latest_snapshot` every night and the I2
pre-apply gate would start reporting its own reconcile passes as unexplained operator drift.

**Refusing to guess is a first-class outcome.** Measured against a real tenant, one of three lab
origins sits behind a BIG-IP that answers direct requests with `403 Direct origin access denied`.
Unreachable origins are not an edge case, so "I could not prove the fix works, so I am leaving the
band-aid on" (`probe_skipped`) is a normal, frequent result — not an error. Every branch that
cannot establish a fact holds the control rather than removing it.

**Report-only by default.** `apply=False` computes and records every outcome but detaches nothing.
`--apply` is the human gate; authoring the crontab exercises it once, deliberately."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from . import audit, inventory, ledger

TARGETS_ENV = "VPCOPILOT_RECONCILE_TARGETS"
INTERVAL_ENV = "VPCOPILOT_RECONCILE_MIN_INTERVAL_HOURS"
WEBHOOK_ENV = "VPCOPILOT_ESCALATION_WEBHOOK"
RENOTIFY_ENV = "VPCOPILOT_RECONCILE_RENOTIFY_HOURS"

# Verdicts that stand until something changes. A transient "nothing to do this pass" must not
# erase one of these — the operator reads the last outcome as the current state of the finding.
_MATERIAL = ("fix_ineffective", "escalated", "would_retire", "retired")

DEFAULT_MIN_INTERVAL_HOURS = 24
DEFAULT_RENOTIFY_HOURS = 168
_LOCK_STALE_MINUTES = 60


# ---------------------------------------------------------------- targets


def targets() -> dict[str, str]:
    """Parse `VPCOPILOT_RECONCILE_TARGETS` — `lb=origin_url` pairs, comma or whitespace separated.

    An explicit allowlist, never inferred from the ledger or from live tenant state. Reconcile
    fires real, destructive exploits unattended; "which host do I attack at 3am" is a decision that
    belongs to a human editing a config line, not to whatever an LB happens to point at today.
    Bare `lb` with no origin is allowed and means "reconcile may escalate this LB but can never
    probe it", which is exactly right for an origin that refuses direct access.
    """
    raw = (os.environ.get(TARGETS_ENV) or "").strip()
    out: dict[str, str] = {}
    for chunk in raw.replace(",", " ").split():
        lb, _, origin = chunk.partition("=")
        lb = lb.strip()
        if lb:
            out[lb] = origin.strip()
    return out


def _min_interval_hours() -> int:
    return _int_env(INTERVAL_ENV, DEFAULT_MIN_INTERVAL_HOURS)


def _renotify_hours() -> int:
    return _int_env(RENOTIFY_ENV, DEFAULT_RENOTIFY_HOURS)


def _int_env(name: str, default: int) -> int:
    try:
        raw = (os.environ.get(name) or "").strip()
        return int(raw) if raw else default
    except ValueError:
        return default


# ---------------------------------------------------------------- time


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str | None) -> datetime | None:
    """Tolerant ISO parse. A malformed timestamp must not crash a pass — it means "unknown", and
    unknown always resolves toward holding the control."""
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def expiry(entry: dict, now: datetime) -> dict:
    """Age and TTL remaining for one ledger entry, None-safe against pre-I1 entries.

    An entry with no TTL is treated as **never expiring**, not as expired. Entries written before
    I1 shipped, and every hand-built test fixture, have no `ttl` key; reading that as "overdue"
    would escalate the entire back catalogue on the first pass."""
    t = entry.get("ttl") or {}
    applied, expires = _parse(t.get("applied_at")), _parse(t.get("expires_at"))
    age_h = (now - applied).total_seconds() / 3600 if applied else None
    remaining_h = (expires - now).total_seconds() / 3600 if expires else None
    return {
        "applied_at": t.get("applied_at"), "expires_at": t.get("expires_at"),
        "ttl_hours": t.get("ttl_hours"),
        "age_hours": round(age_h, 2) if age_h is not None else None,
        "remaining_hours": round(remaining_h, 2) if remaining_h is not None else None,
        "expired": bool(expires and now >= expires),
    }


# ---------------------------------------------------------------- pass lock


class PassLock:
    """An `O_EXCL` file lock so two passes never interleave read-modify-write on the ledger.

    `ledger._LOCK` is a threading lock — it does nothing across processes, and cron plus a console
    scan are two processes. A second pass **exits cleanly** rather than blocking: cron jobs that
    wait pile up, and a reconcile pass that piles up eventually runs forty of itself at once."""

    def __init__(self, out_dir: str, *, now: Callable[[], datetime] = _now):
        self.path = Path(out_dir) / "reconcile.lock"
        self._now = now
        self.acquired = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._break_if_stale()
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return self
        with os.fdopen(fd, "w") as f:
            json.dump({"pid": os.getpid(), "ts": self._now().isoformat()}, f)
        self.acquired = True
        return self

    def __exit__(self, *exc):
        if self.acquired:
            self.path.unlink(missing_ok=True)
        return False

    def _break_if_stale(self):
        """A pass killed mid-run leaves its lock behind. Without this, one SIGKILL disables
        reconcile forever and nobody notices, because the whole point is that nobody is watching."""
        try:
            held = _parse(json.loads(self.path.read_text()).get("ts"))
        except (OSError, json.JSONDecodeError, AttributeError):
            held = None
        if not self.path.exists():
            return
        if held is None or self._now() - held > timedelta(minutes=_LOCK_STALE_MINUTES):
            self.path.unlink(missing_ok=True)


# ---------------------------------------------------------------- origin


def origin_is_an_lb(origin_url: str, lb_obj: dict) -> bool:
    """Is the declared "origin" actually the load balancer's own front door?

    If it is, the band-aid is in the request path and gets to vouch for its own removal: the
    exploit is blocked by the control we are trying to retire, that reads as "the app is fixed",
    and the protection comes off. `targets()` cannot catch this on its own — it never looks the LB
    up — but the pass already holds an XC client, so the check is one comparison."""
    host = (urlparse(origin_url).hostname or "").lower()
    if not host:
        return False
    domains = {str(d).lower() for d in ((lb_obj.get("spec") or {}).get("domains") or [])}
    return host in domains


def origin_health(origin_url: str, *, log: Callable = print) -> dict:
    """Is the origin actually answering, before we read anything into a probe result?

    Without this, an unreachable origin returns connection errors that read as "the exploit did not
    succeed", which reads as "the fix works", which retires a live band-aid protecting a still-
    vulnerable app. That is the worst outcome this module can produce, so it is checked first and
    separately."""
    import httpx
    try:
        with httpx.Client(timeout=10, verify=False, follow_redirects=True) as c:  # noqa: S501
            r = c.get(origin_url)
        # Any HTTP answer proves something is listening and routable. A 403 from a BIG-IP refusing
        # direct origin access is NOT healthy — it is a wall we cannot probe through — and a 5xx is
        # the origin failing rather than serving. A 401, by contrast, is an auth-protected app (the
        # common real target) answering normally: the authenticated probe (Layer B) arbitrates it,
        # so 401 must NOT short-circuit here or reconcile could never auto-retire any origin that
        # answers 401 at `/`.
        if r.status_code == 403:
            return {"ok": False, "status": r.status_code,
                    "reason": f"origin answered {r.status_code} — it refuses direct access"}
        if r.status_code >= 500:
            return {"ok": False, "status": r.status_code,
                    "reason": f"origin answered {r.status_code} — it is failing, not serving"}
        return {"ok": True, "status": r.status_code, "reason": ""}
    except Exception as e:  # noqa: BLE001 — every transport failure is the same answer: cannot probe
        return {"ok": False, "status": None, "reason": f"{type(e).__name__}: {e}"}


def _reconcile_auth() -> dict:
    """Probe auth built here rather than via `apply._probe_auth_from_env`.

    That helper always sets `login_path` when it returns anything, so a token-only setup still
    fires a `POST /api/login` with empty credentials before every probe. Once a night, per finding,
    that is a synthetic failed-login stream feeding straight into the Malicious-User detection this
    tool demonstrates. Same env vars, minus the spurious login."""
    token = (os.environ.get("VPCOPILOT_PROBE_TOKEN") or "").strip()
    user = (os.environ.get("VPCOPILOT_PROBE_USER") or "").strip()
    pw = (os.environ.get("VPCOPILOT_PROBE_PASS") or "").strip()
    login = (os.environ.get("VPCOPILOT_PROBE_LOGIN_PATH") or "").strip()
    auth: dict = {}
    if token:
        auth["token"] = token
    if user:
        auth.update({"username": user, "password": pw, "login_path": login or "/api/login"})
    return auth


# ---------------------------------------------------------------- webhook


def notify(payload: dict, *, log: Callable = print) -> str:
    """POST an escalation to `VPCOPILOT_ESCALATION_WEBHOOK`. Silent when unset.

    Returns `sent` / `skipped` / `failed`. A webhook that is down must never fail the pass or
    change an outcome — the audit record is the durable notification; this is the convenient one."""
    url = (os.environ.get(WEBHOOK_ENV) or "").strip()
    if not url:
        return "skipped"
    import httpx
    try:
        with httpx.Client(timeout=10) as c:
            r = c.post(url, json=payload)
        if r.status_code >= 400:
            log(f"  ⚠ escalation webhook returned {r.status_code} — audit record still written")
            return "failed"
        return "sent"
    except Exception as e:  # noqa: BLE001
        log(f"  ⚠ escalation webhook unreachable ({type(e).__name__}) — audit record still written")
        return "failed"


# ---------------------------------------------------------------- the pass


def _cure_state(entry: dict, cache: dict, *, log: Callable) -> str:
    """`merged` / `open` / `none` / `unknown`. `unknown` on any GitHub failure, and `unknown`
    always holds — a rate-limited token must never read as "no cure, escalate"."""
    cure = entry.get("cure") or {}
    url = cure.get("pr_url")
    if not url:
        return "none"
    if url in cache:
        return cache[url]
    from .retire import pr_is_merged
    try:
        state = "merged" if pr_is_merged(url) else "open"
    except Exception as e:  # noqa: BLE001 — one bad PR must not end the pass
        log(f"  ⚠ could not read {url}: {type(e).__name__}: {e}")
        state = "unknown"
    cache[url] = state
    return state


def _probe(entry: dict, out_dir: str, origin: str, *, log: Callable) -> dict:
    """Fire this finding's recorded exploit at the origin. `{}` when it cannot be fired.

    Only findings with a real entry in `out/probes.json` are probed. There is no fallback to the
    Nimbus-specific `probe_sqli` / `probe_negative_pay` helpers: firing crAPI's SQLi probe at VAmPI
    would produce a confident, wrong answer about an unrelated app."""
    from .apply import _load_probe
    from .probe import probe_from_spec
    spec = _load_probe(out_dir, entry.get("finding_id")) or {}
    # Fireable = an exploit path (the block-style probe) OR a leak path (the response-masking probe,
    # which carries `leak`/`leak_secrets` and NO `exploit` leg). Without the leak branch a
    # `waf_data_guard` finding short-circuits to `{}` here and holds at `skipped_no_probe`, so the
    # leak exemption in `_one` and the reconcile auto-retire it enables are dead code in production —
    # `probe_from_spec` already handles the leak shape.
    fireable = (spec.get("exploit") or {}).get("path") or (spec.get("leak") or {}).get("path")
    if not fireable:
        return {}
    try:
        return probe_from_spec(origin, spec, log=log, auth=_reconcile_auth())
    except Exception as e:  # noqa: BLE001 — a DNS failure on one finding must not end the pass
        log(f"  ⚠ probe failed for {entry.get('finding_id')}: {type(e).__name__}: {e}")
        # NOT `{}`. An empty dict is what "there is no probe recorded for this finding" returns,
        # and that is a PERMANENT condition an operator can only fix by re-scanning. A probe that
        # exists and blew up in transport is a TRANSIENT one — the origin was unreachable, TLS
        # failed, the connection dropped — and it will very likely work on the next pass. Reporting
        # the second as the first sends someone to fix the wrong thing, which is the same
        # collapse `auth_failed` already exists to prevent one case of.
        return {"probe_error": f"{type(e).__name__}: {e}"}


def _due_for_probe(entry: dict, now: datetime, *, force: bool) -> bool:
    """Throttle only the destructive part. The TTL check and the PR check are free reads and run
    every pass, so an escalation is never delayed by a probe cooldown."""
    if force:
        return True
    last = _parse((entry.get("reconcile") or {}).get("last_probe_at"))
    return last is None or (now - last) >= timedelta(hours=_min_interval_hours())


def _should_escalate(entry: dict, now: datetime) -> bool:
    """Escalate once, then only on a change or after a long re-notify interval. Otherwise a nightly
    cron writes another escalation record every night forever and the audit trail becomes noise."""
    rec = entry.get("reconcile") or {}
    if not rec.get("escalated_at"):
        return True
    last = _parse(rec.get("escalated_at"))
    return last is None or (now - last) >= timedelta(hours=_renotify_hours())


def reconcile(out_dir: str = "out", *, apply: bool = False, finding_id: str | None = None,
              force_probe: bool = False, trigger: str = "cli",
              now: Callable[[], datetime] | None = None,
              allow_protected: bool = False, log: Callable = print) -> dict:
    """One reconcile pass. Read-only against the tenant unless `apply=True`.

    `now` is injected rather than read from the clock so the not-yet-expired branch is testable —
    the same constructor-injection the apply spine uses for `sleep`."""
    clock = now or _now
    # Documented as cli/console/cron, but cron invokes the CLI — so an operator marks a scheduled
    # pass by exporting VPCOPILOT_RECONCILE_TRIGGER=cron in the crontab. Without this the value
    # `cron` appeared in the docs and in no record ever written.
    trigger = (os.environ.get("VPCOPILOT_RECONCILE_TRIGGER") or "").strip() or trigger
    t0 = clock()
    pass_id = uuid.uuid4().hex[:12]
    out = Path(out_dir)

    # Safety net: pull this session's live band-aids into the global inventory if they are not there
    # yet — a ledger written before the split, a first pass, or a patch applied on another machine.
    # Idempotent (never overwrites an existing inventory entry); then the pass reads inventory.
    inventory.migrate_from_dirs([out_dir])

    if not inventory.exists() and not (out / "ledger.json").exists():
        raise RuntimeError(
            f"nothing to reconcile — no inventory at {inventory._path()} and no ledger at "
            f"{out / 'ledger.json'}. Live band-aids are recorded in the inventory on apply; a cron "
            "job with no working directory (or one pointed at the wrong dir) will otherwise report "
            "zero patches forever. Set VPCOPILOT_INVENTORY_DIR if the inventory lives elsewhere.")

    if force_probe and not finding_id:
        # Guarding this only in the CLI left the console able to mass-replay every destructive
        # exploit at once. One module function, two surfaces — so the rule lives here.
        raise RuntimeError("force_probe requires a finding_id — replaying every destructive "
                           "exploit at once is not something to do by accident.")
    allow = targets()
    if not allow:
        raise RuntimeError(
            f"{TARGETS_ENV} is not set. Reconcile fires real exploits unattended, so its targets "
            "are an explicit allowlist, never inferred. Set e.g. "
            f"{TARGETS_ENV}='crapi-lab=http://10.0.0.5:8888 vampi-lab=http://10.0.0.5:5000'.")

    from .engine import protected_lbs
    protected = protected_lbs()
    # The global live-band-aid inventory is the source of truth now, not any one session's ledger —
    # so a reconcile pass sees every live patch across every session/target, and can never miss one
    # a re-scan pruned from its session ledger.
    entries = inventory.live()
    if finding_id:
        entries = {k: v for k, v in entries.items() if k == finding_id}

    summary = {"pass_id": pass_id, "trigger": trigger, "apply": apply, "started_at": t0.isoformat(),
               "checked": 0, "actions": [], "skipped": [], "escalations": 0, "retired": 0,
               "fix_ineffective": 0, "lock": "acquired"}

    with PassLock(str(inventory.inventory_dir()), now=clock) as lock:
        if not lock.acquired:
            log("another reconcile pass is running — exiting without doing anything")
            summary["lock"] = "busy"
            return summary
        pr_cache: dict = {}
        health_cache: dict = {}
        for fid, e in sorted(entries.items()):
            mit = e.get("mitigation")
            if not mit or e.get("state") not in ("mitigated", "remediated"):
                continue
            summary["checked"] += 1
            try:
                res = _one(fid, e, out_dir=out_dir, allow=allow, protected=protected,
                           allow_protected=allow_protected, apply=apply, now=clock(),
                           force_probe=force_probe, pass_id=pass_id, trigger=trigger,
                           pr_cache=pr_cache, health_cache=health_cache, log=log)
            except Exception as ex:  # noqa: BLE001
                # Every external call inside _one is already guarded, but XC and retire are not —
                # and an unattended pass that dies on finding #2 silently never computes the
                # escalations for #3..#40. Each finding fails alone.
                log(f"  ⚠ {fid}: pass error — {type(ex).__name__}: {ex}")
                inventory.record_reconcile(fid, last_run_at=clock().isoformat(),
                                        reason=f"pass error: {type(ex).__name__}: {ex}")
                res = {"finding_id": fid, "outcome": "skipped_error", "reason": str(ex)}
            summary["actions"].append(res)
            if res["outcome"] == "retired":
                summary["retired"] += 1
            elif res["outcome"] == "escalated":
                summary["escalations"] += 1
            elif res["outcome"] == "fix_ineffective":
                summary["fix_ineffective"] += 1
            elif res["outcome"].startswith("skipped"):
                summary["skipped"].append(fid)

    summary["finished_at"] = clock().isoformat()
    log(f"reconcile {pass_id}: {summary['checked']} live patch(es) · "
        f"{summary['retired']} retired · {summary['escalations']} escalated · "
        f"{summary['fix_ineffective']} fix_ineffective")
    return summary


def _one(fid: str, e: dict, *, out_dir: str, allow: dict, protected: set | list,
         allow_protected: bool, apply: bool, now: datetime, force_probe: bool, pass_id: str,
         trigger: str, pr_cache: dict, health_cache: dict, log: Callable) -> dict:
    """One finding, one decision. Every path that cannot establish a fact holds the control."""
    mit = e.get("mitigation") or {}
    # The session the band-aid was applied from — where this finding's probe spec + audit trail live.
    # Inventory entries carry it; `out_dir` is the fallback for any entry written before the split.
    sess = e.get("session") or out_dir
    lb, control = mit.get("lb"), mit.get("control")
    exp = expiry(e, now)
    base = {"finding_id": fid, "lb": lb, "control": control, "policy": mit.get("policy_name"),
            "expiry": exp, "pass_id": pass_id}

    def hold(outcome: str, reason: str, **extra):
        """Record and return one non-retiring outcome.

        `ok` is TRANSIENT — "nothing to do on this pass" — and must never overwrite a material
        verdict. Without this, the pass after a `fix_ineffective` hits the probe cooldown, records
        `ok`, and the dashboard shows a known-broken fix as fine while cron goes green."""
        log(f"  {fid}: {outcome} — {reason}")
        fields = {"last_run_at": now.isoformat(), "reason": reason,
                  **{k: v for k, v in extra.items() if k != "probe"}}
        prior = (e.get("reconcile") or {}).get("outcome")
        if outcome != "ok" or prior not in _MATERIAL:
            fields["outcome"] = outcome
        else:
            fields["transient"] = reason      # said, but not in place of the standing verdict
        inventory.record_reconcile(fid, **fields)
        return {**base, "outcome": outcome, "reason": reason, "standing": prior, **extra}

    if lb not in allow:
        return hold("skipped_not_allowlisted",
                    f"'{lb}' is not in {TARGETS_ENV} — reconcile only touches declared targets")
    if lb in protected and not allow_protected:
        return hold("skipped_protected", f"'{lb}' is a protected LB")

    cure_state = _cure_state(e, pr_cache, log=log)
    inventory.record_reconcile(fid, cure_state=cure_state)

    # --- branch 3: overdue with no merged cure. Needs no probe, so it is checked first and is
    # never delayed by an unreachable origin or a probe cooldown.
    if cure_state != "merged":
        if not exp["expired"]:
            return hold("ok", f"cure {cure_state}, {_fmt_remaining(exp)} of TTL remaining")
        if not _should_escalate(e, now):
            return hold("ok", "already escalated; nothing changed since")
        return _escalate(fid, e, base, out_dir=sess, now=now, cure_state=cure_state,
                         trigger=trigger, pass_id=pass_id, log=log)

    # --- the cure merged. Now the only question that matters: is the bug actually gone?
    origin = allow.get(lb) or ""
    if not origin:
        return hold("skipped_no_origin",
                    f"cure merged, but no origin declared for '{lb}' — cannot prove the fix works, "
                    "so the band-aid stays on")
    # If the declared origin is actually this LB's own front door, the band-aid is in the request
    # path and would block its own exploit — the control we are trying to retire gets to vouch for
    # its own removal. `targets()` cannot catch this (it never looks the LB up); one comparison here
    # can, whenever XC is reachable. If XC is unreachable we fall through — `blocked_by_edge` still
    # catches the live case from the probe response, and crashing the pass over a read is worse.
    try:
        from .xc import XC
        lb_obj = XC().get_lb(lb)
    except Exception:  # noqa: BLE001 — an XC read failure is not a reason to end the pass
        lb_obj = None
    if lb_obj is not None and origin_is_an_lb(origin, lb_obj):
        return hold("skipped_not_at_origin",
                    f"the declared origin {origin} is '{lb}'s own domain — probing it would fire "
                    "the exploit through the load balancer whose band-aid is under test, letting "
                    "the control vouch for its own removal")
    if origin not in health_cache:
        health_cache[origin] = origin_health(origin, log=log)
    health = health_cache[origin]
    if not health["ok"]:
        return hold("skipped_origin_unhealthy",
                    f"cure merged, but origin {origin} is not probeable ({health['reason']}) — "
                    "holding the band-aid")
    if not _due_for_probe(e, now, force=force_probe):
        return hold("ok", f"cure merged; probe cooling down (<{_min_interval_hours()}h since the "
                          "last one). These exploits are destructive and feed the same telemetry "
                          "the tenant reports on.")

    from .apply import _load_probe
    probe = _probe(e, sess, origin, log=log)
    if probe.get("exploit_status") is not None:
        # Only a probe that actually FIRED THE EXPLOIT arms the cooldown and replaces the stored
        # result. The cooldown exists to throttle destructive replays; a missing probes.json, a DNS
        # failure, or a login that 404s never fires one, and stamping `last_probe_at` for those
        # would silence the real probe for 24h over a misconfiguration — observed live, where a
        # wrong login path put a finding into a day-long "cooling down" with no probe behind it.
        inventory.record_reconcile(fid, last_probe_at=now.isoformat(), probe=probe)
    # `probe_from_spec` returns auth_failed with every field None rather than a misleading "not
    # blocked". Distinguish it from "there is no probe at all" — one is a credential to fix, the
    # other is a finding that can never be auto-retired, and at 3am the difference is the whole
    # message.
    if probe.get("auth_failed"):
        return hold("skipped_auth_failed",
                    "cure merged, but the probe could not authenticate at origin — check "
                    "VPCOPILOT_PROBE_USER/PASS/LOGIN_PATH; holding the band-aid")
    if probe.get("probe_error"):
        return hold("skipped_probe_error",
                    f"cure merged, but the probe could not reach the origin ({probe['probe_error']}) "
                    f"— this is a transient failure, not a missing probe; the band-aid stays on and "
                    f"the next pass will retry")
    if not probe or probe.get("exploit_status") is None:
        return hold("skipped_no_probe",
                    "cure merged, but this finding has no runnable probe — cannot prove the fix "
                    "works, so the band-aid stays on")
    spec = _load_probe(sess, fid) or {}
    if not spec.get("legit") and not spec.get("leak"):
        # `probe_from_spec` defaults legit_ok to True when a probe has no legit leg, so the
        # sanity gate below would pass vacuously — and "the exploit did not succeed" at a target
        # nothing confirmed we can reach is exactly the reading that must never retire a control.
        # A response-masking (`leak`) probe is exempt: it carries no `legit` leg, but its own leak
        # request doubles as the baseline — for a leak probe `legit_ok` means "the leak response was
        # actually observed (a real 2xx, not a 4xx/edge-block)", so the gate below is not vacuous.
        return hold("skipped_no_legit_baseline",
                    "cure merged, but this probe has no legit request to confirm the origin is "
                    "really serving the app — cannot trust the exploit result, holding")
    if probe.get("legit_ok") is False:
        return hold("skipped_origin_unhealthy",
                    "cure merged, but the legit request failed at origin — the target is wrong or "
                    "broken, so the exploit result cannot be trusted")

    # At the origin there is no band-aid in the path, so `exploit_blocked` should be the APP's own
    # verdict. If the response carries an XC block page, it is not — the request reached the load
    # balancer (a redirect to the public host, a mistyped origin) and the control we are about to
    # remove is the thing that blocked it. That is the one reading that must never become a retire.
    if probe.get("blocked_by_edge"):
        return hold("skipped_not_at_origin",
                    "the exploit was blocked by an F5 edge response, not by the app — the probe "
                    f"reached a load balancer rather than {origin}. Refusing to treat a band-aid "
                    "blocking its own exploit as proof the code was fixed.")
    if probe.get("exploit_blocked"):
        return _retire(fid, e, base, out_dir=sess, now=now, probe=probe, apply=apply,
                       allow_protected=allow_protected, trigger=trigger, pass_id=pass_id,
                       hold=hold, log=log)
    return _ineffective(fid, e, base, out_dir=sess, now=now, probe=probe, trigger=trigger,
                        pass_id=pass_id, log=log)


# waf_data_guard's masking rules live on the LB's attached app_firewall. Detach the WAF and the
# Data Guard band-aid dies with it, silently, while its ledger entry still says "mitigated".
_DEPENDS_ON = {"waf_data_guard": "waf"}


def shared_control_holders(entries: dict, fid: str, lb: str, control: str) -> list[dict]:
    """Other live findings that would lose their protection if this control were detached.

    Six of the seven controls are LB-wide: `_detach_waf` pops `app_firewall` wholesale, so retiring
    finding A's WAF removes finding B's too. `_control_present` cannot see this — it answers "is a
    control of this kind attached", not "is this MY band-aid and does anyone else need it". Without
    the check, an unattended pass proves finding A's fix at origin and quietly strips protection
    from findings whose cures never merged, leaving their ledger entries still claiming
    `mitigated`."""
    out = []
    for other, e in entries.items():
        if other == fid or e.get("state") not in ("mitigated", "remediated"):
            continue
        m = e.get("mitigation") or {}
        if m.get("lb") != lb:
            continue
        if m.get("control") == control or _DEPENDS_ON.get(m.get("control")) == control:
            out.append({"finding_id": other, "control": m.get("control"),
                        "depends": _DEPENDS_ON.get(m.get("control")) == control})
    return out


def _fmt_remaining(exp: dict) -> str:
    r = exp["remaining_hours"]
    return "no TTL" if r is None else f"{r / 24:.1f}d"


def _denorm(e: dict) -> dict:
    """Copy title/vuln_class/severity onto the record itself. `build_audit_events` joins those from
    `findings.json` and `ledger.json` at export time, and both are rewritten by the next scan — so
    a record that relies on the join loses its own justification the moment someone re-scans."""
    return {k: e.get(k) for k in ("title", "vuln_class", "severity",
                                   "cwe", "owasp", "cwe_source") if e.get(k)}


def _escalate(fid, e, base, *, out_dir, now, cure_state, trigger, pass_id, log) -> dict:
    mit = e.get("mitigation") or {}
    exp = expiry(e, now)
    cure = e.get("cure") or {}
    over = abs(exp["remaining_hours"] or 0) / 24
    reason = (f"TTL expired {over:.1f}d ago with no merged cure (PR {cure_state})")
    log(f"  ⚠ {fid}: ESCALATED — {reason}; band-aid left in place")
    count = int((e.get("reconcile") or {}).get("escalation_count") or 0) + 1
    payload = {"event": "vpcopilot.escalation", "finding_id": fid, "reason": reason,
               "lb": mit.get("lb"), "control": mit.get("control"), "policy": mit.get("policy_name"),
               "cure_url": cure.get("pr_url"), "cure_state": cure_state,
               "applied_at": exp["applied_at"], "expires_at": exp["expires_at"],
               "age_days": round((exp["age_hours"] or 0) / 24, 1),
               "escalation_count": count, "pass_id": pass_id, **_denorm(e)}
    delivery = notify(payload, log=log)
    audit.record(out_dir, "escalation", finding_id=fid, lb=mit.get("lb"),
                 control=mit.get("control"), policy=mit.get("policy_name"),
                 cure_url=cure.get("pr_url"), cure_state=cure_state, reason=reason,
                 applied_at=exp["applied_at"], expires_at=exp["expires_at"],
                 ttl_hours=exp["ttl_hours"], age_hours=exp["age_hours"],
                 escalation_count=count, kept=True, trigger=trigger, pass_id=pass_id,
                 notified=delivery, **_denorm(e))
    inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="escalated",
                            reason=reason, escalated_at=now.isoformat(), escalation_count=count,
                            notified=delivery)
    return {**base, "outcome": "escalated", "reason": reason, "escalation_count": count,
            "notified": delivery}


def _ineffective(fid, e, base, *, out_dir, now, probe, trigger, pass_id, log) -> dict:
    mit = e.get("mitigation") or {}
    cure = e.get("cure") or {}
    reason = ("cure merged but the exploit still reproduces at origin — the fix did not work; "
              "band-aid held")
    log(f"  ⚠ {fid}: FIX INEFFECTIVE — {reason}")
    audit.record(out_dir, "fix_ineffective", finding_id=fid, lb=mit.get("lb"),
                 control=mit.get("control"), policy=mit.get("policy_name"),
                 cure_url=cure.get("pr_url"), reason=reason, kept=True, trigger=trigger,
                 pass_id=pass_id, origin_probe=probe, **_denorm(e))
    inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="fix_ineffective",
                            reason=reason, probe=probe)
    return {**base, "outcome": "fix_ineffective", "reason": reason, "probe": probe}


def _retire(fid, e, base, *, out_dir, now, probe, apply, allow_protected, trigger, pass_id,
            hold, log) -> dict:
    mit = e.get("mitigation") or {}
    if not apply:
        reason = "cure merged and the exploit no longer reproduces at origin — would retire"
        log(f"  {fid}: {reason} (report-only; pass --apply to detach)")
        inventory.record_reconcile(fid, last_run_at=now.isoformat(),
                                outcome="would_retire", reason=reason, probe=probe)
        return {**base, "outcome": "would_retire", "reason": reason, "probe": probe}

    # Would detaching this take protection away from a finding whose cure never merged?
    others = shared_control_holders(inventory.load(), fid, mit.get("lb"), mit.get("control"))
    if others:
        who = ", ".join(f"{o['finding_id']}"
                        + (f" (needs {mit['control']})" if o["depends"] else "") for o in others)
        return hold("skipped_shared_control",
                    f"'{mit.get('control')}' on {mit.get('lb')} is also the live band-aid for {who}"
                    " — detaching it would remove their protection too; retire it by hand once "
                    "their cures land", shared_with=[o["finding_id"] for o in others])

    # A BIG-IP AWAF band-aid detaches on the appliance (`retire_bigip`), not with an XC PUT. Route it
    # here, before the XC-specific presence checks below — those call `XC().get_lb(lb)` for an LB that
    # only exists on the box (a bring-your-own-BIG-IP user has no XC at all). The shared-control guard
    # above is ledger-based and already applied.
    if mit.get("control") == "bigip_awaf":
        return _retire_bigip(fid, e, base, mit, out_dir=out_dir, now=now, probe=probe,
                             allow_protected=allow_protected, trigger=trigger, pass_id=pass_id, log=log)
    # An NGINX App Protect band-aid detaches on the box (`retire_nginx`, remove our managed include),
    # not with an XC PUT — routed here for the same reason as BIG-IP: a bring-your-own-NGINX user has
    # no XC, so the `XC().get_lb(lb)` checks below would fail on an lb that only exists on the box.
    if mit.get("control") == "nginx_app_protect":
        return _retire_nginx(fid, e, base, mit, out_dir=out_dir, now=now, probe=probe,
                             allow_protected=allow_protected, trigger=trigger, pass_id=pass_id, log=log)

    # The control may already be gone — someone retired it by hand, or a previous pass did. Detach
    # writes `disable_*` regardless and would claim a removal that did not happen.
    from .drift import _control_present
    from .xc import XC
    xc = XC()
    live_spec = xc.get_lb(mit["lb"]).get("spec") or {}
    if mit.get("control") == "service_policy":
        # Presence is not identity: `_detach_service_policy` pops the whole oneof, so retiring this
        # finding would detach whatever policy is attached — very possibly a LATER finding's, since
        # every apply replaces the list wholesale (see I2's displacement finding).
        names = [pp.get("name") for pp in
                 ((live_spec.get("active_service_policies") or {}).get("policies") or [])]
        if names and names != [mit.get("policy_name")]:
            return hold("skipped_not_our_policy",
                        f"{mit.get('lb')} now carries {names}, not '{mit.get('policy_name')}' — "
                        "detaching would remove someone else's policy")
    if not _control_present(live_spec, mit["control"]):
        log(f"  {fid}: already detached from {mit['lb']} — marking retired without a PUT")
        inventory.mark_retired(fid)
        audit.record(out_dir, "retire", finding_id=fid, control=mit.get("control"),
                     lb=mit.get("lb"), namespace=xc.ns, forced=False, trigger=trigger,
                     pass_id=pass_id, already_detached=True, **_denorm(e))
        inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="retired",
                                reason="already detached", probe=probe)
        return {**base, "outcome": "retired", "reason": "already detached", "probe": probe}

    from .retire import retire_finding
    # force=True because reconcile has ALREADY proven more than retire's own gate checks: retire
    # verifies the PR merged, reconcile verified that AND that the exploit is genuinely gone from
    # the app. Re-running the weaker check would only add a second GitHub call.
    r = retire_finding(out_dir, fid, force=True, allow_protected=allow_protected, log=log)
    audit.record(out_dir, "reconcile_retire", finding_id=fid, control=mit.get("control"),
                 lb=mit.get("lb"), trigger=trigger, pass_id=pass_id,
                 cure_url=(e.get("cure") or {}).get("pr_url"),
                 origin_probe=probe, **_denorm(e))
    reason = "cure merged and the exploit no longer reproduces at origin"
    inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="retired",
                            reason=reason, probe=probe)
    return {**base, "outcome": "retired", "reason": reason, "probe": probe,
            "retire_status": r.get("status")}


def _retire_bigip(fid, e, base, mit, *, out_dir, now, probe, allow_protected, trigger, pass_id,
                  log) -> dict:
    """Reconcile-retire a BIG-IP AWAF band-aid: detach it on the appliance via `retire_bigip` (redeploy
    the app WITHOUT our WAF) instead of the XC PUT, the same routing the console's `do_retire` uses.
    tenant/app come from the ledger's `mitigation.lb` ('tenant/app'). `retire_bigip` is idempotent —
    `_detach_waf` only strips OUR ref and no-ops when it is already gone — so a band-aid a prior pass or
    a human already removed needs no separate 'already detached' probe, the XC path's equivalent."""
    from .bigip_apply import retire_bigip
    tenant, _, app = (mit.get("lb") or "").partition("/")
    r = retire_bigip(fid, tenant=tenant or "vpcopilot_lab", app=app or "lab", out_dir=out_dir,
                     allow_protected=allow_protected, log=log)
    audit.record(out_dir, "reconcile_retire", finding_id=fid, control=mit.get("control"),
                 lb=mit.get("lb"), trigger=trigger, pass_id=pass_id,
                 cure_url=(e.get("cure") or {}).get("pr_url"), origin_probe=probe, **_denorm(e))
    reason = "cure merged and the exploit no longer reproduces at origin"
    inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="retired",
                            reason=reason, probe=probe)
    return {**base, "outcome": "retired", "reason": reason, "probe": probe,
            "retire_status": r.get("retired")}


def _retire_nginx(fid, e, base, mit, *, out_dir, now, probe, allow_protected, trigger, pass_id,
                  log) -> dict:
    """Reconcile-retire an NGINX App Protect band-aid: detach the managed include on the box via
    `retire_nginx` (remove our `vpcopilot-` files + reload) instead of an XC PUT, the same routing the
    console's `do_retire` uses. server/location come from the ledger's `mitigation.lb`
    ('server/location'). `retire_nginx` is idempotent — `_detach` no-ops when our files are already
    gone — so a band-aid a prior pass or a human already removed needs no separate 'already detached'
    probe, the XC path's equivalent."""
    from .nginx_apply import _unlb, retire_nginx
    server, location = _unlb(mit.get("lb") or "")
    r = retire_nginx(fid, server=server, location=location, out_dir=out_dir,
                     allow_protected=allow_protected, log=log)
    audit.record(out_dir, "reconcile_retire", finding_id=fid, control=mit.get("control"),
                 lb=mit.get("lb"), trigger=trigger, pass_id=pass_id,
                 cure_url=(e.get("cure") or {}).get("pr_url"), origin_probe=probe, **_denorm(e))
    reason = "cure merged and the exploit no longer reproduces at origin"
    inventory.record_reconcile(fid, last_run_at=now.isoformat(), outcome="retired",
                            reason=reason, probe=probe)
    return {**base, "outcome": "retired", "reason": reason, "probe": probe,
            "retire_status": r.get("retired")}


# ---------------------------------------------------------------- patches-list


def list_patches(out_dir: str = "out", *, now: Callable[[], datetime] | None = None) -> list[dict]:
    """Every live band-aid with its age, TTL remaining, and cure state. Pure read — no XC, no
    GitHub, no probe. `patches-list` has to stay cheap enough to run constantly."""
    clock = (now or _now)()
    inventory.migrate_from_dirs([out_dir])   # pick up this session's live patches if not yet in inventory
    rows = []
    # Global inventory, not a session ledger — `patches-list` shows every live band-aid across
    # sessions. `out_dir` is accepted for call-site compatibility but no longer selects the source.
    for fid, e in sorted(inventory.live().items()):
        mit = e.get("mitigation")
        if not mit or e.get("state") not in ("mitigated", "remediated"):
            continue
        exp = expiry(e, clock)
        rec = e.get("reconcile") or {}
        rows.append({
            "finding_id": fid, "title": e.get("title"), "severity": e.get("severity"),
            "state": e.get("state"), "control": mit.get("control"), "lb": mit.get("lb"),
            "policy": mit.get("policy_name"),
            "applied_at": exp["applied_at"], "ttl_hours": exp["ttl_hours"],
            "age_hours": exp["age_hours"], "remaining_hours": exp["remaining_hours"],
            "expired": exp["expired"],
            "cure_url": (e.get("cure") or {}).get("pr_url"),
            "cure_state": rec.get("cure_state") or ("open" if e.get("cure") else "none"),
            "last_run_at": rec.get("last_run_at"), "last_probe_at": rec.get("last_probe_at"),
            "outcome": rec.get("outcome"), "reason": rec.get("reason"),
            "escalated_at": rec.get("escalated_at"),
            "escalation_count": rec.get("escalation_count") or 0,
        })
    return rows
