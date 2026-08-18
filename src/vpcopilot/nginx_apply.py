"""NGINX App Protect live-apply — the module analogue of `bigip_apply.py`.

Attach a finding's declarative App Protect policy to the operator's OWN NGINX+App-Protect box,
validated against the finding's real exploit:

  snapshot the clean slate → emit the policy → write it + a copilot-owned managed `include` →
  `nginx -t` → reload → fire the exploit/legit THROUGH the box → keep or roll back.

Retire redeploys without the include. The copilot only ever writes files under `vpcopilot-`, so a
detach removes exactly our band-aid and never a user's own `app_protect_policy_file` on the same
server. It never keeps a band-aid it could not prove blocks, and never reloads a config `nginx -t`
rejects — the same discipline as the BIG-IP path.

Reused unchanged from the XC/BIG-IP paths: `emitters.emit` (target `nginx-app-protect`),
`apply._run_validation`, `probe.probe_negative_pay`, `ledger`, `audit`. The one new discriminator is
the ledger control string `nginx_app_protect`.

Precondition: the copilot's server/location `include`s `<include_dir>/vpcopilot-active/*.conf` (the
`vpcopilot nginx-lab create` step); an empty dir is the clean slate — nginx tolerates a glob include
that matches nothing.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

from . import audit, ledger
from .apply import _run_validation
from .emitters import emit as emit_policy
from .nginx import Nginx, NginxError
from .nginx_lab import guard_site
from .probe import probe_negative_pay

CONTROL = "nginx_app_protect"
POLICY_PREFIX = "vpcopilot-"        # every file we own is named vpcopilot-<finding_id>
INCLUDE_TAG = "# vpcopilot-managed"  # sentinel first line of a managed include
ACTIVE_SUBDIR = "vpcopilot-active"   # the location-include glob dir the copilot owns


def _lb(server: str, location: str) -> str:
    """The ledger `lb` token — server + location, so retire (console/CLI/reconcile) recovers both."""
    return f"{server}{location}" if location.startswith("/") else f"{server}/{location}"


def _unlb(lb: str) -> tuple[str, str]:
    server, sep, rest = (lb or "").partition("/")
    return server, ("/" + rest if sep else "/")


def _paths(nx: Nginx, finding_id: str) -> tuple[str, str]:
    """(policy-json path, managed-include path) for a finding. Both `vpcopilot-` prefixed so a detach
    matches only our files."""
    return (f"{nx.policy_dir}/{POLICY_PREFIX}{finding_id}.json",
            f"{nx.include_dir}/{ACTIVE_SUBDIR}/{POLICY_PREFIX}{finding_id}.conf")


def _status(v: dict) -> dict:
    return {k: v.get(k) for k in ("exploit_status", "exploit_blocked", "legit_ok")}


def _emit_for_finding(out_dir: str, finding_id: str, protocol: str):
    """The finding's declarative NAP policy — or an EmitResult that DECLINES with a named reason. Same
    finding→emit wiring `bigip_apply` and the console `/api/emit` use, `target='nginx-app-protect'`."""
    pol_path = Path(out_dir) / "policies.json"
    entries = json.loads(pol_path.read_text()) if pol_path.exists() else []
    entry = next((e for e in entries if e.get("finding_id") == finding_id), None)
    if entry is None:
        raise NginxError(f"no generated band-aid for {finding_id!r} in {pol_path} — run a scan first")
    probes_path = Path(out_dir) / "probes.json"
    probes = {p.get("finding_id"): p for p in
              (json.loads(probes_path.read_text()) if probes_path.exists() else [])
              if isinstance(p, dict)}
    control, name = entry.get("control", ""), entry.get("policy_name", "")
    spec_path = Path(out_dir) / "policies" / f"{control}.{name}.json"
    spec = json.loads(spec_path.read_text()) if spec_path.exists() else None
    res = emit_policy(target="nginx-app-protect", control=control, policy_name=name, spec=spec,
                      probe=probes.get(finding_id), protocol=protocol)
    return res, entry


def _detach(nx: Nginx, finding_id: str) -> None:
    """Remove ONLY our managed include + policy for this finding — the surgical detach. Idempotent."""
    pol, inc = _paths(nx, finding_id)
    nx.remove_file(inc)
    nx.remove_file(pol)


def _write_bandaid(nx: Nginx, finding_id: str, policy: dict) -> None:
    """Write the policy JSON + the managed include that turns App Protect on for the location with it."""
    pol, inc = _paths(nx, finding_id)
    nx.put_file(pol, json.dumps(policy, indent=2))
    nx.put_file(inc, f"{INCLUDE_TAG}\napp_protect_enable on;\napp_protect_policy_file \"{pol}\";\n")


def _await_enforcement(url, finding_id, out_dir, log, *, timeout: float, interval: float) -> dict:
    """Validate, then poll until the exploit is actually blocked (or `timeout`).

    PROVEN on a live box: App Protect compiles + loads a policy into the enforcer ASYNCHRONOUSLY after
    a reload — `nginx -T` proves the config *references* the policy, but the enforcer only starts
    blocking a second or two later (§10.4). A single-shot validation right after reload races that
    load and reports "still succeeds" for a policy that does block. Polling a bounded window closes
    the race without ever reporting a false block: a policy that genuinely does not block just polls
    to the timeout and stays not-blocked (→ rollback)."""
    res = _run_validation(url, finding_id, out_dir, probe_negative_pay, log)
    deadline = time.monotonic() + timeout
    while not (res.get("exploit_blocked") and res.get("legit_ok")) and time.monotonic() < deadline:
        time.sleep(interval)
        res = _run_validation(url, finding_id, out_dir, probe_negative_pay, log)
    return res


def apply_nginx(finding_id: str, *, server: str, location: str, url: str,
                dry_run: bool = False, keep: bool = False, protocol: str = "http",
                out_dir: str = "out", allow_protected: bool = False,
                settle_timeout: float = 30.0, settle_interval: float = 3.0,
                client: Nginx | None = None, log: Callable = print) -> dict:
    """Apply one finding's NAP band-aid to the box, validated against its real exploit. Mirrors
    `apply_bigip` step for step; see the module docstring for the spine."""
    guard_site(server, allow_protected=allow_protected, dry_run=dry_run)
    res, _entry = _emit_for_finding(out_dir, finding_id, protocol)
    if not res.supported:
        # Honest decline — a named reason and NO deploy, never a policy that enforces nothing.
        log(f"  no NGINX App Protect band-aid for this finding: {res.reason}")
        return {"applied": False, "emitted": False, "reason": res.reason,
                "finding_id": finding_id, "server": server}

    nx = client or Nginx()

    # 1. self-test: stage the files, `nginx -t`, then roll the staging back (the AS3 dry-run analogue).
    _write_bandaid(nx, finding_id, res.policy)
    try:
        nx.test_config()
    except NginxError:
        # A rejected config is a box ERROR, surfaced as one (the CLI/console show 'box error' and
        # exit non-zero) — never a benign "would deploy" dry-run, which would be exactly the
        # "looks applied and is not" false-positive this project exists to prevent.
        _detach(nx, finding_id)
        raise
    if dry_run:
        _detach(nx, finding_id)
        log("  dry-run OK — nginx -t accepted the policy; nothing was reloaded")
        return {"applied": False, "dry_run": True, "passed": None, "finding_id": finding_id,
                "server": server, "policy_name": res.policy_name}

    # 2. before: the genuinely-undefended clean slate (our include removed + reload), so a no-op
    #    reload can't masquerade as a working block.
    _detach(nx, finding_id)
    nx.reload()
    before = _run_validation(url, finding_id, out_dir, probe_negative_pay, log)
    log(f"  before: exploit {'blocked' if before.get('exploit_blocked') else 'succeeded'}")

    # 3. the real apply: policy + include back, `nginx -t`, reload, validate THROUGH the box.
    _write_bandaid(nx, finding_id, res.policy)
    nx.test_config()
    nx.reload()
    after = _await_enforcement(url, finding_id, out_dir, log,
                              timeout=settle_timeout, interval=settle_interval)
    passed = bool(after.get("exploit_blocked") and after.get("legit_ok"))
    log(f"  after:  exploit {'blocked ✓' if after.get('exploit_blocked') else 'STILL succeeds'}, "
        f"legit {'ok' if after.get('legit_ok') else 'BROKEN'}")

    rolled = False
    if not passed or not keep:
        _detach(nx, finding_id)
        nx.reload()
        rolled = True
    kept = passed and keep

    if kept:
        # lb carries server+location so retire (console/CLI/reconcile) recovers both from the ledger.
        ledger.mark_mitigated(out_dir, finding_id, control=CONTROL,
                              policy_name=res.policy_name, lb=_lb(server, location))
    audit.record(out_dir, "apply_nginx_app_protect", finding_id=finding_id, server=server,
                 location=location, policy_name=res.policy_name, passed=passed, kept=kept,
                 rolled_back=rolled,
                 before_after={"before": _status(before), "after": _status(after)})
    return {"applied": True, "passed": passed, "kept": kept, "rolled_back": rolled,
            "finding_id": finding_id, "server": server, "location": location,
            "policy_name": res.policy_name, "before": before, "after": after}


def retire_nginx(finding_id: str, *, server: str, location: str, out_dir: str = "out",
                 allow_protected: bool = False, client: Nginx | None = None,
                 log: Callable = print) -> dict:
    """Detach the band-aid: remove our managed include + policy and reload — the XC-retire analogue.
    Never a delete of the vhost; `_detach` strips only our `vpcopilot-` files, so a user's own policy
    on the same server is untouched. Idempotent."""
    guard_site(server, allow_protected=allow_protected, dry_run=False)
    nx = client or Nginx()
    _detach(nx, finding_id)
    nx.reload()
    ledger.mark_retired(out_dir, finding_id)
    audit.record(out_dir, "retire_nginx_app_protect", finding_id=finding_id, server=server,
                 location=location)
    return {"retired": True, "finding_id": finding_id, "server": server, "location": location}
