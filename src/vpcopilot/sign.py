"""J1 — a detached minisign signature over an evidence bundle's manifest.

`manifest.json` already SHA-256s every member, so tampering with a *member* is detectable from
inside the bundle. What it cannot do is bind the bundle to whoever produced it: `generated_by` and
`generated_on` are unauthenticated strings anyone can edit. A detached signature over the manifest
closes that, and covers every member transitively through their digests.

**Signing is optional at every level.** No key configured, no `minisign` on PATH, an unreadable key,
a signer that exits non-zero — each means no signature and a successful export. An evidence bundle
that refuses to be produced because a signing key is missing is worse than an unsigned one.

**No new dependency.** This shells out to the `minisign` binary rather than pulling in a crypto
library, which keeps `export.py` stdlib-only and means a reviewer verifies with the same one-line
command whether or not they have this toolchain installed.

**No passphrase handling.** The key must be an unencrypted minisign key (`minisign -G -W`). A
signing passphrase is a credential this tool has no business holding; requiring an unencrypted key
managed by whatever already manages your secrets is the honest trade, and it is documented rather
than discovered."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

KEY_ENV = "VPCOPILOT_MINISIGN_KEY"
BIN_ENV = "VPCOPILOT_MINISIGN_BIN"


def configured() -> bool:
    """Whether the operator asked for signing at all — distinct from whether it will succeed."""
    return bool((os.environ.get(KEY_ENV) or "").strip())


def _binary() -> str | None:
    explicit = (os.environ.get(BIN_ENV) or "").strip()
    if explicit:
        return explicit if Path(explicit).is_file() and os.access(explicit, os.X_OK) else None
    return shutil.which("minisign")


def sign_bytes(data: bytes, *, log: Callable = print, comment: str = "") -> bytes | None:
    """Detached signature over `data`, or None when signing is unconfigured or unavailable.

    Every failure path returns None and logs one line. Callers must treat None as "unsigned",
    never as an error."""
    if not configured():
        return None
    key = os.environ[KEY_ENV].strip()
    if not Path(key).is_file():
        log(f"  ⚠ signing skipped — no minisign key at {key} (bundle exported unsigned)")
        return None
    binary = _binary()
    if not binary:
        log("  ⚠ signing skipped — `minisign` not found on PATH "
            f"(set {BIN_ENV}, or install it; bundle exported unsigned)")
        return None

    with tempfile.TemporaryDirectory() as td:
        src, sig = Path(td) / "manifest.json", Path(td) / "manifest.json.minisig"
        src.write_bytes(data)
        cmd = [binary, "-S", "-s", key, "-m", str(src), "-x", str(sig)]
        if comment:
            cmd += ["-t", comment]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except Exception as e:  # noqa: BLE001 — a broken signer must never fail an export
            log(f"  ⚠ signing skipped — could not run minisign: {e} (bundle exported unsigned)")
            return None
        if r.returncode != 0 or not sig.exists():
            detail = (r.stderr or r.stdout or "").strip().splitlines()
            why = detail[-1] if detail else f"exit {r.returncode}"
            log(f"  ⚠ signing skipped — minisign failed: {why} (bundle exported unsigned)")
            return None
        log("  signed manifest.json (detached minisign signature)")
        return sig.read_bytes()
