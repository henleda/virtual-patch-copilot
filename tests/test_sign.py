"""J1 — a detached minisign signature over the bundle manifest.

Signing is OPTIONAL at every level: no key configured, no binary on PATH, or a signer that fails
all mean no signature and a successful export. An evidence bundle that refuses to be produced
because a signing key is missing is worse than an unsigned one."""
import io
import os
import stat
import zipfile

from vpcopilot import audit, export, sign


def _run(tmp_path):
    out = tmp_path / "out-run"
    audit.record(str(out), "apply_waf", finding_id="f-1", lb="lab", namespace="ns")
    return out


def _stub_signer(tmp_path, *, body="untrusted comment: x\nRWSIG\ntrusted comment: y\nSIGBYTES\n", code=0):
    """A fake `minisign` on PATH: writes a signature file at -x and exits `code`."""
    p = tmp_path / "bin" / "minisign"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "#!/bin/sh\n"
        "while [ $# -gt 0 ]; do case $1 in -x) shift; OUT=$1;; -m) shift; IN=$1;; esac; shift; done\n"
        f"printf %s '{body}' > \"$OUT\"\n"
        f"exit {code}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p.parent)


# ---- optional at every level ----
def test_no_key_configured_means_no_signature_and_a_clean_export(tmp_path, monkeypatch):
    monkeypatch.delenv("VPCOPILOT_MINISIGN_KEY", raising=False)
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(_run(tmp_path)))))
    assert "manifest.json" in z.namelist()
    assert not [n for n in z.namelist() if n.endswith(".minisig")]


def test_a_configured_key_with_no_binary_warns_but_still_exports(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("VPCOPILOT_MINISIGN_BIN", str(tmp_path / "definitely-not-here"))
    logs = []
    data = export.bundle_bytes(str(_run(tmp_path)), log=logs.append)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert "manifest.json" in z.namelist()
    assert not [n for n in z.namelist() if n.endswith(".minisig")]
    assert any("sign" in m.lower() for m in logs)          # said so, rather than failing silently


def test_a_missing_key_file_does_not_fail_the_export(tmp_path, monkeypatch):
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "nope.key"))
    monkeypatch.setenv("PATH", _stub_signer(tmp_path) + os.pathsep + os.environ["PATH"])
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(_run(tmp_path)), log=lambda m: None)))
    assert not [n for n in z.namelist() if n.endswith(".minisig")]


def test_a_signer_that_fails_does_not_fail_the_export(tmp_path, monkeypatch):
    (tmp_path / "key").write_text("untrusted comment: minisign secret key\nRWRTY\n")
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("PATH", _stub_signer(tmp_path, code=3) + os.pathsep + os.environ["PATH"])
    logs = []
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(_run(tmp_path)), log=logs.append)))
    assert "manifest.json" in z.namelist()
    assert not [n for n in z.namelist() if n.endswith(".minisig")]
    assert any("sign" in m.lower() for m in logs)


# ---- the happy path ----
def test_the_signature_ships_beside_the_manifest(tmp_path, monkeypatch):
    (tmp_path / "key").write_text("untrusted comment: minisign secret key\nRWRTY\n")
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("PATH", _stub_signer(tmp_path) + os.pathsep + os.environ["PATH"])
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(_run(tmp_path)), log=lambda m: None)))
    assert "manifest.json.minisig" in z.namelist()
    assert b"RWSIG" in z.read("manifest.json.minisig")


def test_the_signature_covers_exactly_the_manifest_that_shipped(tmp_path, monkeypatch):
    """Signing a different byte string than the one in the bundle would make every verification
    fail — or, worse, pass against something the reviewer never received."""
    (tmp_path / "key").write_text("k")
    signed = tmp_path / "signed-input"
    p = tmp_path / "bin" / "minisign"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\n"
                 "while [ $# -gt 0 ]; do case $1 in -x) shift; OUT=$1;; -m) shift; IN=$1;; esac; shift; done\n"
                 f"cp \"$IN\" '{signed}'\n"
                 "printf 'RWSIG\\n' > \"$OUT\"\n")
    p.chmod(0o755)
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("PATH", str(p.parent) + os.pathsep + os.environ["PATH"])
    z = zipfile.ZipFile(io.BytesIO(export.bundle_bytes(str(_run(tmp_path)), log=lambda m: None)))
    assert signed.read_bytes() == z.read("manifest.json")


def test_every_run_in_a_multi_run_bundle_is_signed(tmp_path, monkeypatch):
    for n in ("out-a", "out-b"):
        audit.record(str(tmp_path / n), "retire", finding_id="f-1", lb="lab")
    (tmp_path / "key").write_text("k")
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("PATH", _stub_signer(tmp_path) + os.pathsep + os.environ["PATH"])
    z = zipfile.ZipFile(io.BytesIO(export.bundle_all_bytes(str(tmp_path), log=lambda m: None)))
    sigs = sorted(n for n in z.namelist() if n.endswith(".minisig"))
    assert sigs == ["out-a/manifest.json.minisig", "out-b/manifest.json.minisig"]


# ---- what the bundle says about it ----
def test_the_manifest_states_what_a_signature_does_and_does_not_attest(tmp_path):
    caveats = " ".join(export.build_manifest(str(_run(tmp_path)))["caveats"]).lower()
    assert "minisig" in caveats
    assert "out of band" in caveats                  # a key shipped inside proves nothing
    assert "who exported" in caveats or "exported" in caveats


def test_sign_manifest_returns_none_when_unconfigured(tmp_path, monkeypatch):
    monkeypatch.delenv("VPCOPILOT_MINISIGN_KEY", raising=False)
    assert sign.sign_bytes(b"x", log=lambda m: None) is None


def test_sign_is_reported_as_configured_or_not(tmp_path, monkeypatch):
    monkeypatch.delenv("VPCOPILOT_MINISIGN_KEY", raising=False)
    assert sign.configured() is False
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "k"))
    assert sign.configured() is True
