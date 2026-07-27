"""J2 — `vpcopilot export --verify`: re-read a bundle and check it against its own manifest.

The digest half is stdlib-only and works on any bundle, signed or not. The signature half is a
THIRD state, not a boolean: without a public key it genuinely cannot be checked, and a key shipped
inside the bundle proves nothing about that bundle."""
import io
import json
import os
import stat
import zipfile

from vpcopilot import audit, export


def _bundle(tmp_path, name="out-run"):
    out = tmp_path / name
    audit.record(str(out), "apply_waf", finding_id="f-1", lb="lab", namespace="ns")
    return export.write_bundle(str(out), str(tmp_path / "b.zip"))


def _rewrite(path, mutate):
    """Rebuild a zip with `mutate(name, data) -> data|None` applied to each member."""
    src = zipfile.ZipFile(path)
    items = [(n, src.read(n)) for n in src.namelist()]
    src.close()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in items:
            nd = mutate(n, d)
            if nd is not None:
                z.writestr(n, nd)
    open(path, "wb").write(buf.getvalue())
    return path


# ---- the digest half ----
def test_a_clean_bundle_verifies(tmp_path):
    r = export.verify_bundle(_bundle(tmp_path))
    assert r["ok"] is True
    assert r["members_checked"] > 0 and not r["problems"]
    assert r["runs"][0]["signature"] == "absent"


def test_a_tampered_member_is_reported_by_name(tmp_path):
    p = _bundle(tmp_path)
    _rewrite(p, lambda n, d: d + b"tampered\n" if n == "audit.log" else d)
    r = export.verify_bundle(p)
    assert r["ok"] is False
    bad = [x for x in r["problems"] if x["member"] == "audit.log"]
    assert bad and bad[0]["problem"] == "mismatch"


def test_a_member_listed_but_absent_is_reported(tmp_path):
    p = _bundle(tmp_path)
    _rewrite(p, lambda n, d: None if n == "audit.log" else d)
    r = export.verify_bundle(p)
    assert r["ok"] is False
    assert any(x["member"] == "audit.log" and x["problem"] == "missing" for x in r["problems"])


def test_a_member_added_after_export_is_reported(tmp_path):
    """A file ADDED to a bundle is exactly as suspicious as one altered — a check over only the
    listed members would wave it through."""
    p = _bundle(tmp_path)
    z = zipfile.ZipFile(p, "a")
    z.writestr("smuggled.txt", "hello")
    z.close()
    r = export.verify_bundle(p)
    assert r["ok"] is False
    assert any(x["member"] == "smuggled.txt" and x["problem"] == "unlisted" for x in r["problems"])


def test_the_manifest_and_its_signature_are_not_themselves_unlisted(tmp_path):
    """They cannot appear in the manifest that lists members — they must not read as smuggled."""
    r = export.verify_bundle(_bundle(tmp_path))
    assert not [x for x in r["problems"] if x["member"].endswith(("manifest.json", ".minisig"))]


def test_a_corrupt_zip_is_reported_not_raised(tmp_path):
    p = tmp_path / "broken.zip"
    p.write_bytes(b"PK\x03\x04 this is not a zip")
    r = export.verify_bundle(str(p))
    assert r["ok"] is False and r["error"]


def test_a_missing_file_is_reported_not_raised(tmp_path):
    r = export.verify_bundle(str(tmp_path / "nope.zip"))
    assert r["ok"] is False and r["error"]


def test_a_bundle_with_no_manifest_is_reported(tmp_path):
    p = tmp_path / "empty.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "nothing to see")
    r = export.verify_bundle(str(p))
    assert r["ok"] is False and "manifest" in (r["error"] or "").lower()


def test_every_run_in_a_multi_run_bundle_is_verified(tmp_path):
    for n in ("out-a", "out-b"):
        audit.record(str(tmp_path / n), "retire", finding_id="f-1", lb="lab")
    p = export.write_bundle_all(str(tmp_path), str(tmp_path / "all.zip"))
    r = export.verify_bundle(p)
    assert r["ok"] is True and len(r["runs"]) == 2
    assert {run["run"] for run in r["runs"]} == {"out-a/", "out-b/"}


def test_one_bad_run_fails_the_bundle_and_names_which(tmp_path):
    for n in ("out-a", "out-b"):
        audit.record(str(tmp_path / n), "retire", finding_id="f-1", lb="lab")
    p = export.write_bundle_all(str(tmp_path), str(tmp_path / "all.zip"))
    _rewrite(p, lambda n, d: d + b"x" if n == "out-b/audit.log" else d)
    r = export.verify_bundle(p)
    assert r["ok"] is False
    assert any(x["run"] == "out-b/" for x in r["problems"])
    assert not [x for x in r["problems"] if x["run"] == "out-a/"]


# ---- the signature half: four states, not a boolean ----
def _stub_verifier(tmp_path, code=0):
    p = tmp_path / "bin" / "minisign"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"#!/bin/sh\nexit {code}\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(p.parent)


def _signed(tmp_path, monkeypatch):
    sp = tmp_path / "bin" / "minisign"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("#!/bin/sh\n"
                  "while [ $# -gt 0 ]; do case $1 in -x) shift; OUT=$1;; esac; shift; done\n"
                  "printf 'RWSIG\\n' > \"$OUT\"\n")
    sp.chmod(0o755)
    (tmp_path / "key").write_text("k")
    monkeypatch.setenv("VPCOPILOT_MINISIGN_KEY", str(tmp_path / "key"))
    monkeypatch.setenv("PATH", str(sp.parent) + os.pathsep + os.environ["PATH"])
    return _bundle(tmp_path)


def test_a_signature_with_no_public_key_is_unverified_but_not_a_failure(tmp_path, monkeypatch):
    """A reviewer without the key must still be able to check the digests. Reporting this as a
    failure would make the honest 'I cannot check this' indistinguishable from 'this is forged'."""
    p = _signed(tmp_path, monkeypatch)
    monkeypatch.delenv("VPCOPILOT_MINISIGN_KEY", raising=False)
    r = export.verify_bundle(p)
    assert r["ok"] is True
    assert r["runs"][0]["signature"] == "present-unverified"


def test_a_signature_that_checks_out_is_reported_verified(tmp_path, monkeypatch):
    p = _signed(tmp_path, monkeypatch)
    (tmp_path / "pub").write_text("RWQpublickey\n")
    monkeypatch.setenv("PATH", _stub_verifier(tmp_path, 0) + os.pathsep + os.environ["PATH"])
    r = export.verify_bundle(p, pubkey=str(tmp_path / "pub"))
    assert r["runs"][0]["signature"] == "verified" and r["ok"] is True


def test_a_signature_that_fails_fails_the_bundle(tmp_path, monkeypatch):
    p = _signed(tmp_path, monkeypatch)
    (tmp_path / "pub").write_text("RWQpublickey\n")
    monkeypatch.setenv("PATH", _stub_verifier(tmp_path, 1) + os.pathsep + os.environ["PATH"])
    r = export.verify_bundle(p, pubkey=str(tmp_path / "pub"))
    assert r["runs"][0]["signature"] == "failed" and r["ok"] is False


def test_asking_to_verify_an_unsigned_bundle_says_absent_not_failed(tmp_path):
    r = export.verify_bundle(_bundle(tmp_path), pubkey="/some/key.pub")
    assert r["runs"][0]["signature"] == "absent" and r["ok"] is True


def test_verification_is_read_only(tmp_path):
    """Evidence gathering never mutates what it records — and neither does checking it."""
    p = _bundle(tmp_path)
    before = open(p, "rb").read()
    export.verify_bundle(p)
    assert open(p, "rb").read() == before
    assert json.loads(zipfile.ZipFile(p).read("manifest.json"))["kind"] == "vpcopilot-audit-bundle"


def test_a_pubkey_path_that_does_not_exist_is_unverified_not_failed(tmp_path, monkeypatch):
    """Pointing at a key that isn't there is an operator mistake, not evidence of forgery."""
    p = _signed(tmp_path, monkeypatch)
    r = export.verify_bundle(p, pubkey=str(tmp_path / "no-such.pub"))
    assert r["runs"][0]["signature"] == "present-unverified" and r["ok"] is True
