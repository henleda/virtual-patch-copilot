"""H2 — a dependency manifest in, a list of installed package coordinates out.

Pure parsing. No network, no model, no judgement: this module turns `requirements.txt`,
`package-lock.json` and `pom.xml` into `(ecosystem, name, version)` triples that OSV can be asked
about, and an explicit list of the lines it *refused* to turn into one.

**Why refusing matters more here than anywhere else in this codebase.** Querying OSV with a version
string it cannot parse does not error — measured against the live API on 2026-07-29, `aiohttp` at
version `not-a-version`, `1.0.0-SNAPSHOT` and `${project.version}` each returned **81 advisories**,
against 70 for the real `3.9.1` and 87 for no version at all. So an unresolved `${...}` property or
an unpinned `flask>=2.0` does not produce an error, or even an empty result — it produces a
confident, larger, wrong answer, and every downstream stage would treat it as fact. Every version
this module cannot establish is therefore dropped into `skipped` with a reason, and the reason is
carried all the way to the report. A dependency we cannot pin is a dependency we say nothing about.

The three formats fail differently, and the parsers are shaped by how:

* **requirements.txt** is a *request*, not a lockfile. Only `==` pins an exact version; `>=`, `~=`
  and a bare name describe a range that some resolver will decide later. Those are skipped.
* **package-lock.json** is a true lockfile — every version is exact. Its trap is shape: v2 carries
  BOTH the v3 `packages` map and the v1 `dependencies` tree describing the same installs, so a
  parser reading both counts everything twice.
* **pom.xml** is a *template*. `${...}` properties, `<dependencyManagement>`, and inherited `<parent>`
  versions mean a version may simply not be knowable without resolving the whole Maven reactor,
  which this does not do. Those are skipped by name.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# Ecosystem names are OSV's and are case-sensitive — `pypi`, `NPM` and `maven` are all HTTP 400s,
# and one rejected entry fails a whole `querybatch`. The set OSV accepts lives in `osv.py`; these
# parsers emit only the three it is certain about.
MAX_BYTES = 8_000_000     # a manifest larger than this is not a manifest
_MAVEN_NS = re.compile(r"^\{[^}]+\}")
# A pinned requirement: name, optional [extras], '==', version. Anything else is a range.
_REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")
_REQ_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_UNRESOLVED = re.compile(r"\$\{[^}]*\}")


class ManifestError(RuntimeError):
    """The file is not a manifest of the kind claimed. Distinct from 'parsed, but nothing usable'."""


def normalize_pypi(name: str) -> str:
    """PEP 503: runs of `-`, `_` and `.` collapse to a single `-`, lowercased. `Flask_Login` and
    `flask-login` are one package, and counting them twice would resolve the same advisories twice."""
    return re.sub(r"[-_.]+", "-", name).lower()


def detect_kind(path: str | Path) -> str:
    """`pip` | `npm` | `maven`, by filename first and content second.

    Filename is decisive when it is one of the three canonical names. Everything else is sniffed,
    because `requirements-dev.txt`, `reqs.txt` and `deps/prod.txt` are all real, and refusing them
    for not being spelled right would be pedantry."""
    p = Path(path)
    n = p.name.lower()
    if n == "package-lock.json" or n == "npm-shrinkwrap.json":
        return "npm"
    if n == "pom.xml":
        return "maven"
    if n.startswith("requirements") and n.endswith(".txt"):
        return "pip"
    try:
        head = p.read_text(errors="replace")[:4000].lstrip()
    except OSError as e:
        raise ManifestError(f"cannot read {path}: {e}") from e
    if head.startswith("{"):
        if '"lockfileVersion"' in head or '"packages"' in head or '"dependencies"' in head:
            return "npm"
        raise ManifestError(f"{p.name} is JSON but has no lockfileVersion/packages/dependencies — "
                            "is it a package-lock.json?")
    if head.startswith("<?xml") or head.startswith("<project"):
        return "maven"
    if n.endswith(".txt") or n.endswith(".in"):
        return "pip"
    raise ManifestError(f"cannot tell what kind of manifest {p.name} is — expected "
                        "requirements.txt, package-lock.json or pom.xml")


def _read(path: Path) -> str:
    if not path.is_file():
        raise ManifestError(f"no such manifest: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ManifestError(f"{path.name} is {path.stat().st_size} bytes — refusing to parse a "
                            f"manifest over {MAX_BYTES}")
    return path.read_text(errors="replace")


# --------------------------------------------------------------------------- requirements.txt
def _parse_requirements(path: Path, *, _seen: set[str] | None = None, _depth: int = 0) -> tuple[list, list]:
    """`-r other.txt` includes are followed (depth-bounded, cycle-guarded) because splitting
    requirements across files is the norm, and a scan that silently ignored `-r base.txt` would
    report on a fraction of the tree while looking complete."""
    seen = _seen if _seen is not None else set()
    pkgs: list[dict] = []
    skipped: list[dict] = []
    try:
        resolved = str(path.resolve())
    except OSError:
        resolved = str(path)
    if resolved in seen:
        return pkgs, skipped
    seen.add(resolved)

    text = _read(path)
    # Join backslash continuations first so `pkg==1.0 \\\n  --hash=...` is one logical line.
    logical, buf, start = [], "", 1
    for i, raw in enumerate(text.splitlines(), start=1):
        if not buf:
            start = i
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        logical.append((start, buf + raw))
        buf = ""
    if buf:
        logical.append((start, buf))

    for lineno, raw in logical:
        line = raw.split(" #", 1)[0].strip()
        if line.startswith("#"):
            line = ""
        if not line:
            continue
        low = line.lower()
        if low.startswith(("-r ", "--requirement ", "-r", "--requirement=")):
            target = re.sub(r"^(-r|--requirement)\s*=?\s*", "", line, flags=re.I).strip()
            if _depth >= 3:
                skipped.append({"raw": line, "line": lineno, "reason": "include-too-deep",
                                "detail": "-r include nesting deeper than 3 levels"})
                continue
            inc = (path.parent / target)
            try:
                sub_p, sub_s = _parse_requirements(inc, _seen=seen, _depth=_depth + 1)
                pkgs += sub_p
                skipped += sub_s
            except ManifestError as e:
                skipped.append({"raw": line, "line": lineno, "reason": "include-unreadable",
                                "detail": str(e)})
            continue
        if line.startswith("-"):        # -e, -c, --index-url, --hash on its own line, …
            reason = "editable" if low.startswith(("-e", "--editable")) else "pip-option"
            skipped.append({"raw": line, "line": lineno, "reason": reason,
                            "detail": "not a version-pinned requirement"})
            continue
        # Strip an environment marker; it gates whether the package is installed, not which version.
        marker = ""
        if ";" in line:
            line, marker = line.split(";", 1)
            line, marker = line.strip(), marker.strip()
        if "@" in line and not line.startswith("@"):   # `pkg @ https://…` direct reference
            skipped.append({"raw": line, "line": lineno, "reason": "direct-reference",
                            "detail": "installed from a URL/VCS, not a released version"})
            continue
        m = _REQ_PIN.match(line)
        if not m:
            nm = _REQ_NAME.match(line)
            skipped.append({"raw": line, "line": lineno, "reason": "unpinned",
                            "detail": f"'{(nm.group(1) if nm else line)[:60]}' is not pinned with "
                                      "'==' — the installed version is decided by a resolver, and "
                                      "guessing one would query OSV for the wrong thing"})
            continue
        version = m.group(3).strip()
        if version.endswith(".*") or _UNRESOLVED.search(version):
            skipped.append({"raw": line, "line": lineno, "reason": "unpinned",
                            "detail": f"'{version}' is a wildcard, not an exact version"})
            continue
        pkgs.append({"ecosystem": "PyPI", "name": normalize_pypi(m.group(1)), "version": version,
                     "scope": "runtime", "line": lineno, "source": path.name,
                     "note": f"marker: {marker}" if marker else ""})
    return pkgs, skipped


# --------------------------------------------------------------------------- package-lock.json
def _parse_package_lock(path: Path) -> tuple[list, list]:
    text = _read(path)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise ManifestError(f"{path.name} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ManifestError(f"{path.name} is JSON but not an object — not a package-lock")
    pkgs: list[dict] = []
    skipped: list[dict] = []
    lockver = doc.get("lockfileVersion")

    if isinstance(doc.get("packages"), dict):
        # lockfileVersion 2 and 3. v2 ALSO carries the legacy `dependencies` tree describing the
        # same installs; reading both would double-count every package, so `packages` wins and
        # `dependencies` is not read at all when it is present.
        for key, ent in doc["packages"].items():
            if not isinstance(ent, dict):
                continue
            if key == "":
                continue          # the root project itself, not a dependency
            if ent.get("link"):
                skipped.append({"raw": key, "line": 0, "reason": "workspace-link",
                                "detail": "a symlink to a local workspace package, not a registry release"})
                continue
            if "node_modules/" not in key:
                # v2/v3 `packages` keys are project-relative PATHS. Only `node_modules/...` are
                # installed registry releases; a workspace's own source sits under its directory
                # (`packages/internal-tools`). Emitting those as registry coordinates asks OSV
                # about first-party code under a name that may collide with a public package —
                # and where the entry carries no `name`, the coordinate became the directory
                # path itself, which is not a legal npm name.
                skipped.append({"raw": key, "line": 0, "reason": "workspace-source",
                                "detail": "a workspace's own source tree, not an installed "
                                          "registry release — its dependencies are listed "
                                          "separately under node_modules/"})
                continue
            name = ent.get("name") or key.split("node_modules/")[-1]
            version = (ent.get("version") or "").strip()
            if not version:
                skipped.append({"raw": key, "line": 0, "reason": "no-version",
                                "detail": "lock entry carries no version"})
                continue
            if ent.get("resolved", "").startswith(("git+", "file:")) or version.startswith(("git+", "file:")):
                skipped.append({"raw": key, "line": 0, "reason": "direct-reference",
                                "detail": "installed from git/file, not a registry release"})
                continue
            pkgs.append({"ecosystem": "npm", "name": name, "version": version,
                         "scope": "dev" if (ent.get("dev") or ent.get("devOptional")) else "runtime",
                         "line": 0, "source": path.name, "note": ""})
    elif isinstance(doc.get("dependencies"), dict):
        # A package.json ALSO carries a `dependencies` map, and `detect_kind` cannot tell the two
        # apart by name when the file is called something else. The difference is the value: a
        # lockfile maps name → {version, …}, a package.json maps name → RANGE STRING. Walking the
        # latter matched nothing and produced zero packages, zero skips and no error — a file full
        # of dependencies reading exactly like a clean lockfile, which is the one confusion this
        # module exists to prevent. Refuse it instead: a package.json has no installed versions to
        # check (the resolver picks them), so asking for the lock file is the honest answer.
        dmap = doc["dependencies"]
        if dmap and not any(isinstance(v, dict) for v in dmap.values()):
            raise ManifestError(
                f"{path.name} looks like a package.json, not a package-lock.json: its "
                "'dependencies' map names version ranges, not installed versions. Point at "
                "package-lock.json or npm-shrinkwrap.json — the versions actually installed, "
                "which are the only ones OSV can be asked about, live only there.")

        def walk(tree: dict, depth: int = 0) -> None:
            if depth > 24:
                return
            for name, ent in tree.items():
                if not isinstance(ent, dict):
                    # Never silently drop a named dependency: it would be indistinguishable from
                    # the file not naming it at all.
                    skipped.append({"raw": name, "line": 0, "reason": "not-a-lock-entry",
                                    "detail": f"'{name}' maps to {type(ent).__name__}, not a lock "
                                              "entry object carrying a version"})
                    continue
                version = (ent.get("version") or "").strip()
                if version and not version.startswith(("git+", "file:")):
                    pkgs.append({"ecosystem": "npm", "name": name, "version": version,
                                 "scope": "dev" if ent.get("dev") else "runtime",
                                 "line": 0, "source": path.name, "note": ""})
                elif version:
                    skipped.append({"raw": name, "line": 0, "reason": "direct-reference",
                                    "detail": "installed from git/file, not a registry release"})
                else:
                    # The v2/v3 branch above refuses a versionless entry explicitly; this one used
                    # to fall through both arms and drop it with no trace, so the same lockfile
                    # content was invisible risk in v1 and a reported refusal in v3.
                    skipped.append({"raw": name, "line": 0, "reason": "no-version",
                                    "detail": "lock entry carries no version"})
                if isinstance(ent.get("dependencies"), dict):
                    walk(ent["dependencies"], depth + 1)
        walk(doc["dependencies"])
    else:
        raise ManifestError(f"{path.name} has neither a 'packages' nor a 'dependencies' map "
                            f"(lockfileVersion={lockver!r}) — not a package-lock")
    return pkgs, skipped


# --------------------------------------------------------------------------- pom.xml
def _tag(el) -> str:
    return _MAVEN_NS.sub("", el.tag)


def _child(el, name: str):
    for c in el:
        if _tag(c) == name:
            return c
    return None


def _text(el, name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None and c.text else ""


def _parse_pom(path: Path) -> tuple[list, list]:
    text = _read(path)
    # ElementTree resolves internal entities, so a pom carrying a DTD is a billion-laughs vector and
    # `defusedxml` is not a dependency here. A dependency manifest has no business declaring one.
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise ManifestError(f"{path.name} declares a DTD or entity — refusing to parse it "
                            "(a dependency manifest does not need one)")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise ManifestError(f"{path.name} is not well-formed XML: {e}") from e
    if _tag(root) != "project":
        raise ManifestError(f"{path.name} root element is <{_tag(root)}>, not <project> — not a pom")

    props: dict[str, str] = {}
    pel = _child(root, "properties")
    if pel is not None:
        for c in pel:
            props[_tag(c)] = (c.text or "").strip()
    own_version = _text(root, "version")
    parent = _child(root, "parent")
    if not own_version and parent is not None:
        own_version = _text(parent, "version")
    for alias in ("project.version", "pom.version", "version"):
        if own_version:
            props.setdefault(alias, own_version)

    def expand(raw: str, depth: int = 0) -> str:
        """Substitute `${…}` from <properties>, bounded so a self-referential property terminates."""
        v = raw
        for _ in range(6):
            m = _UNRESOLVED.search(v)
            if not m:
                return v.strip()
            key = m.group(0)[2:-1]
            if key not in props:
                return v.strip()
            v = v[:m.start()] + props[key] + v[m.end():]
        return v.strip()

    # <dependencyManagement> declares versions that <dependencies> entries may omit. It is a
    # fallback, not a source of installs in its own right — a managed dependency nobody depends on
    # is not on the classpath.
    managed: dict[str, str] = {}
    dm = _child(root, "dependencyManagement")
    if dm is not None:
        deps = _child(dm, "dependencies")
        for d in (deps if deps is not None else []):
            if _tag(d) != "dependency":
                continue
            g, a, v = _text(d, "groupId"), _text(d, "artifactId"), _text(d, "version")
            if g and a and v:
                managed[f"{expand(g)}:{expand(a)}"] = expand(v)

    pkgs: list[dict] = []
    skipped: list[dict] = []
    deps = _child(root, "dependencies")
    for d in (deps if deps is not None else []):
        if _tag(d) != "dependency":
            continue
        group, artifact = expand(_text(d, "groupId")), expand(_text(d, "artifactId"))
        scope = (_text(d, "scope") or "compile").lower()
        coord = f"{group}:{artifact}"
        if not group or not artifact:
            skipped.append({"raw": coord, "line": 0, "reason": "incomplete",
                            "detail": "dependency has no groupId or no artifactId"})
            continue
        if _UNRESOLVED.search(coord):
            # `expand()` runs on groupId/artifactId too, but only the version was tested. Neither
            # `${project.groupId}` nor `${project.artifactId}` is ever in `props`, and anything
            # inherited from a parent POM is absent as well — so a literal `${...}` reached OSV
            # inside the coordinate NAME, came back empty, and was counted as checked-and-clean.
            # `${project.groupId}` for intra-project dependencies is ordinary multi-module Maven.
            skipped.append({"raw": coord, "line": 0, "reason": "unresolved-property",
                            "detail": f"coordinate is '{coord}' and no <properties> entry defines "
                                      "it — asking OSV under this name would answer for nothing"})
            continue
        version = expand(_text(d, "version")) or managed.get(coord, "")
        if not version:
            skipped.append({"raw": coord, "line": 0, "reason": "inherited-version",
                            "detail": "version comes from a parent POM or an imported BOM; "
                                      "resolving it needs the Maven reactor, which this does not do"})
            continue
        if _UNRESOLVED.search(version):
            skipped.append({"raw": coord, "line": 0, "reason": "unresolved-property",
                            "detail": f"version is '{version}' and no <properties> entry defines it "
                                      "— OSV would answer for a different version, not error"})
            continue
        pkgs.append({"ecosystem": "Maven", "name": coord, "version": version,
                     "scope": "test" if scope in ("test", "provided") else "runtime",
                     "line": 0, "source": path.name, "note": f"scope: {scope}" if scope != "compile" else ""})
    return pkgs, skipped


_PARSERS = {"pip": _parse_requirements, "npm": _parse_package_lock, "maven": _parse_pom}


def parse(path: str | Path, kind: str = "") -> dict:
    """One manifest → `{kind, path, packages, skipped}`.

    `packages` are coordinates OSV can be asked about. `skipped` is every line that named a
    dependency but whose version could not be established, each with a machine-readable `reason` —
    it is reported, never silently dropped, because "we did not check this one" and "this one is
    clean" are the two answers that must never be confused."""
    p = Path(path)
    kind = kind or detect_kind(p)
    if kind not in _PARSERS:
        raise ManifestError(f"unknown manifest kind '{kind}' — expected pip, npm or maven")
    pkgs, skipped = _PARSERS[kind](p)

    # Collapse duplicates: a transitive dep pinned at one version appears in many package-lock
    # subtrees, and the same (ecosystem, name, version) is one install to ask OSV about.
    uniq: dict[tuple, dict] = {}
    for e in pkgs:
        key = (e["ecosystem"], e["name"], e["version"])
        if key in uniq:
            # runtime beats dev/test: if anything reaches it at runtime, it is in the request path.
            if e["scope"] == "runtime":
                uniq[key]["scope"] = "runtime"
            continue
        uniq[key] = e
    return {"kind": kind, "path": str(p), "packages": list(uniq.values()), "skipped": skipped}


def parse_all(paths: list[str]) -> dict:
    """Several manifests → one merged coordinate set, plus a per-file record of what happened.

    A file that fails to parse does not abort the others: it lands in `errors` and the rest are
    still resolved. One malformed pom must not cost a Python service its dependency scan."""
    packages: dict[tuple, dict] = {}
    skipped: list[dict] = []
    files: list[dict] = []
    errors: list[dict] = []
    for raw in paths:
        try:
            res = parse(raw)
        except ManifestError as e:
            errors.append({"path": str(raw), "error": str(e)})
            files.append({"path": str(raw), "kind": "", "packages": 0, "skipped": 0, "error": str(e)})
            continue
        for e in res["packages"]:
            key = (e["ecosystem"], e["name"], e["version"])
            if key not in packages:
                packages[key] = e
            elif e["scope"] == "runtime":
                packages[key]["scope"] = "runtime"
        skipped += [{**s, "path": res["path"]} for s in res["skipped"]]
        files.append({"path": res["path"], "kind": res["kind"],
                      "packages": len(res["packages"]), "skipped": len(res["skipped"]), "error": ""})
    return {"files": files, "packages": list(packages.values()), "skipped": skipped, "errors": errors}
