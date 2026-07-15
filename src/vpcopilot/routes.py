"""Collect the app's DECLARED route map — its OpenAPI/Swagger spec paths plus framework
route-registration lines (Flask blueprints/`url_prefix`, FastAPI routers, Express mounts,
Django urlpatterns, Spring `@*Mapping`, …). Feeding this to discover/verify turns a finding's
endpoint into a LOOKUP against real routes instead of an INFERENCE, which a weaker model does
badly (it hallucinates paths like /api/users/get). Returns None when no route context is found,
so the caller can warn loudly that endpoints are inferred."""
from __future__ import annotations

import re
from pathlib import Path

from .repo_scan import CODE_EXT, SKIP_DIRS

_SPEC_EXT = {".yaml", ".yml", ".json"}
_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "options"}

# Framework route-registration signals — broad + language-agnostic. Substrings first (fast),
# plus a couple of decorator/url regexes.
_ROUTE_HINTS = (
    "register_blueprint", "url_prefix", "Blueprint(", "APIRouter(", "include_router(",
    "add_url_rule", "app.use(", "express.Router", "urlpatterns",
    "@RequestMapping", "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping", "@PatchMapping",
)
_ROUTE_RE = re.compile(r"@\w+\.(route|get|post|put|delete|patch)\b|\b(re_path|path|url)\(", re.I)


def _is_spec_file(p: Path, root: Path) -> bool:
    if p.suffix.lower() not in _SPEC_EXT:
        return False
    name, parent = p.name.lower(), p.parent.name.lower()
    return any(k in name or k in parent for k in ("openapi", "swagger", "api-spec", "api_spec"))


def _openapi_paths(spec_path: Path) -> list[str]:
    """`METHOD... /path` for each declared path (with a Swagger-2 basePath prefix if present)."""
    try:
        import yaml  # safe_load parses JSON too (JSON ⊂ YAML)
        data = yaml.safe_load(spec_path.read_text(errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return []
    base = (data.get("basePath") or "").rstrip("/")
    out = []
    for path, item in data["paths"].items():
        full = f"{base}{path}" if base else path
        methods = sorted(m.upper() for m in item if m.lower() in _HTTP_VERBS) if isinstance(item, dict) else []
        out.append(f"{' '.join(methods) + ' ' if methods else ''}{full}")
    return out


def _route_registrations(root: Path, max_lines: int = 120) -> list[str]:
    out: list[str] = []
    for p in sorted(root.rglob("*")):
        if len(out) >= max_lines:
            break
        if not p.is_file() or p.suffix not in CODE_EXT:
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except Exception:  # noqa: BLE001
            continue
        rel = str(p.relative_to(root))
        for i, ln in enumerate(lines):
            if any(h in ln for h in _ROUTE_HINTS) or _ROUTE_RE.search(ln):
                out.append(f"{rel}:{i + 1}: {ln.strip()[:200]}")
                if len(out) >= max_lines:
                    break
    return out


def collect_route_context(root: str, max_chars: int = 4000) -> str | None:
    """The app's declared routes (OpenAPI spec paths + framework registrations), bounded, or None."""
    root = Path(root)
    parts: list[str] = []
    for sp in sorted(p for p in root.rglob("*") if p.is_file() and _is_spec_file(p, root)
                     and not any(part in SKIP_DIRS for part in p.relative_to(root).parts))[:10]:
        paths = _openapi_paths(sp)
        if paths:
            parts.append(f"OpenAPI routes ({sp.relative_to(root)}):\n"
                         + "\n".join("  " + x for x in paths))
    regs = _route_registrations(root)
    if regs:
        parts.append("Route registrations (framework code):\n" + "\n".join("  " + x for x in regs))
    if not parts:
        return None
    ctx = "\n\n".join(parts)
    return ctx if len(ctx) <= max_chars else ctx[:max_chars] + "\n  … (route context truncated)"
