"""Walk a target repo and collect candidate source files for the discover agent.
Caps are explicit and surfaced (no silent truncation): files skipped for size or the
max-files limit are returned so the pipeline can log them."""
from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".next", "dist", "build", "__pycache__",
    ".venv", "venv", ".terraform", "out", ".pytest_cache",
    "vendor", "target", ".gradle", ".mvn", "migrations",
}
CODE_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".java",
    ".php", ".cs", ".sql",
}


def collect_files(root: str, max_bytes: int = 60_000, max_files: int = 200):
    root = Path(root)
    files: list[Path] = []
    skipped: list[tuple[str, str]] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.suffix not in CODE_EXT:
            continue
        if p.stat().st_size > max_bytes:
            skipped.append((str(p.relative_to(root)), "too-large"))
            continue
        files.append(p)
        if len(files) >= max_files:
            skipped.append(("<remaining>", "max-files-reached"))
            break
    return files, skipped


def read_numbered(path: Path) -> str:
    """Return file contents with 1-based line numbers so the agent can cite lines."""
    lines = Path(path).read_text(errors="replace").splitlines()
    return "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(lines))
