"""Detect unresolved merge conflict markers in text files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

MARKERS = ("<<<<<<< ", "=======", ">>>>>>> ")
SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "logs",
    "outputs",
    "run",
    "runs",
}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".rst",
    ".sh",
    ".toml",
    ".ts",
    ".txt",
    ".yaml",
    ".yml",
}


def should_scan(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES


def find_conflict_markers(root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or not should_scan(path.relative_to(root)):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(line.startswith(marker) for marker in MARKERS):
                findings.append((path.relative_to(root), lineno, line[:80]))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if unresolved merge conflict markers are present."
    )
    parser.add_argument("root", nargs="?", default=".", help="Repository root to scan")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    findings = find_conflict_markers(root)
    if findings:
        for rel_path, lineno, marker in findings:
            print(f"{rel_path}:{lineno}: unresolved conflict marker {marker!r}")
        return 1

    print("No unresolved merge conflict markers found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
