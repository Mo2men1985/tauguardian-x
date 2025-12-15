from pathlib import Path
from typing import Iterable

CONFLICT_MARKERS = ("<<<<<<<", "=======", ">>>>>>>")

# Limit to common text-based extensions to avoid scanning binary blobs
TARGET_EXTENSIONS: set[str] = {
    ".py",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".bat",
}

IGNORE_DIRS: set[str] = {".git", "logs", "__pycache__", ".mypy_cache", ".pytest_cache"}


def iter_candidate_files(root: Path) -> Iterable[Path]:
    stack = [root]
    while stack:
        current = stack.pop()
        for child in current.iterdir():
            if child.name in IGNORE_DIRS:
                continue
            if child.is_dir():
                stack.append(child)
                continue
            if child.suffix and child.suffix.lower() in TARGET_EXTENSIONS:
                yield child


def has_conflict_marker(lines: list[str]) -> bool:
    for line in lines:
        stripped = line.lstrip()
        if any(stripped.startswith(marker) for marker in CONFLICT_MARKERS):
            return True
    return False


def test_no_merge_conflict_markers() -> None:
    root = Path(__file__).resolve().parent.parent
    offenders: list[str] = []

    for file_path in iter_candidate_files(root):
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        if has_conflict_marker(lines):
            offenders.append(str(file_path))

    assert not offenders, "Unresolved merge conflict markers found: " + ", ".join(offenders)
