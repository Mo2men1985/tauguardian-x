import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from tg_swebench_cli import normalize_patch_text


def test_normalize_patch_preserves_whitespace_context_line() -> None:
    raw_lines = [
        "    diff --git a/file.py b/file.py",
        "    --- a/file.py",
        "    +++ b/file.py",
        "    @@ -1,2 +1,3 @@",
        "    -old",
        "    +new",
        "     ",
        "    +added",
    ]
    raw_patch = "\n".join(raw_lines) + "\n"

    normalized = normalize_patch_text(raw_patch)
    lines = normalized.splitlines()

    # Find the start of the first hunk and validate only hunk body lines.
    try:
        hunk_start = next(i for i, ln in enumerate(lines) if ln.startswith("@@"))
    except StopIteration:
        raise AssertionError("Normalized patch missing hunk header")

    hunk_body = lines[hunk_start + 1 :]
    assert hunk_body, "Expected hunk body lines"
    for ln in hunk_body:
        assert ln, "Hunk line should not be empty after normalization"
        assert ln[0] in {" ", "+", "-", "\\"}, f"Unexpected hunk prefix in line: {ln!r}"
