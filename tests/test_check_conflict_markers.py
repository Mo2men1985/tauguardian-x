import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.check_conflict_markers import find_conflict_markers


def test_find_conflict_markers_reports_text_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("print('before')\n<<<<<<< HEAD\nprint('after')\n", encoding="utf-8")

    findings = find_conflict_markers(tmp_path)

    assert findings == [(Path("sample.py"), 2, "<<<<<<< HEAD")]


def test_find_conflict_markers_skips_generated_dirs(tmp_path: Path) -> None:
    generated = tmp_path / "logs" / "run_instance.log"
    generated.parent.mkdir()
    generated.write_text("<<<<<<< HEAD\n", encoding="utf-8")

    assert find_conflict_markers(tmp_path) == []
