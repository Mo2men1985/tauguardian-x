import subprocess
from pathlib import Path

import tg_post_apply_security_scan as scan


def test_prepare_worktree_runs_in_repo_dir(tmp_path: Path, monkeypatch) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    worktree_dir = tmp_path / "worktree"

    calls: list[tuple[list[str], Path | None]] = []

    def fake_run(cmd, cwd=None, input_text=None):
        calls.append((cmd, cwd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(scan, "_run_cmd", fake_run)

    scan._prepare_worktree(repo_dir, worktree_dir, "abc123")

    assert calls
    assert calls[0][0] == ["git", "worktree", "prune"]
    assert calls[0][1] == repo_dir
    assert calls[1][0] == ["git", "worktree", "add", "--detach", str(worktree_dir), "abc123"]
    assert calls[1][1] == repo_dir
