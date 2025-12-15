from pathlib import Path

import tg_post_apply_security_scan as scan_mod


def test_prepare_worktree_uses_repo_cwd(monkeypatch, tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    worktree_dir = tmp_path / "worktree"
    repo_dir.mkdir()

    calls = []

    def fake_run(cmd, cwd=None, input_text=None):
        calls.append((cmd, cwd))

        class Dummy:
            def __init__(self):
                self.returncode = 0
                self.stdout = ""
                self.stderr = ""

        return Dummy()

    monkeypatch.setattr(scan_mod, "_run_cmd", fake_run)

    scan_mod._prepare_worktree(repo_dir, worktree_dir, "deadbeef")

    assert any(
        cmd[:3] == ["git", "worktree", "add"] and cwd == repo_dir
        for cmd, cwd in calls
    )
