from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from tg_msa_force_rerun import force_rerun


def _write_yaml(path: Path, content: dict) -> None:
    path.write_text(yaml.safe_dump(content, sort_keys=False), encoding="utf-8")


def test_force_rerun_flat_format(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()
    flat_content = {"a": "done", "b": "done"}
    yaml_path = msa_dir / "exit_statuses_0.yaml"
    _write_yaml(yaml_path, flat_content)

    force_rerun(msa_dir, ["a"], dry_run=False)

    updated = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert "a" not in updated
    assert updated.get("b") == "done"

    # Idempotent
    force_rerun(msa_dir, ["a"], dry_run=False)
    updated_again = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert updated_again == updated


def test_force_rerun_nested_format(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()
    nested_content = {"instances_by_exit_status": {"Submitted": ["x", "y"], "Timeout": ["z"]}}
    yaml_path = msa_dir / "exit_statuses_nested.yaml"
    _write_yaml(yaml_path, nested_content)

    force_rerun(msa_dir, ["y", "z"], dry_run=False)

    updated = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    submitted = updated["instances_by_exit_status"].get("Submitted", [])
    timeout = updated["instances_by_exit_status"].get("Timeout", [])
    assert submitted == ["x"]
    assert timeout == []

    # Dry-run does not mutate
    force_rerun(msa_dir, ["x"], dry_run=True)
    updated_after_dry = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    assert updated_after_dry == updated
