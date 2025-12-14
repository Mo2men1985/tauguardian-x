"""Helper utility to reset mini-SWE-agent completion markers for selected instances."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

import yaml


def _load_yaml(path: Path) -> Dict:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_yaml(path: Path, data: Dict) -> None:
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)


def _reset_flat_format(data: Dict, targets: List[str]) -> bool:
    modified = False
    for inst_id in targets:
        if inst_id in data:
            data.pop(inst_id, None)
            modified = True
    return modified


def _reset_nested_format(data: Dict, targets: List[str]) -> bool:
    modified = False
    ibs = data.get("instances_by_exit_status")
    if not isinstance(ibs, dict):
        return False

    for status, instances in ibs.items():
        if not isinstance(instances, list):
            continue
        before = len(instances)
        ibs[status] = [inst for inst in instances if inst not in targets]
        if len(ibs[status]) != before:
            modified = True
    return modified


def reset_instances(msa_dir: Path, targets: List[str], dry_run: bool = False) -> None:
    paths = sorted(msa_dir.glob("exit_statuses_*.yaml"))
    if not paths:
        print(f"[WARN] No exit_statuses_*.yaml files found under {msa_dir}")
        return

    for path in paths:
        data = _load_yaml(path)
        if not data:
            continue

        modified = False
        if "instances_by_exit_status" in data:
            modified = _reset_nested_format(data, targets)
        else:
            modified = _reset_flat_format(data, targets)

        if modified:
            if dry_run:
                print(f"[DRY-RUN] Would update {path}")
            else:
                _write_yaml(path, data)
                print(f"[UPDATED] {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove instance IDs from mini-SWE-agent exit status YAML files",
    )
    parser.add_argument("--msa-dir", required=True, help="mini-SWE-agent output directory")
    parser.add_argument(
        "--instances",
        required=True,
        help="Comma-separated instance IDs to reset",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")

    args = parser.parse_args()
    targets = [inst.strip() for inst in args.instances.split(",") if inst.strip()]
    if not targets:
        raise SystemExit("[ERROR] No instance IDs provided")

    reset_instances(Path(args.msa_dir), targets, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
