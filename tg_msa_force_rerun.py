"""Force mini-SWE-agent instances to rerun by clearing exit status stamps.

This tool edits ``exit_statuses_*.yaml`` files in a mini-SWE-agent output
directory and removes the provided instance IDs from either the flat or nested
structures. It mirrors the reset helper but is targeted at the common case
where reruns are skipped because an instance is already marked done.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, List

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


def _remove_from_flat(data: Dict, targets: Iterable[str]) -> List[str]:
    removed: List[str] = []
    for inst in targets:
        if inst in data:
            data.pop(inst, None)
            removed.append(inst)
    return removed


def _remove_from_nested(data: Dict, targets: Iterable[str]) -> List[str]:
    removed: List[str] = []
    ibs = data.get("instances_by_exit_status")
    if not isinstance(ibs, dict):
        return removed

    for status, inst_list in ibs.items():
        if not isinstance(inst_list, list):
            continue
        before = set(inst_list)
        filtered = [inst for inst in inst_list if inst not in targets]
        ibs[status] = filtered
        removed.extend(list(before - set(filtered)))
    return removed


def _process_file(path: Path, targets: List[str], dry_run: bool) -> List[str]:
    data = _load_yaml(path)
    if not data:
        return []

    removed: List[str] = []
    if "instances_by_exit_status" in data:
        removed = _remove_from_nested(data, targets)
    else:
        removed = _remove_from_flat(data, targets)

    if removed and not dry_run:
        _write_yaml(path, data)

    if removed:
        action = "[DRY-RUN]" if dry_run else "[UPDATED]"
        print(f"{action} {path}: removed {sorted(set(removed))}")
    return removed


def force_rerun(msa_dir: Path, targets: List[str], dry_run: bool = False) -> None:
    yaml_paths = sorted(msa_dir.glob("exit_statuses_*.yaml"))
    if not yaml_paths:
        print(f"[WARN] No exit_statuses_*.yaml under {msa_dir}")
        return

    for path in yaml_paths:
        _process_file(path, targets, dry_run)


def parse_instances(raw: str) -> List[str]:
    return [inst.strip() for inst in raw.split(",") if inst.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Force mini-SWE-agent reruns by clearing exit status stamps.",
    )
    parser.add_argument("--msa-dir", required=True, help="mini-SWE-agent output directory")
    parser.add_argument("--instances", required=True, help="Comma-separated instance IDs")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")

    args = parser.parse_args()
    targets = parse_instances(args.instances)
    if not targets:
        raise SystemExit("[ERROR] No instances specified")

    force_rerun(Path(args.msa_dir), targets, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
