"""Utility to extract model patches from mini-swe-agent trajectories.

This script bridges saved ``*.traj.json`` files into a ``preds_filled.json`` file
that can be consumed by SWE-bench evaluation utilities.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any


def _looks_like_diff(text: str) -> bool:
    """Return True if the provided text resembles a unified diff."""
    if "diff --git" in text:
        return True

    lines = text.splitlines()
    has_old = any(line.startswith("--- ") for line in lines)
    has_new = any(line.startswith("+++ ") for line in lines)
    return has_old and has_new


def extract_predictions(run_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load trajectory files from ``run_dir`` and build predictions mapping."""
    preds: Dict[str, Dict[str, Any]] = {}

    traj_files = sorted(run_dir.glob("*.traj.json"))
    if not traj_files:
        print(f"[WARN] No trajectory files found under {run_dir}")

    for traj_path in traj_files:
        try:
            data = json.loads(traj_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"[ERROR] Failed to read {traj_path.name}: {exc}")
            continue

        submission = data.get("info", {}).get("submission", "")
        if submission is None:
            submission = ""
        elif not isinstance(submission, str):
            submission = str(submission)

        raw_len = len(submission.encode("utf-8"))

        if _looks_like_diff(submission):
            patch = submission.rstrip() + "\n"
        else:
            patch = ""

        patch_len = len(patch.encode("utf-8"))
        instance_id = traj_path.name.removesuffix(".traj.json")

        preds[instance_id] = {
            "model_name_or_path": "extracted_from_trajectory",
            "instance_id": instance_id,
            "model_patch": patch,
        }

        print(
            f"[INFO] {instance_id}: traj_submission={raw_len} bytes, "
            f"patch_written={patch_len} bytes, nonempty={bool(patch.strip())}"
        )

    return preds


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract SWE-bench predictions from mini-swe trajectories",
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Directory containing *.traj.json files produced by mini-swe-agent",
    )

    args = parser.parse_args()
    run_dir = Path(args.run_dir)

    if not run_dir.exists():
        raise SystemExit(f"Run directory not found: {run_dir}")

    preds = extract_predictions(run_dir)

    # Mapping form for τGuardian + post-apply scanner
    preds_mapping_path = run_dir / "preds.json"
    preds_mapping_path.write_text(json.dumps(preds, indent=2), encoding="utf-8")

    # SWE-bench wrapper predictions (mapping is fine; loader accepts both)
    preds_filled_path = run_dir / "preds_filled.json"
    preds_filled_path.write_text(json.dumps(preds, indent=2), encoding="utf-8")

    print(
        f"[INFO] Wrote predictions to {preds_mapping_path} and "
        f"{preds_filled_path} ({len(preds)} instances)"
    )


if __name__ == "__main__":
    main()
