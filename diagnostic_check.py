"""Lightweight diagnostics for mini-swe-agent runs.

The script inspects trajectory files and prediction outputs to reveal whether
patches are being propagated correctly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any


def _looks_like_diff(text: str) -> bool:
    if "diff --git" in text:
        return True
    lines = text.splitlines()
    has_old = any(line.startswith("--- ") for line in lines)
    has_new = any(line.startswith("+++ ") for line in lines)
    return has_old and has_new


def _load_predictions(run_dir: Path) -> tuple[Path | None, Dict[str, Any]]:
    preds_path = None
    for candidate in [run_dir / "preds_filled.json", run_dir / "preds.json"]:
        if candidate.exists():
            preds_path = candidate
            break
    if not preds_path:
        return None, {}

    try:
        return preds_path, json.loads(preds_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[ERROR] Failed to read {preds_path}: {exc}")
        return preds_path, {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose mini-swe-agent outputs")
    parser.add_argument("--run-dir", required=True, help="Run directory to inspect")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        raise SystemExit(f"Run directory not found: {run_dir}")

    traj_files = sorted(run_dir.glob("*.traj.json"))
    print(f"Run directory: {run_dir}")
    print(f"Trajectory files: {len(traj_files)}")

    preds_path, preds = _load_predictions(run_dir)
    if preds_path:
        print(f"Predictions file: {preds_path}")
    else:
        print("Predictions file: not found")

    print()
    header = f"{'instance_id':<45} {'traj_bytes':>12} {'pred_bytes':>12} {'looks_like_diff':>17}"
    print(header)
    print("-" * len(header))

    for traj_path in traj_files:
        try:
            data = json.loads(traj_path.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[ERROR] {traj_path.name}: {exc}")
            continue

        submission = data.get("info", {}).get("submission", "") or ""
        instance_id = traj_path.name.removesuffix(".traj.json")
        traj_len = len(str(submission).encode("utf-8"))

        pred_patch = ""
        if isinstance(preds, dict):
            pred_entry = preds.get(instance_id) if instance_id in preds else None
            if isinstance(pred_entry, dict):
                pred_patch = pred_entry.get("model_patch", "") or ""

        pred_len = len(str(pred_patch).encode("utf-8"))
        print(
            f"{instance_id:<45} {traj_len:>12} {pred_len:>12} "
            f"{str(_looks_like_diff(str(pred_patch))).rjust(17)}"
        )


if __name__ == "__main__":
    main()
