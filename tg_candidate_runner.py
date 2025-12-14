"""Run multiple mini-extra swebench candidates safely with manifest logging."""

from __future__ import annotations

import argparse
import json
import random
import re
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, List, Sequence

from tg_output_stamp import make_timestamped_dirname


def _models_for_candidates(k: int, models_str: str) -> List[str]:
    """Expand models to match the number of candidates."""

    models = [m.strip() for m in (models_str or "").split(",") if m.strip()]
    if not models:
        raise ValueError("At least one model must be provided via --models")

    if len(models) == 1:
        return models * k
    if len(models) == k:
        return models
    raise ValueError("--models must specify 1 or exactly K entries")


def _combine_filter(instances_str: str | None, filter_str: str | None) -> str | None:
    """Combine explicit instances and a user filter into a regex string."""

    parts: List[str] = []
    if filter_str:
        parts.append(f"({filter_str})")

    instance_ids: List[str] = []
    if instances_str:
        instance_ids = [s.strip() for s in instances_str.split(",") if s.strip()]
    if instance_ids:
        escaped = [re.escape(inst) for inst in instance_ids]
        parts.append(f"({'|'.join(escaped)})")

    if not parts:
        return None
    if len(parts) == 1:
        return parts[0][1:-1] if parts[0].startswith("(") and parts[0].endswith(")") else parts[0]
    return "|".join(parts)


def _build_mini_extra_cmd(
    base_cmd: Sequence[str],
    subset: str,
    split: str,
    output_dir: Path,
    workers: int,
    model: str,
    *,
    limit: int | None = None,
    filter_text: str | None = None,
    extra_args: Iterable[str] | None = None,
) -> List[str]:
    cmd: List[str] = list(base_cmd)
    cmd += ["--subset", subset, "--split", split, "--output", str(output_dir)]
    cmd += ["--model", model, "--workers", str(workers)]
    if limit is not None:
        cmd += ["--limit", str(limit)]
    if filter_text:
        cmd += ["--filter", filter_text]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def main() -> None:
    parser = argparse.ArgumentParser(description="Run K mini-extra swebench candidates")
    parser.add_argument("--outbase", required=True, help="Base output directory (msa_runXX)")
    parser.add_argument("--k", type=int, default=3, help="Number of candidates to run")
    parser.add_argument("--subset", default="lite", help="SWE-bench subset")
    parser.add_argument("--split", default="test", help="Dataset split")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers per run")
    parser.add_argument("--limit", type=int, default=None, help="Optional limit on instances")
    parser.add_argument("--filter", dest="instance_filter", default=None, help="Instance filter regex")
    parser.add_argument("--instances", default=None, help="Comma-separated instance IDs")
    parser.add_argument("--models", required=True, help="Comma-separated models (1 or K entries)")
    parser.add_argument(
        "--roulette-models",
        dest="roulette_models",
        default=None,
        help="Comma-separated models for roulette candidate (candidate 2)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for roulette mode")
    parser.add_argument(
        "--base-cmd",
        default="mini-extra swebench",
        help="Base command to invoke the runner (e.g., 'mini-extra swebench')",
    )
    parser.add_argument("--extra-args", default=None, help="Additional args passed through to each run")
    parser.add_argument("--stamp-outdir", action="store_true", help="Append timestamp to outbase")
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue to next candidates even if one fails",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")

    args = parser.parse_args()

    base_cmd = shlex.split(args.base_cmd)
    extra_args = shlex.split(args.extra_args) if args.extra_args else []

    outbase = args.outbase
    if args.stamp_outdir:
        outbase = make_timestamped_dirname(outbase)

    models_per_candidate = _models_for_candidates(args.k, args.models)
    roulette_models = [m.strip() for m in (args.roulette_models or "").split(",") if m.strip()]

    combined_filter = _combine_filter(args.instances, args.instance_filter)

    manifest = {
        "outbase": outbase,
        "k": args.k,
        "subset": args.subset,
        "split": args.split,
        "workers": args.workers,
        "limit": args.limit,
        "filter": combined_filter,
        "instances": args.instances,
        "models": models_per_candidate,
        "roulette_models": roulette_models,
        "seed": args.seed,
        "base_cmd": base_cmd,
        "extra_args": extra_args,
        "commands": [],
    }

    rng = random.Random(args.seed)

    for idx in range(1, args.k + 1):
        cand_dir = Path(f"{outbase}_cand{idx}")
        cand_dir.mkdir(parents=True, exist_ok=True)

        model = models_per_candidate[idx - 1]
        roulette_choice = None
        if idx == 2 and roulette_models:
            roulette_choice = rng.choice(roulette_models)
            model = roulette_choice

        cmd = _build_mini_extra_cmd(
            base_cmd,
            args.subset,
            args.split,
            cand_dir,
            args.workers,
            model,
            limit=args.limit,
            filter_text=combined_filter,
            extra_args=extra_args,
        )

        manifest_entry = {
            "candidate": idx,
            "msa_dir": str(cand_dir),
            "model": model,
            "roulette_choice": roulette_choice,
            "cmd": cmd,
            "status": "pending",
        }

        print(f"[CANDIDATE {idx}] {' '.join(shlex.quote(part) for part in cmd)}")

        if args.dry_run:
            manifest_entry["status"] = "dry-run"
        else:
            try:
                subprocess.run(cmd, check=True)
                manifest_entry["status"] = "success"
            except subprocess.CalledProcessError as exc:  # pragma: no cover - subprocess failure path
                manifest_entry["status"] = f"failed: {exc}"
                manifest_entry["returncode"] = exc.returncode
                if not args.keep_going:
                    manifest["commands"].append(manifest_entry)
                    break
        manifest["commands"].append(manifest_entry)

    manifest_path = Path(f"{outbase}_manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote manifest to {manifest_path}")


if __name__ == "__main__":
    main()
