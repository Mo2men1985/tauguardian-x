#!/usr/bin/env python3
"""
run_ablation_experiment.py

Orchestrate ablation experiments for τGuardian.

Usage example:

    python run_ablation_experiment.py \
        --subset-file tests/easy_subset.txt \
        --models "dashscope/qwen3-coder-480b-a35b-instruct" \
        --configs "Full,-SAD,-CRI,-TAU,baseline" \
        --repeats 2 \
        --outdir experiments/ablation_run01 \
        --resume-file experiments/ablation_run01/state.json

Notes:
- Requires auto_runs.py, swe_eval_wrapper.py, analyze_mini_swe_results.py,
  and tools/generate_proofcard.py to be callable as:
      python <script> ...
  from the repo root.
- Uses environment flags to toggle ablation behavior:
    NO_SAD        -> disable SAD (security) checks
    FORCE_CRION   -> force CRI to a trivial value for ablation
    UNLIMITED_TAU -> remove/relax tau_max
    BASELINE_MODE -> bypass τGuardian harness (raw model behavior)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_STATE_FILENAME = "ablation_state.json"


def load_subset(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(f"subset-file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    return lines


def run_command(cmd: List[str], env: Dict[str, str] | None = None, cwd: Path = Path(".")) -> int:
    print(f"[run_ablation] RUN: {' '.join(cmd)}")
    env_local = os.environ.copy()
    if env:
        env_local.update(env)
    proc = subprocess.Popen(cmd, env=env_local, cwd=str(cwd))
    rc = proc.wait()
    return rc


def call_auto_runs(model: str, instance_filter: str, output_dir: Path, extra_env: Dict[str, str]) -> Path:
    """Calls auto_runs.py swe-qwen (or equivalent) for a single instance.

    Expects that auto_runs writes a JSONL predictions file into output_dir.
    Returns path to produced predictions file (JSONL or JSON).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python",
        "auto_runs.py",
        "swe-qwen",
        "--qwen-model",
        model,
        "--output-dir",
        str(output_dir),
        "--filter",
        instance_filter,
    ]
    rc = run_command(cmd, env=extra_env)
    if rc != 0:
        raise RuntimeError(f"auto_runs failed (rc={rc}) for instance={instance_filter}")

    # Common naming patterns: *.jsonl or preds.json
    candidates = list(output_dir.glob("*.jsonl")) + list(output_dir.glob("*.JSONL"))
    if candidates:
        return candidates[0]

    fallback = output_dir / "preds.json"
    if fallback.exists():
        return fallback

    raise FileNotFoundError(f"No predictions file produced in {output_dir}")


def call_swe_eval(predictions_path: Path, run_id: str, eval_outdir: Path) -> Path:
    """Calls swe_eval_wrapper.py to run SWE-bench-style evaluation.

    Expected primary output:
        <eval_outdir>/<run_id>/instance_results.jsonl

    Fallback:
        <eval_outdir>/instance_results.jsonl
    """
    eval_outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python",
        "swe_eval_wrapper.py",
        "--predictions-path",
        str(predictions_path),
        "--run-id",
        run_id,
        "--outdir",
        str(eval_outdir),
    ]
    rc = run_command(cmd)
    if rc != 0:
        raise RuntimeError(f"swe_eval_wrapper failed (rc={rc}) for predictions={predictions_path}")

    primary = eval_outdir / run_id / "instance_results.jsonl"
    if primary.exists():
        return primary

    alt = eval_outdir / "instance_results.jsonl"
    if alt.exists():
        return alt

    raise FileNotFoundError(
        f"Expected instance_results.jsonl at {primary} or {alt}, but neither exists."
    )


def generate_proofcard(enriched_jsonl: Path, outdir: Path, sign_key: str | None = None) -> Path:
    """Calls tools/generate_proofcard.py to build a ProofCard from enriched JSONL."""
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python",
        "tools/generate_proofcard.py",
        "--enriched-path",
        str(enriched_jsonl),
        "--out-dir",
        str(outdir),
    ]
    if sign_key:
        cmd.extend(["--sign-key", sign_key])

    rc = run_command(cmd)
    if rc != 0:
        raise RuntimeError(f"generate_proofcard.py failed (rc={rc}) for {enriched_jsonl}")

    proofcard_path = outdir / "ProofCard.json"
    return proofcard_path


def save_state(state_path: Path, state: Dict[str, Any]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, sort_keys=True, indent=2), encoding="utf-8")


def load_state(state_path: Path) -> Dict[str, Any]:
    if not state_path.exists():
        return {}
    return json.loads(state_path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run ablation experiment matrix for τGuardian.")
    parser.add_argument("--subset-file", required=True, help="File with instance ids (one per line).")
    parser.add_argument("--models", required=True, help="Comma-separated list of model ids.")
    parser.add_argument(
        "--configs",
        required=True,
        help="Comma-separated list of configs (e.g. Full,-SAD,-CRI,-TAU,baseline).",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=1,
        help="How many repeats per (model, config, instance).",
    )
    parser.add_argument("--outdir", required=True, help="Top-level outdir for experiments.")
    parser.add_argument(
        "--resume-file",
        default=None,
        help="Path to resume state JSON (default: <outdir>/ablation_state.json).",
    )
    parser.add_argument(
        "--sign-key",
        default=None,
        help="Optional signing key path passed to tools/generate_proofcard.py.",
    )
    args = parser.parse_args()

    subset = load_subset(Path(args.subset_file))
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]

    outdir = Path(args.outdir)
    state_path = Path(args.resume_file) if args.resume_file else outdir / DEFAULT_STATE_FILENAME

    state: Dict[str, Any] = load_state(state_path)
    # state format:
    # { "<model>|<config>|<instance>|r<rep>": {"status": "done"/"failed", "meta": {...}, ...} }

    results: List[Dict[str, Any]] = []

    for model in models:
        for config in configs:
            for rep in range(1, args.repeats + 1):
                for instance in subset:
                    key = f"{model}|{config}|{instance}|r{rep}"
                    if state.get(key, {}).get("status") == "done":
                        print(f"[run_ablation] SKIP already done: {key}")
                        continue

                    extra_env: Dict[str, str] = {}
                    if config == "-SAD":
                        extra_env["NO_SAD"] = "1"
                    if config == "-CRI":
                        extra_env["FORCE_CRION"] = "1"
                    if config == "-TAU":
                        extra_env["UNLIMITED_TAU"] = "1"
                    if config == "baseline":
                        extra_env["BASELINE_MODE"] = "1"

                    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())

                    try:
                        run_label = (
                            f"{model.replace('/', '_')}_"
                            f"{config.replace('-', 'no')}_"
                            f"r{rep}_"
                            f"{instance.replace('/', '_')}"
                        )

                        run_outdir = outdir / run_label
                        run_outdir.mkdir(parents=True, exist_ok=True)

                        # 1) Call auto_runs to get predictions
                        predictions = call_auto_runs(model, instance, run_outdir, extra_env)

                        # 2) Call SWE eval wrapper
                        eval_outdir = outdir / "evaluation_results"
                        instance_results = call_swe_eval(predictions, run_label, eval_outdir)

                        # 3) Integrate preds + eval into enriched JSONL
                        integrated_jsonl = run_outdir / f"{predictions.stem}.enriched.jsonl"

                        try:
                            # Prefer programmatic import if available
                            from analyze_mini_swe_results import (  # type: ignore
                                integrate_swe_eval_into_jsonl,
                            )

                            enriched_path_str = integrate_swe_eval_into_jsonl(
                                str(predictions),
                                str(eval_outdir / run_label),
                            )
                            enriched = Path(enriched_path_str)
                            if not enriched.exists():
                                candidates = list(run_outdir.glob("*.enriched.jsonl"))
                                if candidates:
                                    enriched = candidates[0]
                                else:
                                    raise FileNotFoundError(
                                        "integrate_swe_eval_into_jsonl did not produce an enriched JSONL."
                                    )
                        except Exception:
                            # Fallback to CLI
                            cli_cmd = [
                                "python",
                                "analyze_mini_swe_results.py",
                                "--msa-dir",
                                str(run_outdir),
                                "--model-id",
                                model,
                                "--output",
                                str(integrated_jsonl),
                            ]
                            rc = run_command(cli_cmd, env=extra_env)
                            if rc != 0:
                                raise RuntimeError("analyze_mini_swe_results.py failed (CLI).")
                            enriched = integrated_jsonl

                        # 4) Generate ProofCard
                        proof_outdir = run_outdir / "proofcard"
                        proofcard_path = generate_proofcard(enriched, proof_outdir, sign_key=args.sign_key)

                        # 5) Collect metadata and update state
                        meta = {
                            "model": model,
                            "config": config,
                            "instance": instance,
                            "rep": rep,
                            "timestamp": timestamp,
                            "predictions": str(predictions),
                            "instance_results": str(instance_results),
                            "enriched": str(enriched),
                            "proofcard": str(proofcard_path),
                        }

                        state[key] = {
                            "status": "done",
                            "meta": meta,
                            "timestamp": timestamp,
                        }
                        save_state(state_path, state)
                        results.append(meta)
                        print(f"[run_ablation] DONE {key}")

                    except Exception as exc:
                        state[key] = {
                            "status": "failed",
                            "error": str(exc),
                            "timestamp": timestamp,
                        }
                        save_state(state_path, state)
                        print(f"[run_ablation] ERROR run failed for {key}: {exc}")
                        # Continue to next item instead of aborting all runs
                        continue

    # Final aggregation
    agg = {
        "summary": {
            "models": models,
            "configs": configs,
            "n_instances": len(subset),
            "repeats": args.repeats,
            "completed_runs": len(
                [k for k, v in state.items() if v.get("status") == "done"]
            ),
        },
        "results": results,
        "state_file": str(state_path),
    }
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "ablation_results.json").write_text(
        json.dumps(agg, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    print(f"[run_ablation] FINISH wrote ablation_results.json to {outdir}")


if __name__ == "__main__":
    main()
