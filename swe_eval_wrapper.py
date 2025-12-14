#!/usr/bin/env python3
"""swe_eval_wrapper.py

Thin CLI wrapper for SWE / mini-SWE evaluation in τGuardian.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path


DEFAULT_CLI = (
    "{python} tg_swebench_cli.py --predictions-path {predictions} "
    "--run-id {run_id} --outdir {outdir}"
)


def _run_shell_command(cmd: str, cwd: Path | None, timeout: int) -> int:
    print(f"[swe_eval_wrapper] RUN: {cmd}")
    args = shlex.split(cmd)
    proc = subprocess.Popen(args, cwd=str(cwd or Path(".")))
    try:
        rc = proc.wait(timeout=timeout)
        return rc
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(f"External SWE evaluator timed out after {timeout} seconds")


def main() -> None:
    if sys.platform.startswith("win"):
        raise SystemExit(
            "SWE-bench harness evaluation is not supported on native Windows. "
            "Run this command from WSL/Linux (e.g., `wsl ...`) or inside a Linux environment."
        )
    parser = argparse.ArgumentParser(
        description="Wrapper around SWE / mini-SWE evaluation for τGuardian."
    )
    parser.add_argument(
        "--predictions-path",
        required=True,
        help="Path to model predictions (JSON or JSONL).",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run identifier (used in output directory structure).",
    )
    parser.add_argument(
        "--outdir",
        required=True,
        help="Root output directory for evaluation results.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Timeout in seconds for external evaluator (default: 3600).",
    )
    args = parser.parse_args()

    predictions_path = Path(args.predictions_path).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    run_id = args.run_id
    timeout = args.timeout

    outdir.mkdir(parents=True, exist_ok=True)
    instance_results_path = outdir / "instance_results.jsonl"

    if instance_results_path.exists():
        print(f"[swe_eval_wrapper] Reusing existing {instance_results_path}")
        return

    cli_template = os.environ.get("TG_SWE_EVAL_CLI")
    if cli_template:
        cli = cli_template
    else:
        python_bin = os.environ.get("PYTHON", "python")
        cli = DEFAULT_CLI.format(
            python=python_bin,
            predictions="{predictions}",
            run_id="{run_id}",
            outdir="{outdir}",
        )

    cmd = cli.format(
        predictions=str(predictions_path),
        run_id=run_id,
        outdir=str(outdir),
    )
    rc = _run_shell_command(cmd, cwd=None, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"External SWE eval CLI failed (rc={rc})")

    if not instance_results_path.exists():
        raise FileNotFoundError(
            f"Expected instance_results.jsonl at {instance_results_path} after running external CLI"
        )

    print(f"[swe_eval_wrapper] Found instance_results at {instance_results_path}")
    print(instance_results_path)


if __name__ == "__main__":
    main()
