"""
Single-task τGuardian runner for local Gemma.

Usage (from repo root, after activating .venv):

    set LLM_PROVIDER=local_gemma
    set GEMMA_MODEL_PATH=E:\hf_cache\hub\models--google--gemma-3n-E4B-it\snapshots\...
    set LLM_MODEL_NAME=gemma-3n-E4B-it

    python run_single_task_gemma.py --task rate_limiter_python --tau-max 2

This reuses harness.example_tasks / run_baseline / run_wrapped and prints a
compact summary for the selected task.
"""

import argparse
import os

from harness import example_tasks, run_baseline, run_wrapped


def find_task(task_name: str):
    tasks = example_tasks()
    for t in tasks:
        if t.name == task_name:
            return t
    available = ", ".join(sorted(t.name for t in tasks))
    raise SystemExit(f"Unknown task {task_name!r}. Available tasks: {available}")


def print_single_task_summary(model_name: str, task_name: str, baseline, wrapped, tau_max: int) -> None:
    print("=" * 72)
    print("τGuardian single-task run")
    print(f"  Model      : {model_name}")
    print(f"  Provider   : {os.getenv('LLM_PROVIDER', 'openai')}")
    print(f"  Task       : {task_name}")
    print(f"  τ max      : {tau_max}")
    print("=" * 72)

    # --- Baseline ---
    b_checks = baseline.checks
    b_metrics = baseline.metrics
    b_passed = b_checks.total_tests - b_checks.tests_failed
    b_failed = b_checks.tests_failed
    b_total = b_checks.total_tests
    b_rate = (b_passed / b_total) if b_total else 0.0

    print("\n[Baseline]")
    print(f"  tests      : {b_passed}/{b_total} (failed={b_failed}, pass_rate={b_rate:.3f})")
    print(f"  CRI / τ    : cri={b_metrics.cri:.3f}, tau={b_metrics.tau}, sad_flag={b_metrics.sad_flag}")
    print(f"  sec_viol   : {len(b_checks.security_violations)} -> {b_checks.security_violations}")
    print(f"  linter_err : {len(b_checks.linter_errors)} -> {b_checks.linter_errors}")

    # --- Wrapped τ-loop ---
    print("\n[Wrapped τ-loop]")
    if not wrapped.iterations:
        print("  No iterations recorded (wrapped run produced no results).")
        return

    w_iters = wrapped.iterations
    w_last = w_iters[-1]
    w_checks = w_last.checks
    w_metrics = w_last.metrics
    w_passed = w_checks.total_tests - w_checks.tests_failed
    w_failed = w_checks.tests_failed
    w_total = w_checks.total_tests
    w_rate = (w_passed / w_total) if w_total else 0.0

    cri_history = [it.metrics.cri for it in w_iters]
    tau_history = [it.metrics.tau for it in w_iters]

    print(f"  decision   : {wrapped.final_decision}")
    print(f"  iterations : {len(w_iters)}")
    print(f"  last tests : {w_passed}/{w_total} (failed={w_failed}, pass_rate={w_rate:.3f})")
    print(f"  last CRI   : {w_metrics.cri:.3f}, last τ={w_metrics.tau}, last SAD={w_metrics.sad_flag}")
    print(f"  CRI hist   : {cri_history}")
    print(f"  τ hist     : {tau_history}")
    print(f"  sec_viol   : {len(w_checks.security_violations)} -> {w_checks.security_violations}")
    print(f"  linter_err : {len(w_checks.linter_errors)} -> {w_checks.linter_errors}")

    print("\n" + "=" * 72)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Run a single τGuardian task on local Gemma.")
    parser.add_argument(
        "--task",
        required=True,
        help="Task name to run (e.g. rate_limiter_python, funds_transfer_secure, ...).",
    )
    parser.add_argument(
        "--tau-max",
        type=int,
        default=int(os.getenv("TAU_MAX", "1")),
        help="Maximum τ iterations for the wrapped run (default: env TAU_MAX or 1).",
    )
    parser.add_argument(
        "--model",
        default=os.getenv("LLM_MODEL_NAME", "gemma-3n-E4B-it"),
        help="Logical model name (default: env LLM_MODEL_NAME or gemma-3n-E4B-it).",
    )
    args = parser.parse_args(argv)

    # Default provider to local_gemma if not explicitly set.
    os.environ.setdefault("LLM_PROVIDER", "local_gemma")

    task = find_task(args.task)
    baseline = run_baseline(args.model, task)
    wrapped = run_wrapped(args.model, task, tau_max=args.tau_max)

    print_single_task_summary(args.model, task.name, baseline, wrapped, args.tau_max)


if __name__ == "__main__":
    main()
