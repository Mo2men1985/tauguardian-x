
"""Command-line entrypoint to run τGuardian on SWE-bench tasks."""

import argparse
import json
import os

from swe_runner import SweConfig, swe_experiment, load_swebench_tasks


def main() -> None:
    parser = argparse.ArgumentParser(description="Run τGuardian on SWE-bench tasks.")
    parser.add_argument(
        "--model",
        default=os.getenv("LLM_MODEL_NAME", "gpt-5.1"),
        help="Model name to evaluate (default: env LLM_MODEL_NAME or gpt-5.1).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Maximum number of SWE-bench tasks to load.",
    )
    parser.add_argument(
        "--subset",
        default="lite",
        choices=["lite", "full"],
        help="SWE-bench subset to use (lite or full).",
    )
    parser.add_argument(
        "--tau-max",
        type=int,
        default=int(os.getenv("TAU_MAX", "3")),
        help="Maximum τ iterations for wrapped runs.",
    )
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="Run tests inside Docker sandbox (requires Docker).",
    )
    parser.add_argument(
        "--output",
        default="swe_results.jsonl",
        help="Path to JSONL file where results will be written.",
    )

    args = parser.parse_args()

    # Load SWE-bench tasks
    print(f"Loading {args.limit} tasks from SWE-bench ({args.subset}) ...")
    tasks = load_swebench_tasks(
        subset=args.subset,
        limit=args.limit,
        workspace_dir="./swe_workspace",
    )

    if not tasks:
        print("No tasks loaded. Check SWE-bench installation and dataset path.")
        return

    # Configure τGuardian SWE experiment
    cfg = SweConfig(
        model_name=args.model,
        tau_max=args.tau_max,
        use_sandbox=args.sandbox,
    )

    print()
    print(f"Running τGuardian on {len(tasks)} tasks")
    print(f"  Model   : {cfg.model_name}")
    print(f"  τ_max   : {cfg.tau_max}")
    print(f"  Sandbox : {cfg.use_sandbox}")
    print(f"  Output  : {args.output}")
    print()

    swe_experiment(cfg, tasks, results_path=args.output)

    # Summarize results
    baseline_pass = 0
    wrapped_pass = 0
    total_tasks = 0
    seen_tasks = set()

    try:
        with open(args.output, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                rec_type = rec.get("type")
                task_name = rec.get("task")

                # Count total tasks using baseline entries
                if rec_type == "baseline":
                    total_tasks += 1
                    if task_name is not None:
                        seen_tasks.add(task_name)
                    if rec.get("test_pass_rate") == 1.0:
                        baseline_pass += 1
                elif rec_type == "wrapped":
                    # last_test_pass_rate is the pass rate after final τ iteration
                    if rec.get("last_test_pass_rate") == 1.0:
                        wrapped_pass += 1
    except FileNotFoundError:
        print(f"Results file {args.output} not found, skipping summary.")
        return

    if total_tasks == 0 and seen_tasks:
        total_tasks = len(seen_tasks)

    print("\n" + "=" * 60)
    print("SWE-bench Results Summary")
    print("=" * 60)
    print(f"Tasks               : {total_tasks}")
    if total_tasks > 0:
        print(f"Baseline pass rate  : {baseline_pass}/{total_tasks} ({baseline_pass/total_tasks*100:.1f}%)")
        print(f"Wrapped pass rate   : {wrapped_pass}/{total_tasks} ({wrapped_pass/total_tasks*100:.1f}%)")
        improvement = (wrapped_pass - baseline_pass) / total_tasks * 100.0
        print(f"Improvement         : {improvement:+.1f} percentage points")
    else:
        print("No tasks found in results; nothing to summarize.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()

