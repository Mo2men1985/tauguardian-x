import argparse
import json
from collections import defaultdict
from typing import Dict, Any, List


def load_results(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def summarize_model(results_path: str, model_name: str) -> None:
    records = [r for r in load_results(results_path) if r.get("model") == model_name]
    if not records:
        print(f"No records found for model={model_name!r} in {results_path}")
        return

    by_task: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for rec in records:
        task = rec.get("task", "<unknown>")
        rec_type = rec.get("type", "<unknown>")
        by_task[task][rec_type] = rec

    print("=" * 72)
    print(f"τGuardian results for model: {model_name}")
    print(f"Source file             : {results_path}")
    print(f"Tasks (unique)          : {len(by_task)}")
    print("=" * 72)

    baseline_full_pass = 0
    wrapped_ok = 0
    wrapped_abstain = 0
    wrapped_veto = 0

    for task, kinds in sorted(by_task.items()):
        baseline = kinds.get("baseline")
        wrapped = kinds.get("wrapped")

        print(f"\nTask: {task}")
        print("-" * (6 + len(task)))

        if baseline:
            total = baseline.get("total_tests")
            passed = baseline.get("tests_passed")
            failed = baseline.get("tests_failed")
            pass_rate = baseline.get("test_pass_rate")
            cri = baseline.get("cri")
            sad = baseline.get("sad_flag")
            tau = baseline.get("tau")

            if total and passed == total:
                baseline_full_pass += 1

            print(f"  Baseline:")
            print(f"    tests      : {passed}/{total} (failed={failed}, pass_rate={pass_rate})")
            print(f"    CRI / τ    : cri={cri}, tau={tau}, sad_flag={sad}")
            print(f"    sec_viol   : {baseline.get('security_violation_count')}")

        if wrapped:
            decision = wrapped.get("final_decision")
            last_passed = wrapped.get("last_tests_passed")
            last_total = wrapped.get("last_total_tests")
            last_failed = wrapped.get("last_tests_failed")
            last_rate = wrapped.get("last_test_pass_rate")
            last_cri = wrapped.get("last_cri")
            last_tau = wrapped.get("last_tau")
            last_sad = wrapped.get("last_sad")
            cri_hist = wrapped.get("cri_history")

            if decision == "OK":
                wrapped_ok += 1
            elif decision == "ABSTAIN":
                wrapped_abstain += 1
            elif decision == "VETO":
                wrapped_veto += 1

            print(f"  Wrapped:")
            print(f"    decision   : {decision}")
            print(f"    last tests : {last_passed}/{last_total} (failed={last_failed}, pass_rate={last_rate})")
            print(f"    CRI / τ    : last_cri={last_cri}, last_tau={last_tau}, last_sad={last_sad}")
            print(f"    CRI history: {cri_hist}")

    print("\n" + "=" * 72)
    print("Aggregate:")
    print(f"  Baseline full-pass tasks : {baseline_full_pass}/{len(by_task)}")
    print(f"  Wrapped OK               : {wrapped_ok}")
    print(f"  Wrapped ABSTAIN          : {wrapped_abstain}")
    print(f"  Wrapped VETO             : {wrapped_veto}")
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect τGuardian results for a single model.")
    parser.add_argument("--results", default="results.jsonl", help="Path to results JSONL file.")
    parser.add_argument("--model", required=True, help="Model name to filter on (e.g. gemma-3n-E4B-it).")
    args = parser.parse_args()
    summarize_model(args.results, args.model)


if __name__ == "__main__":
    main()
