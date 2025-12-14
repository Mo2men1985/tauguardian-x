
# Simple analysis script for results.jsonl
import json
from collections import defaultdict


def load_results(path: str = "results.jsonl"):
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def main():
    recs = load_results()
    by_model_task = defaultdict(list)
    for r in recs:
        key = (r["model"], r["task"])
        by_model_task[key].append(r)

    for (model, task), items in by_model_task.items():
        baseline = next((x for x in items if x["type"] == "baseline"), None)
        wrapped = next((x for x in items if x["type"] == "wrapped"), None)
        print(f"=== {model} / {task} ===")
        if baseline:
            print(f"  Baseline pass rate: {baseline.get('test_pass_rate')}")
            print(f"  Baseline sec violations: {baseline.get('security_violation_count')}")
        if wrapped:
            print(f"  Wrapped final decision: {wrapped.get('final_decision')}")
            print(f"  Wrapped last pass rate: {wrapped.get('last_test_pass_rate')}")
            print(f"  Wrapped cri history: {wrapped.get('cri_history')}")
            print(f"  Wrapped last security violations: {wrapped.get('last_security_violations')}")
        print()


if __name__ == "__main__":
    main()


