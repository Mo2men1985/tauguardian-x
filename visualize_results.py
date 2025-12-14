

import json
import matplotlib.pyplot as plt
import sys
import os
from typing import List, Dict, Any


def load_results(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        print(f"Error: File {path} not found.")
        return records

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def plot_cri_history(records: List[Dict[str, Any]], output_file: str = "cri_history.png") -> None:
    wrapped_records = [r for r in records if r.get("type") == "wrapped"]

    if not wrapped_records:
        print("No 'wrapped' records found to visualize.")
        return

    plt.figure(figsize=(10, 6))
    colors = plt.cm.tab10.colors

    for i, rec in enumerate(wrapped_records):
        task_name = rec.get("task", "Unknown Task")
        model_name = rec.get("model", "Unknown Model")
        cri_history = rec.get("cri_history", [])

        if not cri_history:
            continue

        steps = list(range(1, len(cri_history) + 1))
        label = f"{task_name} ({model_name})"
        color = colors[i % len(colors)]

        plt.plot(steps, cri_history, marker="o", linestyle="-", linewidth=2, label=label, color=color)

        plt.text(
            steps[0],
            cri_history[0],
            f"{cri_history[0]:.2f}",
            fontsize=8,
            verticalalignment="bottom",
            color=color,
        )
        plt.text(
            steps[-1],
            cri_history[-1],
            f"{cri_history[-1]:.2f}",
            fontsize=8,
            verticalalignment="bottom",
            color=color,
        )

    plt.title("Code Reliability Improvement (CRI) over Symbolic Time (τ)", fontsize=14)
    plt.xlabel("Iteration Step (τ)", fontsize=12)
    plt.ylabel("CRI Score (0.0 - 1.0)", fontsize=12)
    plt.ylim(0, 1.1)
    plt.grid(True, linestyle="--", alpha=0.7)
    plt.legend()
    plt.tight_layout()

    print(f"Saving plot to {output_file}...")
    plt.savefig(output_file)
    print("Done.")


if __name__ == "__main__":
    file_path = "results.jsonl"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]

    data = load_results(file_path)
    plot_cri_history(data)
