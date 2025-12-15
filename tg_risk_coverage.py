#!/usr/bin/env python3
"""Compute risk/coverage sweep from enriched eval JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List


def load_rows(jsonl_path: Path) -> List[Dict]:
    if not jsonl_path.exists():
        raise SystemExit(f"[ERROR] JSONL not found: {jsonl_path}")
    rows: List[Dict] = []
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def parse_thresholds(arg: str) -> List[float]:
    parts = [p.strip() for p in arg.split(",") if p.strip()]
    thresholds: List[float] = []
    for part in parts:
        try:
            thresholds.append(float(part))
        except ValueError as exc:  # pragma: no cover - defensive
            raise SystemExit(f"Invalid threshold value: {part}") from exc
    return thresholds


def summarize(rows: Iterable[Dict], thresholds: List[float]) -> List[Dict[str, float]]:
    rows_list = list(rows)
    total = len(rows_list)
    output: List[Dict[str, float]] = []

    for thr in thresholds:
        accepted = 0
        false_accepts = 0
        resolved_ok = 0
        veto = 0
        abstain = 0

        for row in rows_list:
            final_decision = row.get("final_decision")
            sad_flag = bool(row.get("sad_flag"))
            security_scan_failed = bool(row.get("security_scan_failed"))
            cri = float(row.get("cri", 0.0) or 0.0)
            resolved = row.get("resolved")

            if final_decision == "VETO":
                veto += 1
            elif final_decision == "ABSTAIN":
                abstain += 1

            if (
                final_decision == "OK"
                and not sad_flag
                and not security_scan_failed
                and cri >= thr
            ):
                accepted += 1
                if resolved is False:
                    false_accepts += 1
                elif resolved is True:
                    resolved_ok += 1

        risk = (false_accepts / accepted) if accepted else 0.0
        coverage = (accepted / total) if total else 0.0

        output.append(
            {
                "threshold": thr,
                "total": total,
                "accepted": accepted,
                "coverage": coverage,
                "false_accepts": false_accepts,
                "risk": risk,
                "resolved_ok": resolved_ok,
                "veto": veto,
                "abstain": abstain,
            }
        )

    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Risk/coverage sweep from enriched eval JSONL")
    parser.add_argument("--jsonl", required=True, help="Path to enriched eval JSONL")
    parser.add_argument(
        "--thresholds",
        default="0.0,0.5,0.8,0.9,0.95",
        help="Comma-separated CRI thresholds",
    )
    args = parser.parse_args()

    jsonl_path = Path(args.jsonl)
    rows = load_rows(jsonl_path)
    thresholds = parse_thresholds(args.thresholds)

    summaries = summarize(rows, thresholds)
    print("threshold,total,accepted,coverage,false_accepts,risk,resolved_ok,veto,abstain")
    for row in summaries:
        print(
            f"{row['threshold']},{row['total']},{row['accepted']},{row['coverage']}"
            f",{row['false_accepts']},{row['risk']},{row['resolved_ok']},{row['veto']},{row['abstain']}"
        )


if __name__ == "__main__":
    main()
