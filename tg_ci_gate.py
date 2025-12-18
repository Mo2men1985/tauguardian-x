#!/usr/bin/env python3
"""
Simple CI gate for τGuardian-governed SWE-bench runs.

Usage:
    python tg_ci_gate.py --input path/to/governed_results.jsonl

The script prints a summary of OK / ABSTAIN / VETO decisions and
exits with a non-zero status code if any VETO decisions are present.
"""

import argparse
import json
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="τGuardian CI gate for governed SWE-bench results."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to the governed JSONL file produced by analyze_mini_swe_results.py.",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"[CI] ERROR: governed results file not found: {path}", file=sys.stderr)
        sys.exit(2)

    ok = abstain = veto = 0
    total = 0

    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"[CI] WARNING: skipping invalid JSON on line {lineno}: {exc}",
                    file=sys.stderr,
                )
                continue

            total += 1
            decision = str(rec.get("final_decision") or "ABSTAIN").upper()
            if decision == "OK":
                ok += 1
            elif decision == "VETO":
                veto += 1
            else:
                abstain += 1

    print(f"[CI] τGuardian decisions from {path}:")
    print(f"  Total   : {total}")
    print(f"  OK      : {ok}")
    print(f"  ABSTAIN : {abstain}")
    print(f"  VETO    : {veto}")

    if veto > 0:
        print(f"[CI] FAIL: {veto} VETO decision(s) present. Failing the job.")
        sys.exit(1)

    print("[CI] PASS: no VETO decisions. Build is green.")
    sys.exit(0)


if __name__ == "__main__":
    main()
