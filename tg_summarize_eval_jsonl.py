from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize τGuardian eval JSONL outputs")
    parser.add_argument("path", nargs="?", default="swe_results.jsonl", help="Path to eval JSONL file")
    args = parser.parse_args()

    path = Path(args.path).expanduser()
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    final_decision = Counter()
    resolved_status = Counter()
    security_scan_failed = Counter()
    security_scan_scope = Counter()

    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            final_decision.update([str(obj.get("final_decision"))])
            resolved_status.update([str(obj.get("resolved_status"))])
            security_scan_failed.update([bool(obj.get("security_scan_failed"))])
            scope = obj.get("security_scan_scope")
            if scope:
                security_scan_scope.update([str(scope)])

    print("final_decision counts:")
    for key, count in final_decision.most_common():
        print(f"  {key}: {count}")

    print("\nresolved_status counts:")
    for key, count in resolved_status.most_common():
        print(f"  {key}: {count}")

    print("\nsecurity_scan_failed counts:")
    for key, count in security_scan_failed.most_common():
        label = "true" if key else "false"
        print(f"  {label}: {count}")

    print("\ntop security_scan_scope counts:")
    for key, count in security_scan_scope.most_common():
        print(f"  {key}: {count}")


if __name__ == "__main__":
    main()
