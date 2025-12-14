"""
CI helper: verify golden vectors.

Expected layout:

    tests/golden_vectors/gold-001/
        preds.json
        instance_results.jsonl      # optional if integrator uses it
        expected_enriched.jsonl

For each gold-* directory:

- If analyze_mini_swe_results.integrate_swe_eval_into_jsonl is available:
    - Call it with (preds_path, eval_dir) to produce enriched JSONL.
- Otherwise:
    - Use a simple fallback enrichment based on preds.json.

Then we canonicalize both produced and expected JSONL and compare bytes.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GOLD_DIR = ROOT / "golden_vectors"

try:
    from analyze_mini_swe_results import integrate_swe_eval_into_jsonl  # type: ignore

    HAVE_INTEGRATOR = True
except Exception:
    HAVE_INTEGRATOR = False


def canonicalize_jsonl(path: Path) -> bytes:
    """Return canonicalized bytes for a JSONL file:
    - parse each line as JSON
    - re-dump with sorted keys and compact separators
    - join with '\n' and add trailing newline
    """
    out_lines = []
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            out_lines.append(
                json.dumps(
                    obj,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
            )
    return ("\n".join(out_lines) + "\n").encode("utf-8")


def run_one(gdir: Path) -> bool:
    preds = gdir / "preds.json"
    inst = gdir / "instance_results.jsonl"
    expected = gdir / "expected_enriched.jsonl"

    if not preds.exists() or not expected.exists():
        print(
            f"[golden_runner] [SKIP] Missing preds.json or expected_enriched.jsonl in {gdir}",
            file=sys.stderr,
        )
        return False

    if HAVE_INTEGRATOR:
        # Preferred: call the real integration logic
        try:
            out_path = integrate_swe_eval_into_jsonl(str(preds), str(gdir))
            if isinstance(out_path, str):
                enriched_path = Path(out_path)
            else:
                enriched_path = Path("preds.enriched.jsonl")

            if not enriched_path.exists():
                # try any *.enriched.jsonl in same folder
                candidates = list(gdir.glob("*.enriched.jsonl"))
                if candidates:
                    enriched_path = candidates[0]
                else:
                    print(
                        f"[golden_runner] [ERROR] integrator did not produce enriched file for {gdir}",
                        file=sys.stderr,
                    )
                    return False

            produced_bytes = canonicalize_jsonl(enriched_path)
        except Exception as exc:
            print(
                f"[golden_runner] [ERROR] integrate_swe_eval_into_jsonl failed for {gdir}: {exc}",
                file=sys.stderr,
            )
            return False
    else:
        # Fallback: simple enrichment from preds.json
        try:
            with preds.open("r", encoding="utf-8") as fh:
                preds_obj = json.load(fh)

            enriched_obj = {
                "run_id": preds_obj.get("run_id", "gold_run"),
                "instance_id": preds_obj.get("task", preds_obj.get("instance", "gold_instance")),
                "model": preds_obj.get("model", "gold-model"),
                "patch": preds_obj.get("patch", ""),
                "tests_passed": preds_obj.get("tests_passed", 0),
                "tests_failed": preds_obj.get("tests_failed", 0),
                "total_tests": preds_obj.get("total_tests", 0),
            }
            produced_bytes = (
                json.dumps(
                    enriched_obj,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            ).encode("utf-8")
        except Exception as exc:
            print(
                f"[golden_runner] [ERROR] fallback enrichment failed for {gdir}: {exc}",
                file=sys.stderr,
            )
            return False

    expected_bytes = canonicalize_jsonl(expected)

    if produced_bytes != expected_bytes:
        print(f"[golden_runner] [MISMATCH] golden vector failed: {gdir}")
        debug_dir = ROOT / "golden_debug"
        debug_dir.mkdir(parents=True, exist_ok=True)
        (debug_dir / f"{gdir.name}.produced.jsonl").write_bytes(produced_bytes)
        (debug_dir / f"{gdir.name}.expected.jsonl").write_bytes(expected_bytes)
        print(f"[golden_runner] [INFO] Wrote produced/expected to {debug_dir} for inspection.")
        return False

    print(f"[golden_runner] [OK] golden vector matched: {gdir}")
    return True


def main() -> None:
    if not GOLD_DIR.exists():
        print(
            f"[golden_runner] [SKIP] No golden_vectors directory at {GOLD_DIR}; "
            f"create tests/golden_vectors/gold-001/ ...",
            file=sys.stderr,
        )
        sys.exit(0)

    all_dirs = sorted(
        [d for d in GOLD_DIR.iterdir() if d.is_dir() and d.name.startswith("gold-")]
    )
    if not all_dirs:
        print(
            f"[golden_runner] [SKIP] No gold-* directories found under {GOLD_DIR}",
            file=sys.stderr,
        )
        sys.exit(0)

    failures = []
    for g in all_dirs:
        ok = run_one(g)
        if not ok:
            failures.append(g.name)

    if failures:
        print(
            f"[golden_runner] [FAIL] {len(failures)} golden vectors failed: {failures}",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"[golden_runner] [OK] All golden vectors passed ({len(all_dirs)}).")
    sys.exit(0)


if __name__ == "__main__":
    main()
