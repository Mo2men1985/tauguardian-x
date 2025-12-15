#!/usr/bin/env python3
"""Run the SWE-bench harness and emit instance-level results.

This thin wrapper normalizes mini-SWE predictions into a format the
``swebench`` harness expects, executes the harness, and converts its
report into a compact ``instance_results.jsonl`` for downstream tooling.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional


def normalize_patch_text(text: str) -> str:
    """Normalize model output into a patch string suitable for SWE-bench.

    Design constraints (must-haves):
    - Never strip leading whitespace per line; unified-diff *context* lines begin
      with a single leading space that is semantically meaningful.
    - Never truncate multi-file patches; SWE-bench frequently requires edits in
      more than one file.
    - Be tolerant to LLM wrappers (markdown fences, leading prose).

    Strategy:
    1) Normalize newlines.
    2) If a fenced code block exists, prefer the first fenced block.
    3) Drop leading prose by cutting from the first diff header ("diff --git")
       or a unified diff header ("---" followed by "+++").
    4) Dedent only *common indentation* (safe for fenced/indented blocks), and
       ensure a trailing newline.
    """

    if text is None:
        text = ""

    # Normalize newlines early.
    raw = str(text).replace("\r\n", "\n").replace("\r", "\n")
    raw = raw.lstrip("\ufeff")

    # Prefer the first fenced block if present (```diff / ```patch / ```).
    fenced_match = re.search(r"(?ms)```(?:diff|patch)?\s*\n(.*?)\n```\s*", raw)
    if fenced_match:
        candidate = fenced_match.group(1)
    else:
        # Keep leading indentation so textwrap.dedent can correctly remove
        # common indentation across *all* diff lines.
        candidate = raw.strip("\n")

        # If the whole content is fenced (possibly indented), strip the outer fences.
        if re.match(r"(?ms)^\s*```", candidate):
            candidate = re.sub(r"(?ms)^\s*```(?:diff|patch)?\s*\n?", "", candidate, count=1)
            candidate = re.sub(r"(?ms)\n?\s*```\s*$", "", candidate, count=1)

    lines = candidate.splitlines()

    def _find_start_index() -> Optional[int]:
        for i, line in enumerate(lines):
            if line.lstrip().startswith("diff --git "):
                return i
        for i, line in enumerate(lines):
            if line.lstrip().startswith("--- "):
                # Ensure a +++ follows (avoid prose that happens to contain ---).
                if any(l.lstrip().startswith("+++ ") for l in lines[i + 1 :]):
                    return i
        return None

    start_idx = _find_start_index()
    if start_idx is not None:
        block_lines = [ln for ln in lines[start_idx:] if not ln.strip().startswith("```")]
        normalized = "\n".join(block_lines)
    else:
        # No diff markers found; return as-is (still newline-normalized).
        normalized = candidate

    # Dedent common indentation (safe for fenced/indented blocks) while preserving
    # whitespace-only diff context lines.
    normalized = _safe_dedent_preserve_diff(normalized).strip("\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _safe_dedent_preserve_diff(text: str) -> str:
    """Remove common indentation without stripping diff prefixes.

    ``textwrap.dedent`` treats whitespace-only lines as indented content and will
    collapse a single-space diff context line (" ") into an empty string. That
    breaks unified-diff hunks (``git apply`` reports "corrupt patch").

    This helper computes the common indentation from non-blank lines only and
    never strips a whitespace-only line down to ``""``.
    """

    lines = text.splitlines()
    if not lines:
        return text

    indent_candidates = []
    for line in lines:
        stripped = line.lstrip()
        if stripped:
            indent_candidates.append(len(line) - len(stripped))

    if not indent_candidates:
        return text

    margin = min(indent_candidates)
    if margin <= 0:
        return text

    dedented: List[str] = []
    for line in lines:
        if not line:
            dedented.append(line)
            continue
        if len(line) <= margin:
            trimmed = ""
        else:
            trimmed = line[margin:]
        if trimmed == "" and line.strip() == "":
            dedented.append(" ")
        else:
            dedented.append(trimmed)
    return "\n".join(dedented)


def _ensure_instance_id(record: Dict[str, Any], fallback: str) -> Dict[str, Any]:
    """Return a copy of ``record`` with a best-effort instance_id.

    mini-SWE outputs sometimes omit ``instance_id`` and use alternate keys
    such as ``task`` or ``id``. This helper standardizes the field so the
    SWE-bench harness can consume the predictions list.
    """

    out = dict(record)
    instance_id = (
        out.get("instance_id")
        or out.get("task")
        or out.get("id")
        or out.get("task_id")
        or fallback
    )
    out["instance_id"] = instance_id
    return out


def _normalize_prediction_mapping(mapping: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Handle ``{instance_id: payload}`` style predictions."""

    normalized: List[Dict[str, Any]] = []
    for instance_id, payload in mapping.items():
        if isinstance(payload, dict):
            rec = dict(payload)
        else:
            rec = {"model_patch": payload}
        rec.setdefault("instance_id", instance_id)
        normalized.append(rec)
    return normalized


def _normalize_prediction_obj(obj: Any) -> List[Dict[str, Any]]:
    """Convert various JSON/JSONL shapes into a list of dicts."""

    if obj is None:
        return []
    if isinstance(obj, list):
        result: List[Dict[str, Any]] = []
        for idx, rec in enumerate(obj, start=1):
            if not isinstance(rec, dict):
                rec = {"model_patch": rec}
            result.append(_ensure_instance_id(rec, f"instance_{idx}"))
        return result
    if isinstance(obj, dict):
        if any(k in obj for k in ("instance_id", "task", "id", "task_id")):
            return [_ensure_instance_id(dict(obj), "instance_unknown")]
        return _normalize_prediction_mapping(obj)
    return [_ensure_instance_id({"model_patch": obj}, "instance_unknown")]


def load_predictions(predictions_path: Path) -> List[Dict[str, Any]]:
    """Load predictions from JSON, JSONL, or mapping formats.

    Accepts:
    - JSON array of prediction dicts
    - JSON mapping of instance_id -> payload
    - JSON Lines file (one JSON object per line)

    Leading BOMs or stray whitespace are ignored.
    """

    if not predictions_path.exists():
        raise FileNotFoundError(f"predictions-path not found: {predictions_path}")

    raw_text = predictions_path.read_text(encoding="utf-8-sig")
    if not raw_text.strip():
        return []

    try:
        parsed = json.loads(raw_text)
        raw_preds = _normalize_prediction_obj(parsed)
    except json.JSONDecodeError:
        raw_preds = []
        for idx, line in enumerate(raw_text.splitlines(), start=1):
            ln = line.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            raw_preds.extend(
                _normalize_prediction_obj(obj or {"instance_id": f"line_{idx}"})
            )

    preds: List[Dict[str, Any]] = []
    for rec in raw_preds:
        rec_copy = dict(rec)
        rec_copy["model_patch"] = normalize_patch_text(rec_copy.get("model_patch", ""))
        preds.append(rec_copy)
    return preds


def _write_normalized_predictions(predictions: Iterable[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(list(predictions), fh)


def _run_swebench_harness(
    predictions_path: Path,
    run_id: str,
    outdir: Path,
    dataset_name: str,
    split: str,
) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "swebench.harness.run_evaluation",
        "--dataset_name",
        dataset_name,
        "--split",
        split,
        "--predictions_path",
        str(predictions_path),
        "--run_id",
        run_id,
    ]
    print(f"[tg_swebench_cli] RUN: {' '.join(cmd)} (cwd={outdir})")
    proc = subprocess.run(cmd, cwd=outdir)
    if proc.returncode != 0:
        raise SystemExit(f"SWE-bench harness failed with rc={proc.returncode}")


def _find_report(outdir: Path, run_id: str) -> Path:
    pattern = f"*.{run_id}.json"
    candidates = sorted(outdir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        raise FileNotFoundError(
            f"Unable to find SWE-bench report matching {pattern} under {outdir}"
        )
    return candidates[0]


def _extract_report_instances(report_data: Any) -> Dict[str, Dict[str, Any]]:
    def _attach(inst_id: Optional[str], payload: Mapping[str, Any]) -> None:
        if inst_id:
            instances[str(inst_id)] = dict(payload)

    instances: Dict[str, Dict[str, Any]] = {}
    if isinstance(report_data, dict):
        for key in ("report", "results", "instances"):
            section = report_data.get(key)
            if isinstance(section, dict):
                for inst_id, payload in section.items():
                    if isinstance(payload, Mapping):
                        _attach(inst_id, payload)
            elif isinstance(section, list):
                for payload in section:
                    if isinstance(payload, Mapping):
                        inst_id = (
                            payload.get("instance_id")
                            or payload.get("task")
                            or payload.get("id")
                            or payload.get("task_id")
                        )
                        _attach(inst_id, payload)
        if not instances and "instance_id" in report_data:
            _attach(report_data.get("instance_id"), report_data)
    elif isinstance(report_data, list):
        for payload in report_data:
            if isinstance(payload, Mapping):
                inst_id = (
                    payload.get("instance_id")
                    or payload.get("task")
                    or payload.get("id")
                    or payload.get("task_id")
                )
                _attach(inst_id, payload)
    return instances


def _resolve_from_report(payload: Mapping[str, Any]) -> Dict[str, Any]:
    resolved = bool(payload.get("resolved", False))
    patch_applied = payload.get("patch_successfully_applied")
    if patch_applied is False:
        return {"resolved": False, "resolved_status": "PATCH_APPLY_FAILED"}
    return {"resolved": resolved, "resolved_status": "RESOLVED" if resolved else "UNRESOLVED"}


def _parse_run_instance_log(log_path: Path) -> Optional[Dict[str, Any]]:
    try:
        text = log_path.read_text(encoding="utf-8")
    except OSError:
        return None

    failure_markers = (
        "Patch Apply Failed",
        "Only garbage was found in the patch input",
        "patch unexpectedly ends in middle of line",
    )
    if any(marker in text for marker in failure_markers):
        return {"resolved": False, "resolved_status": "PATCH_APPLY_FAILED"}

    m = re.search(r"resolved:\s*(True|False)", text)
    if m:
        resolved_flag = m.group(1) == "True"
        return {
            "resolved": resolved_flag,
            "resolved_status": "RESOLVED" if resolved_flag else "UNRESOLVED",
        }

    return None


def _find_run_instance_log(outdir: Path, run_id: str, instance_id: str) -> Optional[Path]:
    base = outdir / "logs" / "run_evaluation"
    if (base / run_id).exists():
        base = base / run_id
    pattern = f"**/{instance_id}/run_instance.log"
    matches = list(base.glob(pattern)) if base.exists() else []
    if matches:
        return sorted(matches, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    return None


def _build_instance_results(
    predictions: Iterable[Mapping[str, Any]],
    report_path: Optional[Path],
    outdir: Path,
    run_id: str,
) -> Path:
    report_instances: Dict[str, Dict[str, Any]] = {}
    if report_path and report_path.exists():
        try:
            with report_path.open("r", encoding="utf-8") as fh:
                report_data = json.load(fh)
            report_instances = _extract_report_instances(report_data)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[tg_swebench_cli] WARN: Failed to parse report {report_path}: {exc}")

    out_path = outdir / "instance_results.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for pred in predictions:
            instance_id = str(pred.get("instance_id"))
            payload: Optional[Mapping[str, Any]] = report_instances.get(instance_id)
            result: Optional[Dict[str, Any]] = None

            if payload:
                result = _resolve_from_report(payload)
            if result is None:
                log_path = _find_run_instance_log(outdir, run_id, instance_id)
                if log_path:
                    result = _parse_run_instance_log(log_path)

            if result is None:
                result = {"resolved": False, "resolved_status": "UNRESOLVED"}

            fh.write(
                json.dumps(
                    {
                        "instance_id": instance_id,
                        "resolved": bool(result.get("resolved", False)),
                        "resolved_status": result.get("resolved_status", "UNRESOLVED"),
                    }
                )
                + "\n"
            )
            written += 1

    print(f"[tg_swebench_cli] Wrote {written} rows to {out_path}")
    return out_path


def main() -> None:
    if sys.platform.startswith("win"):
        raise SystemExit(
            "SWE-bench harness execution is not supported on native Windows (missing Unix-only `resource`). "
            "Run this CLI from WSL/Linux."
        )
    parser = argparse.ArgumentParser(description="Run SWE-bench evaluation for τGuardian")
    parser.add_argument("--predictions-path", required=True, help="Path to predictions JSON/JSONL")
    parser.add_argument("--run-id", required=True, help="Run identifier passed to SWE-bench")
    parser.add_argument("--outdir", required=True, help="Directory for harness outputs")
    parser.add_argument(
        "--dataset-name",
        default="SWE-bench/SWE-bench_Lite",
        help="SWE-bench dataset name (default: SWE-bench/SWE-bench_Lite)",
    )
    parser.add_argument("--split", default="test", help="Dataset split (default: test)")
    args = parser.parse_args()

    predictions_path = Path(args.predictions_path).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()

    predictions = load_predictions(predictions_path)
    normalized_preds_path = outdir / "normalized_predictions.json"
    _write_normalized_predictions(predictions, normalized_preds_path)

    _run_swebench_harness(
        predictions_path=normalized_preds_path,
        run_id=args.run_id,
        outdir=outdir,
        dataset_name=args.dataset_name,
        split=args.split,
    )

    try:
        report = _find_report(outdir, args.run_id)
    except FileNotFoundError as exc:
        print(f"[tg_swebench_cli] WARN: {exc}")
        report = None

    _build_instance_results(predictions, report, outdir, args.run_id)


if __name__ == "__main__":
    main()
