"""Select the best candidate predictions under τGuardian governance rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from analyze_mini_swe_results import extract_security_violations_from_patch


def _load_preds(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    preds: Dict[str, Dict[str, Any]] = {}
    if isinstance(data, list):
        for rec in data:
            if not isinstance(rec, dict):
                continue
            inst = str(rec.get("instance_id"))
            preds[inst] = rec
    elif isinstance(data, dict):
        for inst, rec in data.items():
            if not isinstance(rec, dict):
                rec = {"model_patch": rec}
            rec.setdefault("instance_id", inst)
            preds[str(inst)] = rec
    return preds


def _load_instance_results(path: Path) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return results
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        inst = obj.get("instance_id")
        if inst:
            results[str(inst)] = obj
    return results


def _load_security_report(reports_dir: Optional[Path], instance_id: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    if reports_dir is None:
        return None, False
    path = reports_dir / f"{instance_id}.json"
    if not path.exists():
        return None, False
    try:
        return json.loads(path.read_text(encoding="utf-8")), True
    except Exception:
        return {"scan_failed": True, "new_violations": [], "scan_scope": "postapply_fullfile_delta_v1"}, True


def _count_changed_files(patch: str) -> int:
    return sum(1 for ln in patch.splitlines() if ln.startswith("diff --git "))


def evaluate_candidate(
    instance_id: str,
    cand_dir: Path,
    security_reports_dir: Optional[Path],
) -> Dict[str, Any]:
    preds = _load_preds(cand_dir / "preds.json")
    instance_results = _load_instance_results(cand_dir / "instance_results.jsonl")
    rec = preds.get(instance_id, {"model_patch": ""})
    patch = rec.get("model_patch", "")

    report, report_found = _load_security_report(security_reports_dir, instance_id)
    if report_found and report is not None:
        security_scan_scope = str(report.get("scan_scope", "postapply_fullfile_delta_v1"))
        security_scan_failed = bool(report.get("scan_failed", False))
        security_violations = report.get("new_violations") or []
    else:
        security_scan_scope = "diff_fragment_fallback_v2"
        security_violations, security_scan_failed = extract_security_violations_from_patch(patch)

    sad_flag = bool(security_violations)

    resolved = False
    resolved_status = None
    cri = 0.0
    if instance_id in instance_results:
        res = instance_results[instance_id]
        resolved = bool(res.get("resolved"))
        resolved_status = res.get("resolved_status")
        if "cri" in res:
            try:
                cri = float(res.get("cri", 0.0))
            except Exception:
                cri = 0.0

    if sad_flag:
        final_decision = "VETO"
    elif security_scan_failed:
        final_decision = "ABSTAIN"
    elif resolved:
        final_decision = "OK"
    else:
        final_decision = "ABSTAIN"

    return {
        "candidate_dir": str(cand_dir),
        "instance_id": instance_id,
        "patch": patch,
        "resolved": resolved,
        "resolved_status": resolved_status,
        "cri": cri,
        "security_violations": security_violations,
        "security_scan_failed": security_scan_failed,
        "security_scan_scope": security_scan_scope,
        "sad_flag": sad_flag,
        "final_decision": final_decision,
        "changed_files": _count_changed_files(patch),
        "patch_size": len(patch or ""),
        "security_report_found": report_found,
    }


def _priority(info: Dict[str, Any]) -> Tuple[int, float, int, int]:
    if info["final_decision"] == "VETO":
        tier = 3
    elif info["resolved"] and info["final_decision"] == "OK":
        tier = 0
    elif info["resolved"]:
        tier = 1
    else:
        tier = 2

    return (
        tier,
        -float(info.get("cri", 0.0)),
        info.get("changed_files", 0),
        info.get("patch_size", 0),
    )


def select_best(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    return sorted(candidates, key=_priority)[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Select best candidate outputs")
    parser.add_argument("--cand-dirs", required=True, help="Comma-separated candidate directories")
    parser.add_argument("--outdir", required=True, help="Merged output directory")
    parser.add_argument(
        "--security-reports-dirs",
        default=None,
        help="Comma-separated security report dirs matching candidates",
    )

    args = parser.parse_args()
    cand_dirs = [Path(p.strip()) for p in args.cand_dirs.split(",") if p.strip()]
    if not cand_dirs:
        raise SystemExit("[ERROR] No candidate directories provided")

    report_dirs: List[Optional[Path]] = []
    if args.security_reports_dirs:
        report_dirs = [Path(p.strip()) for p in args.security_reports_dirs.split(",") if p.strip()]
    while len(report_dirs) < len(cand_dirs):
        report_dirs.append(None)

    # Collect all instance_ids
    all_instances: set[str] = set()
    for cand in cand_dirs:
        preds = _load_preds(cand / "preds.json")
        all_instances.update(preds.keys())

    merged: List[Dict[str, Any]] = []
    selection_rows: List[str] = []

    for instance_id in sorted(all_instances):
        evaluated: List[Dict[str, Any]] = []
        for cand, report_dir in zip(cand_dirs, report_dirs):
            if not (cand / "preds.json").exists():
                continue
            evaluated.append(evaluate_candidate(instance_id, cand, report_dir))

        if not evaluated:
            continue

        chosen = select_best(evaluated)
        merged.append({"instance_id": instance_id, "model_patch": chosen.get("patch", "")})
        selection_rows.append(json.dumps(chosen))
        print(f"[SELECT] {instance_id} -> {chosen['candidate_dir']}")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "preds.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
    (outdir / "selection_report.jsonl").write_text("\n".join(selection_rows) + "\n", encoding="utf-8")
    print(f"[INFO] Wrote merged preds to {outdir / 'preds.json'}")


if __name__ == "__main__":
    main()
