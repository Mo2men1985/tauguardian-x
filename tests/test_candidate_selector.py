import json
from pathlib import Path

from tg_candidate_select import evaluate_candidate, select_best


def _write_preds(path: Path, records: list[dict]) -> None:
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _write_instance_results(path: Path, rows: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _write_report(dir_path: Path, instance_id: str, **overrides: object) -> None:
    report = {
        "instance_id": instance_id,
        "scan_scope": "postapply_fullfile_delta_v1",
        "scan_failed": False,
        "new_violations": [],
    }
    report.update(overrides)
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / f"{instance_id}.json").write_text(json.dumps(report), encoding="utf-8")


def test_selector_prefers_ok_over_veto(tmp_path: Path) -> None:
    cand_a = tmp_path / "cand_a"
    cand_b = tmp_path / "cand_b"
    cand_a.mkdir(); cand_b.mkdir()

    _write_preds(cand_a / "preds.json", [{"instance_id": "x", "model_patch": "diff --git a/f b/f"}])
    _write_preds(cand_b / "preds.json", [{"instance_id": "x", "model_patch": "diff --git a/f b/f"}])
    _write_instance_results(cand_a / "instance_results.jsonl", [{"instance_id": "x", "resolved": True, "resolved_status": "RESOLVED", "cri": 0.9}])
    _write_instance_results(cand_b / "instance_results.jsonl", [{"instance_id": "x", "resolved": True, "resolved_status": "RESOLVED", "cri": 0.9}])

    reports_a = tmp_path / "reports_a"
    reports_b = tmp_path / "reports_b"
    _write_report(reports_a, "x", new_violations=[])
    _write_report(reports_b, "x", new_violations=["NO_TRANSACTION_FOR_MULTI_WRITE"])

    eval_a = evaluate_candidate("x", cand_a, reports_a)
    eval_b = evaluate_candidate("x", cand_b, reports_b)

    chosen = select_best([eval_b, eval_a])
    assert chosen["candidate_dir"] == str(cand_a)
    assert chosen["final_decision"] == "OK"


def test_selector_prefers_ok_over_abstain(tmp_path: Path) -> None:
    cand_a = tmp_path / "cand_a"
    cand_b = tmp_path / "cand_b"
    cand_a.mkdir(); cand_b.mkdir()

    _write_preds(cand_a / "preds.json", [{"instance_id": "x", "model_patch": "diff --git a/f b/f"}])
    _write_preds(cand_b / "preds.json", [{"instance_id": "x", "model_patch": "diff --git a/f b/f"}])
    _write_instance_results(cand_a / "instance_results.jsonl", [{"instance_id": "x", "resolved": True, "resolved_status": "RESOLVED"}])
    _write_instance_results(cand_b / "instance_results.jsonl", [{"instance_id": "x", "resolved": True, "resolved_status": "RESOLVED"}])

    reports_a = tmp_path / "reports_a"
    reports_b = tmp_path / "reports_b"
    _write_report(reports_a, "x", new_violations=[])
    _write_report(reports_b, "x", scan_failed=True)

    eval_a = evaluate_candidate("x", cand_a, reports_a)
    eval_b = evaluate_candidate("x", cand_b, reports_b)

    chosen = select_best([eval_b, eval_a])
    assert chosen["candidate_dir"] == str(cand_a)
    assert chosen["final_decision"] == "OK"


def test_selector_uses_cri_and_patch_size(tmp_path: Path) -> None:
    cand_a = tmp_path / "cand_a"
    cand_b = tmp_path / "cand_b"
    cand_a.mkdir(); cand_b.mkdir()

    patch_small = "diff --git a/f b/f\n+pass"
    patch_large = "diff --git a/f b/f\n+" + "a" * 50

    _write_preds(cand_a / "preds.json", [{"instance_id": "x", "model_patch": patch_small}])
    _write_preds(cand_b / "preds.json", [{"instance_id": "x", "model_patch": patch_large}])

    _write_instance_results(cand_a / "instance_results.jsonl", [{"instance_id": "x", "resolved": False, "cri": 0.8}])
    _write_instance_results(cand_b / "instance_results.jsonl", [{"instance_id": "x", "resolved": False, "cri": 0.6}])

    eval_a = evaluate_candidate("x", cand_a, None)
    eval_b = evaluate_candidate("x", cand_b, None)

    chosen = select_best([eval_b, eval_a])
    assert chosen["candidate_dir"] == str(cand_a)
    assert chosen["cri"] == 0.8
