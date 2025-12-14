import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from analyze_mini_swe_results import build_eval_records, extract_security_violations_from_patch


def _write_security_report(reports_dir: Path, instance_id: str, **overrides: object) -> None:
    report = {
        "instance_id": instance_id,
        "repo": "demo/repo",
        "base_commit": "abcdef",
        "scan_scope": "postapply_fullfile_delta_v1",
        "scan_failed": False,
        "scan_error": None,
        "skipped": False,
        "skip_reason": None,
        "changed_files": ["file.py"],
        "files": [],
        "new_violations": [],
    }
    report.update(overrides)
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"{instance_id}.json").write_text(
        json.dumps(report), encoding="utf-8"
    )


def _write_exit_status(msa_dir: Path, instance_ids: list[str], status: str) -> None:
    content = {"instances_by_exit_status": {status: instance_ids}}
    (msa_dir / "exit_statuses_0.yaml").write_text(json.dumps(content), encoding="utf-8")


def test_instance_results_join_and_decisions(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    preds = [
        {"instance_id": "demo__proj-1", "model_patch": "diff --git a/file.py b/file.py"},
        {"instance_id": "demo__proj-2", "model_patch": "diff --git a/other.py b/other.py"},
        {"instance_id": "demo__proj-3", "model_patch": "diff --git a/third.py b/third.py"},
    ]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, [rec["instance_id"] for rec in preds], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "instance_id": "demo__proj-1",
                        "resolved": True,
                        "resolved_status": "RESOLVED",
                    }
                ),
                json.dumps(
                    {
                        "instance_id": "demo__proj-2",
                        "resolved": False,
                        "resolved_status": "UNRESOLVED",
                    }
                ),
                json.dumps(
                    {
                        "instance_id": "demo__proj-3",
                        "resolved": False,
                        "resolved_status": "PATCH_APPLY_FAILED",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
    )

    assert total == 3
    assert success == 1

    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    row1, row2, row3 = rows
    assert row1["resolved"] is True
    assert row1["final_decision"] == "OK"
    assert row2["final_decision"] == "ABSTAIN"
    assert row3["resolved_status"] == "PATCH_APPLY_FAILED"


def test_resolved_instance_with_scan_failed_abstains(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +from __future__ import annotations
    +def broken(
    +    foo
    """
    preds = [{"instance_id": "demo__proj-scanfail", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-scanfail"], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({
            "instance_id": "demo__proj-scanfail",
            "resolved": True,
            "resolved_status": "RESOLVED",
        })
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
    )

    assert total == 1
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["resolved"] is True
    assert row["sad_flag"] is False
    assert row["security_scan_failed"] is True
    assert row["final_decision"] == "ABSTAIN"


def test_infra_timeout_before_patch_bucket(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    timed out after 3600 seconds while waiting for docker
    """
    preds = [{"instance_id": "demo__proj-timeout", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-timeout"], "Submitted")

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=None,
    )

    assert total == 1
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["resolved_status"] == "INFRA_TIMEOUT_BEFORE_PATCH"
    assert row["final_decision"] == "ABSTAIN"
    assert row["sad_flag"] is False
    assert row["security_scan_failed"] is False
    assert row["infra_timeout_before_patch"] is True


def test_security_report_overrides_fallback_to_ok(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +import random
    """
    preds = [{"instance_id": "demo__proj-ok", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-ok"], "Submitted")

    reports_dir = tmp_path / "reports"
    _write_security_report(reports_dir, "demo__proj-ok", new_violations=[], scan_failed=False)

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({"instance_id": "demo__proj-ok", "resolved": True, "resolved_status": "RESOLVED"})
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
        security_reports_dir=reports_dir,
    )

    assert total == 1
    assert success == 1

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["sad_flag"] is False
    assert row["security_report_found"] is True
    assert row["security_scan_scope"] == "postapply_fullfile_delta_v1"
    assert row["final_decision"] == "OK"


def test_security_report_scan_failure_abstains(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +import random
    """
    preds = [{"instance_id": "demo__proj-scan", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-scan"], "Submitted")

    reports_dir = tmp_path / "reports"
    _write_security_report(reports_dir, "demo__proj-scan", scan_failed=True)

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({"instance_id": "demo__proj-scan", "resolved": True, "resolved_status": "RESOLVED"})
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
        security_reports_dir=reports_dir,
    )

    assert total == 1
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["security_scan_failed"] is True
    assert row["final_decision"] == "ABSTAIN"


def test_security_report_with_new_violation_vetoes(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +import random
    """
    preds = [{"instance_id": "demo__proj-violation", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-violation"], "Submitted")

    reports_dir = tmp_path / "reports"
    _write_security_report(
        reports_dir,
        "demo__proj-violation",
        new_violations=["NO_TRANSACTION_FOR_MULTI_WRITE"],
    )

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps(
            {
                "instance_id": "demo__proj-violation",
                "resolved": True,
                "resolved_status": "RESOLVED",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
        security_reports_dir=reports_dir,
    )

    assert total == 1
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["sad_flag"] is True
    assert row["security_violations"] == ["NO_TRANSACTION_FOR_MULTI_WRITE"]
    assert row["final_decision"] == "VETO"


def test_fallback_scan_used_when_report_missing(tmp_path: Path) -> None:
    msa_dir = tmp_path / "msa"
    msa_dir.mkdir()

    patch = """
    diff --git a/file.py b/file.py
    --- a/file.py
    +++ b/file.py
    @@
    +import random
    """
    preds = [{"instance_id": "demo__proj-missing", "model_patch": patch}]
    (msa_dir / "preds.json").write_text(json.dumps(preds), encoding="utf-8")
    _write_exit_status(msa_dir, ["demo__proj-missing"], "Submitted")

    instance_results = tmp_path / "instance_results.jsonl"
    instance_results.write_text(
        json.dumps({"instance_id": "demo__proj-missing", "resolved": True, "resolved_status": "RESOLVED"})
        + "\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "eval.jsonl"
    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id="demo-model",
        output_path=output_path,
        instance_results_path=instance_results,
        security_reports_dir=tmp_path / "reports",  # directory with no report
    )

    assert total == 1
    assert success == 0

    row = json.loads(output_path.read_text(encoding="utf-8").splitlines()[0])
    assert row["security_report_found"] is False
    assert row["security_scan_scope"] == "diff_fragment_fallback_v2"
    assert row["sad_flag"] is True
    assert row["final_decision"] == "VETO"


def test_extract_security_violations_handles_empty_patch() -> None:
    violations, failed = extract_security_violations_from_patch("")
    assert violations == []
    assert failed is False
