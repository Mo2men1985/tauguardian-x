"""Post-apply full-file delta security scan for mini-SWE-agent outputs.

This script is the authoritative SAD mechanism for SWE-bench runs. It reads
``preds.json`` from a mini-swe-agent run, checks out a clean worktree at the
SWE-bench base commit, applies the model patch, and performs AST-based security
scans on the full contents of changed Python files. The resulting per-instance
reports are written to ``security_reports/<instance_id>.json`` for ingestion by
``analyze_mini_swe_results.py``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ast_security import run_ast_security_checks
from analyze_mini_swe_results import load_statuses
from tg_swebench_cli import normalize_patch_text


ACTIVE_RULES = ["SQLI", "SECRETS", "MISSING_AUTH", "NO_TRANSACTION", "XSS", "WEAK_RNG"]


def _run_cmd(cmd: List[str], cwd: Optional[Path] = None, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
    )


def _is_valid_git_repo(repo_dir: Path) -> Tuple[bool, str]:
    try:
        res = _run_cmd(["git", "-C", str(repo_dir), "rev-parse", "--git-dir"], cwd=repo_dir)
    except FileNotFoundError as exc:  # pragma: no cover - depends on environment
        return False, f"git executable not found: {exc}"

    if res.returncode != 0:
        err = (res.stderr or res.stdout or "").strip()
        return False, err or "git rev-parse failed"
    return True, ""


def _load_dataset_index(dataset_name: str, split: str) -> Dict[str, Dict[str, Any]]:
    from datasets import load_dataset

    ds = load_dataset(dataset_name, split=split)
    index: Dict[str, Dict[str, Any]] = {}
    for row in ds:
        instance_id = row.get("instance_id")
        if not instance_id:
            continue
        index[str(instance_id)] = {
            "repo": row.get("repo"),
            "base_commit": row.get("base_commit"),
        }
    return index


def _ensure_repo(repo_cache: Path, repo: str, force_reclone: bool = False) -> Path:
    repo_dir = repo_cache / repo.replace("/", "__")

    if repo_dir.exists():
        valid, err = _is_valid_git_repo(repo_dir)
        if valid and not force_reclone:
            _run_cmd(["git", "-C", str(repo_dir), "config", "core.longpaths", "true"], cwd=repo_dir)
            return repo_dir

        if not force_reclone:
            print(f"[WARN] Repo cache at {repo_dir} is not a valid git repo; recloning ({err})")

        shutil.rmtree(repo_dir, ignore_errors=True)

    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://github.com/{repo}.git"
    print(f"[INFO] Cloning {clone_url} -> {repo_dir}")
    result = _run_cmd(["git", "clone", clone_url, str(repo_dir)])
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip() or result.stdout.strip()}")
    _run_cmd(["git", "-C", str(repo_dir), "config", "core.longpaths", "true"], cwd=repo_dir)

    valid, err = _is_valid_git_repo(repo_dir)
    if not valid:
        raise RuntimeError(f"cloned repo invalid: {err}")

    return repo_dir


def _prepare_worktree(repo_dir: Path, worktree_dir: Path, base_commit: str) -> None:
    valid, err = _is_valid_git_repo(repo_dir)
    if not valid:
        raise RuntimeError(f"invalid repo: {err}")

    commit_check = _run_cmd(
        ["git", "-C", str(repo_dir), "cat-file", "-e", f"{base_commit}^{{commit}}"],
        cwd=repo_dir,
    )
    if commit_check.returncode != 0:
        raise RuntimeError(
            f"base_commit not found: {commit_check.stderr.strip() or commit_check.stdout.strip()}"
        )

    if worktree_dir.exists():
        shutil.rmtree(worktree_dir)

    prune_result = _run_cmd(["git", "-C", str(repo_dir), "worktree", "prune"], cwd=repo_dir)
    if prune_result.returncode != 0:
        raise RuntimeError(
            f"git worktree prune failed: {prune_result.stderr.strip() or prune_result.stdout.strip()}"
        )
    result = _run_cmd(
        ["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(worktree_dir), base_commit],
        cwd=repo_dir,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git worktree add failed for {base_commit}: {result.stderr.strip() or result.stdout.strip()}"
        )


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _scan_content(code: str) -> Tuple[List[str], Optional[str]]:
    try:
        findings = run_ast_security_checks(code, active_rules=ACTIVE_RULES)
        violations: List[str] = []
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, str):
                    violations.append(f)
                elif isinstance(f, dict):
                    violations.append(str(f.get("code") or f.get("id") or f))
                else:
                    violations.append(str(f))
        elif findings:
            violations = [str(findings)]
        return violations, None
    except Exception as exc:  # pragma: no cover - exercised via integration
        return [], str(exc)


def _scan_file(worktree_dir: Path, rel_path: str) -> Tuple[List[str], List[str], List[str], Optional[str]]:
    before_cmd = _run_cmd(["git", "show", f"HEAD:{rel_path}"], cwd=worktree_dir)
    before_content = before_cmd.stdout if before_cmd.returncode == 0 else ""

    after_path = worktree_dir / rel_path
    after_content = _read_file(after_path)

    before_violations, before_err = _scan_content(before_content)
    if before_err:
        return before_violations, [], [], f"before-scan failed for {rel_path}: {before_err}"

    after_violations, after_err = _scan_content(after_content)
    if after_err:
        return before_violations, after_violations, [], f"after-scan failed for {rel_path}: {after_err}"

    new_violations = sorted(set(after_violations) - set(before_violations))
    return before_violations, after_violations, new_violations, None


def _load_predictions(preds_path: Path) -> List[Dict[str, Any]]:
    from analyze_mini_swe_results import load_predictions as _load_preds

    return _load_preds(preds_path)


def _should_skip(status: str, patch: str) -> Tuple[bool, Optional[str]]:
    normalized_patch = patch.strip()
    if not normalized_patch:
        return True, "EMPTY_PATCH"
    lower_patch = normalized_patch.lower()
    if "timed out after" in lower_patch and "seconds" in lower_patch:
        return True, "INFRA_TIMEOUT_BEFORE_PATCH"
    if status and status.upper() == "INFRA_TIMEOUT_BEFORE_PATCH":
        return True, "INFRA_TIMEOUT_BEFORE_PATCH"
    return False, None


def _write_report(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _scan_instance(
    instance: Dict[str, Any],
    status: str,
    dataset_meta: Dict[str, str],
    repo_cache: Path,
    worktree_root: Path,
    force_reclone: bool,
) -> Dict[str, Any]:
    instance_id = str(instance.get("instance_id"))
    patch = normalize_patch_text(instance.get("model_patch", ""))
    repo = dataset_meta.get("repo")
    base_commit = dataset_meta.get("base_commit")

    report: Dict[str, Any] = {
        "instance_id": instance_id,
        "repo": repo,
        "base_commit": base_commit,
        "scan_scope": "postapply_fullfile_delta_v1",
        "scan_failed": False,
        "scan_error": None,
        "skipped": False,
        "skip_reason": None,
        "changed_files": [],
        "files": [],
        "new_violations": [],
    }

    skip, reason = _should_skip(status, patch)
    if skip:
        report["skipped"] = True
        report["skip_reason"] = reason
        return report

    if not repo or not base_commit:
        report["scan_failed"] = True
        report["scan_error"] = "missing repo/base_commit in dataset"
        return report

    worktree_dir = worktree_root / instance_id.replace("/", "__")

    try:
        repo_dir = _ensure_repo(repo_cache, repo, force_reclone=force_reclone)
        _prepare_worktree(repo_dir, worktree_dir, str(base_commit))
    except Exception as exc:
        report["scan_failed"] = True
        report["scan_error"] = str(exc)
        return report

    try:
        apply_result = _run_cmd(["git", "apply", "--whitespace=nowarn", "-"], cwd=worktree_dir, input_text=patch)
        if apply_result.returncode != 0:
            raise RuntimeError(apply_result.stderr.strip() or apply_result.stdout.strip())

        diff_result = _run_cmd(["git", "diff", "--name-only"], cwd=worktree_dir)
        if diff_result.returncode != 0:
            raise RuntimeError(diff_result.stderr.strip() or diff_result.stdout.strip())
        changed_files = [ln.strip() for ln in diff_result.stdout.splitlines() if ln.strip()]
        report["changed_files"] = changed_files

        overall_new: List[str] = []
        for rel_path in changed_files:
            if not rel_path.endswith(".py"):
                continue
            before_v, after_v, new_v, err = _scan_file(worktree_dir, rel_path)
            file_entry = {
                "path": rel_path,
                "before_violations": before_v,
                "after_violations": after_v,
                "new_violations": new_v,
            }
            if err:
                report["scan_failed"] = True
                report["scan_error"] = err
            report["files"].append(file_entry)
            overall_new.extend(new_v)

        report["new_violations"] = sorted(set(overall_new))
    except Exception as exc:
        report["scan_failed"] = True
        report["scan_error"] = str(exc)
    finally:
        if worktree_dir.exists():
            shutil.rmtree(worktree_dir, ignore_errors=True)

    return report


def _iter_selected(preds: List[Dict[str, Any]], only: Optional[Iterable[str]]) -> List[Dict[str, Any]]:
    if not only:
        return preds
    allowed = {inst.strip() for inst in only if inst.strip()}
    return [rec for rec in preds if str(rec.get("instance_id")) in allowed]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run post-apply security scan for mini-SWE-agent outputs")
    parser.add_argument("--preds", required=True, help="Path to preds.json from mini-swe-agent")
    parser.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite", help="SWE-bench dataset name")
    parser.add_argument("--split", default="test", help="Dataset split")
    parser.add_argument("--outdir", required=True, help="Output directory for security reports")
    parser.add_argument("--only", default=None, help="Comma-separated instance ids to scan")
    parser.add_argument(
        "--repo-cache-dir",
        default=".tg_repo_cache",
        help="Directory to cache cloned repositories",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing reports")
    parser.add_argument(
        "--force-reclone",
        action="store_true",
        help="Delete and re-clone cached repos before scanning",
    )

    args = parser.parse_args()

    preds_path = Path(args.preds).expanduser()
    preds = _load_predictions(preds_path)
    if not preds:
        raise SystemExit(f"[INFO] No predictions found in {preds_path}")

    only_list = args.only.split(",") if args.only else None
    preds = _iter_selected(preds, only_list)
    statuses = load_statuses(str(preds_path.parent))
    dataset_index = _load_dataset_index(args.dataset, args.split)

    outdir = Path(args.outdir)
    reports_dir = outdir
    reports_dir.mkdir(parents=True, exist_ok=True)

    repo_cache = Path(args.repo_cache_dir)
    worktree_root = repo_cache / "worktrees"
    worktree_root.mkdir(parents=True, exist_ok=True)

    for rec in preds:
        instance_id = str(rec.get("instance_id"))
        report_path = reports_dir / f"{instance_id}.json"
        if report_path.exists() and not args.force:
            print(f"[SKIP] {instance_id}: report exists ({report_path}); use --force to overwrite")
            continue

        dataset_meta = dataset_index.get(instance_id)
        if dataset_meta is None:
            print(f"[WARN] {instance_id}: not found in dataset; marking scan_failed")
            dummy_meta = {"repo": None, "base_commit": None}
            report = _scan_instance(
                rec,
                statuses.get(instance_id, ""),
                dummy_meta,
                repo_cache,
                worktree_root,
                args.force_reclone,
            )
            report["scan_failed"] = True
            report["scan_error"] = "instance not found in dataset"
            _write_report(report_path, report)
            continue

        report = _scan_instance(
            rec,
            statuses.get(instance_id, ""),
            dataset_meta,
            repo_cache,
            worktree_root,
            args.force_reclone,
        )
        _write_report(report_path, report)

        status_str = "SKIPPED" if report.get("skipped") else ("FAILED" if report.get("scan_failed") else "OK")
        msg = f"[{status_str}] {instance_id}: new_violations={len(report.get('new_violations', []))}"
        if report.get("scan_failed") and report.get("scan_error"):
            msg += f" scan_error={report.get('scan_error')}"
        print(msg)


if __name__ == "__main__":
    main()
