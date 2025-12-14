#!/usr/bin/env python3
"""tg_post_apply_security_scan.py

Post-apply security scan for SWE-bench predictions.

Why:
- Diff-snippet AST scanning is inherently fragile (incomplete fragments).
- This script scans *real, parseable Python files* after applying the patch
  to the task's repo at the SWE-bench base_commit, then reports *new* violations
  introduced by the patch (delta between before vs after).

Run in WSL/Linux (requires git + network + `datasets`).
"""
from __future__ import annotations

def normalize_patch_text(patch: str) -> str:
    """Best-effort normalization for patches/diffs.

    - Normalize newlines.
    - Unwrap ```diff ... ``` fences if present.
    - Strip leading chatter before the first diff header.
    - Ensure trailing newline.
    """
    if patch is None:
        return ""
    txt = str(patch)
    txt = txt.replace("\r\n", "\n").replace("\r", "\n").lstrip("\ufeff")

    # Unwrap markdown fences
    m = re.search(r"```(?:diff)?\n(.*?)```", txt, flags=re.DOTALL | re.IGNORECASE)
    if m:
        txt = m.group(1)

    lines = txt.splitlines()
    start = 0
    for i, l in enumerate(lines):
        if l.startswith(("diff --git", "--- ", "+++ ", "@@ ")):
            start = i
            break
    txt = "\n".join(lines[start:]).strip("\n")
    if txt and not txt.endswith("\n"):
        txt += "\n"
    return txt

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ast_security import run_ast_security_checks

try:
    from datasets import load_dataset  # type: ignore
except Exception as exc:  # pragma: no cover
    load_dataset = None
    _DATASETS_IMPORT_ERROR = exc
else:
    _DATASETS_IMPORT_ERROR = None


_INFRA_DOCKER_TIMEOUT_RE = re.compile(r"timed out after\s+\d+\s+seconds", re.IGNORECASE)


def _run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=check)


def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _load_predictions(preds_path: Path) -> Dict[str, str]:
    """Load mini-SWE-agent preds.json mapping instance_id -> model_patch."""
    obj = json.loads(preds_path.read_text(encoding="utf-8-sig"))
    if isinstance(obj, dict):
        out: Dict[str, str] = {}
        for k, v in obj.items():
            if isinstance(v, dict):
                out[str(k)] = str(v.get("model_patch", ""))
            else:
                out[str(k)] = str(v)
        return out
    raise SystemExit(f"Unsupported preds.json format at {preds_path} (expected object mapping)")


def _is_infra_timeout_patch(patch: str) -> bool:
    if not patch:
        return False
    lower = patch.lower()
    return ("docker" in lower) and bool(_INFRA_DOCKER_TIMEOUT_RE.search(patch))


def _changed_files_from_patch(patch: str) -> List[str]:
    files: List[str] = []
    for ln in patch.splitlines():
        if ln.startswith("+++ "):
            # +++ b/path/to/file.py
            parts = ln.split()
            if len(parts) >= 2:
                path = parts[1]
                if path.startswith("b/"):
                    path = path[2:]
                if path != "/dev/null":
                    files.append(path)
    # de-dupe preserving order
    seen = set()
    out: List[str] = []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _ensure_repo_cache(repo_cache_dir: Path, repo_slug: str) -> Path:
    """Ensure we have a cached git clone for repo_slug (e.g., 'django/django')."""
    url = f"https://github.com/{repo_slug}.git"
    # Store as repo_cache_dir/django__django
    local_name = repo_slug.replace("/", "__")
    dst = repo_cache_dir / local_name
    if dst.exists() and (dst / ".git").exists():
        return dst
    _safe_mkdir(repo_cache_dir)
    print(f"[post_apply_scan] cloning {url} -> {dst}")
    _run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(dst)], check=True)
    return dst


def _fetch_commit(repo_dir: Path, commit: str) -> None:
    # Try fetching the commit by SHA (cheap).
    try:
        _run(["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", commit], check=True)
    except Exception:
        # Fallback: fetch more history.
        _run(["git", "-C", str(repo_dir), "fetch", "--all"], check=True)


def _worktree_for_commit(repo_dir: Path, commit: str, worktrees_root: Path) -> Path:
    _safe_mkdir(worktrees_root)
    wt = worktrees_root / f"wt_{commit[:12]}"
    if wt.exists():
        shutil.rmtree(wt, ignore_errors=True)
    _fetch_commit(repo_dir, commit)
    _run(["git", "-C", str(repo_dir), "worktree", "add", "--detach", str(wt), commit], check=True)
    return wt


def _remove_worktree(repo_dir: Path, wt: Path) -> None:
    try:
        _run(["git", "-C", str(repo_dir), "worktree", "remove", "--force", str(wt)], check=False)
    finally:
        shutil.rmtree(wt, ignore_errors=True)


def _apply_patch(workdir: Path, patch_text: str) -> Tuple[bool, str]:
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".diff") as f:
        f.write(patch_text.replace("\r\n", "\n"))
        patch_file = f.name
    try:
        # default
        p = subprocess.run(["git", "apply", "--check", patch_file], cwd=str(workdir), text=True, capture_output=True)
        if p.returncode == 0:
            subprocess.run(["git", "apply", patch_file], cwd=str(workdir), check=True)
            return True, "applied_default"
        # 3way
        p = subprocess.run(["git", "apply", "--3way", patch_file], cwd=str(workdir), text=True, capture_output=True)
        if p.returncode == 0:
            return True, "applied_3way"
        return False, (p.stderr or p.stdout or "git apply failed").strip()[:4000]
    finally:
        try:
            os.unlink(patch_file)
        except OSError:
            pass


def _scan_file_delta(before: str, after: str, active_rules: List[str]) -> Tuple[List[str], bool]:
    before_v = run_ast_security_checks(before, active_rules=active_rules)
    after_v = run_ast_security_checks(after, active_rules=active_rules)
    error_markers = {"SYNTAX_ERROR_PREVENTS_SECURITY_SCAN"}
    # If after fails to parse, treat as scan failed.
    if any(v in error_markers for v in after_v):
        return ([], True)
    # Drop syntax markers from before/after for stable set ops.
    b = set(v for v in before_v if v not in error_markers)
    a = set(v for v in after_v if v not in error_markers)
    new = sorted(a - b)
    return (new, False)


def main() -> None:
    ap = argparse.ArgumentParser(description="Post-apply security scan for SWE-bench predictions (WSL/Linux).")

    ap.add_argument("--preds", required=True, help="Path to mini-SWE preds.json (msa_*/preds.json)")
    ap.add_argument("--dataset", default="princeton-nlp/SWE-bench_Lite", help="SWE-bench dataset name")
    ap.add_argument("--split", default="test", help="Dataset split")
    ap.add_argument("--outdir", default="security_reports", help="Output directory for per-instance JSON reports")
    ap.add_argument("--repo-cache", default=".tg_repo_cache", help="Local cache of cloned repos")
    ap.add_argument("--worktrees", default=".tg_worktrees", help="Temporary worktrees root")
    ap.add_argument("--only", default="", help="Comma-separated instance_ids to scan (optional)")

    args = ap.parse_args()

    if load_dataset is None:
        raise SystemExit(
            "`datasets` is required. Install in WSL: pip install datasets\n"
            f"Import error: {_DATASETS_IMPORT_ERROR}"
        )

    preds_path = Path(args.preds)
    outdir = Path(args.outdir)
    repo_cache_dir = Path(args.repo_cache)
    worktrees_root = Path(args.worktrees)
    _safe_mkdir(outdir)

    preds = _load_predictions(preds_path)

    only: Optional[set[str]] = None
    if args.only.strip():
        only = set(x.strip() for x in args.only.split(",") if x.strip())

    print(f"[post_apply_scan] loading dataset {args.dataset} split={args.split}")
    ds = load_dataset(args.dataset, split=args.split)

    # Try common id keys
    id_key = None
    for candidate in ("instance_id", "task_id", "id"):
        if candidate in ds.column_names:
            id_key = candidate
            break
    if id_key is None:
        raise SystemExit(f"Dataset missing instance id field. Columns: {ds.column_names}")

    # Build index
    index: Dict[str, Dict[str, Any]] = {}
    for row in ds:
        iid = str(row.get(id_key))
        index[iid] = dict(row)

    active_rules = ["SQLI", "SECRETS", "MISSING_AUTH", "NO_TRANSACTION", "XSS", "WEAK_RNG"]

    total = 0
    wrote = 0

    for iid, patch in preds.items():
        patch = normalize_patch_text(patch)

        if only is not None and iid not in only:
            continue

        total += 1
        report_path = outdir / f"{iid}.json"
        if report_path.exists():
            continue

        rep: Dict[str, Any] = {
            "instance_id": iid,
            "scan_ok": False,
            "scan_failed": False,
            "violations": [],
            "scope": "post_apply_fullfile_delta",
            "note": None,
        }

        if _is_infra_timeout_patch(patch):
            rep.update(
                {
                    "scan_ok": False,
                    "scan_failed": True,
                    "note": "infra_timeout_before_patch",
                }
            )
            report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            wrote += 1
            continue

        meta = index.get(iid)
        if not meta:
            rep.update({"scan_failed": True, "note": "instance_not_found_in_dataset"})
            report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            wrote += 1
            continue

        repo_slug = meta.get("repo") or meta.get("repository") or meta.get("repo_name")
        base_commit = meta.get("base_commit") or meta.get("base_sha") or meta.get("commit")
        if not repo_slug or not base_commit:
            rep.update({"scan_failed": True, "note": "missing_repo_or_base_commit"})
            report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            wrote += 1
            continue

        rep["repo"] = repo_slug
        rep["base_commit"] = base_commit

        changed_files = _changed_files_from_patch(patch)
        py_files = [f for f in changed_files if f.endswith(".py")]
        rep["changed_files"] = changed_files
        rep["py_files"] = py_files

        if not py_files:
            rep.update({"scan_ok": True, "violations": [], "note": "no_python_files_changed"})
            report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            wrote += 1
            continue

        try:
            repo_dir = _ensure_repo_cache(repo_cache_dir, str(repo_slug))
            wt = _worktree_for_commit(repo_dir, str(base_commit), worktrees_root / repo_slug.replace("/", "__"))
            try:
                # capture before texts for changed files
                before_map: Dict[str, str] = {}
                for f in py_files:
                    fp = wt / f
                    before_map[f] = fp.read_text(encoding="utf-8", errors="ignore") if fp.exists() else ""

                ok, msg = _apply_patch(wt, patch)
                if not ok:
                    rep.update({"scan_failed": True, "note": f"patch_apply_failed: {msg}"})
                    report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
                    wrote += 1
                    continue

                new_violations: List[str] = []
                scan_failed_files: List[str] = []
                for f in py_files:
                    fp = wt / f
                    after_text = fp.read_text(encoding="utf-8", errors="ignore") if fp.exists() else ""
                    before_text = before_map.get(f, "")
                    v, failed = _scan_file_delta(before_text, after_text, active_rules=active_rules)
                    if failed:
                        scan_failed_files.append(f)
                    else:
                        new_violations.extend(v)

                # de-dupe
                new_violations = sorted(set(new_violations))

                if scan_failed_files:
                    rep.update({"scan_failed": True, "scan_ok": False, "files_failed": scan_failed_files})
                else:
                    rep.update({"scan_failed": False, "scan_ok": True})

                rep["violations"] = new_violations
                report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
                wrote += 1
            finally:
                _remove_worktree(repo_dir, wt)
        except Exception as exc:
            rep.update({"scan_failed": True, "note": f"exception: {type(exc).__name__}: {exc}"})
            report_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
            wrote += 1

    print(f"[post_apply_scan] scanned={total} wrote_reports={wrote} outdir={outdir}")


if __name__ == "__main__":
    main()
