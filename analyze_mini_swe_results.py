"""Convert mini-SWE-agent outputs into τGuardian JSONL with optional evaluation.

This script ingests the ``preds.json`` and ``exit_statuses_*.yaml`` artifacts
produced by the mini-SWE-agent runner and emits rows that mirror the fields used
by ``harness.py`` / ``swe_runner.py``.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ast_security import run_ast_security_checks
from tg_swebench_cli import normalize_patch_text
try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore[assignment]

# Optional SWE-bench evaluation
try:  # pragma: no cover - heavy optional dependency
    from swebench.harness.run_evaluation import run_evaluation

    SWEBENCH_AVAILABLE = True
except Exception:  # pragma: no cover
    run_evaluation = None  # type: ignore[assignment]
    SWEBENCH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Prediction loading helpers
# ---------------------------------------------------------------------------


_INFRA_DOCKER_TIMEOUT_RE = re.compile(r"timed out after\s+\d+\s+seconds", re.IGNORECASE)


def classify_infra_failure_from_patch(patch_text: str) -> Optional[str]:
    """Classify infra failures that occur *before* a real diff patch is produced.

    We treat these separately from PATCH_APPLY_FAILED because the harness tried to
    apply an error string rather than a diff.

    Returns a machine-friendly label (e.g., INFRA_TIMEOUT_BEFORE_PATCH) or None.
    """

    if not patch_text:
        return None

    text = str(patch_text)
    lower = text.lower()
    if "docker" in lower and _INFRA_DOCKER_TIMEOUT_RE.search(text):
        return "INFRA_TIMEOUT_BEFORE_PATCH"
    return None


def iterate_added_lines(patch_text: str) -> Iterable[Tuple[Optional[str], str]]:
    """
    Yield (path, line) for each added line in a unified diff.

    - path: the "b/..." file path (without the leading "b/"), or None if unknown
    - line: the added line text, without the leading '+'
    """
    current_path: Optional[str] = None
    in_hunk = False

    for raw in str(patch_text).splitlines():
        line = raw.rstrip("\n")

        # Start of a new diff; reset state
        if line.startswith("diff --git "):
            current_path = None
            in_hunk = False
            continue

        # File header: "+++ b/path/to/file.py"
        if line.startswith("+++ "):
            parts = line.split()
            path = parts[1] if len(parts) >= 2 else ""
            if path.startswith("b/"):
                path = path[2:]
            current_path = path
            continue

        # Hunk header: "@@ -a,b +c,d @@"
        if line.startswith("@@ "):
            in_hunk = True
            continue

        if not in_hunk:
            continue

        # Added line inside a hunk
        if line.startswith("+") and not line.startswith("+++ "):
            yield current_path, line[1:]


def _is_test_path(path: Optional[str]) -> bool:
    """
    Return True if the given path clearly belongs to a test file or tests directory.
    Used only for downgrading obvious test-only secrets.
    """
    if not path:
        return False
    p = path.replace("\\", "/").lower()
    return (
        "/tests/" in p
        or p.startswith("tests/")
        or "/test_" in p
        or p.endswith("_test.py")
        or p.startswith("test_")
    )


def _classify_secret_severity(path: Optional[str], secret_value: str) -> str:
    """
    Classify a hard-coded secret as either 'high' or 'info' severity.

    - Any secret in test files (tests/ directory or test_*.py) → 'info'.
    - Also treat obviously dummy values ('test', 'dummy', 'example', 'sample') as 'info'.
    - Everything else is 'high'.
    """
    if _is_test_path(path):
        return "info"

    v = (secret_value or "").strip().lower()
    dummy_markers = ("test", "dummy", "example", "sample")
    if any(marker in v for marker in dummy_markers):
        return "info"

    return "high"


def _tag_violation(entry: str, severity: str = "high") -> str:
    """
    Ensure every security violation string begins with an explicit severity tag.

    If the entry already starts with '[', we assume it is tagged and leave it alone.
    Otherwise we prefix it with '[high]' or '[info]'.
    """
    if entry is None:
        entry = ""
    entry = str(entry)
    stripped = entry.lstrip()
    if stripped.startswith("["):
        return entry

    sev = (severity or "high").lower()
    if sev not in {"high", "info"}:
        sev = "high"
    return f"[{sev}] {entry}"


def _violation_severity(entry: str) -> str:
    """
    Return normalized severity for a violation:

    - '[info] ...' → 'info'
    - '[high] ...' → 'high'
    - untagged     → 'high' (conservative default)
    """
    if entry is None:
        return "high"
    s = str(entry).lstrip()
    if s.startswith("[info]"):
        return "info"
    if s.startswith("[high]"):
        return "high"
    return "high"


def _is_infra_timeout_before_patch(patch_text: str) -> bool:
    """Detect infra failures (e.g., docker timeout) before patch creation."""

    if not patch_text:
        return False
    pattern = re.compile(r"timed out after\s+\d+\s+seconds", re.IGNORECASE)
    return bool(pattern.search(patch_text))


def _decision_reason(
    final_decision: str,
    sad_flag: bool,
    security_scan_failed: bool,
    resolved: Optional[bool],
    cri: float,
    cri_threshold: float,
) -> str:
    if sad_flag:
        return "sad_veto"
    if security_scan_failed:
        return "security_scan_failed"
    if final_decision == "OK":
        return "ok"
    if resolved is not True:
        return "not_resolved"
    if cri < cri_threshold:
        return "cri_below_threshold"
    return "abstain"


def _find_artifact(msa_dir: Path, relpaths: Iterable[Path]) -> Optional[str]:
    for rel in relpaths:
        candidate = msa_dir / rel
        if candidate.exists():
            try:
                return str(candidate.relative_to(msa_dir))
            except ValueError:
                return str(candidate)
    return None


def discover_artifacts(msa_dir: Path, instance_id: str) -> Dict[str, Optional[str]]:
    """Locate best-effort artifact paths for an instance relative to msa_dir."""

    traj = _find_artifact(
        msa_dir,
        [
            Path("trajs") / f"{instance_id}.traj.json",
            Path("trajectories") / f"{instance_id}.traj.json",
        ],
    )
    log_path = _find_artifact(
        msa_dir,
        [Path("logs") / f"{instance_id}.log", Path("logs") / f"{instance_id}.txt"],
    )
    proofcard = _find_artifact(
        msa_dir,
        [
            Path("proofcards") / f"{instance_id}.json",
            Path("proofcards") / f"{instance_id}.proofcard.json",
        ],
    )

    return {"traj": traj, "log": log_path, "proofcard": proofcard}

def load_security_reports(security_reports_dir: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Load per-instance security scan reports produced by tg_post_apply_security_scan.py.

    Expected report format (minimal):
      {
        "instance_id": "...",
        "scan_failed": false,
        "violations": ["NO_TRANSACTION_FOR_MULTI_WRITE"],
        "scope": "post_apply_fullfile_delta"
      }
    """
    if not security_reports_dir:
        return {}
    if not security_reports_dir.exists():
        print(f"[WARN] security_reports_dir not found: {security_reports_dir}")
        return {}

    reports: Dict[str, Dict[str, Any]] = {}
    for p in sorted(security_reports_dir.glob("*.json")):
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            iid = str(obj.get("instance_id") or obj.get("task") or p.stem)
            reports[iid] = obj
        except Exception as exc:
            print(f"[WARN] failed to read security report {p}: {exc}")
    print(f"[INFO] Loaded {len(reports)} security scan reports from {security_reports_dir}")
    return reports


def security_from_report(
    reports: Dict[str, Dict[str, Any]],
    instance_id: str,
) -> Optional[Tuple[List[str], bool, str]]:
    """Return (violations, scan_failed, scope) from report map, if present."""
    obj = reports.get(instance_id)
    if not obj:
        return None
    violations = obj.get("violations") or []
    if not isinstance(violations, list):
        violations = [str(violations)]
    violations = [str(v) for v in violations]
    scan_failed = bool(obj.get("scan_failed", False)) or (obj.get("scan_ok") is False)
    scope = str(obj.get("scope") or "post_apply_report")
    return (violations, scan_failed, scope)


def _ensure_instance_id(record: Dict[str, Any], fallback: str) -> Dict[str, Any]:
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


def _normalize_prediction_mapping(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
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


def load_predictions(preds_path: Path) -> List[Dict[str, Any]]:
    if not preds_path.exists():
        raise SystemExit(f"[ERROR] preds.json not found at {preds_path}")

    raw_text = preds_path.read_text(encoding="utf-8-sig")
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
        preds.append(_ensure_instance_id(rec_copy, f"instance_{len(preds)+1}"))
    return preds


# ---------------------------------------------------------------------------
# Status loading
# ---------------------------------------------------------------------------


def load_statuses(msa_dir: str) -> Dict[str, str]:
    """Load and merge exit_statuses_*.yaml with defensive parsing."""

    status_map: Dict[str, str] = {}
    pattern = os.path.join(msa_dir, "exit_statuses_*.yaml")
    paths = sorted(glob.glob(pattern))

    if not paths:
        print(f"[WARN] No exit_statuses_*.yaml files found under {msa_dir}")
        return status_map

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                if yaml is None:
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
        except Exception as exc:
            print(f"[ERROR] Failed to read {path}: {exc}")
            continue

        if not isinstance(data, dict):
            print(f"[WARN] {path} does not contain a mapping; skipping")
            continue

        # Nested format
        if "instances_by_exit_status" in data:
            ibs = data.get("instances_by_exit_status")
            if not isinstance(ibs, dict):
                print(f"[WARN] {path} has malformed instances_by_exit_status")
                continue

            for status, instances in ibs.items():
                if not isinstance(instances, (list, tuple)):
                    print(f"[WARN] {path}: status '{status}' has non-list instances")
                    continue
                for inst_id in instances:
                    if inst_id is None:
                        continue
                    status_map[str(inst_id)] = str(status)
            continue

        # Flat format
        for inst_id, status in data.items():
            if inst_id is None or status is None:
                continue
            status_map[str(inst_id)] = str(status)

    print(f"[INFO] Loaded {len(status_map)} statuses from {len(paths)} files")
    return status_map


# ---------------------------------------------------------------------------
# SWE-bench integration
# ---------------------------------------------------------------------------


def run_swebench_eval(
    predictions: List[Dict[str, str]],
    dataset_name: str,
    split: str = "test",
    timeout: int = 300,
) -> Dict[str, Dict[str, Any]]:
    """Optionally run the SWE-bench harness for ground-truth outcomes."""

    if sys.platform.startswith("win"):
        print("[WARN] SWE-bench harness evaluation is not supported on native Windows; run in WSL/Linux.")
        return {}

    if not SWEBENCH_AVAILABLE or run_evaluation is None:
        print("[WARN] swebench not installed; skipping ground-truth evaluation")
        return {}

    print(f"[INFO] Running SWE-bench evaluation on {len(predictions)} predictions…")
    results = run_evaluation(
        predictions=predictions,
        dataset_name=dataset_name,
        split=split,
        timeout=timeout,
    )
    return results


# ---------------------------------------------------------------------------
# AST-based security for SWE patches
# ---------------------------------------------------------------------------


def extract_security_violations_from_patch(
    patch_text: Optional[str],
) -> Tuple[List[str], bool]:
    """
    Diff-fragment-based security analysis used when we do not have a full post-apply
    security report (or when --allow-diff-fallback is set).

    Returns:
        (violations, scan_failed)

        - violations: list of human-readable violation codes with severity tags.
          Each entry is a string beginning with either "[high]" or "[info]".
          Untagged entries are treated as "[high]" by downstream consumers.
        - scan_failed: True only when we effectively have *zero* security coverage
          (no regex hits, no AST findings) due to a parsing / scanning error.

    Pipeline:
      1) Lightweight regex search for obviously hard-coded secrets in added lines.
      2) Optional AST-based security scan over the concatenated Python additions.
      3) Error handling for syntactically broken fragments.
      4) Normalization and de-duplication of all findings.
    """
    if patch_text is None:
        # No patch means we could not inspect anything → coverage failure.
        return ([], True)

    patch_text = str(patch_text)

    # Quick detection of whether there is any plausible Python content.
    has_python = any(
        tok in patch_text for tok in ("def ", "class ", "import ", "from ", "async ")
    )

    # --- 1) Regex-based detection of hard-coded secrets in added lines ----------
    # Capture both the variable name and the literal value so we can classify severity.
    secrets_re = re.compile(
        r"(?P<name>api[_-]?key|secret|token|password)\s*=\s*['\"](?P<value>[^'\"]+)['\"]",
        re.IGNORECASE,
    )

    light_violations: List[str] = []

    for path, line in iterate_added_lines(patch_text):
        if not line or line.lstrip().startswith("#"):
            continue

        normalized = line.strip()

        for m in secrets_re.finditer(normalized):
            raw_value = m.group("value")
            severity = _classify_secret_severity(path, raw_value)

            label = "SECRETS_POSSIBLE_HARDCODED"
            snippet = normalized
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            if path:
                label += f"@{path}: {snippet}"
            else:
                label += f": {snippet}"

            light_violations.append(_tag_violation(label, severity=severity))

    # If there is no Python-like content, we skip AST scanning but still return any
    # regex-based violations. In that case scan_failed is False if we found anything,
    # otherwise True (zero coverage).
    if not has_python:
        if light_violations:
            return (sorted(set(light_violations)), False)
        return ([], True)

    # --- 2) AST-based scan over the Python additions ---------------------------
    added_python_lines: List[str] = []
    for _path, line in iterate_added_lines(patch_text):
        if not line:
            continue
        if line.lstrip().startswith("#"):
            continue
        added_python_lines.append(line.rstrip("\n"))

    python_snippet = "\n".join(added_python_lines)
    python_snippet = textwrap.dedent(python_snippet)

    if not python_snippet.strip():
        if light_violations:
            return (sorted(set(light_violations)), False)
        return ([], True)

    active_rules = [
        "SQLI_POSSIBLE_RAW_QUERY",
        "HARDCODED_SECRETS",
        "MISSING_AUTH_CHECK",
        "NO_TRANSACTION_FOR_MULTI_WRITE",
        "POTENTIAL_XSS",
        "WEAK_RNG_USAGE",
    ]
    error_markers = {
        "SYNTAX_ERROR_PREVENTS_SECURITY_SCAN",
        "SECURITY_SCAN_ERROR",
    }

    findings: Any = None
    has_error_marker = False

    try:
        findings = run_ast_security_checks(
            python_snippet,
            active_rules=active_rules,
        )
    except SyntaxError:
        findings = "SYNTAX_ERROR_PREVENTS_SECURITY_SCAN"
    except Exception:
        findings = "SECURITY_SCAN_ERROR"

    violations_from_ast: List[str] = []

    def _to_code(entry: Any) -> str:
        if isinstance(entry, str):
            return entry
        if isinstance(entry, Mapping):
            code = entry.get("code") or entry.get("type") or entry.get("msg")
            return str(code or "UNKNOWN_AST_SECURITY_ISSUE")
        return str(entry)

    if isinstance(findings, list):
        for item in findings:
            code = _to_code(item)
            if code in error_markers:
                has_error_marker = True
            else:
                violations_from_ast.append(_tag_violation(code, severity="high"))
    elif findings:
        code = _to_code(findings)
        if code in error_markers:
            has_error_marker = True
        else:
            violations_from_ast.append(_tag_violation(code, severity="high"))

    merged = list(light_violations) + list(violations_from_ast)
    deduped = sorted(set(merged))

    # --- 3) Decide whether the scan effectively failed -------------------------
    # Only call this a scan failure when:
    #   - The AST layer reported an error marker, AND
    #   - We have no AST violations, AND
    #   - We also have no regex-based violations.
    scan_failed = bool(has_error_marker and not violations_from_ast and not light_violations)

    return (deduped, scan_failed)


def compute_cri(
    tests_passed: int,
    total_tests: int,
    security_violations: List[str],
    security_scan_failed: bool,
    eval_status: Optional[str] = None,
) -> float:
    """
    Continuous CRI contract:

        cri = (tests_passed / total_tests) * (1 - infra_penalty) - security_penalty

    where:
      - infra_penalty is derived from eval_status (resolved / error / infra_*),
      - security_penalty is derived from violation severity and scan coverage,
      - result is clipped into [0.0, 1.0].
    """
    if total_tests <= 0:
        pass_rate = 0.0
    else:
        pass_rate = max(0.0, min(1.0, float(tests_passed) / float(total_tests)))

    # Severity buckets
    high_count = 0
    info_count = 0
    for v in security_violations or []:
        sev = _violation_severity(v)
        if sev == "high":
            high_count += 1
        else:
            info_count += 1

    # Infrastructure penalty: only matters once we have an eval_status.
    infra_penalty = 0.0
    if eval_status:
        if eval_status in {"infra_error", "infra_failure"}:
            infra_penalty = 0.5
        elif eval_status == "infra_timeout_before_patch":
            infra_penalty = 1.0
        elif eval_status == "error":
            infra_penalty = 0.25

    # Security penalty:
    security_penalty = 0.0
    security_penalty += 0.4 * high_count
    security_penalty += 0.05 * info_count

    # Moderate penalty if the scan failed and produced zero findings.
    if security_scan_failed and not (security_violations or []):
        security_penalty += 0.25

    cri_raw = pass_rate * (1.0 - infra_penalty) - security_penalty
    if cri_raw < 0.0:
        return 0.0
    if cri_raw > 1.0:
        return 1.0
    return float(cri_raw)


def normalize_resolved_status(resolved_status: Any, resolved_flag: Any) -> Optional[str]:
    """Normalize SWE-bench resolved status to a canonical string."""

    if isinstance(resolved_status, str) and resolved_status.strip():
        status_norm = resolved_status.strip().lower()
        if status_norm in {"resolved", "pass", "passed"}:
            return "resolved"
        return "unresolved"

    if isinstance(resolved_flag, bool):
        return "resolved" if resolved_flag else "unresolved"

    return None


def map_status_to_metrics(
    status: Optional[str],
    eval_result: Optional[Dict[str, Any]] = None,
) -> Tuple[int, int, int, str]:
    """Translate mini-SWE-agent status (plus optional eval) into τGuardian fields."""

    if eval_result is not None:
        resolved = bool(eval_result.get("resolved", False))
        if resolved:
            return 1, 0, 1, "OK"
        return 0, 1, 1, "ABSTAIN"

    status_norm = str(status or "").strip().lower()

    if status_norm in {"success", "ok", "pass", "passed", "resolved"}:
        return 1, 0, 1, "OK"

    if status_norm in {"runtimeerror", "timeout", "environmenterror", "error"}:
        return 0, 1, 1, "VETO"

    if status_norm in {"submitted", "pending"}:
        return 0, 0, 0, "ABSTAIN"

    if not status_norm or status_norm in {"unknown", "none"}:
        return 0, 0, 0, "ABSTAIN"

    return 0, 1, 1, "ABSTAIN"


def load_instance_results(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Load instance_results.jsonl into a mapping."""

    if path is None:
        return {}

    if not path.exists():
        raise FileNotFoundError(f"instance_results file not found: {path}")

    results: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            obj = json.loads(ln)
            instance_id = obj.get("instance_id")
            if instance_id:
                results[str(instance_id)] = obj
    print(f"[INFO] Loaded {len(results)} instance results from {path}")
    return results


def apply_instance_eval(
    base_row: Dict[str, Any],
    instance_eval: Optional[Dict[str, Any]],
    sad_flag: bool,
    security_scan_failed: bool,
    infra_failure_class: Optional[str] = None,
    cri_threshold: float = 0.9,
) -> Dict[str, Any]:
    """
    Merge SWE-bench instance_results.jsonl signals into a single evaluation row.

    Rules:
      - If instance_eval is missing, return base_row unchanged.
      - resolved / resolved_status from instance_eval are the source of truth.
      - eval_status is derived from resolved_status.
      - CRI is re-computed using the continuous contract:

            cri = (tests_passed/total_tests) * (1 - infra_penalty) - security_penalty

      - final_decision obeys τGuardian governance:

          * Any high-severity security violation  → VETO
          * Else, zero-coverage security scan    → ABSTAIN
          * Else, if resolved and cri ≥ threshold → OK
          * Else                                  → ABSTAIN
    """
    if not instance_eval:
        return base_row

    resolved_raw = instance_eval.get("resolved")
    resolved_status = (instance_eval.get("resolved_status") or "").upper() or None

    if isinstance(resolved_raw, bool):
        resolved: Optional[bool] = resolved_raw
    elif resolved_status == "RESOLVED":
        resolved = True
    elif resolved_status in {"UNRESOLVED", "PATCH_APPLY_FAILED"}:
        resolved = False
    else:
        resolved = None

    # Map resolved_status into a compact eval_status.
    eval_status: Optional[str] = None
    if resolved is True:
        eval_status = "resolved"
    elif resolved_status == "UNRESOLVED":
        eval_status = "unresolved"
    elif resolved_status == "PATCH_APPLY_FAILED":
        eval_status = "error"

    # If we have an explicit infra_failure_class and the harness reports
    # PATCH_APPLY_FAILED, treat this as pure infrastructure and short-circuit.
    if infra_failure_class and resolved_status == "PATCH_APPLY_FAILED":
        base_row.update(
            {
                "resolved": False,
                "resolved_status": resolved_status,
                "eval_status": infra_failure_class,
                "tests_passed": 0,
                "tests_failed": 0,
                "total_tests": 0,
                "test_pass_rate": 0.0,
                "cri": 0.0,
                "final_decision": "ABSTAIN",
            }
        )
        return base_row

    # Update base row with the canonical resolved state.
    base_row["resolved"] = resolved
    base_row["resolved_status"] = resolved_status
    base_row["eval_status"] = eval_status

    # If we still cannot interpret eval_status, keep earlier CRI/decision.
    if eval_status is None:
        return base_row

    # Binary test metrics based on resolved / unresolved.
    if resolved:
        tests_passed, tests_failed, total_tests = 1, 0, 1
    else:
        tests_passed, tests_failed, total_tests = 0, 1, 1
    test_pass_rate = float(tests_passed) / float(total_tests)

    # Recompute SAD from severity-tagged violations (only [high] drives SAD).
    security_violations = base_row.get("security_violations") or []
    high_sev = any(_violation_severity(v) == "high" for v in security_violations)
    sad_flag_effective = high_sev
    base_row["sad_flag"] = sad_flag_effective

    # Compute CRI with full knowledge of eval_status and scan coverage.
    cri = compute_cri(
        tests_passed=tests_passed,
        total_tests=total_tests,
        security_violations=security_violations,
        security_scan_failed=security_scan_failed,
        eval_status=eval_status,
    )

    # Final decision logic under the τGuardian contract.
    if sad_flag_effective:
        final_decision = "VETO"
    elif security_scan_failed:
        final_decision = "ABSTAIN"
    elif resolved and cri >= cri_threshold:
        final_decision = "OK"
    elif resolved:
        final_decision = "ABSTAIN"
    else:
        final_decision = "ABSTAIN"

    base_row.update(
        {
            "tests_passed": tests_passed,
            "tests_failed": tests_failed,
            "total_tests": total_tests,
            "test_pass_rate": test_pass_rate,
            "cri": cri,
            "final_decision": final_decision,
        }
    )
    return base_row


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_eval_records(
    msa_dir: Path,
    model_id: str,
    output_path: Path,
    instance_results_path: Optional[Path] = None,
    run_eval: bool = False,
    dataset: str = "princeton-nlp/SWE-bench_Lite",
    timeout: int = 300,
    security_reports_dir: Optional[Path] = None,
    allow_diff_fallback: bool = False,
    tau_max: int = 3,
    cri_threshold: float = 0.9,
) -> Tuple[int, int]:
    """Generate the τGuardian eval JSONL for a mini-SWE run."""

    preds_path = msa_dir / "preds.json"
    predictions = load_predictions(preds_path)

    statuses = load_statuses(str(msa_dir))
    instance_results = load_instance_results(instance_results_path)

    eval_results: Dict[str, Dict[str, Any]] = {}
    if run_eval:
        eval_results = run_swebench_eval(
            predictions,
            dataset_name=dataset,
            timeout=timeout,
        )

    total = 0
    success = 0

    with output_path.open("w", encoding="utf-8") as out_f:
        for rec in predictions:
            instance_id = str(rec.get("instance_id"))
            patch = rec.get("model_patch", "")
            patch_bytes = len(patch.encode("utf-8"))
            patch_sha256 = hashlib.sha256(patch.encode("utf-8")).hexdigest()
            status = statuses.get(instance_id, "Unknown")
            eval_result = eval_results.get(instance_id)

            instance_eval = instance_results.get(instance_id)

            artifacts = discover_artifacts(msa_dir, instance_id)

            infra_failure_class = classify_infra_failure_from_patch(patch)
            if infra_failure_class:
                tau_step = int(rec.get("tau_step", 1))
                row: Dict[str, Any] = {
                    "model": model_id,
                    "provider": rec.get("provider", "unknown"),
                    "task": instance_id,
                    "type": "external_swe_agent",
                    "source": "mini-swe-agent",
                    "status": status,
                    "resolved": False,
                    "resolved_status": infra_failure_class,
                    "eval_status": "infra_error",
                    "tests_passed": 0,
                    "tests_failed": 0,
                    "total_tests": 0,
                    "test_pass_rate": 0.0,
                    "cri": 0.0,
                    "sad_flag": False,
                    "security_scan_failed": False,
                    "security_scan_error": None,
                    "security_scan_scope": "skipped_infra_timeout_before_patch",
                    "security_report_found": False,
                    "decision_reason": _decision_reason(
                        "ABSTAIN", False, False, None, 0.0, cri_threshold
                    ),
                    "tau": tau_step,
                    "tau_max": tau_max,
                    "cri_threshold": cri_threshold,
                    "final_decision": "ABSTAIN",
                    "iterations": tau_step,
                    "patch": patch,
                    "patch_bytes": patch_bytes,
                    "patch_sha256": patch_sha256,
                    "security_violations": [],
                    "infra_timeout_before_patch": True,
                    "artifacts": artifacts,
                }

                out_f.write(json.dumps(row) + "\n")
                total += 1
                continue

            if _is_infra_timeout_before_patch(patch) and instance_eval is None:
                tau_step = int(rec.get("tau_step", 1))
                row: Dict[str, Any] = {
                    "model": model_id,
                    "provider": rec.get("provider", "unknown"),
                    "task": instance_id,
                    "type": "external_swe_agent",
                    "source": "mini-swe-agent",
                    "status": status,
                    "resolved": False,
                    "resolved_status": "INFRA_TIMEOUT_BEFORE_PATCH",
                    "eval_status": "infra_timeout_before_patch",
                    "tests_passed": 0,
                    "tests_failed": 0,
                    "total_tests": 0,
                    "test_pass_rate": 0.0,
                    "cri": 0.0,
                    "sad_flag": False,
                    "security_scan_failed": False,
                    "security_scan_error": None,
                    "security_scan_scope": "skipped_infra_timeout_before_patch",
                    "security_report_found": False,
                    "decision_reason": _decision_reason(
                        "ABSTAIN", False, False, False, 0.0, cri_threshold
                    ),
                    "tau": tau_step,
                    "tau_max": tau_max,
                    "cri_threshold": cri_threshold,
                    "final_decision": "ABSTAIN",
                    "iterations": tau_step,
                    "patch": patch,
                    "patch_bytes": patch_bytes,
                    "patch_sha256": patch_sha256,
                    "security_violations": [],
                    "infra_timeout_before_patch": True,
                    "artifacts": artifacts,
                }

                out_f.write(json.dumps(row) + "\n")
                total += 1
                continue

            # 1) Map raw SWE status/eval to tests + preliminary decision
            tests_passed, tests_failed, total_tests, base_decision = map_status_to_metrics(
                status, eval_result
            )

            # 2) Compute pass rate
            pass_rate = (tests_passed / total_tests) if total_tests else 0.0

            # 3) AST-based security scan for SWE patch (real SAD)
            security_report_found = False
            security_scan_scope = "diff_fragment_fallback_v2"
            security_violations: List[str] = []
            security_scan_failed = False
            security_scan_error: Optional[str] = None

            if security_reports_dir is not None:
                report_path = security_reports_dir / f"{instance_id}.json"
                if report_path.exists():
                    security_report_found = True
                    try:
                        report = json.loads(report_path.read_text(encoding="utf-8"))
                        security_scan_scope = str(
                            report.get("scan_scope", "postapply_fullfile_delta_v1")
                        )
                        raw_scan_failed = bool(report.get("scan_failed", False))
                        scan_ok = report.get("scan_ok")
                        security_violations = [
                            _tag_violation(v) for v in (report.get("new_violations") or [])
                        ]
                        security_scan_error = report.get("scan_error")

                        # Only treat this as a scan failure when there are no findings at all
                        # (i.e. effectively zero coverage).
                        security_scan_failed = bool(raw_scan_failed or (scan_ok is False)) and not security_violations

                        if security_scan_failed and not security_scan_error:
                            security_scan_error = "security scan marked as failed"
                    except Exception as exc:
                        security_scan_scope = "postapply_fullfile_delta_v1"
                        security_scan_failed = True
                        security_violations = []
                        security_scan_error = str(exc)
                else:
                    security_report_found = False
                    security_violations = []
                    if allow_diff_fallback:
                        security_scan_scope = "diff_fragment_fallback_v2"
                        security_violations, security_scan_failed = extract_security_violations_from_patch(patch)
                        security_scan_error = None if not security_scan_failed else "diff-fragment fallback failed"
                    else:
                        security_scan_scope = "missing_report"
                        security_scan_failed = True
                        security_scan_error = "post-apply security report missing"
            else:
                security_violations, security_scan_failed = extract_security_violations_from_patch(patch)
                security_scan_error = None if not security_scan_failed else "diff-fragment fallback failed"

            # SAD only fires on high-severity issues.
            sad_flag = any(_violation_severity(v) == "high" for v in security_violations)

            # Continuous CRI with eval_status=None at this stage (we only know tests + security).
            cri = compute_cri(
                tests_passed=tests_passed,
                total_tests=total_tests,
                security_violations=security_violations,
                security_scan_failed=security_scan_failed,
                eval_status=None,
            )

            tau_step = int(rec.get("tau_step", 1))

            # Base governance decision, before SWE-bench instance_results.jsonl refinement.
            if sad_flag:
                final_decision = "VETO"
            elif security_scan_failed:
                final_decision = "ABSTAIN"
            elif base_decision == "OK":
                if not total_tests or cri < cri_threshold:
                    final_decision = "ABSTAIN"
                else:
                    final_decision = "OK"
            else:
                final_decision = "ABSTAIN"

            row: Dict[str, Any] = {
                "model": model_id,
                "provider": rec.get("provider", "unknown"),
                "task": instance_id,
                "type": "external_swe_agent",
                "source": "mini-swe-agent",
                "status": status,
                "resolved": None,
                "resolved_status": None,
                "eval_status": None,
                "tests_passed": tests_passed,
                "tests_failed": tests_failed,
                "total_tests": total_tests,
                "test_pass_rate": pass_rate if total_tests else 0.0,
                "cri": cri,
                "sad_flag": sad_flag,
                "security_scan_failed": security_scan_failed,
                "security_scan_error": security_scan_error if security_scan_failed else None,
                "security_scan_scope": security_scan_scope,
                "security_report_found": security_report_found,
                "tau": tau_step,
                "tau_max": tau_max,
                "cri_threshold": cri_threshold,
                "final_decision": final_decision,
                "iterations": tau_step,
                "patch": patch,
                "patch_bytes": patch_bytes,
                "patch_sha256": patch_sha256,
                "security_violations": security_violations,
                "infra_timeout_before_patch": False,
                "artifacts": artifacts,
            }

            row = apply_instance_eval(
                row,
                instance_eval,
                sad_flag,
                security_scan_failed,
                cri_threshold=cri_threshold,
            )

            row["decision_reason"] = _decision_reason(
                row.get("final_decision", "ABSTAIN"),
                row.get("sad_flag", False),
                row.get("security_scan_failed", False),
                row.get("resolved"),
                row.get("cri", 0.0),
                cri_threshold,
            )

            out_f.write(json.dumps(row) + "\n")

            total += 1
            if row.get("final_decision") == "OK":
                success += 1

    return total, success


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert mini-SWE-agent results to τGuardian JSONL, optionally running SWE-bench evaluation.",
    )
    parser.add_argument("--msa-dir", default="msa_outputs", help="mini-SWE-agent output directory")
    parser.add_argument("--model-id", default="mini-swe-agent", help="Logical model identifier")
    parser.add_argument("--output", default="swe_results.jsonl", help="Output JSONL path")
    parser.add_argument(
        "--run-eval", action="store_true", help="Run SWE-bench evaluation harness if installed"
    )
    parser.add_argument(
        "--dataset", default="princeton-nlp/SWE-bench_Lite", help="SWE-bench dataset name for evaluation"
    )
    parser.add_argument("--timeout", type=int, default=300, help="Timeout per instance for evaluation (seconds)")
    parser.add_argument(
        "--instance-results",
        default=None,
        help="Path to instance_results.jsonl produced by SWE-bench harness",
    )
    parser.add_argument(
        "--security-reports-dir",
        default=None,
        help="Directory of per-instance JSON reports from tg_post_apply_security_scan.py (optional). If provided, these reports are the authoritative SAD inputs.",
    )
    parser.add_argument(
        "--allow-diff-fallback",
        action="store_true",
        help=(
            "If set, allow diff-fragment fallback when security reports are missing. "
            "Default: missing report => scan_failed=True"
        ),
    )
    parser.add_argument("--tau-max", type=int, default=3, help="Maximum tau used in the run")
    parser.add_argument(
        "--cri-threshold",
        type=float,
        default=0.9,
        help="CRI threshold for an OK decision",
    )

    args = parser.parse_args()

    instance_results_path = Path(args.instance_results).expanduser() if args.instance_results else None
    security_reports_dir = Path(args.security_reports_dir).expanduser() if args.security_reports_dir else None
    msa_dir = Path(args.msa_dir)
    output_path = Path(args.output)

    total, success = build_eval_records(
        msa_dir=msa_dir,
        model_id=args.model_id,
        output_path=output_path,
        instance_results_path=instance_results_path,
        run_eval=args.run_eval,
        dataset=args.dataset,
        timeout=args.timeout,
        security_reports_dir=security_reports_dir,
        allow_diff_fallback=args.allow_diff_fallback,
        tau_max=args.tau_max,
        cri_threshold=args.cri_threshold,
    )

    if total == 0:
        print(f"[INFO] No predictions found in {msa_dir / 'preds.json'}")
    else:
        rate = success / total if total else 0.0
        print(f"[INFO] Wrote {total} records to {output_path}")
        print(f"[INFO] OK decisions: {success}/{total} ({rate:.1%})")
        if args.run_eval:
            print("[INFO] Ground-truth evaluation completed via swebench")


if __name__ == "__main__":
    main()
