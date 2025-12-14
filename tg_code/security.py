"""tg_code/security.py

Wrapper around ast_security.run_ast_security_checks for τGuardian.

See in-code docstring for details.
"""
from __future__ import annotations

import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:  # pragma: no cover
    from ast_security import run_ast_security_checks as _ast_run_checks  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    _ast_run_checks = None

DEFAULT_RULE_IDS: Sequence[str] = (
    "SQLI_STRING_CONCAT",
    "SQLI_FSTRING",
    "HARDCODED_SECRET",
    "HARDCODED_SECRETS",
    "DANGEROUS_EVAL",
    "DANGEROUS_EXEC",
    "DANGEROUS_OS_SYSTEM",
    "DANGEROUS_SUBPROCESS",
    "DANGEROUS_PICKLE",
)

@dataclass
class SecurityScanResult:
    violations: List[str]

    @property
    def sad_flag(self) -> bool:
        return bool(self.violations)

def _call_ast_scanner(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
) -> Optional[List[str]]:
    if _ast_run_checks is None:
        return None

    if active_rules is not None:
        rules_list: Optional[List[str]] = list(active_rules)
    else:
        rules_list = None

    try:
        return list(_ast_run_checks(code_str, active_rules=rules_list))
    except TypeError:
        try:
            return list(_ast_run_checks(code_str))  # type: ignore[misc]
        except Exception:
            return None
    except Exception:
        return None

def _fallback_scan(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
) -> List[str]:
    text = code_str or ""
    active = set(active_rules) if active_rules is not None else set(DEFAULT_RULE_IDS)

    violations: List[str] = []

    def add(rule: str) -> None:
        if rule in active:
            violations.append(rule)

    lowered = text.lower()

    if "eval(" in text:
        add("DANGEROUS_EVAL")
    if "exec(" in text:
        add("DANGEROUS_EXEC")
    if "os.system(" in text:
        add("DANGEROUS_OS_SYSTEM")
    if "subprocess." in text:
        add("DANGEROUS_SUBPROCESS")
    if "pickle.load(" in text or "pickle.loads(" in text:
        add("DANGEROUS_PICKLE")

    if "select " in lowered or "insert " in lowered or "update " in lowered or "delete " in lowered:
        if 'f"' in text or "f'" in text:
            add("SQLI_FSTRING")

    return violations

def scan_code_for_violations(
    code_str: str,
    active_rules: Optional[Iterable[str]] = None,
    verbose: bool = False,
) -> SecurityScanResult:
    violations = _call_ast_scanner(code_str, active_rules=active_rules)

    error_markers = {"SYNTAX_ERROR_PREVENTS_SECURITY_SCAN", "SECURITY_SCAN_ERROR"}
    if violations:
        if any(v in error_markers for v in violations):
            filtered = [v for v in violations if v not in error_markers]
            violations = filtered if filtered else None

    if violations is None:
        if verbose:
            warnings.warn(
                "AST security scanner unavailable or failed; using fallback heuristic.",
                RuntimeWarning,
            )
        violations = _fallback_scan(code_str, active_rules=active_rules)

    return SecurityScanResult(violations=list(violations))

def scan_file_for_violations(
    path: Path | str,
    active_rules: Optional[Iterable[str]] = None,
    encoding: str = "utf-8",
    verbose: bool = False,
) -> SecurityScanResult:
    p = Path(path)
    try:
        text = p.read_text(encoding=encoding)
    except FileNotFoundError:
        return SecurityScanResult(violations=[])

    return scan_code_for_violations(text, active_rules=active_rules, verbose=verbose)
