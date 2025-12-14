
import ast
from typing import List


class SecurityVisitor(ast.NodeVisitor):
    """AST-based security checker.

    This visitor is intentionally conservative. It looks for structural
    patterns that are hard to catch with simple regexes, and emits generic
    violation tags. The harness then maps those tags to task-level rules.
    """

    def __init__(self) -> None:
        self.violations: List[str] = []
        self.in_transaction_block: bool = False
        self.write_operations_count: int = 0
        self.sql_keywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER"}
        self.sensitive_vars = {"password", "secret", "api_key", "token", "auth_token"}
        # Track weak randomness usage (e.g., `random` module used for security tokens).
        # We do not attempt full data-flow analysis; instead we conservatively
        # flag any import of the `random` module so that tasks which care about
        # secure randomness can enable the WEAK_RNG rule.

    # --- Import handling ---------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # type: ignore[override]
        for alias in node.names:
            if alias.name == "random":
                self.violations.append("WEAK_RNG_USAGE")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # type: ignore[override]
        if node.module == "random":
            self.violations.append("WEAK_RNG_USAGE")
        self.generic_visit(node)

    # --- Call inspection ---------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
        """Check for SQL injection patterns and specific function calls."""
        # 1) SQL injection heuristics on call sites (execute/exec/query).
        is_sql_exec = False
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "exec", "query"):
            is_sql_exec = True
        elif isinstance(node.func, ast.Name) and node.func.id in ("execute", "exec", "query"):
            is_sql_exec = True

        if is_sql_exec and node.args:
            first_arg = node.args[0]
            # query string built via concatenation: "SELECT ..." + user_input
            if isinstance(first_arg, ast.BinOp):
                self.violations.append("SQLI_STRING_CONCAT")
            # f"SELECT ... {user_input}"
            elif isinstance(first_arg, ast.JoinedStr):
                self.violations.append("SQLI_FSTRING")
            # "SELECT ... {}".format(user_input)
            elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == "format":
                    self.violations.append("SQLI_STRING_FORMAT")

        # 2) XSS sinks (very approximate, mostly for Python-backend HTML emit).
        if isinstance(node.func, ast.Attribute) and node.func.attr == "dangerouslySetInnerHTML":
            self.violations.append("POTENTIAL_XSS")

        # 3) Track write operations outside explicit transaction contexts.
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr.lower()
            if any(x in name for x in ["save", "create", "update", "delete", "insert"]):
                if not self.in_transaction_block:
                    self.write_operations_count += 1

        self.generic_visit(node)

    # --- Assign / secrets --------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:  # type: ignore[override]
        """Detect obvious hard-coded secrets."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(s in var_name for s in self.sensitive_vars):
                    if isinstance(node.value, (ast.Constant, ast.Str)):
                        val = node.value.value if isinstance(node.value, ast.Constant) else node.value.s
                        if val and len(val) > 4 and "env" not in str(val).lower():
                            self.violations.append("HARDCODED_SECRETS")
        self.generic_visit(node)

    # --- Transaction tracking ----------------------------------------------

    def visit_With(self, node: ast.With) -> None:  # type: ignore[override]
        """Track transaction-with blocks to reduce false positives."""
        is_transaction = False
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call):
                func = ctx.func
                if isinstance(func, ast.Attribute) and "transaction" in func.attr.lower():
                    is_transaction = True
                elif isinstance(func, ast.Name) and "transaction" in func.id.lower():
                    is_transaction = True
            elif isinstance(ctx, ast.Attribute) and "transaction" in ctx.attr.lower():
                is_transaction = True

        if is_transaction:
            self.in_transaction_block = True
            self.generic_visit(node)
            self.in_transaction_block = False
        else:
            self.generic_visit(node)

    # --- Endpoint auth -----------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # type: ignore[override]
        """Look for obvious missing auth checks on API endpoints."""
        is_endpoint = False
        has_auth_decorator = False

        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    dec_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    dec_name = decorator.func.attr

            if any(x in dec_name for x in ["get", "post", "put", "delete", "route", "app"]):
                is_endpoint = True
            if any(x in dec_name for x in ["login_required", "auth", "verify", "jwt"]):
                has_auth_decorator = True

        mentions_user = False
        manual_auth_check = False
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in ["user_id", "current_user", "userId"]:
                mentions_user = True
            if isinstance(child, ast.Call):
                func_name = ""
                if isinstance(child.func, ast.Name):
                    func_name = child.func.id
                elif isinstance(child.func, ast.Attribute):
                    func_name = child.func.attr
                if "auth" in func_name or "verify" in func_name:
                    manual_auth_check = True

        if is_endpoint and mentions_user and not (has_auth_decorator or manual_auth_check):
            self.violations.append("MISSING_AUTH_CHECK")

        self.generic_visit(node)


def run_ast_security_checks(code_str: str, active_rules: List[str] | None = None) -> List[str]:
    """Parse code and return violation tags filtered by active task rules."""
    if active_rules is None:
        active_rules = []

    try:
        tree = ast.parse(code_str)
    except SyntaxError:
        # If we cannot parse the code, treat that as a security-relevant issue.
        return ["SYNTAX_ERROR_PREVENTS_SECURITY_SCAN"]

    visitor = SecurityVisitor()
    visitor.visit(tree)

    # If we saw multiple write operations outside explicit transaction blocks.
    if visitor.write_operations_count > 1:
        visitor.violations.append("NO_TRANSACTION_FOR_MULTI_WRITE")

    unique_violations = list(set(visitor.violations))

    relevant: List[str] = []
    for v in unique_violations:
        if "SQLI" in active_rules and v.startswith("SQLI"):
            relevant.append(v)
        elif "SECRETS" in active_rules and v == "HARDCODED_SECRETS":
            relevant.append(v)
        elif "MISSING_AUTH" in active_rules and v == "MISSING_AUTH_CHECK":
            relevant.append(v)
        elif "NO_TRANSACTION" in active_rules and v == "NO_TRANSACTION_FOR_MULTI_WRITE":
            relevant.append(v)
        elif "XSS" in active_rules and v == "POTENTIAL_XSS":
            relevant.append(v)
        elif "WEAK_RNG" in active_rules and v == "WEAK_RNG_USAGE":
            relevant.append(v)

    return relevant


