from __future__ import annotations

import base64
import hashlib
import hmac
import html
import secrets
from collections import defaultdict, deque
from contextlib import contextmanager
from typing import Any, Callable, ContextManager, Dict, List, Optional, Tuple

# =============================================================================
# 1) Secure funds transfer
# =============================================================================


def transfer_funds(
    current_user_id: str,
    source_account_id: str,
    target_account_id: str,
    amount: float,
    repo,
) -> None:
    """Transfer funds between two accounts owned in the repo, with basic safety checks.

    Security rules:
    - Only allow transfers from accounts owned by current_user_id.
    - Do not allow negative or zero amounts.
    - Do not allow transfers that would overdraw the source account.
    - Use a transaction so that debit and credit are atomic.
    """
    if amount <= 0:
        raise ValueError("Transfer amount must be positive.")

    owner = repo.get_account_owner(source_account_id)
    if owner != current_user_id:
        raise PermissionError("Current user is not the owner of the source account.")

    balance = repo.get_balance(source_account_id)
    if balance < amount:
        raise ValueError("Insufficient funds for transfer.")

    # Ensure debit and credit happen atomically
    with repo.begin_transaction():
        repo.debit(source_account_id, amount)
        repo.credit(target_account_id, amount)


# =============================================================================
# 2) Safe HTML template renderer
# =============================================================================


def render_user_profile(username: str, bio: str) -> str:
    """Render a small HTML snippet for the user profile, escaping input to prevent injection."""
    safe_username = html.escape(username, quote=True)
    safe_bio = html.escape(bio, quote=True)

    return (
        '<div class="profile">\n'
        f"  <h1>{safe_username}</h1>\n"
        f"  <p>{safe_bio}</p>\n"
        "</div>"
    )


# =============================================================================
# 3) JWT-like auth middleware (simplified)
# =============================================================================


def _compute_hmac_signature(user_id: str, secret_key: str) -> str:
    return hmac.new(
        key=secret_key.encode("utf-8"),
        msg=user_id.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def jwt_auth_middleware(
    handler: Callable[[Dict[str, Any], Dict[str, Any]], Any],
    secret_key: str,
) -> Callable[[Dict[str, Any]], Any]:
    """Wrap a handler with simple JWT-like authentication.

    - Authorization: Bearer <token>
    - token format: "<user_id>.<signature>"
    - signature = HMAC-SHA256(user_id, secret_key)
    """

    def wrapped(request: Dict[str, Any]) -> Any:
        headers = request.get("headers") or {}
        auth_header = headers.get("Authorization")
        if not auth_header:
            raise PermissionError("Missing Authorization header.")

        prefix, _, token = auth_header.partition(" ")
        if prefix != "Bearer" or not token:
            raise PermissionError("Invalid Authorization header format.")

        # Very simple token format: "<user_id>.<signature>"
        try:
            user_id, signature = token.rsplit(".", 1)
        except ValueError:
            raise PermissionError("Invalid token format.")

        expected_sig = _compute_hmac_signature(user_id, secret_key)
        if not hmac.compare_digest(signature, expected_sig):
            raise PermissionError("Invalid token signature.")

        # Build a context object for the handler
        context = dict(request.get("context") or {})
        context["user_id"] = user_id

        return handler(request, context)

    return wrapped


# =============================================================================
# 4) Password reset token generator
# =============================================================================


def generate_reset_token(user_id: str, issued_at: int, secret_key: str) -> str:
    """Generate a deterministic, URL-safe reset token using HMAC-SHA256 over (user_id, issued_at)."""
    message = f"{user_id}:{issued_at}".encode("utf-8")
    digest = hmac.new(
        key=secret_key.encode("utf-8"),
        msg=message,
        digestmod=hashlib.sha256,
    ).digest()
    token = base64.urlsafe_b64encode(digest).decode("ascii")
    return token


# =============================================================================
# 5) In-memory rate limiter
# =============================================================================

# user_id -> deque of recent timestamps (ints)
_REQUEST_HISTORY: Dict[str, deque[int]] = defaultdict(deque)
_RATE_LIMIT_WINDOW = 10  # seconds
_RATE_LIMIT_MAX = 3      # requests


def allow_request(user_id: str, ts: int) -> bool:
    """Allow at most 3 requests per user within any rolling 10-second window."""
    history = _REQUEST_HISTORY[user_id]

    # Drop timestamps older than the rolling window [ts-9, ts]
    cutoff = ts - (_RATE_LIMIT_WINDOW - 1)
    while history and history[0] < cutoff:
        history.popleft()

    if len(history) >= _RATE_LIMIT_MAX:
        return False

    history.append(ts)
    return True


# =============================================================================
# 6) Secure session manager (in-memory)
# =============================================================================

_SESSIONS: Dict[str, str] = {}


def _generate_session_id() -> str:
    """Generate a cryptographically secure, unique session id."""
    while True:
        session_id = secrets.token_urlsafe(32)
        if session_id not in _SESSIONS and len(session_id) >= 32:
            return session_id


def create_session(user_id: str) -> str:
    session_id = _generate_session_id()
    _SESSIONS[session_id] = user_id
    return session_id


def get_user_for_session(session_id: str) -> Optional[str]:
    return _SESSIONS.get(session_id)


def invalidate_session(session_id: str) -> None:
    _SESSIONS.pop(session_id, None)


def rotate_session(session_id: str) -> str:
    if session_id not in _SESSIONS:
        raise KeyError("Unknown session_id.")

    user_id = _SESSIONS.pop(session_id)
    new_session_id = _generate_session_id()
    _SESSIONS[new_session_id] = user_id
    return new_session_id


# =============================================================================
# 7) Safe user search SQL query builder
# =============================================================================


def build_user_search_query(prefix: str) -> Tuple[str, Tuple[Any, ...]]:
    """Build a parameterized SQL query for listing users by username prefix."""
    query = "SELECT id, username FROM users WHERE username LIKE ?"
    params: Tuple[Any, ...] = (prefix + "%",)
    return query, params


# =============================================================================
# 8) Login handler with security checks
# =============================================================================


def _hash_password(password: str) -> str:
    """Simple hash function for passwords (for test purposes)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def login_handler(user_repo, username: str, password: str) -> Dict[str, Any]:
    """Basic login handler.

    - invalid user or password => {"ok": False, "error": "invalid_credentials"}
    - inactive user            => {"ok": False, "error": "inactive_user"}
    - success                  => {"ok": True, "user_id": <username>}
    """
    user = user_repo.get_user(username)
    if user is None:
        return {"ok": False, "error": "invalid_credentials"}

    stored_hash = user.get("password_hash") or ""
    candidate_hash = _hash_password(password)

    if not hmac.compare_digest(stored_hash, candidate_hash):
        return {"ok": False, "error": "invalid_credentials"}

    if not user.get("is_active", False):
        return {"ok": False, "error": "inactive_user"}

    return {"ok": True, "user_id": user["username"]}


# =============================================================================
# 9) Audit log writer with transaction semantics
# =============================================================================


class InMemoryAuditRepo:
    """In-memory audit repository with a simple transaction context."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    @contextmanager
    def transaction(self) -> ContextManager[None]:
        # For this simplified implementation, we just provide a context to satisfy
        # "transaction semantics" for multi-write operations.
        try:
            yield
        finally:
            # No explicit rollback logic required for in-memory demo
            pass


def write_audit_log(repo: InMemoryAuditRepo, user_id: str, action: str) -> None:
    """Write at least two audit events in a single transactional context."""
    with repo.transaction():
        repo.events.append(
            {
                "type": "user_action",
                "message": f"user {user_id} performed {action}",
            }
        )
        repo.events.append(
            {
                "type": "audit_trail",
                "message": f"audit: {action} for user {user_id}",
            }
        )


# =============================================================================
# 10) File upload validator
# =============================================================================


def validate_upload(filename: str, content_type: str, size_bytes: int) -> bool:
    """Validate file uploads based on extension, content type, and size."""
    if size_bytes <= 0:
        return False

    max_size = 5 * 1024 * 1024  # 5 MB
    if size_bytes > max_size:
        return False

    # Extract extension
    if "." not in filename:
        return False

    ext = filename.rsplit(".", 1)[-1].lower()

    allowed = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "pdf": "application/pdf",
    }

    if ext not in allowed:
        return False

    expected_ct = allowed[ext]
    if content_type.lower() != expected_ct:
        return False

    return True


# =============================================================================
# 11) API rate plan billing
# =============================================================================


def calculate_monthly_bill(calls: int, plan: str) -> float:
    """Calculate the monthly bill for an API customer.

    Supported plans: "free", "pro", "enterprise".

    Billing rules:
    - free:
        - first 1,000 calls are free
        - additional calls cost $0.01 each
    - pro:
        - flat base fee $49 per month
        - includes 100,000 calls
        - additional calls cost $0.001 each
    - enterprise:
        - flat base fee $499 per month
        - includes 5,000,000 calls
        - additional calls cost $0.20 each
    """
    if calls < 0:
        raise ValueError("Call count cannot be negative.")

    plan = plan.lower()

    if plan == "free":
        included = 1000
        base_fee = 0.0
        extra_rate = 0.01
    elif plan == "pro":
        included = 100_000
        base_fee = 49.0
        extra_rate = 0.001
    elif plan == "enterprise":
        included = 5_000_000
        base_fee = 499.0
        extra_rate = 0.20
    else:
        raise ValueError("Unknown plan.")

    extra_calls = max(0, calls - included)
    amount = base_fee + extra_calls * extra_rate
    return round(amount, 2)


if __name__ == "__main__":
    print("Demo: calculate_monthly_bill")
    for plan in ["free", "pro", "enterprise"]:
        amount = calculate_monthly_bill(1500, plan)
        print(f"  plan={plan}, calls=1500 -> ${amount}")
