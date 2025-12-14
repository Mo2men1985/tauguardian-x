import hmac
import hashlib
from typing import Dict, Any


def _hash_password(password: str) -> str:
    # Simple SHA-256 hashing for demonstration; in real systems use a strong KDF.
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def login_handler(user_repo, username: str, password: str) -> Dict[str, Any]:
    user = user_repo.get_user(username)
    if not user:
        # Use constant-time comparison with a dummy hash to mitigate user enumeration timing
        dummy_hash = _hash_password("dummy_password")
        hmac.compare_digest(dummy_hash, _hash_password(password))
        return {"ok": False, "error": "invalid_credentials"}

    stored_hash = user.get("password_hash")
    if stored_hash is None:
        return {"ok": False, "error": "invalid_credentials"}

    provided_hash = _hash_password(password)

    if not hmac.compare_digest(stored_hash, provided_hash):
        return {"ok": False, "error": "invalid_credentials"}

    if not user.get("is_active", False):
        return {"ok": False, "error": "inactive_user"}

    return {"ok": True, "user_id": user["username"]}


