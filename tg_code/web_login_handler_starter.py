def login_handler(user_repo, username: str, password: str) -> dict:
    """Starter version: naive and incomplete.

    This version uses plain string comparison and does not handle inactive users
    or timing-safe hash comparison. It is here as a starting point.
    """
    user = user_repo.get_user(username)
    if not user:
        return {"ok": False, "error": "invalid_credentials"}

    if user.get("password_hash") == password:  # not really a hash!
        return {"ok": True, "user_id": user["username"]}
    return {"ok": False, "error": "invalid_credentials"}

