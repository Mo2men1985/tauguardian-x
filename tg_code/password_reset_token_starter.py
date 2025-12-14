def generate_reset_token(user_id: str, issued_at: int, secret_key: str) -> str:
    """Starter implementation: too naive.

    This just concatenates the pieces and is not cryptographically strong.
    """
    return f"{user_id}:{issued_at}:{secret_key}"

