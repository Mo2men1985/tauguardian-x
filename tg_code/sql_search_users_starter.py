from typing import Tuple

def build_user_search_query(prefix: str) -> Tuple[str, tuple]:
    """Starter: returns a very naive query.

    This version is intentionally NOT safe enough and should be improved
    by the model to use parameterized queries.
    """
    # TODO: replace with a parameterized query using a placeholder and params tuple.
    query = f"SELECT id, username FROM users WHERE username LIKE '{prefix}%'"  # unsafe
    return query, ()

