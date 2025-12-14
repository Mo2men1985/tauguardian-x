from typing import Tuple

def build_user_search_query(prefix: str) -> Tuple[str, tuple]:
    query = "SELECT id, username FROM users WHERE username LIKE ?"
    params = (prefix + "%",)
    return query, params


