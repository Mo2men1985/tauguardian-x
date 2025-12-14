from collections import deque
from typing import Deque, Dict

_requests: Dict[str, Deque[int]] = {}

def allow_request(user_id: str, ts: int) -> bool:
    """Starter implementation. Replace with a correct solution."""
    # TODO: implement proper rate limiting logic
    window = 10
    limit = 3
    dq = _requests.setdefault(user_id, deque())
    # naive: just append and always return True
    dq.append(ts)
    return True

