from collections import deque
from typing import Deque, Dict

# Per-user sliding window of request timestamps
_requests: Dict[str, Deque[int]] = {}


def allow_request(user_id: str, ts: int) -> bool:
    """
    Allow at most `limit` requests per user within a sliding window of `window`
    time units (here, 10 units).

    The tests call this with integer timestamps: 0, 1, 2, 3, ...
    For limit = 3 and window = 10, behavior should be:

      - allow_request("u1", 0) -> True
      - allow_request("u1", 1) -> True
      - allow_request("u1", 2) -> True
      - allow_request("u1", 3) -> False  (4th request in same 10-unit window)

    Strategy:
      1. Drop timestamps older than (ts - window + 1).
      2. If we already have >= limit timestamps in-window, block.
      3. Otherwise, record this timestamp and allow.
    """
    window = 10
    limit = 3

    dq = _requests.setdefault(user_id, deque())

    # Drop timestamps outside the sliding window [ts - window + 1, ts]
    cutoff = ts - window + 1
    while dq and dq[0] < cutoff:
        dq.popleft()

    # If we've already seen `limit` requests in the current window, block
    if len(dq) >= limit:
        return False

    # Otherwise record this request and allow it
    dq.append(ts)
    return True
