import random
import string
from typing import Dict, Optional

# NOTE: This starter implementation is intentionally insecure.
# It uses the `random` module to generate session IDs, which is not
# suitable for security-sensitive tokens. The functional behaviour is
# correct, but τGuardian's security checks should flag this.

_SESSIONS: Dict[str, str] = {}
_ALPHABET = string.ascii_letters + string.digits


def _generate_session_id(length: int = 32) -> str:
    return "".join(random.choice(_ALPHABET) for _ in range(length))


def create_session(user_id: str) -> str:
    session_id = _generate_session_id()
    _SESSIONS[session_id] = user_id
    return session_id


def get_user_for_session(session_id: str) -> Optional[str]:
    return _SESSIONS.get(session_id)


def invalidate_session(session_id: str) -> None:
    _SESSIONS.pop(session_id, None)


def rotate_session(session_id: str) -> str:
    user_id = _SESSIONS.get(session_id)
    if user_id is None:
        raise KeyError("Unknown session id")
    # drop old id
    _SESSIONS.pop(session_id, None)
    # issue a new one
    new_session_id = _generate_session_id()
    _SESSIONS[new_session_id] = user_id
    return new_session_id

