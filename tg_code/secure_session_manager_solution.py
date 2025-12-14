import secrets
from typing import Dict, Optional

_SESSIONS: Dict[str, str] = {}


def _generate_session_id(min_length: int = 32) -> str:
    while True:
        session_id = secrets.token_urlsafe(24)
        if len(session_id) < min_length:
            continue
        if session_id not in _SESSIONS:
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
    user_id = _SESSIONS.get(session_id)
    if user_id is None:
        raise KeyError("Unknown session id")
    _SESSIONS.pop(session_id, None)
    new_session_id = _generate_session_id()
    _SESSIONS[new_session_id] = user_id
    return new_session_id


