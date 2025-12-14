from contextlib import contextmanager
from typing import List, Dict, Iterator


class InMemoryAuditRepo:
    def __init__(self):
        self.events: List[Dict[str, str]] = []
        self._in_transaction: bool = False
        self._pending_events: List[Dict[str, str]] = []

    def save_event(self, event_type: str, message: str) -> None:
        event = {"type": event_type, "message": message}
        if self._in_transaction:
            self._pending_events.append(event)
        else:
            self.events.append(event)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        previous_state = self._in_transaction
        if not self._in_transaction:
            self._in_transaction = True
            self._pending_events = []
        try:
            yield
            if not previous_state:
                self.events.extend(self._pending_events)
        finally:
            if not previous_state:
                self._in_transaction = False
                self._pending_events = []


def write_audit_log(repo: InMemoryAuditRepo, user_id: str, action: str) -> None:
    message = f"user={user_id} action={action}"
    with repo.transaction():
        repo.save_event("USER_ACTION", message)
        repo.save_event("AUDIT_TRAIL", message)


