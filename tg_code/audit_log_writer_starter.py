class InMemoryAuditRepo:
    def __init__(self):
        self.events = []

    def save_event(self, event_type: str, message: str):
        self.events.append({"type": event_type, "message": message})


def write_audit_log(repo: InMemoryAuditRepo, user_id: str, action: str) -> None:
    """Starter implementation: writes multiple events without a transaction."""
    message = f"user={user_id} action={action}"
    repo.save_event("USER_ACTION", message)
    repo.save_event("AUDIT_TRAIL", message)

