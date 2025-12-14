class InMemoryRepo:
    def __init__(self):
        self._owners = {}
        self._balances = {}

    def add_account(self, account_id: str, owner_id: str, balance: float):
        self._owners[account_id] = owner_id
        self._balances[account_id] = balance

    def get_account_owner(self, account_id: str) -> str:
        return self._owners[account_id]

    def get_balance(self, account_id: str) -> float:
        return self._balances[account_id]

    def debit(self, account_id: str, amount: float) -> None:
        self._balances[account_id] -= amount

    def credit(self, account_id: str, amount: float) -> None:
        self._balances[account_id] += amount

    def begin_transaction(self):
        from contextlib import contextmanager

        @contextmanager
        def tx():
            # simple transaction stub
            try:
                yield
            finally:
                pass

        return tx()


def transfer_funds(current_user_id: str, source_account_id: str, target_account_id: str, amount: float, repo: InMemoryRepo) -> None:
    """Starter implementation. Replace with a secure solution."""
    # TODO: implement proper checks and transactional transfer
    repo.debit(source_account_id, amount)
    repo.credit(target_account_id, amount)

