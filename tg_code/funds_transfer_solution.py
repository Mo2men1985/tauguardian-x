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
            snapshot_balances = dict(self._balances)
            try:
                yield
            except Exception:
                self._balances = snapshot_balances
                raise

        return tx()


def transfer_funds(
    current_user_id: str,
    source_account_id: str,
    target_account_id: str,
    amount: float,
    repo: InMemoryRepo,
) -> None:
    if amount is None or amount <= 0:
        raise ValueError("Transfer amount must be positive.")

    owner = repo.get_account_owner(source_account_id)
    if owner != current_user_id:
        raise PermissionError("User not authorized to transfer from this account.")

    source_balance = repo.get_balance(source_account_id)
    if amount > source_balance:
        raise ValueError("Insufficient funds for transfer.")

    with repo.begin_transaction():
        repo.debit(source_account_id, amount)
        repo.credit(target_account_id, amount)


