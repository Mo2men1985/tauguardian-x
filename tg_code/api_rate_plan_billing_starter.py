def calculate_monthly_bill(calls: int, plan: str) -> float:
    """Starter implementation: charges a flat rate per call."""
    if calls < 0:
        raise ValueError("calls must be non-negative")
    return float(calls) * 0.01

