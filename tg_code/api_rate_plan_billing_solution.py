def calculate_monthly_bill(calls: int, plan: str) -> float:
    if calls < 0:
        raise ValueError("calls must be non-negative")

    plan = plan.lower()
    if plan == "free":
        included = 1000
        extra_rate = 0.01
        base_fee = 0.0
    elif plan == "pro":
        included = 100000
        extra_rate = 0.001
        base_fee = 49.0
    elif plan == "enterprise":
        included = 5000000
        extra_rate = 0.20
        base_fee = 499.0
    else:
        raise ValueError("unknown plan")

    extra_calls = max(0, calls - included)
    total = base_fee + extra_calls * extra_rate
    return round(total, 2)


