"""Output stamping utility to avoid rerun collisions."""

from __future__ import annotations

from datetime import datetime


def make_timestamped_dirname(base: str) -> str:
    """Return a unique dirname like ``<base>_runYYYYMMDD_HHMMSS``."""

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_clean = base.rstrip("/")
    return f"{base_clean}_run{ts}"


__all__ = ["make_timestamped_dirname"]
