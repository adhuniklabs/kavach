"""Retry backoff helpers shared by the phase and command layers."""

from __future__ import annotations

import os


def backoff_ms(attempt: int, base_ms: int = 5000, cap_ms: int = 120000) -> int:
    return min(cap_ms, base_ms * (2 ** (max(1, attempt) - 1)))


def read_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return val if val > 0 else default
