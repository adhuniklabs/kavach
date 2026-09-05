"""--flag → KAVACH_* env mirroring + lazy env reads."""

from __future__ import annotations

import os

from .retry import read_positive_int_env

FLAG_ENV: dict[str, str] = {
    "max_agents": "KAVACH_MAX_AGENTS",
    "phase_max_retries": "KAVACH_PHASE_MAX_RETRIES",
    "budget": "KAVACH_MAX_DISPATCHES",
    "max_wall_seconds": "KAVACH_MAX_WALL_SECONDS",
    "max_cost_usd": "KAVACH_MAX_COST_USD",
}


def apply_flag_env(namespace) -> None:
    for attr, env in FLAG_ENV.items():
        val = getattr(namespace, attr, None)
        if val is not None:
            os.environ[env] = str(val)


def _read_ceiling_env(name: str, default: int) -> int:
    """Like read_positive_int_env, but 0 is a legal value meaning "unlimited"."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        return default
    return val if val >= 0 else default


def max_agents() -> int:
    # Stays below Claude Code's own CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS (default 20).
    return read_positive_int_env("KAVACH_MAX_AGENTS", 6)


def max_dispatches(default: int) -> int:
    return _read_ceiling_env("KAVACH_MAX_DISPATCHES", default)


def max_wall_seconds(default: int) -> int:
    return _read_ceiling_env("KAVACH_MAX_WALL_SECONDS", default)


def max_cost_usd(default: float) -> float:
    """Dollar ceiling for one audit; 0 means unlimited, like the other two ceilings."""
    raw = os.environ.get("KAVACH_MAX_COST_USD")
    if raw is None:
        return default
    try:
        val = float(raw)
    except ValueError:
        return default
    return val if val >= 0 else default
