"""Dispatch/wall-clock ledger - the ceiling a fan-out is spent against.

A deep run on a mid-size repo plans ~800 subagent dispatches, and a non-fork subagent
does not share the parent's prompt cache, so each one pays full input cost. There was no
ceiling anywhere and no record of what a run chose not to do.

The ledger lives inside the audit's own record in ``audit-state.json`` under a ``budget``
key, so it survives resume without a second file and inherits the state filelock.
``check`` decides and records; ``charge`` accounts. Shedding is recorded at *decision*
time, because a coordinator that crashes after shedding but before charging still owes
the reader an honest note - the shed records are what feed the report's Limits section.

``max_dispatches = 0`` means **unlimited** - for CI runs that manage their own ceiling -
and is deliberately distinct from an exhausted budget, which reports 0 allowed with the
reason ``"dispatch ceiling"``. ``max_wall_seconds = 0`` is unlimited the same way.
"""

from __future__ import annotations

import calendar
import time
from dataclasses import dataclass
from typing import Any

from . import flags, state

DEFAULT_MAX_DISPATCHES = {"lite": 15, "balanced": 60, "deep": 120, "diff": 10,
                          "confirm": 30, "revisit": 80, "merge": 20, "longshot": 40}
DEFAULT_MAX_WALL_SECONDS = 3 * 3600

UNLIMITED = "unlimited"
WITHIN_BUDGET = "within budget"
DISPATCH_CEILING = "dispatch ceiling"
WALL_CLOCK = "wall clock"


@dataclass
class Decision:
    allowed: int
    dropped: int
    reason: str


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _epoch(stamp: str) -> float:
    return calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))


def _audit(f: state.AuditStateFile, audit_id: str) -> state.AuditRunState:
    for a in f.audits:
        if a.audit_id == audit_id:
            return a
    raise KeyError(audit_id)


def _new_ledger(mode: str, max_dispatches: int | None, max_wall_seconds: int | None) -> dict:
    ceiling = (max_dispatches if max_dispatches is not None
               else flags.max_dispatches(DEFAULT_MAX_DISPATCHES.get(mode, 60)))
    wall = (max_wall_seconds if max_wall_seconds is not None
            else flags.max_wall_seconds(DEFAULT_MAX_WALL_SECONDS))
    return {"max_dispatches": ceiling, "max_wall_seconds": wall, "dispatches": 0,
            "started_at": _now(), "by_phase": {}, "shed": []}


def init_budget(audit_dir: str, audit_id: str, mode: str, *, max_dispatches: int | None = None,
                max_wall_seconds: int | None = None) -> dict:
    ledger = _new_ledger(mode, max_dispatches, max_wall_seconds)
    state.mutate_state(audit_dir, lambda f: setattr(_audit(f, audit_id), "budget", ledger))
    return ledger


def _ensure(run: state.AuditRunState) -> dict:
    """Lazily seed a ledger so an audit-state.json written before v0.3 still accounts."""
    if not run.budget:
        run.budget = _new_ledger(run.mode, None, None)
    return run.budget


def show(audit_dir: str, audit_id: str | None = None) -> dict[str, Any]:
    """The stored ledger plus the derived numbers a reader wants: ``remaining`` (None when
    unlimited), ``elapsed_seconds``, and ``exhausted``. ``{}`` when there is no audit."""
    run = (state.latest_audit(audit_dir) if audit_id is None
           else _audit(state.load_state(audit_dir), audit_id))
    if run is None:
        return {}
    ledger = dict(run.budget) if run.budget else {}
    if not ledger:
        return {"audit_id": run.audit_id, "mode": run.mode}
    ceiling = ledger["max_dispatches"]
    remaining = None if ceiling == 0 else max(0, ceiling - ledger["dispatches"])
    return {**ledger, "audit_id": run.audit_id, "mode": run.mode, "remaining": remaining,
            "elapsed_seconds": int(time.time() - _epoch(ledger["started_at"])),
            "exhausted": remaining == 0}


def _decide(ledger: dict, planned: int) -> Decision:
    wall = ledger["max_wall_seconds"]
    if wall and time.time() - _epoch(ledger["started_at"]) >= wall:
        return Decision(allowed=0, dropped=max(0, planned), reason=WALL_CLOCK)
    if ledger["max_dispatches"] == 0:
        return Decision(allowed=max(0, planned), dropped=0, reason=UNLIMITED)
    remaining = max(0, ledger["max_dispatches"] - ledger["dispatches"])
    allowed = max(0, min(planned, remaining))
    dropped = max(0, planned) - allowed
    return Decision(allowed=allowed, dropped=dropped,
                    reason=DISPATCH_CEILING if dropped else WITHIN_BUDGET)


def check(audit_dir: str, audit_id: str, phase: str, planned: int) -> Decision:
    """How many of ``planned`` dispatches this phase may make. Records the shed, if any.

    Does not charge - the caller charges what it actually dispatches.
    """
    box: list[Decision] = []

    def _tx(f: state.AuditStateFile) -> None:
        ledger = _ensure(_audit(f, audit_id))
        decision = _decide(ledger, planned)
        if decision.dropped:
            ledger["shed"].append({
                "phase": phase, "planned": planned, "allowed": decision.allowed,
                "dropped": decision.dropped, "reason": decision.reason, "at": _now(),
            })
        box.append(decision)

    state.mutate_state(audit_dir, _tx)
    return box[0]


def charge(audit_dir: str, audit_id: str, phase: str, n: int) -> dict:
    box: list[dict] = []

    def _tx(f: state.AuditStateFile) -> None:
        ledger = _ensure(_audit(f, audit_id))
        ledger["dispatches"] += n
        ledger["by_phase"][phase] = ledger["by_phase"].get(phase, 0) + n
        box.append(dict(ledger))

    state.mutate_state(audit_dir, _tx)
    return box[0]


def shed_records(audit_dir: str, audit_id: str | None = None) -> list[dict]:
    """Every shed note for an audit, for the report's Limits section."""
    run = (state.latest_audit(audit_dir) if audit_id is None
           else _audit(state.load_state(audit_dir), audit_id))
    return list(run.budget.get("shed", [])) if run and run.budget else []
