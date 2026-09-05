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

DEFAULT_MAX_DISPATCHES = {"lite": 15, "balanced": 60, "deep": 120}
DEFAULT_MAX_WALL_SECONDS = 3 * 3600
# The live tail's own ceiling, added to whichever preset runs it. Live validation provisions
# an environment and executes per finding, so it is priced separately from audit depth.
LIVE_DELTA = 30


def default_ceiling(mode: str, live: bool = False) -> int:
    """The preset's ceiling, or the smallest one for a mode this engine no longer knows.

    `_ensure` seeds a ledger from whatever ``mode`` an ``audit-state.json`` carries, and the
    records it exists for - pre-v0.3 - are exactly the ones naming `revisit`, `confirm`,
    `longshot`, `merge` or `diff`. Indexing on that raised KeyError through a `main()` that
    handles no such thing, so the CLI answered its own accounting verbs with a traceback.

    `cmd_resume` refuses a pre-0.3 dir that recorded a version, and is right to: it re-derives
    what is left to run from a phase contract that has since changed, and a wrong answer there
    reports an unfinished audit as a finished one. A version-less 0.1.0-era dir gets through
    `version_compatible`'s escape hatch regardless, which is exactly what lands here. A ceiling
    makes no such claim - the dispatch, token
    and cost counts stay exact whatever it is, and the only cost of picking the smallest one
    is shedding fan-out, which is recorded at decision time and reaches the reader in the
    report's Limits section. Not accounting at all is the worse failure.
    """
    ceiling = DEFAULT_MAX_DISPATCHES.get(mode, min(DEFAULT_MAX_DISPATCHES.values()))
    return ceiling + (LIVE_DELTA if live else 0)


UNLIMITED = "unlimited"
WITHIN_BUDGET = "within budget"
DISPATCH_CEILING = "dispatch ceiling"
WALL_CLOCK = "wall clock"
COST_CEILING = "cost ceiling"


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


def _new_ledger(mode: str, max_dispatches: int | None, max_wall_seconds: int | None,
                max_cost_usd: float | None = None, live: bool = False) -> dict:
    ceiling = (max_dispatches if max_dispatches is not None
               else flags.max_dispatches(default_ceiling(mode, live)))
    wall = (max_wall_seconds if max_wall_seconds is not None
            else flags.max_wall_seconds(DEFAULT_MAX_WALL_SECONDS))
    cost = flags.max_cost_usd(0.0) if max_cost_usd is None else max_cost_usd
    return {"max_dispatches": ceiling, "max_wall_seconds": wall, "max_cost_usd": cost,
            "dispatches": 0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
            "started_at": _now(), "by_phase": {}, "spend_by_phase": {}, "shed": []}


def init_budget(audit_dir: str, audit_id: str, mode: str, *, max_dispatches: int | None = None,
                max_wall_seconds: int | None = None, max_cost_usd: float | None = None,
                live: bool = False) -> dict:
    ledger = _new_ledger(mode, max_dispatches, max_wall_seconds, max_cost_usd, live)
    state.mutate_state(audit_dir, lambda f: setattr(_audit(f, audit_id), "budget", ledger))
    return ledger


# Ledger keys added after the first ledgers were written. Backfilled on read so an audit
# resumed from an older audit-state.json accounts the same as a fresh one.
_LEDGER_DEFAULTS = {"max_cost_usd": 0.0, "tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0,
                    "spend_by_phase": {}}


def _ensure(run: state.AuditRunState) -> dict:
    """Lazily seed a ledger so an audit-state.json written before v0.3 still accounts."""
    if not run.budget:
        run.budget = _new_ledger(run.mode, None, None)
    for key, default in _LEDGER_DEFAULTS.items():
        run.budget.setdefault(key, type(default)() if isinstance(default, dict) else default)
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
    cost_ceiling = ledger.get("max_cost_usd", 0.0)
    spent = round(ledger.get("cost_usd", 0.0), 6)
    return {**ledger, "audit_id": run.audit_id, "mode": run.mode, "remaining": remaining,
            "cost_usd": spent,
            "cost_remaining": None if not cost_ceiling else round(max(0.0, cost_ceiling - spent), 6),
            "elapsed_seconds": int(time.time() - _epoch(ledger["started_at"])),
            "exhausted": remaining == 0}


def _decide(ledger: dict, planned: int) -> Decision:
    wall = ledger["max_wall_seconds"]
    if wall and time.time() - _epoch(ledger["started_at"]) >= wall:
        return Decision(allowed=0, dropped=max(0, planned), reason=WALL_CLOCK)
    # Cost is checked before the dispatch ceiling for the same reason wall clock is: a run
    # that has spent its money must stop fanning out and go write the report, and the
    # reader is owed the reason it stopped rather than a count that looks unfinished.
    cost_ceiling = ledger.get("max_cost_usd", 0.0)
    if cost_ceiling and ledger.get("cost_usd", 0.0) >= cost_ceiling:
        return Decision(allowed=0, dropped=max(0, planned), reason=COST_CEILING)
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


def charge(audit_dir: str, audit_id: str, phase: str, n: int, *, tokens_in: int = 0,
           tokens_out: int = 0, cost_usd: float = 0.0) -> dict:
    """Account for what actually ran. Token and cost figures come from the harness that
    called the model - the engine never talks to one, so it cannot measure them itself, and
    a ledger that only counts dispatches cannot tell a reader what the audit cost."""
    box: list[dict] = []

    def _tx(f: state.AuditStateFile) -> None:
        ledger = _ensure(_audit(f, audit_id))
        ledger["dispatches"] += n
        ledger["by_phase"][phase] = ledger["by_phase"].get(phase, 0) + n
        ledger["tokens_in"] += tokens_in
        ledger["tokens_out"] += tokens_out
        ledger["cost_usd"] = round(ledger["cost_usd"] + cost_usd, 6)
        spend = ledger["spend_by_phase"].setdefault(
            phase, {"tokens_in": 0, "tokens_out": 0, "cost_usd": 0.0})
        spend["tokens_in"] += tokens_in
        spend["tokens_out"] += tokens_out
        spend["cost_usd"] = round(spend["cost_usd"] + cost_usd, 6)
        box.append(dict(ledger))

    state.mutate_state(audit_dir, _tx)
    return box[0]


def shed_records(audit_dir: str, audit_id: str | None = None) -> list[dict]:
    """Every shed note for an audit, for the report's Limits section."""
    run = (state.latest_audit(audit_dir) if audit_id is None
           else _audit(state.load_state(audit_dir), audit_id))
    return list(run.budget.get("shed", [])) if run and run.budget else []
