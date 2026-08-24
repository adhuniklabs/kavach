"""Gate-driven phase planner. The engine plans; SKILL.md dispatches.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
A phase is "done" when its gate artifacts exist (not merely when state says so),
so an interrupted run resumes from real progress on disk.
"""

from __future__ import annotations

import glob
import json
import os

from . import dispatch, modes, retry, state
from .state import PhaseStatus

_REPORT_GATES = {"reports/final-audit-report.md", "reports/confirmation-report.md"}
# Legacy trees wrote both deliverables at the audit root. A gate that stopped resolving
# for them would re-run every report phase of every audit already on disk.
_LEGACY_ROOT = {gate: gate.split("/", 1)[1] for gate in _REPORT_GATES}
_MIN_REPORT_BYTES = 500
_COVERAGE_SUFFIX = "-coverage.json"


class PrereqError(Exception):
    pass


def _coverage_complete(path: str) -> bool:
    """A coverage artifact only gates when it says the coverage is complete."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get("complete") is True
    except (OSError, ValueError):
        return False


def gate_satisfied(audit_dir: str, phase: str) -> bool:
    patterns = modes.gate_for(phase)
    if not patterns:
        return False
    for pat in patterns:
        matches = glob.glob(os.path.join(audit_dir, pat))
        if not matches and pat in _LEGACY_ROOT:
            matches = glob.glob(os.path.join(audit_dir, _LEGACY_ROOT[pat]))
        if not matches:
            return False
        if pat in _REPORT_GATES and os.path.getsize(matches[0]) < _MIN_REPORT_BYTES:
            return False
        if pat.endswith(_COVERAGE_SUFFIX) and not _coverage_complete(matches[0]):
            return False
    return True


def fanout_pending(audit_dir: str, phase: str) -> list[str]:
    """Roster members of a fan-out phase that have no result on disk.

    A gate artifact is not proof a fan-out finished. Every hunter on BL3 is handed the
    same assigned output path, so the first one home closes the phase for the other
    seven. A harness can keep its own roster ledger while it runs, but that ledger dies
    with the process: measured on a resumed audit where four hunters had failed
    upstream, `plan` never offered BL3 again and the run advanced to BL4 reporting
    itself complete, permanently missing half its static analysis.

    Deliberately consulted by `next_actionable` and not by `phase_status`, so an
    incomplete fan-out is re-planned without also blocking the phases downstream of it.
    A hunter that can never succeed would otherwise wedge the whole audit, and this
    engine reports rather than blocks — `coverage` is where the shortfall belongs.
    """
    roster = modes.roster_for(phase)
    if len(roster) < 2:
        return []
    return [
        name
        for i, name in enumerate(roster, start=1)
        if not os.path.exists(dispatch.result_path_for(audit_dir, phase, name, index=i))
    ]


def phase_status(audit_dir: str, mode: str, phase: str) -> str:
    if gate_satisfied(audit_dir, phase):
        return PhaseStatus.COMPLETE.value
    run = state.latest_audit(audit_dir, mode)
    if run and phase in run.phases:
        return run.phases[phase].status
    return PhaseStatus.PENDING.value


def _done(status: str) -> bool:
    return status in (PhaseStatus.COMPLETE.value, PhaseStatus.SKIPPED.value)


def next_actionable(audit_dir: str, mode: str) -> list[str]:
    out = []
    for phase in modes.phases_for(mode):
        if gate_satisfied(audit_dir, phase) and not fanout_pending(audit_dir, phase):
            continue
        prereqs = modes.prereqs_for(mode, phase)
        if all(_done(phase_status(audit_dir, mode, p)) for p in prereqs):
            out.append(phase)
    return out


def ensure_prereqs(audit_dir: str, mode: str, phase: str) -> None:
    for p in modes.prereqs_for(mode, phase):
        if not _done(phase_status(audit_dir, mode, p)):
            raise PrereqError(f"{phase} needs {p} complete first")


def record_attempt(audit_dir: str, audit_id: str, phase: str, error: str) -> int:
    max_attempts = retry.read_positive_int_env("KAVACH_PHASE_MAX_RETRIES", 5)
    base = retry.read_positive_int_env("KAVACH_PHASE_BACKOFF_MS", 5000)
    cap = retry.read_positive_int_env("KAVACH_PHASE_BACKOFF_CAP_MS", 120000)
    attempt_box: list[int] = []

    def _tx(f: state.AuditStateFile) -> None:
        for a in f.audits:
            if a.audit_id == audit_id:
                ph = a.phases[phase]
                attempt = ph.attempt + 1
                ph.status = PhaseStatus.FAILED.value
                ph.attempt = attempt
                ph.max_attempts = max_attempts
                ph.last_error = error
                ph.retry_backoff_ms = retry.backoff_ms(attempt, base, cap)
                attempt_box.append(attempt)
                return
        raise KeyError(audit_id)

    state.mutate_state(audit_dir, _tx)
    return attempt_box[0]
