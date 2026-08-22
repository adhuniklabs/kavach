"""Resumable audit-state.json manager.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Snake_case keys are the persisted on-disk contract. Writes are serialized by a
filelock and made atomic via os.replace; a corrupt file is moved aside, never
silently overwritten.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable

from filelock import FileLock

from . import __version__

_TRANSIENT_ON_COMPLETE = (
    "error", "last_error", "next_retry_at", "retry_backoff_ms", "heartbeat_at",
)


class RunStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    FAILED = "failed"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PhaseState:
    status: str = PhaseStatus.PENDING.value
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    artifacts: list[str] = field(default_factory=list)
    attempt: int = 0
    max_attempts: int = 1
    retry_backoff_ms: int | None = None
    next_retry_at: str | None = None
    last_error: str | None = None
    heartbeat_at: str | None = None
    run_id: str | None = None


@dataclass
class AuditRunState:
    audit_id: str
    mode: str
    status: str = RunStatus.IN_PROGRESS.value
    commit: str | None = None
    branch: str = "nogit"
    repository: str = ""
    history_available: bool = False
    model: str = ""
    # What produced this audit, and what it was pointed at. Both are written at init, not
    # only at completion: a run resumed under a different engine or against a different tree
    # is not the same audit, and only a recorded value can catch that.
    engine_version: str = ""
    dirty: bool = False
    started_at: str = ""
    completed_at: str | None = None
    budget: dict[str, Any] = field(default_factory=dict)
    phases: dict[str, PhaseState] = field(default_factory=dict)


@dataclass
class AuditStateFile:
    audits: list[AuditRunState] = field(default_factory=list)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def handle(audit_id: str) -> str:
    """The short, typable form of an audit id.

    `audit_id` is `<iso8601>-<pid>-<uuid8>` - unique, and 36 characters with a process id in the
    middle, which nobody is going to type. The trailing hex is already random, so the short handle
    is derived rather than invented: no mapping table to keep, and it reads like a git sha, which
    is a convention the reader already has.
    """
    return audit_id.rsplit("-", 1)[-1]


def find_audit(audit_dir: str, ref: str) -> AuditRunState | None:
    """Resolve a full audit id or a short handle. An ambiguous handle resolves to nothing
    rather than to a guess - picking one of two audits for the user is worse than asking."""
    matches = [a for a in load_state(audit_dir).audits
               if a.audit_id == ref or handle(a.audit_id) == ref]
    return matches[0] if len(matches) == 1 else None


def version_compatible(recorded: str, current: str = __version__) -> bool:
    """Whether `current` may resume an audit created by `recorded`.

    Same major.minor only. On 0.x the minor is the breaking axis, and what breaks across one is
    exactly what resume depends on: the phase list, the prereq graph, and which artifact closes a
    gate. Resuming across it would re-derive "what is left" from a different contract than the one
    that produced the artifacts on disk, and report the result as if it were coherent.

    An audit written before this field existed records "" and is allowed through - refusing every
    pre-existing audit would be a worse failure than the one this prevents.
    """
    if not recorded:
        return True
    return recorded.split(".")[:2] == current.split(".")[:2]


def state_path(audit_dir: str) -> str:
    return os.path.join(audit_dir, "audit-state.json")


def _lock_path(audit_dir: str) -> str:
    return state_path(audit_dir) + ".lock"


def _to_file(raw: dict[str, Any]) -> AuditStateFile:
    audits = []
    for a in raw.get("audits", []):
        phases = {k: PhaseState(**v) for k, v in a.get("phases", {}).items()}
        audits.append(AuditRunState(**{**a, "phases": phases}))
    return AuditStateFile(audits=audits)


def _from_file(f: AuditStateFile) -> dict[str, Any]:
    return {"audits": [
        {**{k: v for k, v in asdict(a).items() if k != "phases"},
         "phases": {pid: asdict(ps) for pid, ps in a.phases.items()}}
        for a in f.audits
    ]}


def load_state(audit_dir: str) -> AuditStateFile:
    path = state_path(audit_dir)
    if not os.path.exists(path):
        return AuditStateFile()
    try:
        with open(path, encoding="utf-8") as fh:
            return _to_file(json.load(fh))
    except (json.JSONDecodeError, TypeError, ValueError):
        os.replace(path, f"{path}.corrupt-{int(time.time())}")
        return AuditStateFile()


def _write_atomic(audit_dir: str, f: AuditStateFile) -> None:
    path = state_path(audit_dir)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(_from_file(f), fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def mutate_state(audit_dir: str, transform: Callable[[AuditStateFile], None]) -> AuditStateFile:
    os.makedirs(audit_dir, exist_ok=True)
    with FileLock(_lock_path(audit_dir)):
        f = load_state(audit_dir)
        transform(f)
        _write_atomic(audit_dir, f)
        return f


def _newest(audits: list[AuditRunState]) -> AuditRunState | None:
    """Latest by started_at; ties resolve to list order, so the later record wins."""
    if not audits:
        return None
    return max(enumerate(audits), key=lambda pair: (pair[1].started_at or "", pair[0]))[1]


def _find(f: AuditStateFile, audit_id: str) -> AuditRunState:
    for a in f.audits:
        if a.audit_id == audit_id:
            return a
    raise KeyError(audit_id)


def init_audit(audit_dir: str, mode: str, phases: list[str], *, commit: str | None = None,
               branch: str = "nogit", repository: str = "", history_available: bool = False,
               model: str = "", dirty: bool = False) -> AuditRunState:
    audit_id = _now() + f"-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    run = AuditRunState(
        audit_id=audit_id, mode=mode, status=RunStatus.IN_PROGRESS.value,
        commit=commit, branch=branch, repository=repository,
        history_available=history_available, model=model, started_at=_now(),
        engine_version=__version__, dirty=dirty,
        phases={p: PhaseState() for p in phases},
    )
    mutate_state(audit_dir, lambda f: f.audits.append(run))
    return run


def set_phase_status(audit_dir: str, audit_id: str, phase: str, status: PhaseStatus,
                     **fields: Any) -> None:
    def _tx(f: AuditStateFile) -> None:
        ph = _find(f, audit_id).phases[phase]
        ph.status = status.value if isinstance(status, PhaseStatus) else status
        if ph.status == PhaseStatus.IN_PROGRESS.value and not ph.started_at:
            ph.started_at = _now()
        if ph.status == PhaseStatus.COMPLETE.value:
            ph.completed_at = _now()
            for t in _TRANSIENT_ON_COMPLETE:
                setattr(ph, t, None if t != "artifacts" else [])
        for key, val in fields.items():
            setattr(ph, key, val)
    mutate_state(audit_dir, _tx)


def complete_audit(audit_dir: str, commit: str | None = None) -> AuditRunState | None:
    """Mark the newest in-progress audit COMPLETE, stamp completed_at, and record its
    commit. Returns None (no-op) if there is no in-progress audit to complete."""
    box: list[AuditRunState] = []

    def _tx(f: AuditStateFile) -> None:
        run = _newest([a for a in f.audits if a.status == RunStatus.IN_PROGRESS.value])
        if run is None:
            return
        run.status = RunStatus.COMPLETE.value
        run.completed_at = _now()
        run.commit = commit
        box.append(run)

    mutate_state(audit_dir, _tx)
    return box[0] if box else None


def latest_audit(audit_dir: str, mode: str | None = None) -> AuditRunState | None:
    audits = [a for a in load_state(audit_dir).audits if mode is None or a.mode == mode]
    return audits[-1] if audits else None


def latest_resumable_audit(audit_dir: str, mode: str | None = None) -> AuditRunState | None:
    """The newest unfinished audit, unless a *newer* run already finished.

    Without the recency comparison an abandoned run outranks a later completed one, and
    `kavach resume` reopens phases the finished audit already closed.
    """
    audits = [a for a in load_state(audit_dir).audits if mode is None or a.mode == mode]
    resumable = _newest([a for a in audits if a.status in
                         (RunStatus.IN_PROGRESS.value, RunStatus.FAILED.value)])
    if resumable is None:
        return None
    complete = _newest([a for a in audits if a.status == RunStatus.COMPLETE.value])
    if complete is not None and (complete.started_at or "") > (resumable.started_at or ""):
        return None
    return resumable
