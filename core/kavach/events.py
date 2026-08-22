"""An append-only record of what the engine did, so a UI does not have to guess.

Progress was only ever observable by watching gate artifacts appear on disk, which is fine
for `plan` and useless for a live view: it cannot say *why* a phase re-ran, what a budget
check decided, or how long a phase took. Anything wanting to render a run had to poll
mtimes and infer.

One JSONL line per engine decision, at the audit root. Reading it is a tail; nothing needs
the state lock to follow a run. Writes are a single `write()` to an `O_APPEND` descriptor
and lines are capped below `PIPE_BUF`, so concurrent phases interleave whole lines rather
than corrupting each other - the same reason this is not a JSON array.
"""

from __future__ import annotations

import json
import os
import time

FILENAME = "events.jsonl"
MAX_LINE = 4000     # below POSIX PIPE_BUF (4096), where O_APPEND writes stay atomic


def path(audit_dir: str) -> str:
    return os.path.join(os.path.abspath(audit_dir), FILENAME)


def emit(audit_dir: str, kind: str, **fields) -> None:
    """Record one event. Never raises: a run must not die because its log could not."""
    record = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **fields}
    try:
        line = json.dumps(record, default=str)
        if len(line) > MAX_LINE:
            record = {"at": record["at"], "kind": kind, "truncated": True}
            line = json.dumps(record)
        os.makedirs(os.path.abspath(audit_dir), exist_ok=True)
        with open(path(audit_dir), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def read(audit_dir: str, *, since: int = 0) -> list[dict]:
    """Every event from line `since` on. A malformed line is skipped, not fatal - the log
    is diagnostic, and a half-written tail must not break the reader that found it."""
    try:
        with open(path(audit_dir), encoding="utf-8") as fh:
            lines = fh.readlines()[since:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
