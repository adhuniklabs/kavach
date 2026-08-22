# Adapted from piolium (github.com/vigolium/piolium) - MIT License, (c) j3ssie.
"""Drift diff + diff-mode changed-file scoping.

Findings are compared on Finding.fingerprint() (stable across line moves), never on
the display id (which renumbers run to run). The prior commit is either explicit
(--since) or the last audit whose state recorded a COMPLETE run - an in-progress or
failed audit is never a valid baseline.
"""

from __future__ import annotations

import gzip
import json
import os
import subprocess

from . import state
from .finding import Finding
from .state import RunStatus


def diff_findings(
    baseline: list[Finding], current: list[Finding],
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    base_ids = {f.fingerprint() for f in baseline}
    cur_ids = {f.fingerprint() for f in current}
    new = [f for f in current if f.fingerprint() not in base_ids]
    fixed = [f for f in baseline if f.fingerprint() not in cur_ids]
    unchanged = [f for f in current if f.fingerprint() in base_ids]
    return new, fixed, unchanged


def resolve_prior_commit(audit_dir: str, since: str | None = None) -> str | None:
    if since:
        return since
    for run in reversed(state.load_state(audit_dir).audits):
        # a COMPLETE run with no commit (target had no git history) isn't a usable
        # baseline for a commit-diff - keep walking back for an older complete run that
        # does have one, rather than stopping on the newest COMPLETE regardless.
        if run.status == RunStatus.COMPLETE.value and run.commit:
            return run.commit
    return None


def baseline_path(audit_dir: str, commit: str) -> str | None:
    """The commit-keyed baseline for ``commit``, gzipped. A plain ``.json``
    written by an earlier release still resolves, so an existing audit tree keeps diffing."""
    stem = os.path.join(audit_dir, "attack-surface", f"findings-baseline-{commit}")
    for path in (f"{stem}.json.gz", f"{stem}.json"):
        if os.path.exists(path):
            return path
    return None


def load_baseline(path: str) -> list[Finding]:
    if not path.endswith(".gz"):
        from .finding import load_findings
        return load_findings(path)
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        payload = json.load(fh)
    return [Finding.from_dict(d) for d in payload.get("findings", [])]


def changed_files(repo: str, prior: str, head: str = "HEAD") -> list[str]:
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{prior}...{head}"],
            cwd=repo, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line]


def scope_guard(files: list[str], max_changed: int = 200) -> bool:
    return 0 < len(files) <= max_changed
