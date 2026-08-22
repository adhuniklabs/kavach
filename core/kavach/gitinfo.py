"""What tree is being audited, right now.

An audit's findings are line-anchored claims about one specific tree. `complete_audit` records
the commit at the *end* of a run, which is enough to key a baseline for a later diff and not
enough for anything happening during the run: an audit resumed after a checkout, a pull, or a
rebase is auditing a different tree than the one its findings on disk describe, and nothing
noticed. So the context is captured at `state init` too, and checked on resume.

`dirty` is recorded because it is the honest caveat on a commit: findings cited against a working
tree with uncommitted edits are not reproducible from that commit alone, and the report should be
able to say so.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class GitContext:
    commit: str | None = None
    branch: str = "nogit"
    dirty: bool = False

    @property
    def available(self) -> bool:
        return self.commit is not None

    def as_dict(self) -> dict:
        return {"commit": self.commit, "branch": self.branch, "dirty": self.dirty}


def _git(repo: str, *args: str, timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(["git", *args], cwd=repo, capture_output=True,
                                text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def context(repo: str = ".") -> GitContext:
    """Never raises. A target with no git history is a normal target, not an error."""
    commit = _git(repo, "rev-parse", "HEAD")
    if commit is None:
        return GitContext()
    branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD") or "detached"
    status = _git(repo, "status", "--porcelain", timeout=30)
    return GitContext(commit=commit, branch=branch, dirty=bool(status))


def short(commit: str | None, n: int = 8) -> str:
    return commit[:n] if commit else "no-git"
