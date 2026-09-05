"""Per-mode transient cleanup; durable artifacts always survive.

Only TRANSIENT paths and a stale state lock are ever removed. An unrecognized file
at the audit root is reported in the summary, never deleted.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil

from filelock import FileLock, Timeout

TRANSIENT = ("tmp", "findings-draft", "confirm-workspace")
DURABLE = ("audit-state.json", "recon.json", "file-manifest.txt", "sweep-summary.json",
           "findings.json", "controls.json", "events.jsonl", "attack-surface", "findings",
           "findings-deferred", "findings-stale", "reports", "runs",
           "final-audit-report.md", "report.json",
           "report.sarif", "confirmation-report.md", "reinvest-report.md")
# Root-level files that predate the runs/ contract or belong to the engine itself.
KNOWN_ROOT = ("agent-*.json", "*-baseline-*.json", "audit-state.json.lock")


def _remove_stale_lock(audit_dir: str) -> bool:
    path = os.path.join(audit_dir, "audit-state.json.lock")
    if not os.path.exists(path):
        return False
    lock = FileLock(path, timeout=0)
    try:
        lock.acquire()
    except Timeout:
        return False        # a live run still holds it
    os.remove(path)
    lock.release()
    return True


def _unexpected(audit_dir: str) -> list[str]:
    known = set(DURABLE) | set(TRANSIENT)
    found = []
    for name in sorted(os.listdir(audit_dir)):
        if name in known or not os.path.isfile(os.path.join(audit_dir, name)):
            continue
        if not any(fnmatch.fnmatch(name, pat) for pat in KNOWN_ROOT):
            found.append(name)
    return found


def cleanup(audit_dir: str, mode: str) -> dict:
    removed, missing = [], []
    for rel in TRANSIENT:
        path = os.path.join(audit_dir, rel)
        if os.path.exists(path):
            shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
            removed.append(rel)
        else:
            missing.append(rel)
    if _remove_stale_lock(audit_dir):
        removed.append("audit-state.json.lock")
    retained = [rel for rel in DURABLE if os.path.exists(os.path.join(audit_dir, rel))]
    os.makedirs(os.path.join(audit_dir, "attack-surface"), exist_ok=True)
    summary = {"mode": mode, "removed": removed, "retained": retained, "missing": missing,
               "unexpected": _unexpected(audit_dir)}
    with open(os.path.join(audit_dir, "attack-surface", "cleanup-summary.json"),
              "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    return summary
