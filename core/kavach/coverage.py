"""Per-finding phase coverage - the gate that makes "complete with 0 PoCs" impossible.

The PoC and report phases used to gate on the *existence* of ``findings/``, which a
zero-work run satisfies. These two functions walk the promoted tree instead and name
every directory that is still missing its artifact, so a phase can only close when the
work it exists to do actually landed on disk.

Aggregate directories are exempt from both: a rolled-up scanner class is never dispatched
to kavach-poc or kavach-reporter, and its report.md is written by the core.

Coverage is **scoped** to the directories that belong to this audit, via the manifest
``consolidate`` writes (see :func:`findings_tree.scope_promoted`). Without that scoping the
gate can be permanently unsatisfiable: ``consolidate`` never deletes, so a tree upgraded
from a legacy ``severity >= medium`` policy carries 238 directories that will never
receive a PoC, and a re-audit whose finding mix changed leaves its own behind. Measured on
the audited tree: 291 directories, 2 satisfiable, 289 demanded forever.

A directory outside that scope is **stale**, not missing: it is counted separately, listed
with the reason it fell out, and left exactly where it is. Reporting it rather than deleting
it is the same principle as cleanup's ``unexpected`` list - and ``kavach consolidate
--prune-stale`` moves them to ``findings-stale/`` when the operator asks.
"""

from __future__ import annotations

import glob
import json
import os

from . import findings_tree, report_finding

KINDS = ("poc", "report")


def _has_poc(finding_dir: str) -> bool:
    return any(os.path.getsize(p) > 0 for p in glob.glob(os.path.join(finding_dir, "poc.*"))
               if os.path.isfile(p))


def _has_report(finding_dir: str) -> bool:
    path = os.path.join(finding_dir, "report.md")
    if not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8") as fh:
        return report_finding.is_complete(fh.read())


_SATISFIES = {"poc": _has_poc, "report": _has_report}
_REASON = {
    "poc": "no poc.* or poc.theoretical.md",
    "report": "report.md missing or fails the vuln-report contract",
}


def coverage(audit_dir: str, kind: str) -> dict:
    satisfies = _SATISFIES[kind]
    live, stale, scoped_by = findings_tree.scope_promoted(audit_dir)
    total = satisfied = exempt = 0
    missing = []
    for fdir in live:
        meta = findings_tree.read_metadata(fdir) or {}
        total += 1
        if findings_tree.is_aggregate(meta):
            exempt += 1
            satisfied += 1
        elif satisfies(fdir):
            satisfied += 1
        else:
            missing.append({
                "display_id": meta.get("display_id", os.path.basename(fdir).split("-", 1)[0]),
                "dir": os.path.relpath(fdir, audit_dir),
                "reason": _REASON[kind],
            })
    return {"kind": kind, "complete": not missing, "total": total, "satisfied": satisfied,
            "aggregates_exempt": exempt, "missing": missing,
            "scoped_by": scoped_by, "stale": len(stale), "stale_dirs": stale}


def poc_coverage(audit_dir: str) -> dict:
    return coverage(audit_dir, "poc")


def report_coverage(audit_dir: str) -> dict:
    return coverage(audit_dir, "report")


def write_coverage(audit_dir: str, phase_kind: str) -> str:
    report = coverage(audit_dir, phase_kind)
    out_dir = os.path.join(audit_dir, "attack-surface")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{phase_kind}-coverage.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    return path
