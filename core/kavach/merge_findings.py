# Adapted from piolium (github.com/vigolium/piolium) - MIT License, (c) j3ssie.
"""Merge-mode (MG1-MG7) deterministic core: aliasing, exact dedup, renumber, summary.

Semantic near-duplicate collapsing (MG2) is chamber-driven at runtime - a subagent's
judgment call, not this module's. What the deterministic core owns is the mechanical
half: give each source a stable alias, fold exact fingerprint duplicates across
sources via sweep.dedupe, produce a stable severity-ordered renumbering, and render
the human-readable merge-summary.md.
"""

from __future__ import annotations

import json
import os
import string

from .finding import Finding, dump_findings, load_findings
from .sweep import dedupe

_WORKSPACE = os.path.join("tmp", "merge-workspace")
# The bulky per-source intermediates stay transient; the three artifacts the MG gates
# resolve against are durable, so cleanup can no longer reopen a finished merge.
_GATE_DIR = "attack-surface"


def _alias(i: int) -> str:
    if i < 26:
        return string.ascii_lowercase[i]
    return f"s{i}"


def _write_json(audit_dir: str, name: str, payload) -> str:
    gate_dir = os.path.join(audit_dir, _GATE_DIR)
    os.makedirs(gate_dir, exist_ok=True)
    path = os.path.join(gate_dir, name)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)
    return path


def index_sources(audit_dir: str, source_dirs: list[str]) -> dict:
    workspace = os.path.join(audit_dir, _WORKSPACE)
    os.makedirs(workspace, exist_ok=True)

    sources = []
    all_findings: list[Finding] = []
    for i, src in enumerate(source_dirs):
        alias = _alias(i)
        findings_path = os.path.join(src, "findings.json")
        findings = load_findings(findings_path) if os.path.exists(findings_path) else []
        for f in findings:
            f.source = f"{alias}:{f.source}"
        all_findings.extend(findings)
        sources.append({"alias": alias, "path": os.path.abspath(src), "count": len(findings)})

    merged = dedupe(all_findings)
    dump_findings(merged, os.path.join(workspace, "findings-merged.json"))

    index = {"sources": sources, "merged_count": len(merged)}
    _write_json(audit_dir, "merge-index.json", index)
    return index


def apply_dedup_decisions(audit_dir: str, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    """Fold kavach-chamber's semantic near-duplicate decisions (MG2) into the merged set.

    ``attack-surface/merge-dedup-decisions.json`` is a list of ``{"drop": <fingerprint>,
    "keep": <fingerprint>, "reason": ...}`` objects, one per pair the chamber judged to be
    the same underlying defect described differently across sources. MG1's exact-fingerprint
    dedupe (``sweep.dedupe`` inside ``index_sources``) already collapsed identical findings;
    this is the semantic layer on top of that. Absent the file - the chamber wasn't
    dispatched for this merge - findings pass through unchanged.
    """
    path = os.path.join(audit_dir, _GATE_DIR, "merge-dedup-decisions.json")
    if not os.path.exists(path):
        return findings, []
    with open(path, encoding="utf-8") as fh:
        decisions = json.load(fh)
    # only act on a complete decision - a "drop" with no "keep" to fold into would just
    # delete a finding outright, which is not what a dedup decision means.
    complete = [d for d in decisions if d.get("drop") and d.get("keep")]
    drop_ids = {d["drop"] for d in complete}
    notes = [
        f"{d['drop']} folded into {d['keep']}" + (f" - {d['reason']}" if d.get("reason") else "")
        for d in complete
    ]
    kept = [f for f in findings if f.id not in drop_ids]
    return kept, notes


def severity_renumber(findings: list[Finding]) -> list[Finding]:
    """Stable severity-ordered renumbering basis: highest severity/CVSS first, ties
    keep their original relative order (Python's sort is stable)."""
    return sorted(findings, key=lambda f: (-f.severity.rank, -f.cvss_score))


def _promoted_display_ids(source_dir: str) -> dict[str, str]:
    """fingerprint -> display_id, read from a source's own findings/<id>-slug/metadata.json."""
    mapping: dict[str, str] = {}
    findings_root = os.path.join(source_dir, "findings")
    if not os.path.isdir(findings_root):
        return mapping
    for name in os.listdir(findings_root):
        meta_path = os.path.join(findings_root, name, "metadata.json")
        if not os.path.exists(meta_path):
            continue
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta.get("kavach_id") and meta.get("display_id"):
            mapping[meta["kavach_id"]] = meta["display_id"]
    return mapping


def rename_map(source_dirs: list[str], promoted_dirs: list[str]) -> dict[str, str]:
    """``"<alias>:<old-display-id>"`` -> new merged display id, for findings that survived
    dedupe and promotion. A finding dropped by dedupe or below the promotion severity band
    gets no entry - there's nothing to rename it to."""
    new_ids: dict[str, str] = {}
    for d in promoted_dirs:
        with open(os.path.join(d, "metadata.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        new_ids[meta["kavach_id"]] = meta["display_id"]

    renames: dict[str, str] = {}
    for i, src in enumerate(source_dirs):
        alias = _alias(i)
        for fingerprint, old_id in _promoted_display_ids(src).items():
            if fingerprint in new_ids:
                renames[f"{alias}:{old_id}"] = new_ids[fingerprint]
    return renames


def write_rename_map(audit_dir: str, renames: dict[str, str]) -> str:
    return _write_json(audit_dir, "merge-rename-map.json", renames)


def merge_summary(audit_dir: str, decisions: dict) -> str:
    lines = ["# Merge Summary", ""]

    sources = decisions.get("sources") or []
    if sources:
        lines += ["## Sources", ""]
        for s in sources:
            lines.append(f"- `{s.get('alias', '?')}` - {s.get('path', '')} "
                        f"({s.get('count', 0)} findings)")
        lines.append("")

    dedup = decisions.get("dedup") or []
    if dedup:
        lines += ["## Deduplication decisions", ""]
        lines += [f"- {d}" for d in dedup]
        lines.append("")

    quarantined = decisions.get("quarantined") or []
    if quarantined:
        lines += ["## Quarantined (unfixable)", ""]
        lines += [f"- {q}" for q in quarantined]
        lines.append("")

    renames = decisions.get("renames") or {}
    if renames:
        lines += ["## Severity renumbering", ""]
        lines += [f"- `{old}` -> `{new}`" for old, new in renames.items()]
        lines.append("")

    path = os.path.join(audit_dir, "attack-surface", "merge-summary.md")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
