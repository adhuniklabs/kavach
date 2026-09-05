"""attack-surface/ knowledge-base writers + KAVACH kill-chains renderer.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
"""

from __future__ import annotations

import os


def _as_dir(audit_dir: str) -> str:
    d = os.path.join(audit_dir, "attack-surface")
    os.makedirs(d, exist_ok=True)
    return d


def write_section(audit_dir: str, filename: str, heading: str, body: str) -> str:
    path = os.path.join(_as_dir(audit_dir), filename)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"## {heading}\n\n{body}\n\n")
    return path


def write_kill_chains(audit_dir: str, chains: list[dict]) -> str:
    lines = ["# Kill Chains", ""]
    for c in chains:
        lines += [f"## Kill chain {c['letter']} - {c['goal']}", ""]
        for leaf in c.get("leaves", []):
            ref = f" ({leaf['ref']})" if leaf.get("ref") else ""
            lines.append(f"- {leaf['technique']} → **{leaf['status']}**{ref}")
        lines += ["", f"Chain verdict: **{c.get('verdict', 'UNKNOWN')}**", ""]
    path = os.path.join(_as_dir(audit_dir), "kill-chains.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
