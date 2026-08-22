"""Per-agent slices of the finding set.

SKILL.md tells the coordinator to hand each domain hunter "its slice of findings.json"
and gives it no way to cut one, so every harness invented its own - or, more often, sent
the whole file to all eight hunters and paid for it eight times. On a repo where the sweep
returns 300 rows that is the single largest avoidable cost in a balanced audit.

A slice is a *lead list*, not a verdict: the hunter still opens each cited line and decides.
So the cut is deliberately generous on its own axis and honest about what it left out -
`excluded` travels with the slice, because a hunter that thinks it saw everything will
report coverage it does not have.
"""

from __future__ import annotations

import json
import os

from .finding import Finding, load_findings
from .triage import sources

# Which scanner ids and category prefixes are a given domain's leads. A domain with no
# scanner behind it (logic, billing) is manual by nature - it gets the reasoned findings
# and its own category prefixes, which is exactly the point of dispatching it at all.
DOMAIN_LEADS: dict[str, dict[str, tuple[str, ...]]] = {
    "kavach-sast": {
        "sources": ("gitleaks", "trufflehog", "builtin-secrets", "rust-secret-apis",
                    "semgrep", "bandit", "gosec"),
        "categories": ("A03", "A07", "A08", "A10"),
    },
    "kavach-api": {"sources": (), "categories": ("API", "A01", "A04")},
    "kavach-llm": {"sources": (), "categories": ("LLM",)},
    "kavach-billing": {"sources": (), "categories": ("Billing",)},
    "kavach-crypto": {"sources": ("rust-secret-apis",), "categories": ("A02",)},
    "kavach-supply": {
        "sources": ("trivy", "pip-audit", "npm-audit", "osv-scanner", "guarddog"),
        "categories": ("A06", "Supply-Chain"),
    },
    "kavach-config": {
        "sources": ("checkov", "kics", "hadolint"),
        "categories": ("A05", "A09"),
    },
    "kavach-logic": {"sources": (), "categories": ("Logic", "A04")},
}


def matches(finding: Finding, agent: str) -> bool:
    leads = DOMAIN_LEADS.get(agent)
    if leads is None:
        return True
    if set(sources(finding)) & set(leads["sources"]):
        return True
    category = (finding.category or "").upper()
    return any(category.startswith(p.upper()) for p in leads["categories"])


def slice_for(findings: list[Finding], agent: str) -> tuple[list[Finding], int]:
    """(this agent's leads, how many findings were left out)."""
    if agent not in DOMAIN_LEADS:
        return list(findings), 0
    mine = [f for f in findings if matches(f, agent)]
    return mine, len(findings) - len(mine)


def write_slice(audit_dir: str, phase: str, agent: str, *, index: int | None = None) -> dict:
    """Cut the slice and land it beside the dispatch that will read it."""
    from .findings_tree import slugify

    findings = load_findings(os.path.join(audit_dir, "findings.json"))
    mine, excluded = slice_for(findings, agent)
    stem = slugify(agent) if index is None else f"{slugify(agent)}-{index}"
    d = os.path.join(os.path.abspath(audit_dir), "runs", slugify(phase), "slices")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, f"{stem}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({
            "agent": agent, "phase": phase, "included": len(mine), "excluded": excluded,
            "note": ("Leads for your domain only. The audit holds "
                     f"{len(findings)} finding(s); {excluded} belong to other domains and are "
                     "not yours to confirm or refute."),
            "findings": [f.to_dict() for f in mine],
        }, fh, indent=2)
    return {"path": path, "included": len(mine), "excluded": excluded, "total": len(findings)}
