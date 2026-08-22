"""Per-finding report.md renderer - the vuln-report disclosure contract.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Reports must be self-contained: no pointers to drafts, debates, or phase ids.
"""

from __future__ import annotations

import os

from .finding import Finding

_SECTIONS = ("## Summary", "## Details", "## Root Cause", "## Proof of Concept", "## Impact")
_BANNED = ("see draft", "see debate", "see the draft", "above finding", "phase ")
_MIN_BYTES = 500


def _locations(finding: Finding) -> str:
    return ", ".join(
        f"`{loc.file}:{loc.line}`" if loc.line else f"`{loc.file}`" for loc in finding.locations
    ) or "_none recorded_"


def render_report(finding: Finding, *, commit: str = "") -> str:
    conf = "Confirmed-in-code" if finding.confidence.value == "confirmed" else "Suspected"
    pin = f" @ `{commit}`" if commit else ""
    return "\n".join([
        f"# {finding.title}",
        "",
        f"- **Severity:** {finding.severity.value.upper()} · **CVSS:** {finding.cvss_score} "
        f"(`{finding.cvss_vector}`) · **Confidence:** {conf}",
        f"- **Category:** {finding.category} · **Location(s):** {_locations(finding)}{pin}",
        "",
        "## Summary", "", finding.what_it_is or "_pending_", "",
        "## Details", "", finding.what_it_is or "_pending_", "",
        "## Root Cause", "", finding.remediation and f"Root cause addressed by: {finding.remediation}"
        or "_pending_", "",
        "## Proof of Concept", "", finding.how_exploited or "_theoretical - see poc.theoretical.md_", "",
        "## Impact", "", finding.business_impact or "_pending_", "",
    ])


def is_complete(text: str) -> bool:
    """The vuln-report contract: five H2 sections in order, >500 bytes, no pointer phrase.

    coverage.py gates the report phases on this predicate, so it is the one place the
    contract is defined - both for agent-written reports and for core-written aggregates.
    """
    if len(text.encode("utf-8")) < _MIN_BYTES:
        return False
    cursor = 0
    for heading in _SECTIONS:
        at = text.find(heading, cursor)
        if at < 0:
            return False
        cursor = at + len(heading)
    lowered = text.lower()
    return not any(b in lowered for b in _BANNED)


def write_report(finding_dir: str, finding: Finding, *, commit: str = "") -> str | None:
    path = os.path.join(finding_dir, "report.md")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            if is_complete(fh.read()):
                return None
    os.makedirs(finding_dir, exist_ok=True)
    text = render_report(finding, commit=commit)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
