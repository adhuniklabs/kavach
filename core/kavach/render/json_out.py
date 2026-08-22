"""Machine-readable JSON report.

Carries the derived model as well as the raw findings, so Annex C's ``jq`` commands can
recompute every quantified claim in the human-facing renderings from this one file.
"""

from __future__ import annotations

import json

from ..finding import Finding
from ..score import GateResult
from . import model


def render(findings: list[Finding], recon: dict, gate: GateResult, meta: dict) -> str:
    report = model.build(findings, recon, gate, meta)
    return json.dumps({
        "meta": meta,
        "gate": gate.to_dict(),
        "stack": {k: recon.get(k) for k in (
            "languages", "frameworks", "datastores", "orms", "auth",
            "llm_providers", "payment_processors", "cloud")},
        "totals": recon.get("totals", {}),
        "class_counts": report.class_counts,
        "scorecard": report.scorecard.to_dict(),
        "promoted": report.promoted,
        "remediation": report.remediation,
        "frameworks": report.to_dict()["frameworks"],
        "limits": report.limits,
        "figure_commands": report.to_dict()["figure_commands"],
        # report.findings, not the argument: the model classifies on load, and a jq recompute
        # of class_counts off a raw findings[] would disagree with the class_counts printed
        # beside it - which is the one property this file exists to provide.
        "findings": [f.to_dict() for f in report.findings],
    }, indent=2)
