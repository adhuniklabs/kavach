"""SARIF 2.1.0 - for GitHub code-scanning and any SARIF-aware CI."""

from __future__ import annotations

import json

from ..finding import Finding, Severity
from ..score import GateResult

_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}


def render(findings: list[Finding], recon: dict, gate: GateResult, meta: dict) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_key = f.rule_id or f.category or f.id
        if rule_key not in rules:
            rules[rule_key] = {
                "id": rule_key,
                "name": f.category or "finding",
                "shortDescription": {"text": f.title[:120]},
                "properties": {"security-severity": f"{f.cvss_score:.1f}"},
            }
        loc = f.locations[0] if f.locations else None
        results.append({
            "ruleId": rule_key,
            "level": _LEVEL[f.severity],
            "message": {"text": f.what_it_is or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": (loc.file if loc else "").lstrip("/")},
                    **({"region": {"startLine": loc.line}} if loc and loc.line else {}),
                }
            }] if loc else [],
            "properties": {"severity": f.severity.value, "source": f.source,
                           "confidence": f.confidence.value, "kavachId": f.id,
                           "findingClass": f.finding_class},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "KAVACH",
                "informationUri": "https://github.com/",
                "version": meta.get("version", "0.1.0"),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
