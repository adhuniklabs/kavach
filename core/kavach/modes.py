"""KAVACH mode/phase registry - the on-disk phase contract.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Phase ids are KAVACH-specific (LT/BL/DP/DF/CF/RV/MG/LS). Keep in sync with
docs/phase-reference.md; nothing else in the tree may redeclare a phase id.
"""

from __future__ import annotations

MODE_PHASES: dict[str, list[str]] = {
    "lite": ["LT0", "LT1", "LT2", "LT3", "LT4"],
    "balanced": ["BL1", "BL2", "BL3", "BL4", "BL5", "BL6", "BL6b", "BL6c", "BL7"],
    "deep": [f"DP{i}" for i in range(1, 18)],
    "diff": ["DF1"],
    "confirm": ["CF1", "CF1_5", "CF2", "CF3", "CF4", "CF5", "CF6", "CF7"],
    "revisit": ["RV0", "RV5", "RV7", "RV8", "RV9", "RV10", "RV10k", "RV11", "RV11b", "RV11c"],
    "merge": ["MG1", "MG2", "MG3", "MG4", "MG5", "MG6", "MG7"],
    "longshot": ["LS1", "LS2", "LS3"],
}

MODES: list[str] = list(MODE_PHASES.keys())

# mode -> phase -> prerequisite phases (empty = eligible once the run starts).
# Deep's DAG is ported verbatim from piolium; other modes are linear (each phase
# depends on its predecessor) unless noted.
_DEEP_PREREQS: dict[str, list[str]] = {
    "DP1": [], "DP2": [], "DP3": [],
    "DP4": ["DP3"],
    "DP5": ["DP3"], "DP6": ["DP3"], "DP7": ["DP3"],
    "DP8": ["DP3", "DP4"],
    "DP9": ["DP4", "DP8"],
    "DP10": ["DP5", "DP6", "DP7", "DP8", "DP9"],
    "DP11": ["DP10"], "DP12": ["DP11"], "DP13": ["DP12"],
    "DP14": ["DP13"], "DP15": ["DP14"], "DP16": ["DP15"], "DP17": ["DP16"],
}


def _linear_prereqs(phases: list[str]) -> dict[str, list[str]]:
    return {p: ([phases[i - 1]] if i else []) for i, p in enumerate(phases)}


PREREQS: dict[str, dict[str, list[str]]] = {
    m: (_DEEP_PREREQS if m == "deep" else _linear_prereqs(MODE_PHASES[m])) for m in MODES
}

PHASE_LABELS: dict[str, str] = {
    # lite
    "LT0": "Source Recon", "LT1": "Secret Exposure Scan", "LT2": "Fast Static Analysis",
    "LT3": "PoC + Consolidate", "LT4": "Verify & Cleanup",
    # balanced
    "BL1": "Intelligence & Dependency Risk", "BL2": "Architecture & Threat Model",
    "BL3": "Static Analysis & Triage", "BL4": "Manual Attack Surface Probe",
    "BL5": "Adversarial Review & FP Check", "BL6": "Proof-of-Concept Construction",
    "BL6b": "Finding Report Drafting", "BL6c": "Final Report Assembly",
    "BL7": "Verification & Cleanup",
    # deep
    "DP1": "Intelligence & Dependency Risk", "DP2": "Patch History & Bypass Review",
    "DP3": "Architecture & Threat Model", "DP4": "Static Analysis & Triage",
    "DP5": "Authorization & Access Control", "DP6": "State Machine & Concurrency",
    "DP7": "Spec, Framework & Parser Gaps", "DP8": "Manual Attack Surface Probe",
    "DP9": "Cross-Service Data Flow", "DP10": "Adversarial Review Chamber",
    "DP11": "False-Positive Verification", "DP12": "Variant Search",
    "DP13": "Proof-of-Concept Construction", "DP14": "Finding Report Drafting",
    "DP15": "Final Report Assembly", "DP16": "Finding Verification", "DP17": "Cleanup",
    # diff
    "DF1": "Changed-file Scan",
    # confirm
    "CF1": "Findings Inventory + Report Repair", "CF1_5": "Intent Cross-Check",
    "CF2": "Environment Discovery", "CF3": "Environment Provisioning",
    "CF4": "Proof-of-Concept Execution", "CF5": "Test-Based Fallback",
    "CF6": "Confirmation Report", "CF7": "Cleanup & Redaction",
    # revisit
    "RV0": "Intent Cartography", "RV5": "Fresh Deep Probe", "RV7": "SAST Reclassification",
    "RV8": "Fresh Review Chambers", "RV9": "False-Positive Verification",
    "RV10": "New Finding Variants", "RV10k": "Known Finding Variants",
    "RV11": "Proof-of-Concept Construction", "RV11b": "Finding Report Drafting",
    "RV11c": "Final Report Assembly",
    # merge
    "MG1": "Copy & Index", "MG2": "Semantic Deduplication", "MG3": "Metadata Auto-Fix",
    "MG4": "Quarantine Unfixable", "MG5": "Severity Renumbering",
    "MG6": "Apply Finding Renames", "MG7": "Final Report Assembly",
    # longshot
    "LS1": "Target Enumeration", "LS2": "Per-File Hail-Mary Hunt", "LS3": "Finding Aggregation",
}

# phase -> executor. "core:<fn>" = deterministic engine step; else = sub-agent name.
PHASE_AGENT: dict[str, str] = {
    "LT0": "core:recon", "LT1": "core:sweep", "LT2": "kavach-sast",
    "LT3": "kavach-poc", "LT4": "core:cleanup",
    "BL1": "kavach-intel", "BL2": "kavach-kb", "BL3": "kavach-sast", "BL4": "kavach-probe",
    "BL5": "kavach-chamber", "BL6": "kavach-poc", "BL6b": "kavach-reporter",
    "BL6c": "core:render", "BL7": "core:cleanup",
    "DP1": "kavach-intel", "DP2": "kavach-history", "DP3": "kavach-kb", "DP4": "kavach-sast",
    "DP5": "kavach-api", "DP6": "kavach-state", "DP7": "kavach-spec", "DP8": "kavach-probe",
    "DP9": "kavach-crossservice", "DP10": "kavach-chamber", "DP11": "kavach-verifier",
    "DP12": "kavach-variant", "DP13": "kavach-poc", "DP14": "kavach-reporter",
    "DP15": "core:render", "DP16": "kavach-confirm-reporter", "DP17": "core:cleanup",
    "DF1": "kavach-sast",
    "CF1": "core:inventory", "CF1_5": "kavach-intent-crosscheck", "CF2": "kavach-env-detective",
    "CF3": "kavach-env-provisioner", "CF4": "kavach-poc-executor", "CF5": "kavach-test-mapper",
    "CF6": "kavach-confirm-reporter", "CF7": "core:cleanup",
    "RV0": "kavach-intent", "RV5": "kavach-probe", "RV7": "kavach-sast", "RV8": "kavach-chamber",
    "RV9": "kavach-verifier", "RV10": "kavach-variant", "RV10k": "kavach-variant",
    "RV11": "kavach-poc", "RV11b": "kavach-reporter", "RV11c": "core:render",
    "MG1": "core:merge", "MG2": "kavach-chamber", "MG3": "core:merge", "MG4": "core:merge",
    "MG5": "core:merge", "MG6": "core:merge", "MG7": "core:render",
    "LS1": "core:enumerate", "LS2": "kavach-longshot-hunter", "LS3": "kavach-longshot-aggregator",
}

# phase -> required artifact globs (relative to the audit dir) that prove completion.
# A gate is satisfied when every glob matches at least one file. Report phases add a
# size check and *-coverage.json gates a complete:true check, both enforced by
# runner.gate_satisfied (see runner.py).
#
# The two report artifacts live under reports/. runner.gate_satisfied also falls back
# to the legacy audit-root path so an existing tree still gates complete; new runs write
# reports/ only.
#
# Invariant, enforced by test_no_gate_under_transient: no gate may resolve under a path
# in cleanup.TRANSIENT. A gate that cleanup deletes makes its phase eligible again on
# every resume, which is how a run pays for the same fan-out twice.
PHASE_GATES: dict[str, list[str]] = {
    "LT0": ["recon.json"], "LT1": ["sweep-summary.json"], "LT2": ["attack-surface/lite-q2-summary.md"],
    "LT3": ["attack-surface/poc-coverage.json"], "LT4": ["attack-surface/lite-cleanup-summary.json"],
    "BL1": ["attack-surface/advisory-summary.md"], "BL2": ["attack-surface/knowledge-base-report.md"],
    "BL3": ["attack-surface/source-sink-flows-all-severities.md"],
    "BL4": ["attack-surface/manual-attack-surface-inventory.md"],
    "BL5": ["attack-surface/balanced-chamber-summary.md"],
    "BL6": ["attack-surface/poc-coverage.json"], "BL6b": ["attack-surface/report-coverage.json"],
    "BL6c": ["reports/final-audit-report.md"],
    "BL7": ["attack-surface/balanced-cleanup-summary.json"],
    "DP1": ["attack-surface/advisory-summary.md"], "DP2": ["attack-surface/patch-bypass-summary.md"],
    "DP3": ["attack-surface/knowledge-base-report.md"],
    "DP4": ["attack-surface/source-sink-flows-all-severities.md"],
    "DP5": ["attack-surface/authz-matrix.md"], "DP6": ["attack-surface/state-concurrency-summary.md"],
    "DP7": ["attack-surface/spec-gap-summary.md"], "DP8": ["attack-surface/deep-probe-summary.md"],
    "DP9": ["attack-surface/cross-service-edges.json"],
    "DP10": ["attack-surface/deep-chamber-summary.md"],
    "DP11": ["attack-surface/adversarial-verification.md"],
    "DP12": ["attack-surface/variant-summary.md"],
    "DP13": ["attack-surface/poc-coverage.json"], "DP14": ["attack-surface/report-coverage.json"],
    "DP15": ["reports/final-audit-report.md"],
    "DP16": ["reports/confirmation-report.md"],
    "DP17": ["attack-surface/deep-cleanup-summary.json"],
    "DF1": ["attack-surface/diff-summary.md"],
    "CF1": ["attack-surface/confirm-findings-inventory.json"],
    "CF1_5": ["attack-surface/confirm-intent-crosscheck.json"],
    "CF2": ["attack-surface/confirm-env-strategies.json"],
    "CF3": ["attack-surface/confirm-env-connection.json"],
    "CF4": ["attack-surface/confirm-poc-results.json"],
    "CF5": ["attack-surface/confirm-test-mapping.json"],
    "CF6": ["reports/confirmation-report.md"],
    "CF7": ["attack-surface/confirm-cleanup-summary.json"],
    "RV0": ["attack-surface/intent-corpus.json"], "RV5": ["attack-surface/revisit-probe-summary.md"],
    "RV7": ["attack-surface/revisit-r7-chamber-summary.md"], "RV8": ["attack-surface/revisit-r8-chamber-summary.md"],
    "RV9": ["findings"], "RV10": ["findings"], "RV10k": ["findings"],
    "RV11": ["attack-surface/poc-coverage.json"], "RV11b": ["attack-surface/report-coverage.json"],
    "RV11c": ["reports/final-audit-report.md"],
    "MG1": ["attack-surface/merge-index.json"], "MG2": ["attack-surface/merge-dedup-decisions.json"],
    "MG3": ["attack-surface/merge-index.json"], "MG4": ["attack-surface/merge-index.json"],
    "MG5": ["attack-surface/merge-rename-map.json"],
    "MG6": ["findings"], "MG7": ["reports/final-audit-report.md"],
    "LS1": ["attack-surface/longshot-targets.json"],
    "LS2": ["attack-surface/longshot-hunt-summary.json"],
    "LS3": ["attack-surface/longshot-summary.md"],
}


def phases_for(mode: str) -> list[str]:
    return list(MODE_PHASES[mode])


def prereqs_for(mode: str, phase: str) -> list[str]:
    return list(PREREQS[mode].get(phase, []))


def gate_for(phase: str) -> list[str]:
    return list(PHASE_GATES.get(phase, []))
