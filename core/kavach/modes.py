"""KAVACH mode/phase registry - the on-disk phase contract.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Phase ids are KAVACH-specific (LT/BL/DP/DF/CF/RV/MG/LS). Keep in sync with
docs/phase-reference.md; nothing else in the tree may redeclare a phase id.
"""

from __future__ import annotations

import os

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


# --- the deterministic passes a mode may not schedule for itself -----------------------
#
# `recon` walks the tree and writes `recon.json` + `file-manifest.txt`. `sweep` runs the
# scanners and is the *only* verb that writes `findings.json`. Almost everything downstream
# reads one of those: `scope` ranks the manifest, and `slice`, `triage` and `render` all
# read findings.json.
#
# `lite` opens with `core:recon` and `core:sweep`, so it prepares itself. `balanced`, `deep`,
# `longshot` and `revisit` list neither. SKILL.md tells an orchestrator to run recon up front
# for the two modes it names, but the requirement is not special to them and it is not only
# recon - a `balanced` run driven without a sweep sends every hunter an empty slice and then
# fails in its report tail on a findings.json nothing wrote.
#
# Reported as data rather than left in prose, so a harness does not have to carry the list.
PREREQ_ARTIFACTS: tuple[tuple[str, str, str], ...] = (
    ("recon", "recon.json", "core:recon"),
    ("sweep", "findings.json", "core:sweep"),
)


def missing_prerequisites(audit_dir: str, mode: str) -> list[dict]:
    """Which deterministic passes this mode needs, does not schedule, and does not have."""
    scheduled = {PHASE_AGENT.get(p, "") for p in phases_for(mode)}
    missing = []
    for verb, artifact, executor in PREREQ_ARTIFACTS:
        if executor in scheduled:
            continue
        if os.path.exists(os.path.join(os.path.abspath(audit_dir), artifact)):
            continue
        missing.append({"verb": verb, "artifact": artifact})
    return missing


# --- the dispatch contract -------------------------------------------------------------
#
# What a phase asks of the agent running it. This lived in SKILL.md prose, which meant
# every harness that was not SKILL.md had to re-read that prose and re-encode it - and
# drift from it silently. `dispatch.compose_prompt` renders these, so `kavach phase-prompt`
# returns a prompt that can be dispatched as-is.
#
# `task` is the imperative; the agent's own `agents/<name>.md` carries the method, so these
# stay short on purpose. `references` are skill-relative and resolved by `paths.reference`.
# `inputs` are audit-relative and *additive*: a phase already inherits its prereqs' gate
# artifacts as inputs (see `inputs_for`), because those are exactly what the prior phases
# produced for it to read.

BASE_REFERENCES: tuple[str, ...] = ("persona.md", "finding-schema.md", "severity-model.md")

# The eight domain hunters of BL3/DP4, in dispatch order. kavach-sast leads because it owns
# the phase's literal gate artifact, so the gate can close in the first batch.
DOMAIN_ROSTER: tuple[str, ...] = (
    "kavach-sast", "kavach-api", "kavach-llm", "kavach-billing",
    "kavach-crypto", "kavach-supply", "kavach-config", "kavach-logic",
)

# Reference files an agent needs whatever phase dispatches it, on top of BASE_REFERENCES.
AGENT_REFERENCES: dict[str, tuple[str, ...]] = {
    "kavach-sast": ("domains/sast.md",),
    "kavach-api": ("domains/api.md",),
    "kavach-llm": ("domains/llm.md",),
    "kavach-billing": ("domains/billing.md",),
    "kavach-crypto": ("domains/crypto.md",),
    "kavach-supply": ("domains/supply.md",),
    "kavach-config": ("domains/config.md", "insecure-defaults.md"),
    "kavach-logic": ("domains/logic.md",),
    "kavach-chamber": ("chamber-protocol.md", "creative-attack-modes.md", "attack-trees.md"),
    "kavach-ideator": ("creative-attack-modes.md", "attack-trees.md"),
    "kavach-tracer": ("chamber-protocol.md",),
    "kavach-advocate": ("chamber-protocol.md", "vuln-class-applicability.md"),
    "kavach-probe": ("probe-protocol.md",),
    "kavach-reasoner-backward": ("probe-protocol.md",),
    "kavach-reasoner-contradiction": ("probe-protocol.md",),
    "kavach-harvester": ("probe-protocol.md", "verification-gates.md"),
    "kavach-verifier": ("verification-gates.md", "vuln-class-applicability.md"),
    "kavach-variant": ("attack-trees.md",),
    "kavach-variant-scout": ("attack-trees.md",),
    "kavach-reporter": ("report-template.md", "report-structure.md"),
    "kavach-confirm-reporter": ("report-template.md", "certification.md"),
    "kavach-spec": ("parser-differentials.md",),
    "kavach-poc": ("probe-protocol.md",),
    "kavach-poc-executor": ("probe-protocol.md",),
    "kavach-intel": ("tool-catalog.md",),
}


class PhaseSpec:
    """One phase's dispatch contract. Frozen by convention, not by dataclass - the registry
    is module-level constant data and nothing mutates it."""

    __slots__ = ("task", "references", "inputs", "roster", "sequential")

    def __init__(self, task: str, *, references: tuple[str, ...] = (),
                 inputs: tuple[str, ...] = (), roster: tuple[str, ...] = (),
                 sequential: bool = False):
        self.task = task
        self.references = references
        self.inputs = inputs
        self.roster = roster
        self.sequential = sequential


_SCAN_TASK = (
    "Treat every scanner hit in your slice as a lead, not a finding: open the cited "
    "file:line, read it, and either confirm it or drop it as a false positive with the "
    "reason. Then hunt what the scanners cannot see in your domain. Every finding cites a "
    "real file:line you have read; every 'control present' claim cites the enforcing line."
)
_POC_TASK = (
    "Build the proof-of-concept for the finding directory you were given - a minimized, "
    "parameterized exploit script, or a theoretical write-up when no live target is "
    "authorized - and write the PoC metadata back into that finding's draft."
)
_REPORT_TASK = (
    "Read the finding directory cold and author its disclosure-ready, self-contained "
    "report.md per the vuln-report contract. No pointers back to a draft, a debate, or a "
    "phase id. Skip a report.md that already satisfies the contract."
)
_CHAMBER_TASK = (
    "Run the review chamber over the clustered attack surface: ideate hypotheses, trace "
    "each through real code, have the advocate build the strongest defense, then weigh "
    "both sides and write drafts only for what survives with calibrated severity."
)
_VERIFY_TASK = (
    "Cold-verify this Critical/High finding with no context from whatever produced it. "
    "Re-trace the path from scratch, re-run the five-layer protection search, and issue "
    "CONFIRMED or DISPROVED against the fixed list of rationalizations you may not accept."
)
_VARIANT_TASK = (
    "Take this confirmed finding's root-cause pattern and search the whole codebase for the "
    "same bug elsewhere - detection signature, sibling components, alternate transports. "
    "Validate each candidate independently before writing it as a new draft."
)

PHASE_SPECS: dict[str, PhaseSpec] = {
    # lite
    "LT2": PhaseSpec(_SCAN_TASK + " You own this phase's gate artifact.",
                     roster=("kavach-sast",)),
    "LT3": PhaseSpec(_POC_TASK),
    # balanced
    "BL1": PhaseSpec(
        "Sweep published advisories (CVE/GHSA/OSV/NVD) for the detected stack and inventory "
        "every third-party component the target relies on. Never invent an advisory id."),
    "BL2": PhaseSpec(
        "Build the threat model: classify the project, map trust boundaries and data flow "
        "into DFD/CFD slices, and carve out the unauthenticated attack surface the rest of "
        "the audit leans on. Read recon.json rather than rediscovering the stack.",
        references=("attack-trees.md",)),
    "BL3": PhaseSpec(_SCAN_TASK, roster=DOMAIN_ROSTER),
    "BL4": PhaseSpec(
        "Probe the attack surface the domain pass just built, by hand. Scanners are done; "
        "what is left is the reasoning they cannot do.",
        references=("probe-protocol.md",)),
    "BL5": PhaseSpec(_CHAMBER_TASK),
    "BL6": PhaseSpec(_POC_TASK),
    "BL6b": PhaseSpec(_REPORT_TASK),
    # deep
    "DP1": PhaseSpec(
        "Sweep published advisories (CVE/GHSA/OSV/NVD) for the detected stack and inventory "
        "every third-party component the target relies on. Never invent an advisory id."),
    "DP2": PhaseSpec(
        "Mine the git history for security-relevant commits carrying no CVE/GHSA label, then "
        "review each candidate patch for soundness across the seven bypass vectors. History "
        "runs first; the bypass review needs its commit context and owns the gate artifact.",
        roster=("kavach-history", "kavach-patch"), sequential=True),
    "DP3": PhaseSpec(
        "Build the threat model: classify the project, map trust boundaries and data flow "
        "into DFD/CFD slices, and carve out the unauthenticated attack surface the rest of "
        "the audit leans on. Read recon.json rather than rediscovering the stack.",
        references=("attack-trees.md",)),
    "DP4": PhaseSpec(_SCAN_TASK, roster=DOMAIN_ROSTER),
    "DP5": PhaseSpec(
        "Trace every endpoint for BOLA/IDOR, BFLA, broken auth, mass assignment, excessive "
        "data exposure and missing rate limits, and write the authorization matrix."),
    "DP6": PhaseSpec(
        "Mine state-holding entities and concurrency primitives, then sweep for TOCTOU, "
        "isolation bugs, state-ordering violations, idempotency failures and double-submit "
        "races - the temporal bugs syntactic analysis misses."),
    "DP7": PhaseSpec(
        "Find security-relevant gaps between the specs and framework contracts this codebase "
        "implements and what it actually does: parsing, normalization, canonicalization, "
        "state-machine compliance, middleware semantics."),
    "DP8": PhaseSpec(
        "Run the deep-probe team over each component: map the attack surface, dispatch both "
        "reasoners in parallel for independent hypothesis rounds, cross-pollinate, then "
        "harvest causal-challenged evidence before any verdict.",
        references=("probe-protocol.md",)),
    "DP9": PhaseSpec(
        "Stitch inter-component data flows into one edge graph and propagate taint across "
        "service boundaries single-codebase analysis cannot follow. A clean no-op on a "
        "single-service project is a valid result."),
    "DP10": PhaseSpec(_CHAMBER_TASK),
    "DP11": PhaseSpec(_VERIFY_TASK),
    "DP12": PhaseSpec(_VARIANT_TASK),
    "DP13": PhaseSpec(_POC_TASK),
    "DP14": PhaseSpec(_REPORT_TASK),
    "DP16": PhaseSpec(
        "Aggregate every confirm_status verdict this run produced into the confirmation "
        "report. The nine states are orthogonal metadata, never a second severity axis.",
        references=("certification.md",)),
    # diff
    "DF1": PhaseSpec(
        _SCAN_TASK + " Scope yourself to the changed files named in "
        "attack-surface/diff-scope.md - nothing outside that set is in scope for this run.",
        inputs=("attack-surface/diff-scope.md",), roster=("kavach-sast",)),
    # confirm
    "CF1_5": PhaseSpec(
        "Compare each draft finding against the intent corpus and emit match / partial / no "
        "/ contested per finding. Annotate; never touch severity or confirm status.",
        inputs=("attack-surface/intent-corpus.json",)),
    "CF2": PhaseSpec(
        "Discover every way this application can be built, run and tested, plus its "
        "datastores, required env vars and auth scaffolding. Discovery only - build nothing."),
    "CF3": PhaseSpec(
        "Provision the sandboxed application by walking the discovered strategies top to "
        "bottom. Refuse any target you cannot positively confirm is sandboxed or local."),
    "CF4": PhaseSpec(
        "Execute each finding's PoC against the live sandboxed application, parse its "
        "structured verdict, and record confirm_status plus evidence. State the blast radius "
        "and wait for explicit go-ahead before every exploit attempt."),
    "CF5": PhaseSpec(
        "For findings live execution could not confirm, generate a minimal inverted-assertion "
        "reproducer in the target's own test framework and run it under double-timeout "
        "discipline."),
    "CF6": PhaseSpec(
        "Aggregate every confirm_status verdict this run produced into the confirmation "
        "report. The nine states are orthogonal metadata, never a second severity axis.",
        references=("certification.md",)),
    # revisit
    "RV0": PhaseSpec(
        "Mine repo-local security documentation into a cited corpus of behaviors this project "
        "declares intentional and risks it explicitly acknowledges."),
    "RV5": PhaseSpec(
        "Probe the target fresh, with the known findings held out, so this pass can only "
        "surface what the prior audit missed.",
        references=("probe-protocol.md",)),
    "RV7": PhaseSpec(_SCAN_TASK, roster=("kavach-sast",)),
    "RV8": PhaseSpec(_CHAMBER_TASK),
    "RV9": PhaseSpec(_VERIFY_TASK),
    "RV10": PhaseSpec(_VARIANT_TASK),
    "RV10k": PhaseSpec(_VARIANT_TASK + " These are the findings already known from the prior "
                       "audit - you are checking whether each has spread, not re-proving it."),
    "RV11": PhaseSpec(_POC_TASK),
    "RV11b": PhaseSpec(_REPORT_TASK),
    # merge
    "MG2": PhaseSpec(
        "Collapse semantic near-duplicates across the source finding sets and record every "
        "dedup decision. Two findings with the same root cause at the same location are one."),
    # longshot
    "LS2": PhaseSpec(
        "Anchor on the single source file you were given, follow its imports and callers "
        "across the repo, and produce evidence-anchored drafts with strict path:line "
        "citations. A no-finding marker is a valid, expected result."),
    "LS3": PhaseSpec(
        "Read every per-anchor draft the swarm produced, deduplicate by root cause, rank by "
        "severity and confidence, and report honestly what you dropped and why."),
}


def spec_for(phase: str) -> PhaseSpec:
    """Every phase has a contract; phases with no registry entry get the generic one so a
    caller never has to branch on presence."""
    return PHASE_SPECS.get(phase) or PhaseSpec(
        f"Execute phase {phase} ({PHASE_LABELS.get(phase, phase)}) and write its gate "
        "artifact.")


def roster_for(phase: str) -> list[str]:
    """The agents this phase dispatches, in order. A single-agent phase returns its one
    executor; a `core:` phase returns nothing to dispatch."""
    spec = PHASE_SPECS.get(phase)
    if spec is not None and spec.roster:
        return list(spec.roster)
    agent = PHASE_AGENT.get(phase, "")
    return [] if not agent or agent.startswith("core:") else [agent]


def references_for(phase: str, agent: str | None = None) -> list[str]:
    """Skill-relative reference paths for one dispatch, deduplicated, in load order."""
    out: list[str] = []
    for name in BASE_REFERENCES + spec_for(phase).references + AGENT_REFERENCES.get(agent or "", ()):
        if name not in out:
            out.append(name)
    return out


def inputs_for(mode: str, phase: str) -> list[str]:
    """Audit-relative artifacts this phase reads. A phase's prereqs' gate artifacts are
    exactly what the phases before it produced for it, so they are inherited rather than
    restated - `findings` is a directory gate, not a file, and is dropped."""
    out = ["recon.json", "findings.json"]
    for prereq in prereqs_for(mode, phase):
        for artifact in gate_for(prereq):
            if artifact != "findings" and artifact not in out:
                out.append(artifact)
    for artifact in spec_for(phase).inputs:
        if artifact not in out:
            out.append(artifact)
    return out
