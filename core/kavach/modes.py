"""KAVACH mode/phase registry - the on-disk phase contract.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Phase ids are semantic and global: a mode names a subset of PIPELINE, never its own
ids. Keep in sync with docs/phase-reference.md; nothing else in the tree may
redeclare a phase id.
"""

from __future__ import annotations

# The pipeline. One ordered list, one id namespace. A mode is a subset of it, never a
# parallel copy - which is what eight hand-maintained lists had drifted into.
PIPELINE: tuple[str, ...] = (
    "recon", "sweep", "intent", "intel", "kb", "history", "hunt", "authz", "state",
    "spec", "probe", "crossservice", "chamber", "verify", "variant", "crosscheck",
    "poc", "report", "render",
    "inventory", "envscan", "provision", "exploit", "testgen", "certify",
    "cleanup",
)

# Selected only by --live. `cleanup` sits after them in PIPELINE so the tail runs first.
LIVE_PHASES: frozenset[str] = frozenset({
    "inventory", "envscan", "provision", "exploit", "testgen", "certify"})

_AUDIT: frozenset[str] = frozenset(p for p in PIPELINE if p not in LIVE_PHASES)

PRESETS: dict[str, frozenset[str]] = {
    "lite": frozenset({"recon", "sweep", "hunt", "poc", "render", "cleanup"}),
    "balanced": frozenset({"recon", "sweep", "intent", "intel", "kb", "hunt", "probe",
                           "chamber", "crosscheck", "poc", "report", "render", "cleanup"}),
    "deep": _AUDIT,
}

MODES: list[str] = list(PRESETS)

# `hunt` is the only phase whose roster varies by intensity: lite runs the one agent that
# owns the gate artifact, the other two run all eight domains.
PRESET_ROSTERS: dict[str, dict[str, tuple[str, ...]]] = {
    "lite": {"hunt": ("kavach-sast",)},
}

# Declared once, against the whole pipeline. A preset takes the induced subgraph.
PREREQ_EDGES: dict[str, tuple[str, ...]] = {
    "recon": (), "sweep": ("recon",), "intent": ("recon",), "intel": ("recon",),
    "kb": ("recon",), "history": ("recon",),
    "hunt": ("sweep", "kb"),
    "authz": ("kb",), "state": ("kb",), "spec": ("kb",),
    "probe": ("kb", "hunt"), "crossservice": ("hunt",),
    "chamber": ("hunt", "probe", "authz", "state", "spec", "crossservice",
                "intel", "history"),
    "verify": ("chamber",), "variant": ("verify",),
    "crosscheck": ("intent", "variant"),
    "poc": ("crosscheck",), "report": ("poc",), "render": ("report",),
    "inventory": ("render",), "envscan": ("inventory",), "provision": ("envscan",),
    "exploit": ("provision",), "testgen": ("exploit",),
    "certify": ("exploit", "testgen"),
    "cleanup": ("render", "certify"),
}


def _members(mode: str, live: bool) -> frozenset[str]:
    return PRESETS[mode] | (LIVE_PHASES if live else frozenset())


def _induced(phase: str, members: frozenset[str]) -> list[str]:
    """Prereqs restricted to `members`. An edge into a phase the preset drops is replaced
    by edges to that phase's own prerequisites, transitively - so dropping `history` moves
    chamber's dependency onto `recon` rather than leaving it unsatisfiable."""
    out: list[str] = []

    def walk(p: str) -> None:
        # `.get`, not `[]`: a phase id the registry does not know has no prerequisites,
        # the same way it has no gate, no roster and a generic spec. A stale id out of the
        # docs gets a generic prompt instead of a traceback out of the CLI.
        for q in PREREQ_EDGES.get(p, ()):
            if q in members:
                if q not in out:
                    out.append(q)
            else:
                walk(q)

    walk(phase)
    return out


PHASE_LABELS: dict[str, str] = {
    "recon": "Source Recon", "sweep": "Secret Exposure Scan",
    "intent": "Intent Cartography", "intel": "Intelligence & Dependency Risk",
    "kb": "Architecture & Threat Model", "history": "Patch History & Bypass Review",
    "hunt": "Static Analysis & Triage", "authz": "Authorization & Access Control",
    "state": "State Machine & Concurrency", "spec": "Spec, Framework & Parser Gaps",
    "probe": "Manual Attack Surface Probe", "crossservice": "Cross-Service Data Flow",
    "chamber": "Adversarial Review Chamber", "verify": "False-Positive Verification",
    "variant": "Variant Search", "crosscheck": "Intent Cross-Check",
    "poc": "Proof-of-Concept Construction", "report": "Finding Report Drafting",
    "render": "Final Report Assembly",
    "inventory": "Findings Inventory + Report Repair", "envscan": "Environment Discovery",
    "provision": "Environment Provisioning", "exploit": "Proof-of-Concept Execution",
    "testgen": "Test-Based Fallback", "certify": "Confirmation Report",
    "cleanup": "Cleanup & Redaction",
}

# phase -> executor. "core:<fn>" = deterministic engine step; else = sub-agent name.
PHASE_AGENT: dict[str, str] = {
    "recon": "core:recon", "sweep": "core:sweep",
    "intent": "kavach-intent", "intel": "kavach-intel", "kb": "kavach-kb",
    "history": "kavach-history", "hunt": "kavach-sast",
    "authz": "kavach-api", "state": "kavach-state", "spec": "kavach-spec",
    "probe": "kavach-probe", "crossservice": "kavach-crossservice",
    "chamber": "kavach-chamber", "verify": "kavach-verifier",
    "variant": "kavach-variant", "crosscheck": "kavach-intent-crosscheck",
    "poc": "kavach-poc", "report": "kavach-reporter", "render": "core:render",
    "inventory": "core:inventory", "envscan": "kavach-env-detective",
    "provision": "kavach-env-provisioner", "exploit": "kavach-poc-executor",
    "testgen": "kavach-test-mapper", "certify": "kavach-confirm-reporter",
    "cleanup": "core:cleanup",
}

# phase -> required artifact globs (relative to the audit dir) that prove completion.
# A gate is satisfied when every glob matches at least one file. Report phases add a size
# check, *-coverage.json gates a complete:true check, and `cleanup` additionally demands an
# audit dir with no transient path left in it - all enforced by runner.gate_satisfied
# (see runner.py).
#
# The two report artifacts live under reports/. runner.gate_satisfied also falls back
# to the legacy audit-root path so an existing tree still gates complete; new runs write
# reports/ only.
#
# Invariant, enforced by test_no_gate_under_transient: no gate may resolve under a path
# in cleanup.TRANSIENT. A gate that cleanup deletes makes its phase eligible again on
# every resume, which is how a run pays for the same fan-out twice.
PHASE_GATES: dict[str, list[str]] = {
    "recon": ["recon.json"], "sweep": ["sweep-summary.json"],
    "intent": ["attack-surface/intent-corpus.json"],
    "intel": ["attack-surface/advisory-summary.md"],
    "kb": ["attack-surface/knowledge-base-report.md"],
    "history": ["attack-surface/patch-bypass-summary.md"],
    "hunt": ["attack-surface/source-sink-flows-all-severities.md"],
    "authz": ["attack-surface/authz-matrix.md"],
    "state": ["attack-surface/state-concurrency-summary.md"],
    "spec": ["attack-surface/spec-gap-summary.md"],
    "probe": ["attack-surface/probe-summary.md"],
    "crossservice": ["attack-surface/cross-service-edges.json"],
    "chamber": ["attack-surface/chamber-summary.md"],
    "verify": ["attack-surface/adversarial-verification.md"],
    "variant": ["attack-surface/variant-summary.md"],
    "crosscheck": ["attack-surface/intent-crosscheck.json"],
    "poc": ["attack-surface/poc-coverage.json"],
    "report": ["attack-surface/report-coverage.json"],
    "render": ["reports/final-audit-report.md"],
    "inventory": ["attack-surface/live-inventory.json"],
    "envscan": ["attack-surface/env-strategies.json"],
    "provision": ["attack-surface/env-connection.json"],
    "exploit": ["attack-surface/poc-results.json"],
    "testgen": ["attack-surface/test-mapping.json"],
    "certify": ["reports/confirmation-report.md"],
    # Not mode-flavoured, unlike the three per-mode names it replaces: one phase shared by
    # three presets cannot gate on a filename that varies with the preset. The prefix was
    # also what re-opened cleanup for a second pass over the same audit dir; that job now
    # belongs to gate_satisfied's transient check, not to the filename.
    "cleanup": ["attack-surface/cleanup-summary.json"],
}


def phases_for(mode: str, live: bool = False) -> list[str]:
    members = _members(mode, live)
    return [p for p in PIPELINE if p in members]


def prereqs_for(mode: str, phase: str, live: bool = False) -> list[str]:
    return _induced(phase, _members(mode, live))


def gate_for(phase: str) -> list[str]:
    return list(PHASE_GATES.get(phase, []))


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

# The eight domain hunters of `hunt`, in dispatch order. kavach-sast leads because it owns
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
    "intent": PhaseSpec(
        "Mine repo-local security documentation into a cited corpus of behaviors this project "
        "declares intentional and risks it explicitly acknowledges."),
    "intel": PhaseSpec(
        "Sweep published advisories (CVE/GHSA/OSV/NVD) for the detected stack and inventory "
        "every third-party component the target relies on. Never invent an advisory id."),
    "kb": PhaseSpec(
        "Build the threat model: classify the project, map trust boundaries and data flow "
        "into DFD/CFD slices, and carve out the unauthenticated attack surface the rest of "
        "the audit leans on. Read recon.json rather than rediscovering the stack.",
        references=("attack-trees.md",)),
    "history": PhaseSpec(
        "Mine the git history for security-relevant commits carrying no CVE/GHSA label, then "
        "review each candidate patch for soundness across the seven bypass vectors. History "
        "runs first; the bypass review needs its commit context and owns the gate artifact.",
        roster=("kavach-history", "kavach-patch"), sequential=True),
    "hunt": PhaseSpec(_SCAN_TASK, roster=DOMAIN_ROSTER),
    "authz": PhaseSpec(
        "Trace every endpoint for BOLA/IDOR, BFLA, broken auth, mass assignment, excessive "
        "data exposure and missing rate limits, and write the authorization matrix."),
    "state": PhaseSpec(
        "Mine state-holding entities and concurrency primitives, then sweep for TOCTOU, "
        "isolation bugs, state-ordering violations, idempotency failures and double-submit "
        "races - the temporal bugs syntactic analysis misses."),
    "spec": PhaseSpec(
        "Find security-relevant gaps between the specs and framework contracts this codebase "
        "implements and what it actually does: parsing, normalization, canonicalization, "
        "state-machine compliance, middleware semantics."),
    "probe": PhaseSpec(
        "Probe the attack surface the domain pass just built, by hand. Scanners are done; "
        "what is left is the reasoning they cannot do.",
        references=("probe-protocol.md",)),
    "crossservice": PhaseSpec(
        "Stitch inter-component data flows into one edge graph and propagate taint across "
        "service boundaries single-codebase analysis cannot follow. A clean no-op on a "
        "single-service project is a valid result."),
    "chamber": PhaseSpec(_CHAMBER_TASK),
    "verify": PhaseSpec(_VERIFY_TASK),
    "variant": PhaseSpec(_VARIANT_TASK),
    "crosscheck": PhaseSpec(
        "Compare each draft finding against the intent corpus and emit match / partial / no "
        "/ contested per finding. Annotate; never touch severity or confirm status.",
        inputs=("attack-surface/intent-corpus.json",)),
    "poc": PhaseSpec(_POC_TASK),
    "report": PhaseSpec(_REPORT_TASK),
    "envscan": PhaseSpec(
        "Discover every way this application can be built, run and tested, plus its "
        "datastores, required env vars and auth scaffolding. Discovery only - build nothing."),
    "provision": PhaseSpec(
        "Provision the sandboxed application by walking the discovered strategies top to "
        "bottom. Refuse any target you cannot positively confirm is sandboxed or local."),
    "exploit": PhaseSpec(
        "Execute each finding's PoC against the live sandboxed application, parse its "
        "structured verdict, and record confirm_status plus evidence. State the blast radius "
        "and wait for explicit go-ahead before every exploit attempt."),
    "testgen": PhaseSpec(
        "For findings live execution could not confirm, generate a minimal inverted-assertion "
        "reproducer in the target's own test framework and run it under double-timeout "
        "discipline."),
    "certify": PhaseSpec(
        "Aggregate every confirm_status verdict this run produced into the confirmation "
        "report. The nine states are orthogonal metadata, never a second severity axis.",
        references=("certification.md",)),
}


def spec_for(phase: str) -> PhaseSpec:
    """Every phase has a contract; phases with no registry entry get the generic one so a
    caller never has to branch on presence."""
    return PHASE_SPECS.get(phase) or PhaseSpec(
        f"Execute phase {phase} ({PHASE_LABELS.get(phase, phase)}) and write its gate "
        "artifact.")


def roster_for(phase: str, mode: str) -> list[str]:
    """The agents this phase dispatches, in order. A single-agent phase returns its one
    executor; a `core:` phase returns nothing to dispatch."""
    override = PRESET_ROSTERS.get(mode, {}).get(phase)
    if override is not None:
        return list(override)
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


def inputs_for(mode: str, phase: str, live: bool = False) -> list[str]:
    """Audit-relative artifacts this phase reads. A phase's prereqs' gate artifacts are
    exactly what the phases before it produced for it, so they are inherited rather than
    restated - `findings` is a directory gate, not a file, and is dropped."""
    out = ["recon.json", "findings.json"]
    for prereq in prereqs_for(mode, phase, live):
        for artifact in gate_for(prereq):
            if artifact != "findings" and artifact not in out:
                out.append(artifact)
    for artifact in spec_for(phase).inputs:
        if artifact not in out:
            out.append(artifact)
    return out
