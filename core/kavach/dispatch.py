"""The engine↔skill seam: run dirs, runtime headers, prompt composition, ingest.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
The engine composes prompts and folds results; SKILL.md issues the Task calls.
"""

from __future__ import annotations

import glob
import os
import re
import uuid

from filelock import FileLock

from . import modes, paths
from .finding import load_findings
from .findings_tree import slugify, write_draft


def run_id(phase: str, audit_id: str, attempt: int) -> str:
    clean = audit_id.replace(":", "").replace(".", "")
    return f"{phase}-{clean}-a{attempt}-{uuid.uuid4().hex[:8]}"


def make_run_dir(audit_dir: str, phase: str, audit_id: str, attempt: int) -> str:
    d = os.path.join(audit_dir, "tmp", "runs", run_id(phase, audit_id, attempt))
    os.makedirs(d, exist_ok=True)
    return d


def result_path(audit_dir: str, phase: str, agent: str, *, index: int | None = None) -> str:
    d = os.path.join(os.path.abspath(audit_dir), "runs", slugify(phase))
    os.makedirs(d, exist_ok=True)
    stem = slugify(agent) if index is None else f"{slugify(agent)}-{index}"
    return os.path.join(d, f"{stem}.json")


def result_glob(audit_dir: str, phase: str) -> str:
    return os.path.join(os.path.abspath(audit_dir), "runs", slugify(phase), "*.json")


def build_runtime_header(mode: str, phase: str, audit_dir: str, target: str,
                         output_paths: list[str], *, agent: str | None = None,
                         index: int | None = None) -> str:
    label = modes.PHASE_LABELS.get(phase, phase)
    paths = "\n".join(f"  - {p}" for p in output_paths) or "  - (none)"
    executor = agent or modes.PHASE_AGENT.get(phase, "")
    result = ""
    # A core:* phase runs in-process: no sub-agent to name a result file for, and no
    # empty runs/<phase>/ to create.
    if executor and not executor.startswith("core:"):
        result = (
            "- Write your machine result to exactly this path (create no other file at the "
            "audit root):\n"
            f"  {result_path(audit_dir, phase, executor, index=index)}\n"
        )
    return (
        "## Runtime context\n"
        f"- Target repo root: {target}\n"
        f"- Audit dir: {audit_dir}\n"
        f"- State file: {os.path.join(audit_dir, 'audit-state.json')}\n"
        f"- Mode / phase: {mode} / {phase} - {label}\n"
        "- Assigned output paths (write these, relative to the audit dir):\n"
        f"{paths}\n"
        f"{result}"
        "- Keep all state on disk. If blocked, write a short failure note to your result "
        "file and stop - do not fabricate findings.\n"
    )


def compose_prompt(mode: str, phase: str, task_body: str, audit_dir: str, target: str,
                   output_paths: list[str], *, agent: str | None = None,
                   index: int | None = None) -> str:
    header = build_runtime_header(mode, phase, audit_dir, target, output_paths,
                                  agent=agent, index=index)
    return f"{header}\n---\n\n{task_body}\n"


def _next_draft_number(audit_dir: str, prefix: str) -> int:
    draft_dir = os.path.join(audit_dir, "findings-draft")
    highest = 0
    for path in glob.glob(os.path.join(draft_dir, f"{prefix}-*.md")):
        m = re.match(rf"^{re.escape(prefix)}-(\d+)-", os.path.basename(path))
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def _ingest_lock_path(audit_dir: str, phase: str) -> str:
    lock_dir = os.path.join(audit_dir, "tmp", "locks")
    os.makedirs(lock_dir, exist_ok=True)
    return os.path.join(lock_dir, f"ingest-{phase.lower()}.lock")


def ingest(audit_dir: str, phase: str, result_path: str) -> int:
    findings = load_findings(result_path)
    # fan-out phases (BL3/DP4, LS2, ...) ingest several concurrent dispatches under the
    # same phase id; without a lock, two processes can read the same next-draft-number
    # before either writes, and the second write clobbers the first's draft.
    with FileLock(_ingest_lock_path(audit_dir, phase)):
        start = _next_draft_number(audit_dir, phase.lower())
        for offset, finding in enumerate(findings):
            write_draft(audit_dir, finding, phase, start + offset)
    return len(findings)


def _bullets(items: list[str]) -> str:
    return "\n".join(f"  - {i}" for i in items) or "  - (none)"


def _resolved_references(phase: str, agent: str | None) -> tuple[list[str], list[str]]:
    """(absolute paths that exist, names that do not). A machine without the skill tree
    installed still gets a dispatchable prompt - it is just told what it could not name."""
    found, missing = [], []
    for name in modes.references_for(phase, agent):
        path = paths.reference(name)
        (found if path else missing).append(path or name)
    return found, missing


def _existing_inputs(mode: str, phase: str, audit_dir: str) -> list[str]:
    out = []
    for rel in modes.inputs_for(mode, phase):
        path = os.path.join(os.path.abspath(audit_dir), rel)
        if os.path.exists(path):
            out.append(path)
    return out


def phase_prompt(mode: str, phase: str, audit_dir: str, target: str, *,
                 agent: str | None = None, index: int | None = None) -> str:
    """The whole dispatch, ready to send: runtime header, the files this agent must read,
    and the phase's task. This is what SKILL.md used to assemble by hand from its own prose,
    which is why every non-SKILL.md harness had to re-encode that prose to dispatch at all.
    """
    spec = modes.spec_for(phase)
    executor = agent or modes.PHASE_AGENT.get(phase, "")
    found, missing = _resolved_references(phase, executor)
    inputs = _existing_inputs(mode, phase, audit_dir)

    body = ["## Read these first", "", "References:", _bullets(found)]
    if missing:
        body += ["", f"  Not installed on this machine, so unavailable to you: {', '.join(missing)}"]
    body += ["", "Audit inputs:", _bullets(inputs), "", "---", "", "## Your task", "", spec.task]
    if spec.roster and len(spec.roster) > 1:
        peers = ", ".join(a for a in spec.roster if a != executor)
        body += ["", f"You are one of {len(spec.roster)} agents on this phase "
                     f"({'in sequence' if spec.sequential else 'running concurrently'}). "
                     f"The others are: {peers}. Cover your own domain and do not duplicate theirs."]
    return compose_prompt(mode, phase, "\n".join(body), audit_dir, target,
                          modes.gate_for(phase), agent=agent, index=index)


def dispatch_plan(mode: str, phase: str, audit_dir: str, target: str) -> dict:
    """Everything a harness needs to run one phase without consulting the registry itself:
    who to dispatch, how many, what each one writes, and what closes the gate."""
    executor = modes.PHASE_AGENT.get(phase, "")
    roster = modes.roster_for(phase)
    out = os.path.abspath(audit_dir)
    return {
        "phase": phase,
        "label": modes.PHASE_LABELS.get(phase, phase),
        "mode": mode,
        "executor": executor,
        "kind": "core" if executor.startswith("core:") else ("fanout" if len(roster) > 1 else "agent"),
        "sequential": modes.spec_for(phase).sequential,
        "planned": len(roster),
        "prereqs": modes.prereqs_for(mode, phase),
        "gate": [os.path.join(out, g) for g in modes.gate_for(phase)],
        "inputs": _existing_inputs(mode, phase, out),
        "dispatches": [
            {
                "agent": name,
                "index": i,
                "references": modes.references_for(phase, name),
                "result_path": result_path(out, phase, name, index=i if len(roster) > 1 else None),
            }
            for i, name in enumerate(roster, start=1)
        ],
    }
