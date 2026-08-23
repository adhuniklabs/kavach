"""The engine↔skill seam: run dirs, runtime headers, prompt composition, ingest.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
The engine composes prompts and folds results; SKILL.md issues the Task calls.
"""

from __future__ import annotations

import glob
import json
import os
import re
import time
import uuid

import yaml
from filelock import FileLock

from . import graphindex, modes, paths, scoping
from .finding import Finding
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


def existing_fingerprints(audit_dir: str, phase: str) -> set[str]:
    """Every finding this phase has already drafted, by fingerprint.

    Drafts carry `kavach_id` in their frontmatter, which is the finding's fingerprint and is
    stable across line moves - so it answers "have I already folded this in?" without a
    second index to keep in sync.
    """
    seen: set[str] = set()
    pattern = os.path.join(audit_dir, "findings-draft", f"{phase.lower()}-*.md")
    for path in glob.glob(pattern):
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(2048)
        except OSError:
            continue
        if not text.startswith("---\n"):
            continue
        parts = text.split("---\n", 2)
        if len(parts) < 3:
            continue
        try:
            fm = yaml.safe_load(parts[1]) or {}
        except yaml.YAMLError:
            continue
        fid = fm.get("kavach_id")
        if fid:
            seen.add(str(fid))
    return seen


def quarantine(audit_dir: str, result_path: str) -> str:
    """Move an unreadable result file out of the way and return where it went.

    A dispatch killed mid-write leaves truncated JSON, and the agent writes that file, not the
    engine - so it cannot be made atomic from here. Left in place it fails the whole phase's
    ingest on every resume, taking the valid results with it. Moved aside, `runs/<phase>/*.json`
    holds only readable results, "did this dispatch produce a result?" stays a plain existence
    check, and the evidence survives under runs/, which cleanup keeps.
    """
    d = os.path.join(os.path.dirname(os.path.abspath(result_path)), "corrupt")
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, f"{os.path.basename(result_path)}.{int(time.time())}")
    os.replace(result_path, dest)
    return dest


def agent_from_result(result_path: str) -> str:
    """The dispatch that authored a result file, read back off the name the engine gave it.

    ``result_path`` writes ``<agent>.json`` or ``<agent>-<i>.json``, so the inverse is the
    stem minus a fan-out index. Used to attribute findings whose author did not name
    itself - see :meth:`Finding.from_dict`.
    """
    stem = os.path.splitext(os.path.basename(result_path))[0]
    return re.sub(r"-\d+$", "", stem)


def load_agent_findings(result_path: str) -> list[Finding]:
    """The findings in one agent-authored result, attributed to the dispatch that wrote it.

    A result with no ``findings`` key is not corrupt: BL4's probe result is a protocol status
    object, and quarantining it left the phase re-planning a dispatch that had already done its
    work. `findings.json` keeps the strict read - a missing key *there* is an engine bug.
    """
    with open(result_path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = data.get("findings", []) if isinstance(data, dict) else data
    source = agent_from_result(result_path)
    return [Finding.from_dict(r, source=source) for r in rows]


def ingest(audit_dir: str, phase: str, result_path: str) -> tuple[int, int]:
    """Fold one result file into drafts. Returns (written, skipped-as-already-present).

    Ingest is re-run on every resume, because a phase stays actionable until its gate artifact
    exists - so folding the same result twice is the normal case, not an error case. Numbering
    drafts sequentially made that produce a second copy of every finding, which then reached
    the report as inflated counts.
    """
    findings = load_agent_findings(result_path)
    # fan-out phases (BL3/DP4, LS2, ...) ingest several concurrent dispatches under the
    # same phase id; without a lock, two processes can read the same next-draft-number
    # before either writes, and the second write clobbers the first's draft. The same lock
    # makes the already-drafted check safe against a concurrent ingest of a sibling result.
    written = skipped = 0
    with FileLock(_ingest_lock_path(audit_dir, phase)):
        seen = existing_fingerprints(audit_dir, phase)
        n = _next_draft_number(audit_dir, phase.lower())
        for finding in findings:
            fingerprint = finding.fingerprint()
            if fingerprint in seen:
                skipped += 1
                continue
            write_draft(audit_dir, finding, phase, n)
            seen.add(fingerprint)
            n += 1
            written += 1
    return written, skipped


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


def _existing_inputs(mode: str, phase: str, audit_dir: str, agent: str | None = None) -> list[str]:
    out = []
    for rel in modes.inputs_for(mode, phase):
        path = os.path.join(os.path.abspath(audit_dir), rel)
        if os.path.exists(path):
            out.append(path)
    for rel in (os.path.join("attack-surface", scoping.artifact_name(agent)),
                os.path.join("attack-surface", scoping.artifact_name(None))):
        path = os.path.join(os.path.abspath(audit_dir), rel)
        if os.path.exists(path) and path not in out:
            out.append(path)
            break       # the agent's own scope wins; the repo-wide one is the fallback
    slice_path = _slice_path(audit_dir, phase, agent)
    if slice_path:
        out.append(slice_path)
    return out


def _slice_path(audit_dir: str, phase: str, agent: str | None, index: int | None = None) -> str | None:
    """A slice written by `kavach slice` for this dispatch, if one exists. Named explicitly
    because a hunter handed the whole findings.json reads the whole findings.json."""
    if not agent:
        return None
    d = os.path.join(os.path.abspath(audit_dir), "runs", slugify(phase), "slices")
    stem = slugify(agent)
    for candidate in ([f"{stem}-{index}.json"] if index else []) + [f"{stem}.json"]:
        path = os.path.join(d, candidate)
        if os.path.exists(path):
            return path
    for path in sorted(glob.glob(os.path.join(d, f"{stem}-*.json"))):
        return path
    return None


def phase_prompt(mode: str, phase: str, audit_dir: str, target: str, *,
                 agent: str | None = None, index: int | None = None) -> str:
    """The whole dispatch, ready to send: runtime header, the files this agent must read,
    and the phase's task. This is what SKILL.md used to assemble by hand from its own prose,
    which is why every non-SKILL.md harness had to re-encode that prose to dispatch at all.
    """
    spec = modes.spec_for(phase)
    executor = agent or modes.PHASE_AGENT.get(phase, "")
    found, missing = _resolved_references(phase, executor)
    inputs = _existing_inputs(mode, phase, audit_dir, executor)

    body = ["## Read these first", "", "References:", _bullets(found)]
    if missing:
        body += ["", f"  Not installed on this machine, so unavailable to you: {', '.join(missing)}"]
    body += ["", "Audit inputs:", _bullets(inputs), "", "---", "",
             graphindex.prompt_section(audit_dir), "---", "", "## Your task", "", spec.task]
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
        "graph": graphindex.read_status(out),
        "dispatches": [
            {
                "agent": name,
                "index": i,
                "references": modes.references_for(phase, name),
                "inputs": _existing_inputs(mode, phase, out, name),
                "result_path": result_path(out, phase, name, index=i if len(roster) > 1 else None),
            }
            for i, name in enumerate(roster, start=1)
        ],
    }
