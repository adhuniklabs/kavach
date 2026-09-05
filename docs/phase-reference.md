# KAVACH Phase Reference

This is the on-disk phase contract. Every KAVACH phase id, its label, the agent or core mechanism
that runs it, the gate artifact that proves it complete, and the prerequisite edges between phases
are defined here and **only** here - mirroring `core/kavach/modes.py` exactly. Nothing else in the
tree, including agent frontmatter, may redeclare a phase id. If this file and `modes.py` ever
disagree, `modes.py` is buggy - file it as a bug, don't patch around it here.

There is **one pipeline of 26 phases** and one id namespace. A mode is a *subset* of `PIPELINE`,
never a parallel copy of it: `lite` schedules 6 phases, `balanced` 13, `deep` 20, and `--live` adds
the same 6-phase tail to any of them. The three presets are strictly nested - `lite ⊂ balanced ⊂
deep` - so a phase id means the same work, reads the same inputs and writes the same artifact
whichever preset scheduled it.

A phase is "done" when its gate artifact(s) exist on disk (see `docs/output-structure.md`), not
merely when `audit-state.json` says so - an interrupted run resumes from real progress. Three gate
rules on top of "the glob matches", all enforced in `runner.gate_satisfied`:

- **Report phases** (`reports/final-audit-report.md`, `reports/confirmation-report.md`) require the
  file be larger than 500 bytes; a truncated write does not satisfy the gate. Both live under
  `reports/`; the gate also resolves a legacy copy at the audit root, so an audit tree already on
  disk does not re-run its report phase.
- **Coverage artifacts** (`attack-surface/poc-coverage.json`, `report-coverage.json`) must parse
  **and** carry `"complete": true`. The file existing is not enough - that is the whole point of
  them, and it is why `kavach coverage` must run after every PoC/report batch rather than once.
- **No gate may resolve under a path in `cleanup.TRANSIENT`** (`tmp/`, `findings-draft/`,
  `live-workspace/`), enforced by `test_modes.py::test_no_gate_under_transient`. A gate that
  `cleanup` deletes makes its phase eligible again on every resume, so the run pays for the same
  fan-out twice.

**26 phases, 26 distinct gate artifacts, one apiece**
(`test_modes.py::test_every_phase_in_a_preset_has_a_distinct_gate`). No two phases in a preset share
a gate, so no phase can be closed by another phase's output. Gate filenames carry no mode prefix
either (`test_gate_names_carry_no_mode_prefix`): `cleanup` is one phase shared by three presets, and
it cannot gate on a filename that varies with the preset.

`core:<fn>` in the Agent column means a deterministic engine step, not a sub-agent - no `Task` call
is issued for it.

## The pipeline

| Phase id | Label | Agent / mechanism | Gate artifact | `lite` | `balanced` | `deep` | `--live` |
|---|---|---|---|:-:|:-:|:-:|:-:|
| `recon` | Source Recon | `core:recon` | `recon.json` | ● | ● | ● | · |
| `sweep` | Secret Exposure Scan | `core:sweep` | `sweep-summary.json` | ● | ● | ● | · |
| `intent` | Intent Cartography | `kavach-intent` | `attack-surface/intent-corpus.json` | · | ● | ● | · |
| `intel` | Intelligence & Dependency Risk | `kavach-intel` | `attack-surface/advisory-summary.md` | · | ● | ● | · |
| `kb` | Architecture & Threat Model | `kavach-kb` | `attack-surface/knowledge-base-report.md` | · | ● | ● | · |
| `history` | Patch History & Bypass Review | `kavach-history` | `attack-surface/patch-bypass-summary.md` | · | · | ● | · |
| `hunt` | Static Analysis & Triage | `kavach-sast` | `attack-surface/source-sink-flows-all-severities.md` | ● | ● | ● | · |
| `authz` | Authorization & Access Control | `kavach-api` | `attack-surface/authz-matrix.md` | · | · | ● | · |
| `state` | State Machine & Concurrency | `kavach-state` | `attack-surface/state-concurrency-summary.md` | · | · | ● | · |
| `spec` | Spec, Framework & Parser Gaps | `kavach-spec` | `attack-surface/spec-gap-summary.md` | · | · | ● | · |
| `probe` | Manual Attack Surface Probe | `kavach-probe` | `attack-surface/probe-summary.md` | · | ● | ● | · |
| `crossservice` | Cross-Service Data Flow | `kavach-crossservice` | `attack-surface/cross-service-edges.json` | · | · | ● | · |
| `chamber` | Adversarial Review Chamber | `kavach-chamber` | `attack-surface/chamber-summary.md` | · | ● | ● | · |
| `verify` | False-Positive Verification | `kavach-verifier` | `attack-surface/adversarial-verification.md` | · | · | ● | · |
| `variant` | Variant Search | `kavach-variant` | `attack-surface/variant-summary.md` | · | · | ● | · |
| `crosscheck` | Intent Cross-Check | `kavach-intent-crosscheck` | `attack-surface/intent-crosscheck.json` | · | ● | ● | · |
| `poc` | Proof-of-Concept Construction | `kavach-poc` | `attack-surface/poc-coverage.json` | ● | ● | ● | · |
| `report` | Finding Report Drafting | `kavach-reporter` | `attack-surface/report-coverage.json` | · | ● | ● | · |
| `render` | Final Report Assembly | `core:render` | `reports/final-audit-report.md` | ● | ● | ● | · |
| `inventory` | Findings Inventory + Report Repair | `core:inventory` | `attack-surface/live-inventory.json` | · | · | · | ● |
| `envscan` | Environment Discovery | `kavach-env-detective` | `attack-surface/env-strategies.json` | · | · | · | ● |
| `provision` | Environment Provisioning | `kavach-env-provisioner` | `attack-surface/env-connection.json` | · | · | · | ● |
| `exploit` | Proof-of-Concept Execution | `kavach-poc-executor` | `attack-surface/poc-results.json` | · | · | · | ● |
| `testgen` | Test-Based Fallback | `kavach-test-mapper` | `attack-surface/test-mapping.json` | · | · | · | ● |
| `certify` | Confirmation Report | `kavach-confirm-reporter` | `reports/confirmation-report.md` | · | · | · | ● |
| `cleanup` | Cleanup & Redaction | `core:cleanup` | `attack-surface/cleanup-summary.json` | ● | ● | ● | · |

`certify` is the **only** phase that writes `reports/confirmation-report.md`, and it is `--live`
only. A plain `deep` run therefore never produces one; `deep --live` does.

Two of the live gates are **redaction-constrained by contract**, because durable means "still on disk
long after the run":

- `attack-surface/env-connection.json` (`provision`) records the strategy name, the target class
  (container / local / staging), the reachability verdict, timestamps, ports, and
  `credentials_held_in_transient_only: true`. **Never a credential and never a connection string.**
- `attack-surface/poc-results.json` (`exploit`) records verdicts, exit status, timestamps and
  evidence *pointers*. **Never a captured response body, header or payload.**

Everything credential-bearing stays in the transient workspaces `cleanup` wipes - `live-workspace/`
and `tmp/`, including `tmp/real-env-evidence/<slug>/`.

## Fan-out

Most phases dispatch one agent. Three shapes are not one:

- **`hunt`** dispatches the eight domain hunters - `kavach-sast`, `kavach-api`, `kavach-llm`,
  `kavach-billing`, `kavach-crypto`, `kavach-supply`, `kavach-config`, `kavach-logic` - concurrently,
  bounded by `KAVACH_MAX_AGENTS` (default **6**, which must stay under Claude Code's own
  `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`, default 20). `kavach-sast` leads because it owns the
  phase's literal gate artifact, so the gate can close in the first batch. It is also the **only**
  phase whose roster varies by intensity: under `lite`, `PRESET_ROSTERS` cuts it to `kavach-sast`
  alone.
- **`history`** dispatches `kavach-history` then `kavach-patch` **in sequence** (`sequential=True`):
  the bypass review needs history's commit context, and only `kavach-patch` writes the gate.
- **`poc` and `report`** fan out per finding, not per agent - see below.

Every dispatch is spent against the audit's ledger; `kavach plan --json` reports each phase's roster,
per-dispatch index and result path so a harness never has to derive the fan-out itself. See
`docs/orchestration.md`.

## The per-finding phases (`poc`, `report`)

These two are **scoped** to the directories `consolidate` recorded in
`attack-surface/promoted-index.json` for the current finding set. Anything else under `findings/` is
reported as *stale* and excluded - a directory promoted by an earlier run, or by a legacy policy,
will never receive a proof of concept, so counting it made the gate permanently unsatisfiable
(measured on an upgraded tree: 291 counted, 2 satisfiable). `kavach consolidate --prune-stale` moves
them to `findings-stale/`; nothing is ever deleted.

They used to gate on `findings/` - a directory `consolidate` creates unconditionally, so a run that
built **zero** PoCs satisfied it. That is exactly what the 2026-08-21 audit did: 238 promoted
findings, 0 PoCs, 110 reports, and the mode reported `complete`. They now gate on a coverage artifact
that walks the promoted tree and names every directory still missing its artifact.
`is_aggregate: true` directories (`findings/G*/`) are exempt from both - a rolled-up scanner class is
never dispatched to `kavach-poc` or `kavach-reporter`, and its `report.md` is written by the core.

`lite` schedules `poc` but not `report`: one `kavach-reporter` dispatch per promoted finding is most
of a 15-dispatch ceiling, and lite's deliverable is the assembled audit report rather than a
per-finding write-up.

## Prerequisites, and what a preset does to them

Prerequisite edges are declared **once**, against the whole pipeline, in `PREREQ_EDGES`:

| Phase | Declared prerequisites |
|---|---|
| `recon` | - |
| `sweep` | `recon` |
| `intent` | `recon` |
| `intel` | `recon` |
| `kb` | `recon` |
| `history` | `recon` |
| `hunt` | `sweep`, `kb` |
| `authz` | `kb` |
| `state` | `kb` |
| `spec` | `kb` |
| `probe` | `kb`, `hunt` |
| `crossservice` | `hunt` |
| `chamber` | `hunt`, `probe`, `authz`, `state`, `spec`, `crossservice`, `intel`, `history` |
| `verify` | `chamber` |
| `variant` | `verify` |
| `crosscheck` | `intent`, `variant` |
| `poc` | `crosscheck` |
| `report` | `poc` |
| `render` | `report` |
| `inventory` | `render` |
| `envscan` | `inventory` |
| `provision` | `envscan` |
| `exploit` | `provision` |
| `testgen` | `exploit` |
| `certify` | `exploit`, `testgen` |
| `cleanup` | `render`, `certify` |

A preset does not carry its own copy of this table. It takes the **induced subgraph**: an edge into a
phase the preset drops is replaced by edges to *that* phase's own prerequisites, transitively, until
every edge lands on a phase the preset actually schedules (`modes._induced`). Dropping a phase
therefore never leaves an unsatisfiable dependency behind, and never silently lets a phase run before
its real inputs exist.

Worked example - `poc` under `lite`. `poc` declares one prerequisite, `crosscheck`, and `lite` drops
it, so resolution walks through it:

```
poc → crosscheck                         (dropped)
        ├── intent                       (dropped) → recon        ✓ in lite
        └── variant  (dropped)
              → verify  (dropped)
                → chamber  (dropped)
                    ├── hunt                                      ✓ in lite
                    └── probe, authz, state, spec, crossservice,
                        intel, history   (all dropped)  → kb/recon/hunt
```

`kavach plan --mode lite --json` therefore reports `poc`'s prerequisites as `['recon', 'hunt']` -
the two lite phases the whole subtree bottoms out on. Under `deep`, nothing is dropped and `poc`'s
prerequisite is exactly the declared `['crosscheck']`. Under `balanced`, `chamber`'s eight edges
resolve to `['hunt', 'probe', 'kb', 'intel', 'recon']` and `crosscheck`'s resolve to
`['intent', 'chamber']`.

`--live` adds edges the same way rather than by exception: with the tail scheduled, `cleanup`'s
declared `('render', 'certify')` resolves to both; without it, `certify` is dropped and `cleanup`
resolves to `['render']` alone.

Query it rather than transcribing it: `modes.prereqs_for(mode, phase, live)` is what the planner
uses, and `kavach plan --mode <mode> [--live] --json` prints the resolved list per phase.

## Source of truth

- Code: `core/kavach/modes.py` - `PIPELINE`, `LIVE_PHASES`, `PRESETS`, `PRESET_ROSTERS`,
  `PREREQ_EDGES`, `PHASE_LABELS`, `PHASE_AGENT`, `PHASE_GATES`, `PHASE_SPECS`, and the accessors
  `phases_for`/`prereqs_for`/`gate_for`/`roster_for`/`inputs_for`;
  `core/kavach/runner.py` (`gate_satisfied` - the size, coverage-complete and legacy-path rules);
  `core/kavach/coverage.py` (the two coverage artifacts); `core/kavach/cleanup.py` (`TRANSIENT`,
  the set no gate may resolve under); `core/kavach/budget.py` (`DEFAULT_MAX_DISPATCHES`,
  `LIVE_DELTA`).
