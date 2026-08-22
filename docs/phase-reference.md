# KAVACH Phase Reference

This is the on-disk phase contract. Every KAVACH phase id, its label, the agent or core
mechanism that runs it, its prerequisites, and the gate artifact that proves it complete are
defined here and **only** here - mirroring `core/kavach/modes.py` exactly. Nothing else in the
tree, including agent frontmatter, may redeclare a phase id or a phase number. If this file and
`modes.py` ever disagree, `modes.py` is buggy - file it as a bug, don't patch around it here.

A phase is "done" when its gate artifact(s) exist on disk (see `docs/output-structure.md`), not
merely when `audit-state.json` says so - an interrupted run resumes from real progress. Three
gate rules on top of "the glob matches", all enforced in `runner.gate_satisfied`:

- **Report phases** (`reports/final-audit-report.md`, `reports/confirmation-report.md`) require the
  file be larger than 500 bytes; a truncated write does not satisfy the gate. Both moved under
  `reports/`; the gate also resolves a legacy copy at the audit root, so an audit tree
  already on disk does not re-run its report phase.
- **Coverage artifacts** (`attack-surface/poc-coverage.json`, `report-coverage.json`) must parse
  **and** carry `"complete": true`. The file existing is not enough - that is the whole point of
  them, and it is why `kavach coverage` must run after every PoC/report batch rather than once.
- **No gate may resolve under a path in `cleanup.TRANSIENT`** (`tmp/`, `findings-draft/`,
  `confirm-workspace/`), enforced by `test_modes.py::test_no_gate_under_transient`. A gate the
  mode's own cleanup deletes makes its phase eligible again on every resume, so the run pays for
  the same fan-out twice. 15 gates were in that state - all six `CF*` working-file
  gates, `DP10`, `DP11`, five `MG*`, and `LS2` - and one of them (`CF7`) was provably unsatisfiable,
  because its own `core:cleanup` deleted the directory holding its gate.

`‖` marks phases that fan out in parallel under the scheduler (bounded by `KAVACH_MAX_AGENTS`,
default **6**, which must stay under Claude Code's own `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`,
default 20). Every fan-out is additionally spent against the audit's dispatch ledger - see
`docs/orchestration.md`. `core:<fn>` in the Agent column means a deterministic engine step, not a
sub-agent - no `Task` call is issued for it.

### The per-finding phases (`LT3`, `BL6`, `BL6b`, `DP13`, `DP14`, `RV11`, `RV11b`)

These seven are **scoped** to the directories `consolidate` recorded in
`attack-surface/promoted-index.json` for the current finding set. Anything else under `findings/` is
reported as *stale* and excluded - a directory promoted by an earlier run, or by a legacy
policy, will never receive a proof of concept, so counting it made the gate permanently
unsatisfiable (measured on an upgraded tree: 291 counted, 2 satisfiable). `kavach consolidate
--prune-stale` moves them to `findings-stale/`; nothing is ever deleted.

These seven used to gate on `findings/` - a directory `consolidate` creates unconditionally, so a
run that built **zero** PoCs satisfied it. That is exactly what the 2026-08-21 audit did: 238
promoted findings, 0 PoCs, 110 reports, and the mode reported `complete`. They now gate on a
coverage artifact that walks the promoted tree and names every directory still missing its
artifact. `is_aggregate: true` directories (`findings/G*/`) are exempt from both - a rolled-up
scanner class is never dispatched to `kavach-poc` or `kavach-reporter`, and its `report.md` is
written by the core.

`RV9`, `RV10`, `RV10k` and `MG6` keep `findings` deliberately: they are promotion steps, not
per-finding LLM work, and the directory existing is the honest gate for them.

---

## lite - `LT0 LT1 LT2 LT3 LT4` (fast triage)

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| LT0 | Source Recon | `core:recon` | - | `recon.json` |
| LT1 | Secret Exposure Scan | `core:sweep` | - | `sweep-summary.json` |
| LT2 | Fast Static Analysis | `kavach-sast` | LT1 | `attack-surface/lite-q2-summary.md` |
| LT3 | PoC + Consolidate | `kavach-poc` | LT2 | `attack-surface/poc-coverage.json` |
| LT4 | Verify & Cleanup | `core:cleanup` | LT3 | `attack-surface/lite-cleanup-summary.json` |

LT0 and LT1 run in parallel (both have no prereqs) under a lite-specific retry wrapper.

## balanced - `BL1 BL2 BL3 BL4 BL5 BL6 BL6b BL6c BL7`

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| BL1 | Intelligence & Dependency Risk | `kavach-intel` | - | `attack-surface/advisory-summary.md` |
| BL2 | Architecture & Threat Model | `kavach-kb` | BL1 | `attack-surface/knowledge-base-report.md` |
| BL3 | Static Analysis & Triage | `kavach-sast` | BL2 | `attack-surface/source-sink-flows-all-severities.md` |
| BL4 | Manual Attack Surface Probe | `kavach-probe` | BL3 | `attack-surface/manual-attack-surface-inventory.md` |
| BL5 | Adversarial Review & FP Check | `kavach-chamber` (+ `kavach-advocate`) | BL4 | `attack-surface/balanced-chamber-summary.md` |
| BL6 | Proof-of-Concept Construction | `kavach-poc` (per finding, fan-out) | BL5 | `attack-surface/poc-coverage.json` |
| BL6b | Finding Report Drafting | `kavach-reporter` (per finding, fan-out) | BL6 | `attack-surface/report-coverage.json` |
| BL6c | Final Report Assembly | **VAJRA lead** + `core:render` | BL6b | `reports/final-audit-report.md` |
| BL7 | Verification & Cleanup | `core:cleanup` | BL6c | `attack-surface/balanced-cleanup-summary.json` |

Linear prereq chain (each phase depends only on its predecessor). BL3/BL4 is where the 8 domain
hunters (sast/api/llm/billing/crypto/supply/config/logic) fan out against the attack surface BL2
built. BL5 is the single-pass chamber; deep runs a full multi-agent chamber at DP10 instead.

## deep - `DP1 … DP17` (full adversarial)

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| DP1 | Intelligence & Dependency Risk | `kavach-intel` | - | `attack-surface/advisory-summary.md` |
| DP2 | Patch History & Bypass Review | `kavach-history` → `kavach-patch` | - | `attack-surface/patch-bypass-summary.md` |
| DP3 | Architecture & Threat Model | `kavach-kb` | - | `attack-surface/knowledge-base-report.md` |
| DP4 | Static Analysis & Triage | `kavach-sast` | DP3 | `attack-surface/source-sink-flows-all-severities.md` |
| DP5 | Authorization & Access Control | `kavach-api` (authz-matrix mode) | DP3 ‖ | `attack-surface/authz-matrix.md` |
| DP6 | State Machine & Concurrency | `kavach-state` | DP3 ‖ | `attack-surface/state-concurrency-summary.md` |
| DP7 | Spec, Framework & Parser Gaps | `kavach-spec` | DP3 ‖ | `attack-surface/spec-gap-summary.md` |
| DP8 | Manual Attack Surface Probe | `kavach-probe` → `kavach-reasoner-backward` ‖ `kavach-reasoner-contradiction` → `kavach-harvester` | DP3, DP4 | `attack-surface/deep-probe-summary.md` |
| DP9 | Cross-Service Data Flow | `kavach-crossservice` | DP4, DP8 | `attack-surface/cross-service-edges.json` |
| DP10 | Adversarial Review Chamber | `kavach-chamber` (judge) orchestrating `kavach-ideator` → `kavach-tracer` → `kavach-advocate`; `kavach-variant-scout` in background | DP5, DP6, DP7, DP8, DP9 | `attack-surface/deep-chamber-summary.md` |
| DP11 | False-Positive Verification | `kavach-verifier` (cold, zero-context) | DP10 | `attack-surface/adversarial-verification.md` |
| DP12 | Variant Search | `kavach-variant` (per finding) | DP11 | `attack-surface/variant-summary.md` |
| DP13 | Proof-of-Concept Construction | `kavach-poc` (per finding, fan-out) | DP12 | `attack-surface/poc-coverage.json` |
| DP14 | Finding Report Drafting | `kavach-reporter` (per finding, fan-out) | DP13 | `attack-surface/report-coverage.json` |
| DP15 | Final Report Assembly | **VAJRA lead** + `core:render` | DP14 | `reports/final-audit-report.md` |
| DP16 | Finding Verification | `kavach-confirm-reporter` (embedded confirm subphases, intent cross-check skipped) | DP15 | `reports/confirmation-report.md` |
| DP17 | Cleanup | `core:cleanup` | DP16 | `attack-surface/deep-cleanup-summary.json` |

Prereq DAG (ported verbatim from `_DEEP_PREREQS` in `modes.py`):

```
DP1, DP2, DP3        ← (none, may start immediately)
DP4                  ← DP3
DP5, DP6, DP7        ← DP3                      (fan out together, scheduler cap 3)
DP8                  ← DP3, DP4
DP9                  ← DP4, DP8
DP10                 ← DP5, DP6, DP7, DP8, DP9
DP11                 ← DP10
DP12                 ← DP11
DP13                 ← DP12
DP14                 ← DP13
DP15                 ← DP14
DP16                 ← DP15
DP17                 ← DP16
```

`kavach-triager` runs as a cheap P0/P1/P2/skip gate between DP11 and DP13 - it is not a phase of
its own; it narrows what DP12/DP13 spend budget on.

## diff - `DF1` (derived at runtime)

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| (pre) | recon + prior-commit resolution + `git diff --name-only PRIOR...HEAD`, `max_changed_files` guard (200), empty diff → mode skipped | `core:diffing` | - | - |
| DF1 | Changed-file Scan | `kavach-sast` scoped to changed files + git-blame regression detector | - | `attack-surface/diff-summary.md` |

`diff` has exactly one declared phase; the pre-phase work (commit resolution, file-list scoping)
is engine bookkeeping, not a gated phase.

## confirm - `CF1 CF1_5 CF2 CF3 CF4 CF5 CF6 CF7` (gated on the dynamic-confirm opt-in)

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| CF1 | Findings Inventory + Report Repair | `core:inventory` (+ `kavach-reporter` repair pre-pass) | - | `attack-surface/confirm-findings-inventory.json` |
| CF1_5 | Intent Cross-Check | `kavach-intent-crosscheck` (optional) | CF1 | `attack-surface/confirm-intent-crosscheck.json` |
| CF2 | Environment Discovery | `kavach-env-detective` | CF1_5 | `attack-surface/confirm-env-strategies.json` |
| CF3 | Environment Provisioning | `kavach-env-provisioner` | CF2 | `attack-surface/confirm-env-connection.json` |
| CF4 | Proof-of-Concept Execution | `kavach-poc-executor` | CF3 | `attack-surface/confirm-poc-results.json` |
| CF5 | Test-Based Fallback | `kavach-test-mapper` | CF4 | `attack-surface/confirm-test-mapping.json` |
| CF6 | Confirmation Report | `kavach-confirm-reporter` | CF5 | `reports/confirmation-report.md` |
| CF7 | Cleanup & Redaction | `core:cleanup` | CF6 | `attack-surface/confirm-cleanup-summary.json` |

CF1 and CF6 are fatal-break phases (no report without an inventory, no exit without a report);
CF2-CF5 continue-on-fail so a partial confirmation report still emits if the environment can't be
provisioned or a PoC can't run live.

**No confirm gate resolves under `confirm-workspace/`.** It was in `cleanup.TRANSIENT`,
so `CF7`'s own `core:cleanup` deleted the directory its gate lived in - `CF7` could never be
satisfied - and the CF2-CF5 agents were in fact writing to `tmp/confirm/`, so those four gates
matched nothing on disk in any run. Confirm mode's phase gating was non-functional.

Two of the new durable gates are **redaction-constrained by contract**, because durable means "still
on disk long after the run":

- `attack-surface/confirm-env-connection.json` (CF3) records the strategy name, the target class
  (container / local / staging), the reachability verdict, timestamps, ports, and
  `credentials_held_in_transient_only: true`. **Never a credential and never a connection string.**
- `attack-surface/confirm-poc-results.json` (CF4) records verdicts, exit status, timestamps and
  evidence *pointers*. **Never a captured response body, header or payload.**

Everything credential-bearing stays under `tmp/confirm/` and `tmp/real-env-evidence/<slug>/`, which
cleanup still wipes, per the confirm charter.

## revisit - `RV0 RV5 RV7 RV8 RV9 RV10 RV10k RV11 RV11b RV11c`

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| RV0 | Intent Cartography | `kavach-intent` (non-blocking on failure) | - | `attack-surface/intent-corpus.json` |
| RV5 | Fresh Deep Probe | `kavach-probe` (prior findings as negative list) | RV0 | `attack-surface/revisit-probe-summary.md` |
| RV7 | SAST Reclassification | `kavach-sast` | RV5 | `attack-surface/revisit-r7-chamber-summary.md` |
| RV8 | Fresh Review Chambers | `kavach-chamber` team | RV7 | `attack-surface/revisit-r8-chamber-summary.md` |
| RV9 | False-Positive Verification | `kavach-verifier` | RV8 | `findings` |
| RV10 | New Finding Variants | `kavach-variant` | RV9 | `findings` |
| RV10k | Known Finding Variants | `kavach-variant` | RV10 | `findings` |
| RV11 | Proof-of-Concept Construction | `kavach-poc` | RV10k | `attack-surface/poc-coverage.json` |
| RV11b | Finding Report Drafting | `kavach-reporter` | RV11 | `attack-surface/report-coverage.json` |
| RV11c | Final Report Assembly | **VAJRA lead** + `core:render` | RV11b | `reports/final-audit-report.md` |

Linear chain. RV9/RV10/RV10k/RV11/RV11b all gate on `findings/` - the engine distinguishes
"actionable" for these by state (each is a distinct step even though the artifact glob repeats),
so `--only` and resume still track each phase separately.

## merge - `MG1 … MG7` (requires ≥2 sources)

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| MG1 | Copy & Index | `core:merge_findings` (per-source aliases `a, b, …` into `tmp/merge-workspace/`) | - | `attack-surface/merge-index.json` |
| MG2 | Semantic Deduplication | `kavach-chamber` | MG1 | `attack-surface/merge-dedup-decisions.json` |
| MG3 | Metadata Auto-Fix | `core:merge_findings` | MG2 | `attack-surface/merge-index.json` |
| MG4 | Quarantine Unfixable | `core:merge_findings` | MG3 | `attack-surface/merge-index.json` |
| MG5 | Severity Renumbering | `core:merge_findings` | MG4 | `attack-surface/merge-rename-map.json` |
| MG6 | Apply Finding Renames | `core:merge_findings` | MG5 | `findings` |
| MG7 | Final Report Assembly | **VAJRA lead** + `core:render` | MG6 | `reports/final-audit-report.md` |

MG3-MG6 are deterministic core steps stamped complete once MG2's dedup decisions exist - no
sub-agent runs for them. The five `MG` gate artifacts live under `attack-surface/` for the
same reason the confirm gates did; the bulky per-source intermediates stay in
`tmp/merge-workspace/`, which cleanup wipes.

## longshot - `LS1 LS2 LS3`

| Phase id | Label | Agent / mechanism | Prereqs | Gate artifact |
|---|---|---|---|---|
| LS1 | Target Enumeration | `core:enumerate` | - | `attack-surface/longshot-targets.json` |
| LS2 | Per-File Hail-Mary Hunt | `kavach-longshot-hunter` (per file, scheduler cap = burst cap, per-file timeout) | LS1 | `attack-surface/longshot-hunt-summary.json` |
| LS3 | Finding Aggregation | `kavach-longshot-aggregator` (dedup/rank/curate, no auto-confirm) | LS2 | `attack-surface/longshot-summary.md` |

LS2's gate was `findings-draft` - transient - so any cleanup made the entire per-file swarm eligible
to re-run, the same class of budget bug as the per-finding phases above.

---

## Deferred, not one of the 8

`reinvest` (`RI1 RI2 RI3`, `kavach-wave` cross-model re-verification) and `knowledge-base` (`KB0
K1 K2`, `kavach-kb-loader` + `kavach-kb` doc-intake) are **not** shipped modes. They are noted here
only so nobody mistakes their absence for an oversight.

## Source of truth

- Code: `core/kavach/modes.py` - `MODE_PHASES`, `PREREQS`, `PHASE_LABELS`, `PHASE_AGENT`,
  `PHASE_GATES`, and the accessor functions `phases_for`/`prereqs_for`/`gate_for`;
  `core/kavach/runner.py` (`gate_satisfied` - the size, coverage-complete and legacy-path rules);
  `core/kavach/coverage.py` (the two coverage artifacts); `core/kavach/cleanup.py` (`TRANSIENT`,
  the set no gate may resolve under).
