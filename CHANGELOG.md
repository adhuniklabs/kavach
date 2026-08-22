# Changelog

All notable changes to Adhunik Kavach are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-08-21

First public release.

### The audit

- **Eight modes** over one data flow (`recon → sweep → drafts → chamber → promote → report`):
  `lite`, `balanced` (default), `deep`, `diff`, `confirm`, `revisit`, `merge`, `longshot`.
- **Zero-input recon** fingerprints the stack, then selects the scanners that stack earns.
- **14 scanner adapters**, Docker-first with a native fallback and graceful degradation: a
  dependency-free secret scanner and a bundled offline SAST ruleset run even with no Docker.
- **8 domain subagents** (sast, api, llm, billing, crypto, supply, config, logic) plus the
  specialist, reasoning, review-chamber, validation, and confirm rosters.
- **Six kill chains** with attack trees, CVSS severity chaining, and a fail-closed certification
  gate over eight production-readiness controls.
- **7 companion skills** shipped alongside: codeql, threat-model, spec-compliance,
  variant-analysis, zeroize-audit, ci-agent-actions, semgrep-rule-creator.

### Triage and cost control

- **Finding classes** (`reasoned`, `code`, `secret`, `dependency`, `iac`), assigned
  deterministically from the finding's source, category, and rule id. Promotion keys on class
  *and* severity, so dependency and IaC rows roll up into aggregate directories instead of each
  getting a hand-written write-up. Nothing is dropped: every row stays in `findings.json` and the
  SARIF.
- **A dispatch ledger** per audit, with a per-mode default ceiling and a wall-clock ceiling
  (`--budget`, `--max-wall-seconds`; `0` for unlimited). Work a ceiling drops is recorded and
  printed in the report.
- **Per-agent model tiering** so mechanical single-artifact agents do not run on the most
  expensive model available.

### Gates and resumability

- **Gate-driven phases.** A phase is complete only when its artifact exists on disk, so an
  interrupted run resumes from real progress rather than from remembered state.
- **Coverage gates** for the per-finding phases: `kavach coverage --phase poc|report` walks the
  promoted tree and names every directory still missing its artifact, so a run cannot report
  success with zero proofs of concept.
- **Stale-directory scoping.** `consolidate` records what it wrote to a promoted-index manifest;
  coverage counts only those directories and reports the rest as stale with a reason.
  `consolidate --prune-stale` relocates them to `findings-stale/` and never deletes.
- **Resumable run state** in `audit-state.json`: atomic writes under a lock, retry/backoff
  bookkeeping, and commit-keyed diff baselines.

### Reports

- **One report model** behind every format, so markdown, HTML, PDF, JSON, and SARIF cannot
  disagree about a number.
- **A paged PDF** with a real table of contents, running headers, a six-axis scorecard,
  ASVS/CWE/OWASP/GDPR mapping, per-axis chapters, a three-horizon remediation plan, and an annex
  giving the command behind every figure. `reportlab` is an optional extra
  (`pip install 'kavach-audit[report]'`); without it every text format still renders and the PDF
  path exits with the install command rather than a traceback.
- **A fail-closed scorecard.** An axis or sub-characteristic with no findings and no proving
  control reads `not assessed` and is excluded from the headline figure, never scored as a pass.
- **A `Limits of this run` section** built from shed work, coverage gaps, and every finding still
  marked `suspected`. A budget-constrained audit reads as one.

### Integration

- **Tracker export** to GitHub via the `gh` CLI, in two phases: `kavach issues plan` writes a
  reviewable manifest, and `kavach issues push` creates nothing without an explicit `--yes`.
  Idempotent on the stable finding fingerprint, so a re-audit comments on the existing issue
  instead of filing a duplicate. `secret`-class findings export redacted, with the matched value
  withheld and left in the local audit tree.
- **CI contract:** SARIF 2.1.0 output and a stable exit-code contract (`0` clean, `2` open
  Critical, `3` open High, `4` controls unmet, `5` tooling error, `6` corpus fail, `7` policy not
  met).
- **Engine-owned result paths.** The engine names the file each sub-agent writes, so dispatch
  results land under `runs/<phase>/` instead of accumulating invented filenames at the audit root.

### Notes

- The deterministic core never talks to a model and never dispatches a sub-agent; `skill/SKILL.md`
  is the only thing that issues `Task` calls. That seam is what keeps KAVACH model-agnostic.
- Requires `python3` and `pip` (`PyYAML`, `filelock`). Docker unlocks the full scanner suite.
- 518 unit tests plus a corpus self-validation gate over deliberately-vulnerable fixtures.
- Portions adapted from [piolium](https://github.com/vigolium/piolium) (MIT, © j3ssie); see
  [`NOTICE`](./NOTICE) for the itemized attribution.

[0.1.0]: https://github.com/adhuniklabs/kavach/releases/tag/v0.1.0
