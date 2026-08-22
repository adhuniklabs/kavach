# Changelog

All notable changes to Adhunik Kavach are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Discovery cost: the code graph and the scope

A hunter spends most of its budget on *discovery* - grep for a symbol, open the file, follow the
import, repeat - before it reaches the line it will finally cite. Two optional inputs cut that.

- **`kavach graph index <target>`** - shells out to
  [codegraph](https://github.com/colbymchenry/codegraph) and records the outcome in
  `attack-surface/graph-status.json`. The engine never queries the graph; it establishes whether
  one exists so every dispatch prompt can tell the agent to answer structural questions from it
  before reaching for grep - or say plainly that there is none, because an agent that assumes a
  tool it does not have burns a turn finding out. Missing binary, failed index and timeout all
  give `available: false` with the reason and exit `0`: this is a scanner, not a prerequisite.
  The instruction goes to *every* hunter, not a coordinator - a fan-out where sub-agents still
  read files pays for the index and keeps the crawl.
- **`kavach scope [--agent A] [--limit N]`** - ranks `file-manifest.txt` by security relevance
  into `attack-surface/scope[-<agent>].json`, which `phase-prompt` names as an input (an agent's
  own scope wins over the repo-wide one). Deterministic and path-shaped: no model, no content
  read, because those cost what this exists to save. A high rank is "look here first", never "the
  bug is here" - the manifest still holds every file and the artifact says so.
- `phase-prompt` also names a slice written by `kavach slice` for that dispatch, so a hunter is
  pointed at its own leads rather than the whole finding set.

### Fixed

- **Signals match path tokens, not substrings.** `frag in path` read `ci` out of
  "dependen*ci*es", `api` out of "r*api*d", `key` out of "mon*key*" - the config hunter was
  opening `auth/dependencies.py` because of a two-letter accident. Short signals must be a whole
  token; longer ones may prefix one, which is what lets `authoriz` reach "authorization".
- **Ranking is domain-first, then score.** A generic score sums, so an auth router collects
  auth + session + route + api and outranked every hunter's own files - all eight hunters got the
  same list, which is the same as having no per-domain scope at all.
- **Vendored scaffolding is dampened.** A tree the target ships *to* its users reads as
  application code to every path signal; `_bmad_template/.../review-prompts/*.md` outranked the
  real prompt module for the LLM hunter.

### The engine owns the dispatch contract

`phase-prompt` used to emit one line - `Execute phase BL3 (Static Analysis & Triage).` - and the
real instruction lived in `SKILL.md` prose. That made `SKILL.md` the spec rather than a client of
it: any other harness had to re-read that prose, re-encode it, and drift from it silently.

- **`modes.PHASE_SPECS`** - per-phase task, reference set, fan-out roster, and whether the roster is
  sequential. `modes.AGENT_REFERENCES` carries each agent's own reading list.
  `dispatch.phase_prompt` renders all of it, so `kavach phase-prompt` now returns a complete,
  dispatchable prompt. A reference the machine does not have is *named as missing* rather than
  dropped - an agent is never left assuming it was given something it was not.
- **`kavach plan --json`** - the whole dispatch plan for every actionable phase: roster, 1-based
  index, result path, references, gate artifacts, prereqs, `sequential`. A driver needs nothing
  from `modes.py`.
- **`kavach agents [--json]`** - the roster as data. Each agent gains a provider-neutral
  **`tier:`** (`reasoning` / `mechanical` / `triage`) beside `model:`, which stays for Claude Code.
  `test_agents_load` fails if the two spellings drift.
- **`kavach slice <phase> --agent A --index i`** - that domain's leads out of `findings.json` into
  `runs/<phase>/slices/`. The eight BL3/DP4 hunters were each sent the whole finding set, so a
  300-row sweep was paid for eight times. The slice also states how many findings belong to other
  domains, because a hunter that believes its slice is everything reports coverage it does not have.
- **`kavach inventory`** (CF1) and **`kavach enumerate`** (LS1) - the two phases whose `core:` verb
  did not exist, so `SKILL.md` told every harness to write the same loop by hand.

### Observability and spend

- **`.kavach/events.jsonl`** - one JSON object per engine decision, appended at the audit root and
  durable across `cleanup`. Progress was only derivable by polling gate-artifact mtimes; nothing
  recorded why a phase re-ran or what a budget check decided. `kavach events [--since N]` replays
  it. Single `O_APPEND` writes capped below `PIPE_BUF`, so concurrent phases interleave whole lines.
- **Spend in the ledger** - `kavach budget charge` takes `--tokens-in`, `--tokens-out` and
  `--cost-usd`; `budget show` reports totals and per-phase spend. `--max-cost-usd` is a third
  ceiling that sheds like wall clock, with the reason `cost ceiling` reaching the report's *Limits*
  section. The engine never calls a model, so spend is only as real as the harness reports.
- Ledgers written before these keys existed backfill on read, so a resumed audit accounts the same
  as a fresh one.

### Fixed

- `paths.py` resolves `references/` and `agents/` across all three install shapes (repo checkout,
  `install.sh`, bare pip), with `KAVACH_REFERENCES_DIR` / `KAVACH_AGENTS_DIR` overrides.
- Slicing matches merge-aliased sources (`a:trivy+b:trivy`), which a whole-string comparison misses.

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
