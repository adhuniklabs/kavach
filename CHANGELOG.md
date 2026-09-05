# Changelog

All notable changes to Adhunik Kavach are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/).

## [0.3.0] - 2026-09-05

Eight modes collapse into three intensity presets over one pipeline. This is a breaking release:
phase ids changed, gate filenames changed, and five modes are gone. Finished audits are unaffected -
`findings/` and `reports/` are exactly what they were.

An **in-progress** audit dir does not carry across, and `kavach resume` refuses one rather than
guessing. On 0.x the minor is the breaking axis `state.version_compatible` checks, because what
breaks across one is exactly what resume depends on - the phase list, the prereq graph, and which
artifact closes a gate. All three moved here, so the engine version moves to `0.3.0` with them: a dir
written by any 0.2.x exits `4` naming the engine that made it, instead of re-deriving "what is left"
under a contract that never produced the artifacts on disk. Start a fresh audit dir, or install the
release that made the old one to finish it.

### Eight modes, six advertised, and nobody could tell which was which

`karya-module.json` listed six modes. The engine had eight. `merge` and `confirm` were dispatchable
from any harness that read the registry and named in no manifest, so which modes existed depended on
which file you asked. Underneath, each mode carried its own hand-maintained phase list, its own
prereq table and its own gate filenames - which is how `LT2`, `BL3`, `DP4`, `DF1` and `RV7` ended up
being five ids for one job, closing between them on four different artifacts.

There is now **one 26-phase `PIPELINE`** with one id namespace, and a mode is a subset of it:

| Preset | Phases | Default dispatch ceiling |
|---|---|---|
| `lite` | 6 | 15 |
| `balanced` | 13 | 60 |
| `deep` | 20 | 120 |
| `--live` | +6 | +30 on top of the preset |

The three nest - `lite ⊂ balanced ⊂ deep` - so moving up a preset only ever adds phases, and a
phase id means the same work, reads the same inputs and writes the same artifact whichever preset
scheduled it. Prerequisites are declared once in `PREREQ_EDGES` against the whole pipeline; a preset
takes the induced subgraph, rerouting an edge into a dropped phase onto that phase's own prereqs,
transitively. Under `lite`, `poc`'s declared `crosscheck` resolves to `['recon', 'hunt']` that way -
nothing unsatisfiable, and nothing running before its real inputs exist.

`core/tests/test_manifest_modes.py` asserts the manifest's ids are exactly `modes.MODES` with
`balanced` the only default, so the manifest and the registry cannot drift apart again.

### Five modes removed, each naming its replacement

| Removed | Replacement |
|---|---|
| `diff` | the `kavach diff` verb |
| `confirm` | `--live` on any preset |
| `revisit` | re-run any preset against the existing audit dir |
| `merge` | the `kavach merge-run` verb |
| `longshot` | removed |

Passing one to a mode-taking verb exits non-zero with that replacement named, rather than reporting
an unknown mode - a muscle-memory command deserves better than a shrug. `kavach render --mode` now
runs the same check; it did not, so `kavach render --mode longshot` printed `longshot` on the cover
of a signed report. Rendering with no `--mode` at all is unchanged and still prints no mode.

Gone with them: the `kavach enumerate` verb, `KAVACH_LONGSHOT_LIMIT`, `kb.update_target_status`, and
the `kavach-longshot-hunter`, `kavach-longshot-aggregator` and `kavach-wave` agents.

### `--live` replaces confirm mode

Live PoC validation was a mode, which made it a *choice against* depth: you could have `deep`, or
you could have execution against a running instance, and getting both meant two audits over one
tree. It is now a flag. `--live` appends six phases - `inventory`, `envscan`, `provision`,
`exploit`, `testgen`, `certify` - to whichever preset is running, and adds `LIVE_DELTA` 30 to its
ceiling, because provisioning an environment and executing per finding is a cost orthogonal to audit
depth. Every rail is unchanged: static-only remains the permanent default, and the charter in
`persona.md` still governs absolutely.

Two consequences worth stating plainly:

- **A plain `deep` run no longer writes `reports/confirmation-report.md`.** `certify` owns that
  artifact and `certify` is a `--live` phase. Under 0.2.x `deep` ended on a `DP16` that wrote one
  anyway - and a confirmation report is a claim about execution, which `deep` does none of.
- **`cleanup` waits for the tail.** Its prereqs resolve to `render` and `certify` together under
  `--live`, and to `render` alone without it, so the redaction pass is always last.

`confirm-workspace/` is now `live-workspace/`, and it is still transient - `cleanup.TRANSIENT` is
exactly `tmp/`, `findings-draft/` and `live-workspace/`.

### Phase ids are semantic, and gate filenames lost their mode prefixes

`BL3` is `hunt`. `DP12` is `variant`. `CF1_5` is `crosscheck`. An id now says what the phase does,
and `runs/<phase>/` and `findings-draft/<phase>-NNN-<slug>.md` read as English.

The gates moved with them. One phase shared by three presets cannot gate on a filename that varies
with the preset, so the prefixes are gone: `deep-chamber-summary.md` and `balanced-chamber-summary.md`
are one `chamber-summary.md`; `manual-attack-surface-inventory.md` and `deep-probe-summary.md` are
one `probe-summary.md`; `lite-q2-summary.md` is `source-sink-flows-all-severities.md`; every
`confirm-*` gate dropped its prefix; `<mode>-cleanup-summary.json` is `cleanup-summary.json`. The
result is **26 phases and 26 distinct gate artifacts, one apiece** - no phase can be closed by
another phase's output, which four `revisit` phases sharing a `findings/` gate used to allow.

The prefix was quietly doing a second job: it was also what re-opened `cleanup` for a second pass
over the same audit dir. That job now belongs to the gate rule instead of the filename - `cleanup`
is satisfied by its summary **and** an audit dir with no `tmp/`, `findings-draft/` or
`live-workspace/` left in it. So a `--live` tail over a finished audit, or a heavier preset re-run
over one, gets its own cleanup pass rather than inheriting the first run's summary and leaving its
own transient state (seeded credentials included) on disk.

### `lite` produces a report

`lite` now schedules `render`, so it ends in `reports/final-audit-report.md` instead of a bare
findings tree - a fast triage pass that produced no readable deliverable was a strange thing to
offer. It deliberately does **not** schedule `report`, the per-finding drafting phase: that costs
one `kavach-reporter` dispatch per promoted finding, which is most of a 15-dispatch ceiling.

### The prerequisite pre-flight is gone, along with the problem it reported

`modes.missing_prerequisites()` and `PREREQ_ARTIFACTS` are removed, and `kavach plan --json` no
longer emits a `"prerequisites"` key. They existed because `balanced`, `deep`, `diff`, `longshot`
and `revisit` scheduled neither `recon` nor `sweep` while everything downstream read what those two
write, so a harness had to know to run them by hand. Every preset now schedules both as phases of
its own, and the pre-flight has nothing left to report.

### The codegraph integration is removed

`kavach graph`, `core/kavach/graphindex.py`, the `codegraph` entry in the manifest's `requires`, and
the graph passages in `SKILL.md`, `docs/orchestration.md` and `README.md` are gone. It was optional
from the day it shipped, every hunter already had a grep fallback, and 0.2.5 had to special-case its
telemetry to stop it phoning home about a private repository. The one surviving mention is
`recon.py`'s comment citing a real 23 MB `.codegraph/codegraph.db` as why dot-directories are
skipped as a class - still true, and not about the integration.

### Docs

`docs/modes.md` and `docs/phase-reference.md` are rewritten from the registry rather than edited:
one phase table with preset membership, one `PREREQ_EDGES` table, and the induced-subgraph rule with
a worked example, replacing eight per-mode DAGs. `SKILL.md`'s frontmatter, mode parsing, live gate,
fan-out list and reconciliation tail follow the same three presets, and every phase id named across
`docs/`, `skill/` and `agents/` is re-keyed.

## [0.2.5] - 2026-08-25

A patch, and it holds: an audit written by any 0.2.x still resumes here. No phase id, no prereq
edge, no gate artifact and no CLI output shape moves. What changes is which directory
`consolidate` writes into, which directories `recon` walks, and what `graph index` tells the tool
it spawns. All three were found by driving the engine from a real harness against real trees.

### `consolidate` numbered from scratch, so the tree grew on its own

Display ids were assigned in severity order on every pass. A second pass over a larger finding set
therefore slid every id down a place and wrote a *fresh* directory beside each old one, for
findings that had not changed at all. `scope_promoted` correctly reported half the tree as stale,
and `render` built the deliverable over the duplicates.

Measured on a balanced audit driven from a real harness: **35 finding directories for 24 promoted
findings**, with `C1`-`C8` and `H1`-`H3` each doubled.

`consolidate --prune-stale` has shipped since 0.2.0 and moves superseded directories to
`findings-stale/`, and it is the wrong fix for this. A renumber that lands between a proof of
concept being written and the next promote leaves that PoC in the directory the prune carries away,
and losing evidence a run paid for is worse than a duplicated directory. So the numbering is stable
instead - a bug that cannot be created beats one that has to be cleaned up.

- **Ids are assigned from what is on disk**, not from the sort order. A fingerprint keeps the id,
  and the directory, that first promoted it, so a re-consolidate writes over its own work.
- **A new id is issued above every id on disk**, never into a gap a de-promoted finding left.
  Recycling a number puts two directories on one display id, which the report has no way to tell
  apart; gaps are the cheaper artifact.
- **A severity that crosses bands renames its directory** rather than orphaning it. `sweep.dedupe`
  raises severity when a second scanner corroborates a finding and the fingerprint does not move
  with it, and the evidence belongs to the finding, not to the id it used to carry.
- **A tree an earlier engine already doubled is adopted by its evidence.** Where two directories
  carry one fingerprint, the pass writes into the one holding a PoC, a write-up or a captured
  artifact, so re-consolidating such a tree collapses onto the paid-for copy and leaves the empty
  twin for `--prune-stale`.

`render` read the raw directory listing, so it rendered the twins - and `FP-` renames with them. It
now reads through `findings_tree.scope_promoted`, the reader `coverage` already used, so the gate
and the deliverable describe one set. The Limits section already named the stale count; the annex
now agrees with it.

### `recon` walked dot-directories, so tool state landed in the coverage appendix

`file-manifest.txt` is the report's Appendix B - coverage proven by a script rather than claimed by
a model. The walk skipped build and cache directories by name and followed everything else, so it
pulled a 23 MB `.codegraph/codegraph.db` into that manifest, and `scope` then ranked it.

Dot-directories are now skipped as a class rather than enumerated, because the next tool to invent
one ships before we hear about it. This is deliberately **not** a blanket "skip anything starting
with a dot". `AUDITED_DOT_DIRS` names the exceptions - configuration that ships with the repository
and runs somewhere, which is exactly the surface an audit exists to read: `.github`, `.gitlab`,
`.circleci`, `.buildkite`, `.azure-pipelines`, `.husky`, `.devcontainer`, `.docker`,
`.ebextensions`, `.platform`, `.well-known`, `.config`, `.aws`, `.ssh`, `.gnupg`. The CI detector
already depended on walking `.github/workflows`, and a credential directory committed to a
repository is the highest-value thing a secret scanner can be pointed at.

Dot-*files* are untouched: the filter only ever sees directory names, and `.env` is what a secret
scanner is for.

### `graph index` let codegraph phone home about a private repository

codegraph telemetry is on by default and nothing in `graphindex` said otherwise, so an audit of a
closed tree reported its own symbol graph upstream. Every spawn now carries
`CODEGRAPH_TELEMETRY=0` - `status` and `version` included, since those reach the same binary.

### Tests

659 (was 647), corpus gate green. Ten of the twelve new tests fail against 0.2.4. The other two
guard the dot-directory decision from the other side: `.github/workflows` still reaching the
manifest fails against a blanket dot skip, and `.env` is a file the directory filter never sees.

## [0.2.4] - 2026-08-25

A patch, and deliberately so: an audit written by any 0.2.x still resumes here. Nothing in the
engine changes — the only edit is what the module tells a harness it offers.

### `longshot` and `revisit` were drivable and not advertised

`modes.MODE_PHASES` has carried all eight modes since 0.1; `karya-module.json` declared four. A
harness that validates a requested mode against the manifest — which is the right thing for it to
do, since the manifest is what a module publishes — refused two modes the engine plans cleanly and
a driver walks end to end.

- **`longshot`** — `LS1` `core:enumerate`, `LS2` the per-file hail-mary hunt, `LS3` aggregation.
- **`revisit`** — `RV0` intent cartography through `RV11c`, over a finished audit.

`confirm` and `merge` stay undeclared on purpose. `confirm` runs live proof-of-concept code against
a running service, which every sandbox a harness is likely to impose refuses by design; `merge`
needs a multi-audit driver (`merge-run`, `core:merge --extra`) that does not exist yet.

## [0.2.3] - 2026-08-25

A patch, not a contract change: an audit written by 0.2.0, 0.2.1 or 0.2.2 still resumes here. Both
bugs below lose work a run has already paid for, and both were found by driving `balanced` against
real trees — neither is reachable from a stub.

### A fan-out's gate artifact is not proof the fan-out finished

`BL3` hands all eight domain hunters the same assigned output path, so the first one home writes the
gate artifact and `gate_satisfied` answers true for the whole phase. Within one process a harness
can carry its own roster ledger; that ledger dies with the process.

Measured on a resumed audit of a 25,083-file tree: four hunters failed on a provider 402, one of the
four that succeeded wrote the gate, and on resume `plan` never offered BL3 again — it went straight
to BL4. The audit advanced toward certification permanently missing half its static analysis,
including `kavach-supply`, whose slice held 62 of the audit's 158 leads. Nothing reported the gap.

- **`runner.fanout_pending(audit_dir, phase)`** diffs the roster against `runs/<phase>/*.json`, and
  `next_actionable` keeps a phase open while any member has no result.
- Deliberately **not** consulted by `phase_status`, so an incomplete fan-out is re-planned without
  blocking the phases after it. A hunter that can never succeed would otherwise wedge the audit, and
  this engine reports rather than blocks — `coverage` is where the shortfall belongs.
- **`dispatch.result_path_for`** is `result_path` without the `mkdir`: a planner that only asks
  whether a file exists should not leave a `runs/<phase>/` behind for every phase it considered.
- `cleanup` keeps `runs` (it is in `DURABLE`), so a completed audit stays complete.

### `merge --extra` is a sub-agent result, so it is read like one

`merge` read every `--extra` with `load_findings`, the strict reader written for `findings.json`,
which requires a `findings` key and attributes nothing. BL4's probe and BL5's chamber answer with
`{agent, status, summary, outputs}`, so the strict read raised `KeyError` and a harness passing a
phase's results wholesale lost the whole call.

`load_agent_findings` is the reader for that shape — tolerant of a missing key, and attributing each
finding to the dispatch that wrote it. Its own docstring already drew the line: agent results get
the tolerant read, `findings.json` keeps the strict one. `merge` was on the wrong side of it.

Measured on a full `balanced` audit of `leaky-node`, 13 dispatches and $1.0910: the agents found all
six of the fixture's vulnerabilities with correct line numbers, and the 38 KB report named the three
hardcoded secrets and none of the three logic flaws. Every finding it shipped came from a scanner.
With the tolerant read, on the same result files: `findings.json` 11 → 35, `consolidate` 11 → 24
finding dirs, the report 38 KB → 86.7 KB.

### Tests

647 (was 643), corpus gate green. `test_mode_smoke` advanced the whole balanced chain by writing
gate artifacts alone, never banking a hunter's result — that test was encoding the first bug, and it
now banks BL3's roster.

## [0.2.2] - 2026-08-24

A patch, not a contract change: an audit written by 0.2.0 or 0.2.1 still resumes here. Everything
below was found by driving the engine from a real harness against a real tree, not from fixtures.

### `balanced` was not runnable from a fresh audit directory

`recon` writes `recon.json` and `file-manifest.txt`; `sweep` is the **only** verb that writes
`findings.json`. Almost everything downstream reads one of those — `scope` ranks the manifest, and
`slice`, `triage` and `render` all read `findings.json`. `lite` opens with `core:recon` and
`core:sweep` and so prepares itself; `balanced`, `deep`, `diff`, `longshot` and `revisit` schedule
neither, and nothing said so anywhere a harness could read it.

Driven without them, `balanced` sent all eight BL3 hunters an empty slice and then died in its
report tail on a `findings.json` nothing had written.

- **`plan --json` reports `prerequisites`** — the deterministic passes this mode needs, does not
  schedule, and does not already have on disk. Empty for `lite`; two entries for a fresh
  `balanced`. Keyed on the artifacts rather than the mode, so it empties as they appear and a
  resume re-walks nothing.
- **`modes.missing_prerequisites(audit_dir, mode)`** is the same answer as a function, and a test
  asserts the invariant across every mode in `MODE_PHASES`: each one either schedules a
  deterministic pass or declares it. No mode can silently need an artifact again.
- **SKILL.md** stated this for `longshot` and `revisit` only, and only for `recon`. The note now
  covers any mode that does not schedule them, and names `sweep` as the sole source of
  `findings.json`.

### The code graph was never available on a repository nobody had indexed by hand

`codegraph index <target>` refreshes an existing index and refuses to create the first one — it
exits 1 with "Run codegraph init first". `graph index` called it unconditionally, so it recorded
`available: false` for every unindexed target: a silent fall back to grep on exactly the trees
where a graph pays for itself. One hunter without a graph on a 25k-file tree measured $0.199 and
37 turns.

`status --json` reports `initialized`, so that picks the verb: `init` to build, `index` to refresh.
An unreadable status falls back to `init`, because guessing that way costs a rebuild and guessing
the other way costs the graph. `--quiet` is `index`'s alone; `init` rejects it. The stubs modelled
neither refusal and now do.

Verified against the real codegraph 1.5.0: `init` builds 428 files / 8,389 nodes / 20,440 edges in
1.3s, and `graph index` then writes `available: true`.

### Also

- `karya-module.json` declares kavach as a karya module — one file, no code (#6).

638 tests (was 628), corpus gate passes.

## [0.2.1] - 2026-08-23

A patch, not a contract change: an audit written by 0.2.0 still resumes here.

### The agent result contract was unsatisfiable

Driving a real LT2 dispatch through a harness found two defects that fixtures could not, because
every existing test built its findings in Python rather than parsing one a model wrote.

- **`finding-schema.md`'s own example did not ingest.** The example object omitted `source`,
  which `Finding` requires — so an agent that followed the documented contract exactly produced
  a file the engine quarantined. The example now carries `source`, the field rules explain what
  it is for, and a test parses the example out of the document and ingests it, so the doc and
  the dataclass cannot drift apart again.
- **One invented key threw away the whole file.** `Finding.from_dict` did `cls(**d)`, so a single
  hallucinated field (`exploitability`, `classification`) raised `TypeError`, quarantined the
  result, and lost the six correct findings beside it. Unknown keys are now dropped the same way
  `id` already was — the author does not get to decide the shape. The schema doc says so, so a
  model knows that inventing a field loses the content rather than adding it.
- **A result with no `findings` key is not corrupt.** BL4's probe writes a protocol status
  object rather than a findings envelope, and `ingest` raised `KeyError` on it — so the phase
  kept re-planning a dispatch that had already done its work. `ingest` reads its own results
  tolerantly now; `findings.json` keeps the strict read, because a missing key *there* is an
  engine bug rather than an agent's choice of shape.
- **A result that omits `source` is attributed to its own dispatch.** `ingest` reads the agent
  back off the result filename the engine itself chose. This is not cosmetic: `triage.classify`
  marks a finding `reasoned` only when a source segment names an agent, and only `reasoned`
  findings are promotable — so an unattributed finding was silently unpromotable.

628 tests (was 622), corpus gate passes.

## [0.2.0] - 2026-08-23

**Breaking for anything driving the engine.** `dispatch.ingest` returns `(written, skipped)`
instead of a count, and `phase-prompt` now emits a complete prompt rather than a one-line body.
An audit created by 0.1.x cannot be resumed by 0.2.x — the phase contract moved, and resume
re-derives what is left from that contract. `kavach resume` refuses across the minor and says so
rather than producing an incoherent report.

### Versioning and the audited tree

- **One version.** `kavach.__version__` is the single source; `pyproject.toml` reads it via
  `dynamic = ["version"]`. Two copies disagreed the moment either was bumped alone, and the
  packaged metadata is what a compatibility check reads. A test fails on a missing changelog
  entry for the current version.
- **Audits record the engine that made them.** `engine_version` on the audit record, set at
  `state init`. `kavach resume` refuses an audit from an incompatible engine (same `major.minor`
  only — on 0.x the minor is the breaking axis, and what moves across it is exactly what resume
  depends on: the phase list, the prereq graph, and which artifact closes a gate).
- **Audits record the tree they were pointed at.** `commit`, `branch` and `dirty` are captured at
  `state init`, not only at completion. `complete_audit` recording the commit at the end was
  enough to key a baseline for a later diff and not enough to notice a run resumed after a
  checkout, a pull or a rebase — where the findings on disk cite lines in a tree that no longer
  exists. `resume` reports the drift; it does not block, because re-auditing a moved tree is a
  legitimate thing to want.
- **Short handles.** `state.handle()` gives the trailing hex of an audit id — derived, not
  invented, so there is no mapping table and it reads like a git sha. `kavach resume <handle>`
  takes it; an ambiguous handle resolves to nothing rather than to a guess.
- **`kavach since`** — what changed since the last completed audit: head vs the audited commit,
  the changed file list, whether it is narrow enough for `diff` mode, and the baseline path. The
  engine could already key a baseline by commit and scope a diff; nothing surfaced whether doing
  so was worth it. Re-auditing a whole repo because three files moved is the expensive mistake
  this exists to prevent.


### Fixed — resume safety

Both of these only show up on the path a resume actually takes, which is why they survived: a
phase stays actionable until its gate artifact exists, so `ingest` re-runs over the same result
files on every resume.

- **`ingest` is idempotent.** It skipped nothing and numbered drafts sequentially, so folding a
  result twice wrote a second copy of every finding — and the duplicates reached the report as
  inflated counts. Drafts already carry the finding's fingerprint as `kavach_id`, so that now
  answers "have I folded this in already?" A re-run dispatch that re-reports what it already
  found is deduplicated the same way.
- **A truncated result file no longer fails the whole phase.** The agent writes its own result,
  so the engine cannot make that write atomic; a dispatch killed mid-write left JSON that raised
  on `ingest` and took its seven valid siblings down with it, on every resume. Unreadable results
  are now moved to `runs/<phase>/corrupt/` and reported, the rest fold in, and the phase gate
  stays open so the missing dispatch is re-planned. `runs/<phase>/*.json` therefore holds only
  readable results, which keeps "did this dispatch produce a result?" a plain existence check.

`dispatch.ingest` returns `(written, skipped)` rather than a count.

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

[0.2.0]: https://github.com/adhuniklabs/kavach/releases/tag/v0.2.0
[0.1.0]: https://github.com/adhuniklabs/kavach/releases/tag/v0.1.0
