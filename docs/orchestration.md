# KAVACH Orchestration - the engine/skill seam

KAVACH is a Claude Code skill backed by a Python core. The core **never spawns sub-agents** - it
cannot; a Python process has no `Task` tool. So the work of actually running an audit splits
cleanly down one seam:

- **The Python engine** (`core/kavach/`) is a deterministic **planner + state manager + renderer**.
  It owns the mode/phase registry, the prerequisite DAG, `audit-state.json`, retry/backoff
  bookkeeping, fan-out batch planning, the findings-draft→findings tree, per-finding and KB
  rendering, diff-scoping, merge/dedupe, cleanup, and the score/gate/certification. It never talks
  to a model and never dispatches a sub-agent.
- **A harness** - `SKILL.md` (the VAJRA lead, running inside Claude Code) or any other program -
  is the only thing that issues `Task` calls. It asks the engine "what's actionable right now,"
  gets back a composed prompt per phase, dispatches the actual sub-agent(s), and hands the raw
  result back to the engine to fold in.

**The engine owns the whole dispatch contract, not half of it.** It used to compose a one-line body
(`"Execute phase BL3 (Static Analysis & Triage)."`) and leave the real instruction - which
references to load, which agents fan out, what the phase must produce - in `SKILL.md` prose. That
made `SKILL.md` the spec rather than a client of it: every other harness had to re-read the prose
and re-encode it, and drift from it silently. `modes.PHASE_SPECS` now holds the task, the reference
set and the fan-out roster per phase, `modes.AGENT_REFERENCES` holds each agent's own reading list,
and `dispatch.phase_prompt` renders all of it. `SKILL.md` and a third-party driver dispatch the
same bytes.

Every piece of piolium's in-process machinery (`Scheduler`, `runAgentPhase`, `runBatch`) ports as a
**plan the skill drives**, never as code that spawns anything itself. This is what keeps KAVACH
model-agnostic and host-native - the engine doesn't care which model is running `SKILL.md`.

## The loop

One phase, start to finish, looks like this:

1. **Plan.** `SKILL.md` asks the engine what's actionable: `kavach plan --mode <mode>` (or the
   equivalent `runner.next_actionable(audit_dir, mode)` call) returns the phase ids whose prereqs
   are complete/skipped and whose gate artifact doesn't exist yet, in mode order. `runner.
   ensure_prereqs()` is the safety check behind `--only` - it raises `PrereqError` rather than let a
   phase run out of order.
2. **Budget check.** Before any fan-out, the skill asks the ledger how much of what it planned it
   may actually spend: `kavach budget check --phase <id> --planned N` returns
   `{allowed, dropped, reason}` and **records the shed itself**, at decision time. It exits `7` when
   `allowed < planned`, so the skill can branch in bash. The skill dispatches `allowed`, never
   `planned`. See "The dispatch ledger" below.
3. **Phase-prompt.** For each actionable phase, the harness asks the engine to compose the sub-agent
   prompt: `kavach phase-prompt <phase> --mode <mode> --target <path> [--agent A] [--index i]`
   (backed by `dispatch.phase_prompt`) returns a **complete, dispatchable prompt** - a runtime header -
   target repo root, audit dir, state file path, mode/phase + label, the output paths this phase is
   expected to write, **the exact absolute path this sub-agent must write its machine result to**
   (`dispatch.result_path` → `runs/<phase>/<agent>[-<index>].json`), and the instruction to keep
   state on disk and write a failure note rather than fabricate a result if blocked.

   — followed by the absolute paths of every reference and audit input that agent must read, and
   the phase's task from `PHASE_SPECS`. A reference the machine does not have is *named as missing*
   rather than dropped, so an agent is never left assuming it was given something it was not.

   `--index` is load-bearing on a fan-out: without it, N concurrent dispatches of one phase are all
   told to write the same file and clobber each other. The engine cannot detect that for the skill,
   so the contract is "one distinct `--index` per dispatch, 1-based."

   `kavach plan --mode <mode> --json --target <path>` returns the same for every actionable phase at
   once - roster, per-dispatch index, result path, references, gate artifacts, and whether the roster
   is sequential. A scripted driver needs nothing from `modes.py` and nothing from this document.

   `kavach agents [--json]` is the roster as data: each agent's tools, its `model:` (what Claude Code
   reads) and its `tier:` - `reasoning` / `mechanical` / `triage`, the same decision spelled so a
   harness on any provider can route it. `test_agents_load` fails if the two spellings drift.

   `kavach slice <phase> --agent <name> --index <i>` cuts that domain's leads out of `findings.json`
   into `runs/<phase>/slices/<agent>-<i>.json`, with a count of what was left to other domains. The
   eight BL3/DP4 hunters were each being sent the whole finding set, so a 300-row sweep was paid for
   eight times; the slice also tells the hunter what it did *not* see, because one that believes its
   slice is the whole set reports coverage it does not have.
4. **Task.** `SKILL.md` issues the actual `Task` call(s) - batches of at most `KAVACH_MAX_AGENTS`
   (default 6, and it must stay under Claude Code's own `CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS`,
   default 20) when the phase fans out. The engine never executes a sub-agent; it only told the
   skill how many to run and with what prompt.
5. **Charge.** `kavach budget charge --phase <id> -n <dispatched>` accounts for what actually ran.
   A harness that pays per token adds `--tokens-in N --tokens-out M --cost-usd C`; the engine never
   calls a model, so spend is only ever as real as what the caller reports. With those reported,
   `--max-cost-usd` becomes a third ceiling that sheds exactly like wall clock does.
6. **Ingest.** The skill hands the sub-agents' output back to the engine: `kavach ingest <phase>`
   folds **every** `runs/<phase>/*.json` in one call (or `--result <file>` for exactly one), backed
   by `dispatch.ingest`, into `findings-draft/<phase>-NNN-<slug>.md` entries.
7. **Triage / consolidate / promote.** `kavach triage` writes each finding's `finding_class` back
   into `findings.json`; `kavach consolidate` (backed by `findings_tree.consolidate`) then promotes
   critical/high `reasoned`/`code`/`secret` findings into `findings/<C*|H*>-<slug>/` and rolls the
   scanner classes into at most two `findings/G*/` aggregates, assigning display ids in severity
   order. Triage first: `consolidate` classifies internally but does not persist, so a render from
   an untriaged `findings.json` reports every finding as unclassified.
8. **Coverage.** After a per-finding batch (PoC or report drafting), `kavach coverage --phase
   poc|report` walks the promoted tree and writes `attack-surface/{poc,report}-coverage.json`,
   naming every directory still missing its artifact. Exit `0` complete, `7` incomplete. **These
   artifacts are the gates** for the seven per-finding phases, so this runs after every batch, not
   once at the end.
9. **Gate.** The engine re-checks: does the phase's gate artifact now exist - and, for the report
   phases, is it over 500 bytes; for a coverage artifact, does it say `complete: true`? If yes, the
   phase is complete - gate-driven, not state-driven. `audit-state.json` is a cache of this fact,
   never the source of truth for it.
10. **Repeat** until no phase is actionable - either everything gated complete, or something's
    blocked/failed and needs a retry or a human look.

The skill never invents this loop per-mode; it is the same steps for every one of the 8 modes. What
changes per mode is only which phases exist and what their prereqs/gates are
(`docs/phase-reference.md`).

## The dispatch ledger

A deep run on a mid-size repo plans ~800 sub-agent dispatches, and a non-fork sub-agent does not
share the parent's prompt cache - each one pays full input cost for its persona, references, recon
and its slice of the finding set. Without a ceiling there is no record of what a run chose not to
do.

The ledger lives inside the audit's own record in `audit-state.json` under a `budget` key, so it
survives resume, inherits the state filelock, and needs no second file:

- `kavach state init --budget N --max-wall-seconds S` seeds it. Defaults are per mode (lite 15,
  balanced 60, deep 120, diff 10, confirm 30, revisit 80, merge 20, longshot 40) and 3 hours of wall
  clock. `0` means **unlimited** - distinct from exhausted, which allows 0 with reason
  `"dispatch ceiling"`. Both mirror to `KAVACH_MAX_DISPATCHES` / `KAVACH_MAX_WALL_SECONDS`.
- `check` decides and records; `charge` accounts. Both take the state filelock.
- Wall clock is evaluated **before** the dispatch ceiling. `allowed: 0` with reason `"wall clock"`
  is how a long run degrades gracefully: the skill stops fanning out, finishes the report from what
  it has, and the report's Limits section names what was dropped.
- Every shed record reaches `AuditReport.limits` and prints in §2.3 of every rendered format. That
  is the point of recording at decision time rather than at charge time - a coordinator that
  crashes after shedding still owes the reader an honest note.

The ledger is a ceiling, not a scheduler. Which items get dropped when `allowed < planned` is the
skill's judgement (drop by ascending severity, keep every Critical); the engine only says how many.

## Retry and resume

Every phase attempt is tracked in `audit-state.json` under `phases.<id>`. On failure,
`runner.record_attempt()` increments `attempt`, computes the next backoff
(`retry.backoff_ms`: `min(cap, base * 2**(attempt-1))`, defaults 5s base / 120s cap, overridable via
`KAVACH_PHASE_BACKOFF_MS` / `KAVACH_PHASE_BACKOFF_CAP_MS`), and persists `last_error` +
`next_retry_at`. The skill is expected to honor that backoff before re-dispatching. Per-finding
phases (PoC, report drafting) get their own retry ceiling (`KAVACH_PER_FINDING_MAX_RETRIES`,
default 10) so one stubborn finding doesn't block the phase.

Because completion is **gate-driven** - a phase is complete iff its artifact exists on disk, full
stop - resuming an interrupted run costs nothing extra:

- `audit-state.json` is written atomically (`.tmp-<pid>` → `os.replace`) under a `filelock`, so a
  crash mid-write never leaves a corrupt file for the next run to trip over; if one somehow
  appears, `state.load_state()` moves it aside to `.corrupt-<timestamp>` and starts clean rather
  than silently overwriting or crashing.
- `state.latest_resumable_audit()` picks the newest `in_progress` or `failed` run, and returns
  `None` when a **newer** `complete` run exists - so resume can neither re-open a finished audit nor
  resurrect an abandoned one that a later finished audit has superseded. Scanning `in_progress` then
  `failed` with no recency comparison offers to resume a stale `balanced` run that a newer
  `complete` `deep` audit has already replaced.
- On resume, `runner.next_actionable()` re-derives what's left to do purely from what's on disk plus
  the prereq DAG. A phase that completed before the interrupt (its gate artifact exists) simply
  doesn't show up again; a phase that was mid-flight when the interrupt hit re-appears as
  actionable and gets a fresh attempt.
- `main()` catches `KeyboardInterrupt`, marks the in-progress phase `failed` with a note, and exits
  `130` - so an operator-cancelled run is always resumable, never left in an ambiguous state.

This is also why `SKILL.md` never needs its own resume logic: "what's left to do" is always a
fresh query to the engine, not something the skill has to remember across a session boundary.

## `--headless`

The primary path is skill-orchestrated: a human or an agent host runs `SKILL.md` inside Claude
Code, which issues real `Task` calls. `--headless` is a secondary, CI-oriented path where the
engine itself shells out to `claude -p` via a `concurrent.futures.ThreadPoolExecutor` (bounded by
the same `KAVACH_MAX_AGENTS` cap the scheduler uses for fan-out planning either way). It exists so
KAVACH can run unattended in a pipeline without a live Claude Code session driving it; it is not
the default and it does not change the phase contract, the gate semantics, or the output tree -
it only changes who calls the model. Everything in this document about plan/phase-prompt/ingest/
gate/resume applies identically in `--headless` mode; the difference is purely mechanical (the
engine dispatches instead of the skill).

## The graph and the scope

Two optional inputs, both aimed at the same cost: a hunter spends most of its budget on
*discovery* - grep for a symbol, open the file, follow the import, repeat - before it reaches the
line it will cite.

`kavach graph index <target>` shells out to [codegraph](https://github.com/colbymchenry/codegraph)
and records the outcome in `attack-surface/graph-status.json`. The engine never queries the graph;
it only establishes whether one exists, so `dispatch.phase_prompt` can tell an agent to reach for
it - or tell it plainly that there is none, which matters more, because an agent that assumes a
tool it does not have burns a turn finding out. Missing binary, failed index and timeout are the
same outcome: `available: false` with the reason, exit 0, hunters grep instead. It is a scanner,
not a prerequisite. Every spawn carries `CODEGRAPH_TELEMETRY=0`: the tool reports usage home by
default, and what it would report is the symbol graph of a tree the operator did not choose to
publish.

The graph only pays off when *every* hunter queries it. A fan-out where the lead has the graph and
the eight sub-agents still read files pays for the index and keeps the crawl, so the graph-first
instruction goes into every dispatch prompt, not into a coordinator's preamble.

`kavach scope [--agent A]` ranks `file-manifest.txt` by security relevance and writes
`attack-surface/scope[-<agent>].json`, which `phase_prompt` names as an input (the agent's own
scope wins over the repo-wide one). Ranking is deterministic and path-shaped - no model, no content
read, because those cost exactly what this exists to save. Two details are load-bearing:

- **Signals match path tokens, not substrings.** `frag in path` reads `ci` out of
  "dependen*ci*es" and `api` out of "r*api*d". A short signal must be a whole token; a longer one
  may prefix one, which is what lets `authoriz` reach "authorization".
- **The sort is domain-first, then score.** A generic score sums, so an auth router collects
  auth + session + route + api and outranks every hunter's own files - which handed all eight
  hunters the same list, the same as having no per-domain scope at all.

A high rank is "look here first", never "the bug is here". Nothing is hidden: the manifest is
still there and the scope artifact says so in as many words.

## The event log

Completion is gate-driven, which makes progress *derivable* from disk but not *observable*: nothing
recorded why a phase re-ran, what a budget check decided, or how long anything took, so a live view
had to poll mtimes and guess. `.kavach/events.jsonl` is one JSON object per engine decision,
appended at the audit root and durable across `cleanup`. Reading it is a tail - no state lock, no
coordination with the run. Writes are a single `write()` to an `O_APPEND` descriptor with lines
capped below `PIPE_BUF`, so concurrent phases interleave whole lines; that is also why it is JSONL
and not a JSON array. `kavach events [--since N]` replays it.

## Source of truth

- Code: `core/kavach/runner.py` (planner, gates, retry bookkeeping), `core/kavach/state.py`
  (`audit-state.json` manager), `core/kavach/modes.py` (`PHASE_SPECS` - the dispatch contract),
  `core/kavach/dispatch.py` (prompt composition, dispatch plan, ingest), `core/kavach/agentdefs.py`
  (the roster as data), `core/kavach/slicing.py` (per-agent lead lists), `core/kavach/events.py`
  (the run log), `core/kavach/budget.py` (dispatch / wall-clock / spend ceilings),
  `core/kavach/graphindex.py` (the optional code graph), `core/kavach/scoping.py` (security-relevance
  ranking), `core/kavach/scheduler.py` (fan-out batch planning), `core/kavach/retry.py` (backoff math).
