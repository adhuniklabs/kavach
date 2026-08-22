# MCP-Assisted Semantic Analysis (optional)

This reference covers how to use an MCP-backed semantic/LSP tool (e.g. Serena, or any
symbol-resolution MCP server available in the environment) during zeroize-audit's Stage 4
cross-file semantic pass. This is an **optional delegate** - same posture as the `codeql` skill
toward CodeQL: reach for it when available, fall back to `Grep`/`Read` tracing without it, and
never stop the run over its absence. For flag extraction and pipeline setup unrelated to MCP,
refer to `compile-commands.md`.

---

## Preconditions

Before running any MCP queries, confirm:

| Precondition | Failure behavior |
|---|---|
| `compile_commands.json` valid and readable (C/C++) | If missing, skip MCP entirely - fall back to `Grep`/`Read` tracing |
| An MCP server exposing symbol-resolution tools is configured in this environment | If none is available, skip this stage entirely - it is optional |
| The MCP server can resolve at least one symbol in the TU | If it can't, treat MCP as unavailable for that TU; mark findings from that TU as needing an extra signal per the Confidence Gating rules in SKILL.md |

**Rust note**: Cargo does not natively produce `compile_commands.json`. Use `bear -- cargo build` or `bear -- cargo check` to generate one if an MCP tool needs it for indexing.

---

## What an MCP Semantic Tool Buys You

An LSP-backed MCP server (Serena is one example - it wraps `clangd` for C/C++ and equivalent
language servers for other languages) exposes symbol-name-based queries instead of raw text
search:

| Capability | Why it matters here |
|---|---|
| Resolve where a sensitive symbol is defined, with type info and body | Confirms the exact type/size for wipe-size validation (Stage 5) without guessing from source text |
| Find all use sites and callers across files | Locates adjacent wipe calls and copy destinations that a single-file grep would miss (Stage 6's `SECRET_COPY`) |
| List all symbols in a file | Useful for exploring unfamiliar TUs before scoping a search |
| Trace outgoing calls from a function body | Finds cleanup wrapper functions reachable from a sensitive object's scope |

If no such tool is configured, do all of the above with `Grep`/`Read` directly - slower and more
manual, but it's the same information, just without the language-server's resolved-symbol
convenience. Note in the finding's evidence that resolution was done by hand rather than via MCP;
this affects the signal count per Confidence Gating below.

---

## Query Order (when MCP is available)

Run in this order so each step's output informs the next. Complete all queries for a given TU
before moving to the next TU.

### Step 0 - Activate/index the project

Most LSP-backed MCP servers need an explicit "activate this project root" call before any other
query works (e.g. Serena's `activate_project`). Do this once per run, pointing at the repository
root. If activation fails, treat MCP as unavailable for the rest of the run - don't retry per-TU.

### Step 1 - Resolve symbol definition

Establishes the canonical declaration location and type information used in all subsequent
queries - request the symbol body/type info, not just the location, so Stage 5's size validation
has real typedef/array-size data instead of a source-level guess.

If the symbol name is ambiguous across files, narrow the query with the specific file path.

### Step 2 - Collect all use sites

Find every location where the sensitive symbol is referenced, across files. For each reference in
a file other than the source TU, check that file for its own cleanup path. Filter out references
inside generated/build-output directories.

### Step 3 - Resolve type and size

If you need to follow a typedef or type-alias chain, resolve the type name directly the same way.
Use this to validate wipe sizes - a `sizeof(ptr)` bug becomes obvious once the symbol's real body
reveals `uint8_t [32]` but the wipe call uses `sizeof(uint8_t *)`.

### Step 4 - Trace callers and cleanup paths

Find callers of the function containing the sensitive object (they may hold their own copy of the
secret) and find cleanup paths reachable from wipe wrapper functions. For outgoing calls (what does
this function call?), read the function body and resolve each called symbol in turn.

---

## Interpreting Responses

| Response | Meaning | Action |
|---|---|---|
| Empty results | The tool could not resolve the symbol | Check compile DB path; verify symbol name spelling; retry narrowed by file path |
| Timeout | Query too slow | Don't wait indefinitely - treat that lookup as unavailable for this TU and fall back to manual trace |
| Multiple results for same name | Symbol is defined in multiple TUs or headers | Disambiguate by file path; note the ambiguity in evidence |
| References in generated files | Hits in build-generated sources | Filter by source directory prefix |
| No referencing symbols found | Symbol is unused or not indexed | Acceptable for leaf functions; note in evidence |

---

## Confidence Scoring (mapped onto KAVACH's confirmed/suspected)

MCP evidence (or, absent MCP, a manual cross-file trace you did yourself) is **one signal** toward
the 2-signal threshold for `confirmed` in SKILL.md's Confidence Gating - never a confidence tier of
its own. Concretely:

- Cross-file resolution alone (MCP or manual), with nothing else corroborating → 1 signal →
  `suspected`. Name "resolve every remaining call site" or "run the IR/ASM diff" as the next signal.
- Cross-file resolution **plus** one more independent signal (IR evidence, ASM evidence, a second
  source-level heuristic, a validated PoC) → 2 signals → `confirmed`.
- If MCP was unavailable and you did the cross-file trace by hand, treat it exactly the same way -
  the signal counts the same whether an LSP resolved it or you read every call site yourself. The
  only difference is speed and coverage confidence: note in the evidence field if your manual trace
  might have missed a call site MCP would have caught (e.g. a very large fan-out), so the operator
  knows to treat the `suspected` call as slightly less certain than an MCP-backed one would be.

Do not introduce a third confidence bucket for "resolved via MCP but nothing else confirms it" -
that is exactly the 1-signal case above, and it is `suspected`, same as any other single-signal
finding.
