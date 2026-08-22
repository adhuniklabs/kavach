# Detection Strategy

Full step-by-step guidance for the SKILL.md workflow's Stages 2-10. Stage numbers here match the
`## Workflow` section of `SKILL.md` exactly - Stages 2-6 are source-level, Stages 7-10 are
compiler-level.

---

## Stage 2 - Identify Sensitive Objects

Scan all TUs for objects matching these heuristics. Each heuristic has a confidence level that
propagates to findings (see SKILL.md's Confidence Gating).

**Name patterns (low confidence)** - match substrings case-insensitively:
`key`, `secret`, `seed`, `priv`, `sk`, `shared_secret`, `nonce`, `token`, `pwd`, `pass`

**Type hints (medium confidence)** - byte buffers, fixed-size arrays, or structs whose names or
fields match name patterns above.

**Explicit annotations (high confidence)**:
- Rust: `#[secret]`, `Secret<T>` patterns (project-specific)
- C/C++: `__attribute__((annotate("sensitive")))`, `SENSITIVE` macro (project-specific)

Record each sensitive object with: name, type, location (file:line), confidence level, and the
heuristic that matched.

## Stage 3 - Detect Zeroization Attempts

For each sensitive object identified in Stage 2, check whether a call to an approved wipe API (see
Approved Wipe APIs in SKILL.md) exists within the same scope or a cleanup function reachable from
that scope.

Record: wipe API used, location, and whether the wipe was found at all.

## Stage 4 - Cross-File Semantic Pass (when available)

Run this step **before** correctness validation so that resolved types, aliases, and cross-file
references are available to Stages 5 and 6. Skip and continue with plain `Grep`/`Read` tracing if
no MCP-backed semantic tool is available - see `mcp-analysis.md` for the query sequence and how to
interpret responses either way, and downgrade confidence per SKILL.md's gating rules rather than
stopping the run.

Prioritize resolving sensitive-object names first, then wipe wrapper function names. Score
confidence: name match alone → do not count as a signal on its own; name + type resolved → one
signal; name + type + call chain confirmed → two signals (pushes toward `confirmed`).

## Stage 5 - Validate Correctness

For each sensitive object with a detected wipe, use type and alias data from Stage 4 (if available)
to validate:
- **Size correct**: wipe length matches `sizeof(object)`, not `sizeof(pointer)`. Resolved typedefs
  and array sizes take precedence over source-level estimates.
- **All exits covered** (heuristic): wipe is present on normal exit, early return, and error paths
  visible in source. Flag `NOT_ON_ALL_PATHS` if any path appears uncovered.
- **Ordering correct**: wipe occurs before `free()` or scope end, not after.

Emit `PARTIAL_WIPE` for incorrect size. Emit `NOT_ON_ALL_PATHS` for missing paths (heuristic; Stage
10 CFG analysis provides the definitive version, if run).

## Stage 6 - Data-Flow and Heap Checks

Use cross-file reference data from Stage 4 (if available) to extend tracking beyond the current TU.

**Data-flow (produces `SECRET_COPY`):**
- Detect `memcpy()`/`memmove()` copying sensitive buffers.
- Track struct assignments and array copies of sensitive objects.
- Flag function arguments passed by value (copies on stack).
- Flag secrets returned by value.
- Emit `SECRET_COPY` when any of the above copies exist and no approved wipe is tracked for the
  copy destination.

**Heap (produces `INSECURE_HEAP_ALLOC`):**
- Detect `malloc`/`calloc`/`realloc` used to allocate sensitive objects.
- Check for `mlock()`/`madvise(MADV_DONTDUMP)` - note absence as a warning.
- Recommend secure allocators: `OPENSSL_secure_malloc`, `sodium_malloc`.

---

## Stage 7 - IR Comparison (produces `OPTIMIZED_AWAY_ZEROIZE`)

For each TU containing sensitive objects:

```bash
WORKDIR=".kavach/tmp/zeroize-workspace"; mkdir -p "$WORKDIR"

FLAGS=()
while IFS= read -r flag; do FLAGS+=("$flag"); done < <(
  python3 {baseDir}/tools/extract_compile_flags.py \
    --compile-db <compile_db> --src <file> --format lines)

bash {baseDir}/tools/emit_ir.sh --src <file> \
  --out "$WORKDIR/<tu_hash>.O0.ll" --opt O0 -- "${FLAGS[@]}"

bash {baseDir}/tools/emit_ir.sh --src <file> \
  --out "$WORKDIR/<tu_hash>.O1.ll" --opt O1 -- "${FLAGS[@]}"

bash {baseDir}/tools/emit_ir.sh --src <file> \
  --out "$WORKDIR/<tu_hash>.O2.ll" --opt O2 -- "${FLAGS[@]}"

bash {baseDir}/tools/diff_ir.sh \
  "$WORKDIR/<tu_hash>.O0.ll" \
  "$WORKDIR/<tu_hash>.O1.ll" \
  "$WORKDIR/<tu_hash>.O2.ll"
```

Use `<tu_hash>` (a hash of the source path) to avoid collisions when processing multiple TUs.
`diff_ir.sh` outputs a unified diff to stdout; a non-zero exit code means divergence was detected.
Clean up `$WORKDIR` on completion or failure.

**Interpretation:**
- Wipe present at O0, absent at O1 → simple dead-store elimination. Flag `OPTIMIZED_AWAY_ZEROIZE`.
- Wipe present at O1, absent at O2 → aggressive optimization. Flag `OPTIMIZED_AWAY_ZEROIZE`.
- Include the IR diff as mandatory evidence in the finding.

Key IR patterns: `store volatile i8 0` is the primary wipe signal; its absence at O2 when present
at O0 is DSE. `@llvm.memset` without the volatile flag is elidable. `alloca` with
`@llvm.lifetime.end` and no `store volatile` in the same function indicates stack retention.

## Stage 8 - Assembly Analysis (produces `STACK_RETENTION`, `REGISTER_SPILL`)

Skip if the bundled ASM tools are unavailable (degrade these two categories only).

```bash
bash {baseDir}/tools/emit_asm.sh --src <file> \
  --out "$WORKDIR/<tu_hash>.O2.s" --opt O2 -- "${FLAGS[@]}"

bash {baseDir}/tools/analyze_asm.sh \
  --asm "$WORKDIR/<tu_hash>.O2.s" \
  --out "$WORKDIR/<tu_hash>.asm-analysis.json"
```

`analyze_asm.sh` outputs annotated findings to stdout and to the JSON file.

Check for:
- **Register spills**: `movq`/`movdqa` of secret values to stack offsets → flag `REGISTER_SPILL`.
- **Callee-saved registers**: `rbx`, `r12`-`r15` (x86-64) pushed to stack containing secret values
  → flag `REGISTER_SPILL`.
- **Stack retention**: stack frame size and whether secret bytes are cleared before `ret` → flag
  `STACK_RETENTION`.

Include the relevant assembly excerpt as mandatory evidence.

## Stage 9 - Semantic IR Analysis (produces `LOOP_UNROLLED_INCOMPLETE`)

Only when a manual wipe loop is in play (not a library call).

Parse LLVM IR structurally by reading it yourself - do not use regex on raw IR text:
- Build a mental (or noted) function/basic-block representation.
- Track memory operations in SSA form after the `mem2reg` pass.
- Detect loop-unrolled zeroization: 4 or more consecutive zero stores.
- Verify unrolled stores target the correct addresses and cover the full object size.
- Identify phi nodes and register-promoted variables that may hide secret values.

Flag `LOOP_UNROLLED_INCOMPLETE` when unrolling is detected but does not cover the full object.

## Stage 10 - Control-Flow Graph Analysis (produces `MISSING_ON_ERROR_PATH`, `NOT_DOMINATING_EXITS`)

Only when Stage 5's heuristic needs a definitive answer.

Build a CFG from source or LLVM IR (by reading, not by running a solver):
- Enumerate all execution paths from function entry to exits.
- Reason about dominance: does a wipe node dominate all exit nodes? If not, flag
  `NOT_DOMINATING_EXITS`.
- Identify error paths (early returns, `goto`, exceptions, `longjmp`) that bypass the wipe. Flag
  `MISSING_ON_ERROR_PATH` for each such path.

This step produces definitive results replacing the heuristic `NOT_ON_ALL_PATHS` finding from Stage
5. If both are emitted for the same object, keep only the CFG-backed finding.

---

## Stage 11 - PoC Crafting (mandatory)

Generate a bespoke proof-of-concept for every finding that supports one, regardless of confidence.
Each PoC exits 0 (exploitable) or 1 (not exploitable). See `poc-generation.md` for per-category
technique. Compile and run every PoC before it counts as evidence - an uncompiled or unrun PoC does
not change confidence in either direction.
