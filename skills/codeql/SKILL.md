---
name: codeql
description: KAVACH companion skill building a CodeQL database and running interprocedural data-flow/taint-tracking analysis against a codebase. OPTIONAL delegate for kavach-sast, kavach-crypto, and kavach-supply when a suspected finding needs deeper cross-function taint proof than Semgrep/bandit can give - KAVACH agents fall back to manual taint tracing when CodeQL is unavailable. Supports "run all" (security-and-quality suite) and "important only" (high-precision security findings) scan modes, plus data-extension modeling for project-specific sources/sinks/summaries. Use when a domain agent needs interprocedural proof for a suspected finding, or when explicitly asked to run/build/analyze a CodeQL database.
tools: Bash, Read, Write, Edit, Glob, Grep
model: inherit
---

> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# CodeQL Analysis

Supported languages: Python, JavaScript/TypeScript, Go, Java/Kotlin, C/C++, C#, Ruby, Swift.

**Skill resources:** Reference files and templates are located at `{baseDir}/references/` and `{baseDir}/workflows/`.

## When to reach for this

CodeQL is an **optional delegate**, not a required dependency of any KAVACH domain agent. Reach
for it when a `suspected` finding needs interprocedural taint proof that a single Semgrep/bandit
rule cannot span - a source and sink that cross multiple files or a custom wrapper hides the real
sink from generic rules. If `codeql` is not on `PATH`, or a database will not build after the fix
attempts below, **do not block the audit on it** - fall back to the manual taint-tracing the
domain reference already prescribes (`domains/sast.md` §"Custom-rule gaps", `domains/crypto.md`),
mark the finding `suspected`, and name CodeQL as the runtime test that would confirm it.

This skill runs **zero-input**, matching KAVACH's operating posture: it never prompts mid-run.
Every decision point below (scan mode, pack selection, threat models, database choice) has a
deterministic default. If the invoking agent's task string names an explicit choice, honor it;
otherwise take the default and log what was chosen so the operator can see it in the run log.

## Essential Principles

1. **Database quality is non-negotiable.** A database that builds is not automatically good. Always run quality assessment (file counts, baseline LoC, extractor errors) and compare against expected source files. A cached build produces zero useful extraction.

2. **Data extensions catch what CodeQL misses.** Even projects using standard frameworks (Django, Spring, Express) have custom wrappers around database calls, request parsing, or shell execution. Skipping the create-data-extensions workflow means missing vulnerabilities in project-specific code paths.

3. **Never trust a pack's default suite.** Never pass pack names directly to `codeql database analyze` - each pack's `defaultSuiteFile` applies hidden filters that can produce zero results. Always generate a custom `.qls` suite file.

4. **Zero findings needs investigation, not celebration.** Zero results can indicate poor database quality, missing models, wrong query packs, or silent suite filtering. Investigate before reporting clean.

5. **Follow workflows step by step.** Once a workflow is selected, execute it step by step without skipping phases. Each phase gates the next - skipping quality assessment or data extensions leads to incomplete analysis.

6. **A CodeQL result is a lead, never a verdict.** Feed confirmed SARIF hits back to the calling domain agent as evidence to cite in `locations[].snippet` - the agent still owns the `severity`/`cvss_vector`/`confidence` call per `finding-schema.md` and `severity-model.md`. CodeQL's own `security-severity`/`level` fields are inputs to that judgment, not a substitute for it.

## Output Directory

All generated files (database, build logs, diagnostics, extensions, results) are stored in a single output directory under the target repo's `.kavach/tmp/` - never in the working directory, never inside the audited repo's tracked tree.

- **If the invoking agent specifies an output directory**, use it as `OUTPUT_DIR`.
- **If not specified**, default to `.kavach/tmp/codeql_1`. If that already exists, increment to `_2`, `_3`, etc.

In both cases, **always create the directory** with `mkdir -p` before writing any files.

```bash
# Resolve output directory
if [ -n "$USER_SPECIFIED_DIR" ]; then
  OUTPUT_DIR="$USER_SPECIFIED_DIR"
else
  BASE=".kavach/tmp/codeql"; N=1
  while [ -e "${BASE}_${N}" ]; do
    N=$((N + 1))
  done
  OUTPUT_DIR="${BASE}_${N}"
fi
mkdir -p "$OUTPUT_DIR"
```

The output directory is resolved **once** at the start before any workflow executes. All workflows receive `$OUTPUT_DIR` and store their artifacts there:

```
$OUTPUT_DIR/
├── rulesets.txt                 # Selected query packs (logged after Step 3)
├── codeql.db/                   # CodeQL database (dir containing codeql-database.yml)
├── build.log                    # Build log
├── codeql-config.yml            # Exclusion config (interpreted languages)
├── diagnostics/                 # Diagnostic queries and CSVs
├── extensions/                  # Data extension YAMLs
├── raw/                         # Unfiltered analysis output
│   ├── results.sarif
│   └── <mode>.qls
└── results/                     # Final results (filtered for important-only, copied for run-all)
    └── results.sarif
```

### Database Discovery

A CodeQL database is identified by the presence of a `codeql-database.yml` marker file inside its directory. When searching for existing databases, **always collect all matches** - there may be multiple databases from previous runs or for different languages.

**Discovery command:**

```bash
# Find ALL CodeQL databases (top-level and one subdirectory deep)
find . -maxdepth 3 -name "codeql-database.yml" -not -path "*/\.*" 2>/dev/null \
  | while read -r yml; do dirname "$yml"; done
```

- **Inside `$OUTPUT_DIR`:** `find "$OUTPUT_DIR" -maxdepth 2 -name "codeql-database.yml"`
- **Project-wide (for auto-detection):** `find . -maxdepth 3 -name "codeql-database.yml"` - covers databases at the project top level (`./db-name/`) and one subdirectory deep (`./subdir/db-name/`). Does not search deeper.

Never assume a database is named `codeql.db` - discover it by its marker file.

**When multiple databases are found:** collect metadata (language, creation time) for each, then take the **most recently created** one as the default and proceed - do not stop to ask. Log every discovered database and which one was selected in `$OUTPUT_DIR/build.log` so the operator can see the alternatives:

```bash
for db in $FOUND_DBS; do
  CODEQL_LANG=$(codeql resolve database --format=json -- "$db" 2>/dev/null | jq -r '.languages[0]')
  CREATED=$(grep '^creationMetadata:' -A5 "$db/codeql-database.yml" 2>/dev/null | grep 'creationTime' | awk '{print $2}')
  echo "$db - language: $CODEQL_LANG, created: $CREATED"
done
```

If the invoking agent's task string names a specific database or language, use that instead of the most-recent default.

## Quick Start

For the common case ("run codeql against this codebase"):

```bash
# 1. Verify CodeQL is installed - if not, stop and fall back per "When to reach for this" above
if ! command -v codeql >/dev/null 2>&1; then
  echo "NOT INSTALLED: codeql binary not found on PATH - falling back to manual taint tracing"
else
  codeql --version || echo "ERROR: codeql found but --version failed (check installation)"
fi

# 2. Resolve output directory
BASE=".kavach/tmp/codeql"; N=1
while [ -e "${BASE}_${N}" ]; do N=$((N + 1)); done
OUTPUT_DIR="${BASE}_${N}"; mkdir -p "$OUTPUT_DIR"
```

Then execute the full pipeline: **build database → create data extensions → run analysis** using the workflows below.

## When to Use

- A `suspected` finding needs deeper cross-function taint proof than Semgrep/bandit can give
- Building a CodeQL database from source code (with build capability for compiled languages)
- Finding complex vulnerabilities that require interprocedural taint tracking or AST/CFG analysis
- Confirming or refuting a custom-rule gap the domain agent flagged (§"Custom-rule gaps" in `domains/sast.md`)

## When NOT to Use

- **Writing custom queries from scratch outside this scan** - this skill's job is running analysis, not query R&D
- **CI/CD integration** - out of scope for a local audit run
- **Quick pattern searches** - Semgrep or grep is faster for simple pattern matching; use CodeQL only when data flow actually needs to cross function/file boundaries
- **No build capability** for compiled languages - consider Semgrep instead, or fall back to manual tracing
- **Single-file or lightweight analysis** - CodeQL's setup cost isn't worth it for a one-file check

## Rationalizations to Reject

These shortcuts lead to missed findings. Do not accept them:

- **"security-extended is enough"** - It is the baseline. Always check if Trail of Bits packs and Community Packs are available for the language. They catch categories `security-extended` misses entirely.
- **"The database built, so it's good"** - A database that builds does not mean it extracted well. Always run quality assessment and check file counts against expected source files.
- **"Data extensions aren't needed for standard frameworks"** - Even Django/Spring apps have custom wrappers that CodeQL does not model. Skipping extensions means missing vulnerabilities.
- **"build-mode=none is fine for compiled languages"** - It produces severely incomplete analysis. Only use as an absolute last resort.
- **"No findings means the code is secure"** - Zero findings can indicate poor database quality, missing models, or wrong query packs. Investigate before reporting clean results.
- **"I'll just run the default suite"** / **"I'll just pass the pack names directly"** - Each pack's `defaultSuiteFile` applies hidden filters and can produce zero results. Always use an explicit suite reference - never trust a pack's default suite.
- **"I'll put files in the current directory"** - All generated files must go in `$OUTPUT_DIR` under `.kavach/tmp/`. Scattering files elsewhere makes cleanup impossible and risks overwriting previous runs or, worse, polluting the audited repo's tree.
- **"Just use the first database I find"** - Multiple databases may exist for different languages or from previous runs. Take the most recent by default, but log every alternative found.
- **"A CodeQL result is automatically a finding"** - It's a lead. The calling domain agent still reads the flagged line, computes its own CVSS vector, and decides `confirmed`/`suspected` per `severity-model.md` before it goes in `agent-<domain>.json`.

---

## Workflow Selection

This skill has three workflows. **Once a workflow is selected, execute it step by step without skipping phases.**

| Workflow | Purpose |
|----------|---------|
| [build-database](workflows/build-database.md) | Create CodeQL database using build methods in sequence |
| [create-data-extensions](workflows/create-data-extensions.md) | Detect or generate data extension models for project APIs |
| [run-analysis](workflows/run-analysis.md) | Select rulesets, execute queries, process results |

### Auto-Detection Logic

**If the invoking agent already specifies what to do** (e.g., "build a database", "run analysis on the existing database"), execute that workflow directly.

**Default pipeline for an unqualified request:** discover existing databases first, then decide - with no prompting.

```bash
FOUND_DBS=()
while IFS= read -r yml; do
  db_dir=$(dirname "$yml")
  codeql resolve database -- "$db_dir" >/dev/null 2>&1 && FOUND_DBS+=("$db_dir")
done < <(find . -maxdepth 3 -name "codeql-database.yml" -not -path "*/\.*" 2>/dev/null)

echo "Found ${#FOUND_DBS[@]} existing database(s)"
```

| Condition | Action |
|-----------|--------|
| No databases found | Resolve new `$OUTPUT_DIR`, execute build → extensions → analysis (full pipeline) |
| One database found | Reuse it - proceed straight to extensions → analysis |
| Multiple databases found | Reuse the most recently created one; log the rest as alternatives |
| Invoking agent stated intent explicitly | Act on it directly |

---

## Reference Index

| File | Content |
|------|---------|
| **Workflows** | |
| [workflows/build-database.md](workflows/build-database.md) | Database creation with build method sequence |
| [workflows/create-data-extensions.md](workflows/create-data-extensions.md) | Data extension generation pipeline |
| [workflows/run-analysis.md](workflows/run-analysis.md) | Query execution and result processing |
| **References** | |
| [references/build-fixes.md](references/build-fixes.md) | Build failure fix catalog |
| [references/quality-assessment.md](references/quality-assessment.md) | Database quality metrics and improvements |
| [references/extension-yaml-format.md](references/extension-yaml-format.md) | Data extension YAML column definitions and examples |
| [references/sarif-processing.md](references/sarif-processing.md) | jq commands for SARIF output processing |
| [references/diagnostic-query-templates.md](references/diagnostic-query-templates.md) | QL queries for source/sink enumeration |
| [references/important-only-suite.md](references/important-only-suite.md) | Important-only suite template and generation |
| [references/run-all-suite.md](references/run-all-suite.md) | Run-all suite template |
| [references/ruleset-catalog.md](references/ruleset-catalog.md) | Available query packs by language |
| [references/threat-models.md](references/threat-models.md) | Threat model configuration |
| [references/language-details.md](references/language-details.md) | Language-specific build and extraction details |
| [references/performance-tuning.md](references/performance-tuning.md) | Memory, threading, and timeout configuration |

---

## Feeding results back to the calling domain agent

CodeQL's SARIF `level`/`security-severity` are **not** KAVACH's `severity`/`confidence`. When a
result confirms or refutes a `suspected` finding:

1. Read the exact flagged `file:line` yourself - do not paraphrase the SARIF message as proof.
2. Compute the finding's own `cvss_vector`/`cvss_score` per `severity-model.md` - a CodeQL
   `security-severity: 8.5` does not become the finding's `cvss_score` verbatim; it is one input
   among the metrics you set.
3. Set `confidence: confirmed` only once you (not just CodeQL) have read the source-to-sink path;
   otherwise leave it `suspected` and name the exact CodeQL suite/mode that would confirm it.
4. Hand the enriched finding back to the calling agent (`kavach-sast`, `kavach-crypto`, or
   `kavach-supply`) for inclusion in its `agent-<domain>.json` - this skill never writes directly
   into `.kavach/findings/` or `.kavach/findings-draft/` itself.

## Success Criteria

A complete CodeQL analysis run should satisfy:

- [ ] Output directory resolved under `.kavach/tmp/` (agent-specified or auto-incremented default)
- [ ] All generated files stored inside `$OUTPUT_DIR`
- [ ] Database built (discovered via `codeql-database.yml` marker) with quality assessment passed (baseline LoC > 0, errors < 5%)
- [ ] Data extensions evaluated - either created in `$OUTPUT_DIR/extensions/` or explicitly skipped with justification
- [ ] Analysis run with explicit suite reference (not default pack suite)
- [ ] All installed query packs (official + Trail of Bits + Community) used or explicitly excluded
- [ ] Selected query packs logged to `$OUTPUT_DIR/rulesets.txt`
- [ ] Unfiltered results preserved in `$OUTPUT_DIR/raw/results.sarif`
- [ ] Final results in `$OUTPUT_DIR/results/results.sarif` (filtered for important-only, copied for run-all)
- [ ] Zero-finding results investigated (database quality, model coverage, suite selection)
- [ ] Build log preserved at `$OUTPUT_DIR/build.log` with all commands, fixes, and quality assessments
- [ ] Every result handed back to the calling agent carries a real `cvss_vector` and `confirmed`/`suspected` call - never CodeQL's raw severity passed through unexamined
