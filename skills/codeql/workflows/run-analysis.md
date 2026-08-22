# Run Analysis Workflow

Execute CodeQL security queries on an existing database with ruleset selection and result formatting.

## Scan Modes

Two modes control analysis scope. Both use all installed packs - the difference is filtering.

| Mode | Description | Suite Reference |
|------|-------------|-----------------|
| **Run all** | All queries from all installed packs via `security-and-quality` suite | [run-all-suite.md](../references/run-all-suite.md) |
| **Important only** (default) | Security queries filtered by precision and security-severity threshold | [important-only-suite.md](../references/important-only-suite.md) |

> **WARNING:** Do NOT pass pack names directly to `codeql database analyze` (e.g., `-- codeql/cpp-queries`). Each pack's `defaultSuiteFile` silently applies strict filters and can produce zero results. Always use an explicit suite reference - never trust a pack's default suite.

**Default:** `important-only`, since this skill runs zero-input and the calling agent almost always
wants precision over volume. Switch to `run-all` only if the invoking agent's task string
explicitly asks for maximum coverage (e.g. "run all queries", "comprehensive codeql sweep").

---

## Steps

```
Step 1: Select database and detect language
Step 2: Select scan mode, check additional packs
Step 3: Select query packs, model packs, and threat models
Step 4: Execute analysis
Step 5: Process and report results
```

No step in this workflow prompts the operator. Every decision below has a deterministic default;
if the invoking agent's task string names a specific choice, honor it instead.

---

## Steps

### Step 1: Select Database and Detect Language

**Entry:** `$OUTPUT_DIR` is set (from parent skill). `$DB_NAME` may already be set if the parent skill resolved database selection.
**Exit:** `DB_NAME` and `CODEQL_LANG` variables set; database resolves successfully.

**If `$DB_NAME` is already set** (parent skill handled database selection): validate it and proceed.

**If `$DB_NAME` is not set:** discover databases by looking for `codeql-database.yml` marker files. Search inside `$OUTPUT_DIR` first, then fall back to the project root (top-level and one subdirectory deep).

```bash
# Skip discovery if DB_NAME was already resolved by parent skill
if [ -z "$DB_NAME" ]; then
  # Discover databases inside OUTPUT_DIR
  FOUND_DBS=()
  while IFS= read -r yml; do
    FOUND_DBS+=("$(dirname "$yml")")
  done < <(find "$OUTPUT_DIR" -maxdepth 2 -name "codeql-database.yml" 2>/dev/null)

  # Fallback: search project root (top-level and one subdir deep)
  if [ ${#FOUND_DBS[@]} -eq 0 ]; then
    while IFS= read -r yml; do
      FOUND_DBS+=("$(dirname "$yml")")
    done < <(find . -maxdepth 3 -name "codeql-database.yml" -not -path "*/\.*" 2>/dev/null)
  fi

  if [ ${#FOUND_DBS[@]} -eq 0 ]; then
    echo "ERROR: No CodeQL database found in $OUTPUT_DIR or project root"
    exit 1
  elif [ ${#FOUND_DBS[@]} -eq 1 ]; then
    DB_NAME="${FOUND_DBS[0]}"
  else
    # Multiple databases found - take the most recently created one. No prompting.
    DB_NAME="${FOUND_DBS[0]}"
  fi
fi

CODEQL_LANG=$(codeql resolve database --format=json -- "$DB_NAME" | jq -r '.languages[0]')
echo "Using: $DB_NAME (language: $CODEQL_LANG)"
```

If the database is multi-language and the invoking agent didn't name a language, analyze every
language present rather than guessing one.

---

### Step 2: Select Scan Mode, Check Additional Packs

**Entry:** Step 1 complete (`DB_NAME` and `CODEQL_LANG` set)
**Exit:** Scan mode selected; all available packs (official, ToB, community) checked for installation status; model packs detected

#### 2a: Select Scan Mode

Default to `important-only` unless the invoking agent's task explicitly requested `run-all`.

#### 2b: Query Packs

For each pack available for the detected language (see [ruleset-catalog.md](../references/ruleset-catalog.md)):

| Language | Trail of Bits | Community Pack |
|----------|---------------|----------------|
| C/C++ | `trailofbits/cpp-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-CPP` |
| Go | `trailofbits/go-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Go` |
| Java | `trailofbits/java-queries` | `GitHubSecurityLab/CodeQL-Community-Packs-Java` |
| JavaScript | - | `GitHubSecurityLab/CodeQL-Community-Packs-JavaScript` |
| Python | - | `GitHubSecurityLab/CodeQL-Community-Packs-Python` |
| C# | - | `GitHubSecurityLab/CodeQL-Community-Packs-CSharp` |
| Ruby | - | `GitHubSecurityLab/CodeQL-Community-Packs-Ruby` |

Check if installed (`codeql resolve qlpacks | grep -i "<PACK_NAME>"`). If not installed, skip it and
note the gap in `rulesets.txt` - do not stop to ask whether to install it; installing third-party
packs mid-audit is out of scope for a zero-input run.

#### 2c: Detect Model Packs

Search three locations for data extension model packs:
1. **In-repo model packs** - `qlpack.yml`/`codeql-pack.yml` with `dataExtensions`
2. **In-repo standalone data extensions** - `.yml` files with `extensions:` key
3. **Installed model packs** - resolved by CodeQL

Record all detected packs for Step 3.

---

### Step 3: Select Query Packs and Model Packs

**Entry:** Step 2 complete (scan mode, pack availability, and model packs all determined)
**Exit:** Query packs, model packs, and threat model selection finalized; all flags built (`THREAT_MODEL_FLAG`, `MODEL_PACK_FLAGS`, `ADDITIONAL_PACK_FLAGS`)

#### 3a: Query Packs

Use **all installed packs** by default (official + any installed Trail of Bits/Community packs) -
in both scan modes. This maximizes coverage without a prompt.

#### 3b: Model Packs

Use **all detected model packs** by default (in-repo and installed) - skip only if none were found in Step 2c.

**Notes:**
- In-repo standalone extensions (`.yml`) are auto-discovered - pass source directory via `--additional-packs`
- In-repo model packs (with `qlpack.yml`) need parent directory via `--additional-packs`
- Installed model packs use `--model-packs`

#### 3c: Threat Models

Threat models control which input sources CodeQL treats as tainted. See [threat-models.md](../references/threat-models.md).

Default to `remote` only (no flag) - this fits the vast majority of KAVACH's web-service/API
targets. Escalate automatically, without asking, when the target's recon profile makes it clearly
warranted:

| Recon signal | Escalation |
|---|---|
| CLI tool / batch processor / desktop app (no HTTP server detected) | add `--threat-model local` |
| Reads config from env vars at runtime, not just at startup | add `--threat-model environment` |
| Explicit request for "full coverage" / "audit mode" in the invoking task | `--threat-model all` |

Otherwise stay at the default. Log whichever threat model was chosen and why in `rulesets.txt`.

---

### Step 4: Execute Analysis

**Entry:** Step 3 complete (all flags and pack selections finalized)
**Exit:** `$RAW_DIR/results.sarif` exists and contains valid SARIF output

#### Log selected query packs

Write the selected query packs, model packs, and threat models to `$OUTPUT_DIR/rulesets.txt`:

```bash
cat > "$OUTPUT_DIR/rulesets.txt" << RULESETS
# CodeQL Analysis - Selected Query Packs
# Generated: $(date -Iseconds)
# Scan mode: <run-all|important-only>
# Database: $DB_NAME
# Language: $CODEQL_LANG

## Query packs:
<one pack per line>

## Model packs:
<one pack per line, or "None">

## Threat models:
<threat model selection, or "default (remote)">
RULESETS
```

#### Generate custom suite

**Important-only mode:** Generate the custom `.qls` suite using the template and script in [important-only-suite.md](../references/important-only-suite.md).

**Run-all mode:** Generate the custom `.qls` suite using the template in [run-all-suite.md](../references/run-all-suite.md).

```bash
RAW_DIR="$OUTPUT_DIR/raw"
RESULTS_DIR="$OUTPUT_DIR/results"
mkdir -p "$RAW_DIR" "$RESULTS_DIR"
SUITE_FILE="$RAW_DIR/<mode>.qls"

# Verify suite resolves correctly before running
codeql resolve queries "$SUITE_FILE" | wc -l
```

#### Run analysis

Output goes to `$RAW_DIR/results.sarif` (unfiltered). The final results are produced in Step 5.

```bash
codeql database analyze $DB_NAME \
  --format=sarif-latest \
  --output="$RAW_DIR/results.sarif" \
  --threads=0 \
  $THREAT_MODEL_FLAG \
  $MODEL_PACK_FLAGS \
  $ADDITIONAL_PACK_FLAGS \
  -- "$SUITE_FILE"
```

**Flag reference for model packs:**

| Source | Flag | Example |
|--------|------|---------|
| Installed model packs | `--model-packs` | `--model-packs=myorg/java-models` |
| In-repo model packs | `--additional-packs` | `--additional-packs=./lib/codeql-models` |
| In-repo standalone extensions | `--additional-packs` | `--additional-packs=.` |

### Performance

If codebase is large, read [performance-tuning.md](../references/performance-tuning.md) and apply relevant optimizations.

---

### Step 5: Process and Report Results

**Entry:** Step 4 complete (`$RAW_DIR/results.sarif` exists)
**Exit:** `$RESULTS_DIR/results.sarif` contains final results; findings summarized by severity, rule, and location; zero-finding results investigated; results handed back to the calling agent

#### Produce final results

- **Run-all mode:** Copy unfiltered results to the final location:
  ```bash
  cp "$RAW_DIR/results.sarif" "$RESULTS_DIR/results.sarif"
  ```

- **Important-only mode:** Apply the post-analysis filter from [sarif-processing.md](../references/sarif-processing.md#important-only-post-filter) to remove medium-precision results with `security-severity` < 6.0. The filter reads from `$RAW_DIR/results.sarif` and writes to `$RESULTS_DIR/results.sarif`, preserving the unfiltered original.

Process the final SARIF output (`$RESULTS_DIR/results.sarif`) using the jq commands in [sarif-processing.md](../references/sarif-processing.md): count findings, summarize by level, summarize by security severity, summarize by rule.

#### Hand results back

This skill does not write into `.kavach/findings/` or `.kavach/findings-draft/` itself - see
"Feeding results back to the calling domain agent" in the top-level `SKILL.md`. Each SARIF result
that confirms or refutes a lead the calling agent handed in gets read at its exact `file:line`,
re-scored with a real `cvss_vector`, and marked `confirmed`/`suspected` by that agent before it
becomes a finding.

---

## Final Output

Report to the calling agent:

```
## CodeQL Analysis Complete

**Output directory:** $OUTPUT_DIR
**Database:** $DB_NAME
**Language:** <LANG>
**Scan mode:** Run all | Important only
**Query packs:** <list of query packs used>
**Model packs:** <list of model packs used, or "None">
**Threat models:** <list of threat models, or "default (remote)">

### Results Summary:
- Total findings: <N>
- Error: <N>
- Warning: <N>
- Note: <N>

### Output Files:
- SARIF (final): $OUTPUT_DIR/results/results.sarif
- SARIF (unfiltered): $OUTPUT_DIR/raw/results.sarif
- Rulesets: $OUTPUT_DIR/rulesets.txt
```
