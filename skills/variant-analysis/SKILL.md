---
name: variant-analysis
description: KAVACH companion skill finding every sibling of a vulnerability already found - the same root cause manifesting elsewhere in the codebase - via an abstraction-ladder pattern methodology (exact match to semantic taint pattern) and per-language CodeQL/Semgrep taint skeletons. Post-finding expansion usable by every domain agent (kavach-sast, kavach-api, kavach-llm, kavach-billing, kavach-crypto, kavach-supply, kavach-config, kavach-logic). Use after any domain agent confirms or suspects a finding, before writing it up, to check whether the same mistake repeats elsewhere in the surface. Not for initial vulnerability discovery.
tools: Read, Grep, Glob, Bash
model: inherit
---

> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Variant Analysis

You are running variant analysis: given one confirmed or suspected finding, find every other
place the same root cause manifests. This is a **post-finding expansion technique**, callable by
any KAVACH domain agent (`kavach-sast`, `kavach-api`, `kavach-llm`, `kavach-billing`,
`kavach-crypto`, `kavach-supply`, `kavach-config`, `kavach-logic`) once it has one concrete
instance in hand - not a way to discover the first instance of anything.

## When to Use

Use this skill when:
- A vulnerability has been found (confirmed or suspected) and you need to search for siblings before finalizing the finding count
- Building or refining a Semgrep/CodeQL pattern to sweep a whole vulnerability class across the repo
- A finding's root cause looks like a developer habit or copy-paste boilerplate, not a one-off
- Hunting for the same logic-bug shape (inverted condition, null-equality bypass, wrong default) elsewhere in authz/business-logic code

## When NOT to Use

Do NOT use this skill for:
- Initial vulnerability discovery - that's the domain agent's own checklist (`domains/*.md`), not this skill
- General code review with no known pattern to search for
- Writing the finding's remediation text - that's `finding-schema.md`'s `remediation` field
- Deep unfamiliar-code comprehension before you have any lead at all

## The Five-Step Process

### Step 1: Understand the Original Issue

Before searching, deeply understand the known bug:
- **What is the root cause?** Not the symptom, but WHY it's vulnerable
- **What conditions are required?** Control flow, data flow, state
- **What makes it exploitable?** User control, missing validation, etc.

### Step 2: Create an Exact Match

Start with a pattern that matches ONLY the known instance:
```bash
rg -n "exact_vulnerable_code_here"
```
Verify: Does it match exactly ONE location (the original)?

### Step 3: Identify Abstraction Points

| Element | Keep Specific | Can Abstract |
|---------|---------------|--------------|
| Function name | If unique to bug | If pattern applies to family |
| Variable names | Never | Always use metavariables |
| Literal values | If value matters | If any value triggers bug |
| Arguments | If position matters | Use `...` wildcards |

### Step 4: Iteratively Generalize

**Change ONE element at a time:**
1. Run the pattern
2. Review ALL new matches
3. Classify: true positive or false positive?
4. If FP rate acceptable, generalize next element
5. If FP rate too high, revert and try different abstraction

**Stop when false positive rate exceeds ~50%**

### Step 5: Analyze and Triage Results

For each match, do not invent a new taxonomy - map straight onto KAVACH's own finding fields
(`finding-schema.md`, `severity-model.md`):
- **Location**: `file:line`, function - the same discipline as any other finding's `locations[]`
- **Confidence**: `confirmed` (you read the line and it reproduces the same flaw) or `suspected`
  (pattern matches but you haven't traced reachability yet) - never a third bucket
- **Exploitability / severity**: score it with the same CVSS vector the original finding got,
  adjusted for this instance's actual reachability - a variant in dead code is not automatically
  the same severity as the original
- **Priority**: based on impact and exploitability, same as any other finding

For deeper strategic guidance, see [METHODOLOGY.md](METHODOLOGY.md).

## Tool Selection

| Scenario | Tool | Why |
|----------|------|-----|
| Quick surface search | ripgrep | Fast, zero setup |
| Simple pattern matching | Semgrep | Easy syntax, no build needed |
| Data flow tracking | Semgrep taint / CodeQL | Follows values across functions |
| Cross-function analysis | CodeQL (see the `codeql` skill) | Best interprocedural analysis - reach for it when a variant's taint path crosses files a grep pattern can't span |
| Non-building code | Semgrep | Works on incomplete code |

## Key Principles

1. **Root cause first**: Understand WHY before searching for WHERE
2. **Start specific**: First pattern should match exactly the known bug
3. **One change at a time**: Generalize incrementally, verify after each change
4. **Know when to stop**: 50%+ FP rate means you've gone too generic
5. **Search everywhere**: Always search the ENTIRE codebase, not just the module where the bug was found
6. **Expand vulnerability classes**: One root cause often has multiple manifestations
7. **Never invent a second severity axis**: every variant gets `severity`/`cvss_vector`/`confidence` per the shared schema - a variant taxonomy of its own (EASY/MED/HARD, tiers, etc.) is not a KAVACH finding field

## Critical Pitfalls to Avoid

These common mistakes cause analysts to miss real vulnerabilities:

### 1. Narrow Search Scope

Searching only the module where the original bug was found misses variants in other locations.

**Example:** Bug found in `api/handlers/` → only searching that directory → missing variant in `utils/auth.py`

**Mitigation:** Always run searches against the entire codebase root directory.

### 2. Pattern Too Specific

Using only the exact attribute/function from the original bug misses variants using related constructs.

**Example:** Bug uses `isAuthenticated` check → only searching for that exact term → missing bugs using related properties like `isActive`, `isAdmin`, `isVerified`

**Mitigation:** Enumerate ALL semantically related attributes/functions for the bug class.

### 3. Single Vulnerability Class

Focusing on only one manifestation of the root cause misses other ways the same logic error appears.

**Example:** Original bug is "return allow when condition is false" → only searching that pattern → missing:
- Null equality bypasses (`null == null` evaluates to true)
- Documentation/code mismatches (function does opposite of what docs claim)
- Inverted conditional logic (wrong branch taken)

**Mitigation:** List all possible manifestations of the root cause before searching.

### 4. Missing Edge Cases

Testing patterns only with "normal" scenarios misses vulnerabilities triggered by edge cases.

**Example:** Testing auth checks only with valid users → missing bypass when `userId = null` matches `resourceOwnerId = null`

**Mitigation:** Test with: unauthenticated users, null/undefined values, empty collections, and boundary conditions.

## Output

Do not write a bespoke report format into `.kavach/findings/`. Working notes (pattern history, FP
log, tracking table) go to `.kavach/tmp/variant-workspace/<original-finding-slug>/` - see
[resources/variant-report-template.md](resources/variant-report-template.md) for the tracking-doc
shape; treat it as a scratch artifact for your own iteration, not the finding record. Once a
variant is confirmed or suspected, it becomes a normal entry in the calling agent's own
`agent-<domain>.json`, cross-referencing the original finding's `kavach_id` in its own reasoning -
one root cause, multiple `locations[]`, or multiple linked findings if severity differs per site;
do not silently fold a lower-severity variant into the original's score.

## Resources

Ready-to-use templates in `resources/`:

**CodeQL** (`resources/codeql/`):
- `python.ql`, `javascript.ql`, `java.ql`, `go.ql`, `cpp.ql`

**Semgrep** (`resources/semgrep/`):
- `python.yaml`, `javascript.yaml`, `java.yaml`, `go.yaml`, `cpp.yaml`

**Tracking template**: `resources/variant-report-template.md`
