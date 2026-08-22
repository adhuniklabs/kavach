---
name: semgrep-rule-creator
description: KAVACH maintainer tooling for authoring and testing custom Semgrep rules, and for growing the bundled offline ruleset core/kavach/scanners/assets/semgrep-kavach.yml (KAVACH's dependency-free SAST floor). Use when writing a new Semgrep rule for a vulnerability class KAVACH's bundled rules don't cover yet, when kavach-sast or kavach-verifier flags a custom-rule gap ("no single rule spans this taint path"), or when building custom static-analysis detections in general. Not for running existing rulesets.
tools: Bash, Read, Write, Edit, Glob, Grep, WebFetch
model: inherit
---

> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Semgrep Rule Creator

Create production-quality Semgrep rules with proper testing and validation, and land the verified
ones in KAVACH's bundled offline ruleset.

## When to Use

**Ideal scenarios:**
- Writing a Semgrep rule for a specific bug pattern KAVACH's bundled ruleset doesn't detect yet.
- Writing a rule to detect a security vulnerability class in a codebase KAVACH is auditing.
- Writing taint-mode rules for data-flow vulnerabilities.
- Writing rules to enforce coding standards.
- Growing `core/kavach/scanners/assets/semgrep-kavach.yml` - KAVACH's own dependency-free SAST
  floor that fires even when `--config auto` can't reach the registry (see "KAVACH ruleset
  conventions" below). This is the primary maintainer use case for this skill.
- Closing a **custom-rule gap** a domain agent flagged - `kavach-sast`'s triage pass
  (`agents/kavach-sast.md`) and `kavach-verifier` both name the exact sink/source pattern a rule
  would need when the available scanners structurally can't see a bug (taint spanning multiple
  files, a custom wrapper hiding a sink, an internal DSL). That named gap is this skill's ideal
  input - it already tells you the pattern to encode.

## When NOT to Use

Do NOT use this skill for:
- Running existing Semgrep rulesets (that's `kavach sweep` / `SemgrepScanner`, not this skill).
- General static analysis without custom rules.

## Rationalizations to Reject

When writing Semgrep rules, reject these common shortcuts:

- **"The pattern looks complete"** -> Still run `semgrep --test --config <rule-id>.yaml
  <rule-id>.<ext>` to verify. Untested rules have hidden false positives/negatives.
- **"It matches the vulnerable case"** -> Matching vulnerabilities is half the job. Verify safe
  cases don't match (false positives break trust - and in KAVACH specifically, break the "high-
  signal, low-false-positive" contract `semgrep-kavach.yml`'s header comment promises).
- **"Taint mode is overkill for this"** -> If data flows from user input to a dangerous sink,
  taint mode gives better precision than pattern matching.
- **"One test is enough"** -> Include edge cases: different coding styles, sanitized inputs, safe
  alternatives, and boundary conditions.
- **"I'll optimize the patterns first"** -> Write correct patterns first, optimize after all tests
  pass. Premature optimization causes regressions.
- **"The AST dump is too complex"** -> The AST reveals exactly how Semgrep sees code. Skipping it
  leads to patterns that miss syntactic variations.

## Anti-Patterns

**Too broad** - matches everything, useless for detection:
```yaml
# BAD: Matches any function call
pattern: $FUNC(...)

# GOOD: Specific dangerous function
pattern: eval(...)
```

**Missing safe cases in tests** - leads to undetected false positives:
```python
# BAD: Only tests vulnerable case
# ruleid: my-rule
dangerous(user_input)

# GOOD: Include safe cases to verify no false positives
# ruleid: my-rule
dangerous(user_input)

# ok: my-rule
dangerous(sanitize(user_input))

# ok: my-rule
dangerous("hardcoded_safe_value")
```

**Overly specific patterns** - misses variations:
```yaml
# BAD: Only matches exact format
pattern: os.system("rm " + $VAR)

# GOOD: Matches all os.system calls with taint tracking
mode: taint
pattern-sinks:
  - pattern: os.system(...)
```

## Strictness Level

This workflow is **strict** - do not skip steps:
- **Read documentation first**: See [Documentation](#documentation) before writing Semgrep rules.
- **Test-first is mandatory**: Never write a rule without tests.
- **100% test pass is required**: "Most tests pass" is not acceptable.
- **Optimization comes last**: Only simplify patterns after all tests pass.
- **Avoid generic patterns**: Rules must be specific, not match broad patterns.
- **Prioritize taint mode**: For data-flow vulnerabilities.
- **One YAML file - one Semgrep rule** while authoring/testing: each scratch `<rule-id>.yaml` must
  contain only one Semgrep rule; don't combine multiple rules in a single file during the test-
  first workflow. (The final destination file, `semgrep-kavach.yml`, is the one exception -
  see "Landing the rule" below - it is a single multi-rule file by design, so a verified rule gets
  *appended* to it, not merged during authoring.)
- **No generic rules**: When targeting a specific language, avoid generic pattern matching
  (`languages: generic`).
- **Forbidden `todook` and `todoruleid` test annotations**: `todoruleid: <rule-id>` and
  `todook: <rule-id>` annotations for future rule improvements are forbidden.

## Overview

This skill guides creation of Semgrep rules that detect security vulnerabilities and code
patterns. Rules are created iteratively: analyze the problem, write tests first, analyze AST
structure, write the rule, iterate until all tests pass, optimize the rule, then land it in
`semgrep-kavach.yml`.

**Approach selection:**
- **Taint mode** (prioritize): Data-flow issues where untrusted input reaches a dangerous sink.
- **Pattern matching**: Simple syntactic patterns without data-flow requirements.

**Why prioritize taint mode?** Pattern matching finds syntax but misses context. A pattern
`eval($X)` matches both `eval(user_input)` (vulnerable) and `eval("safe_literal")` (safe). Taint
mode tracks data flow, so it only alerts when untrusted data actually reaches the sink -
dramatically reducing false positives for injection vulnerabilities.

**Iterating between approaches:** It's okay to experiment. If you start with taint mode and it's
not working well (e.g., taint doesn't propagate as expected, too many false positives/negatives),
switch to pattern matching. Conversely, if pattern matching produces too many false positives on
safe cases, try taint mode instead. The goal is a working rule - not rigid adherence to one
approach.

**Scratch output structure** while authoring/testing - exactly 2 files in a scratch directory
named after the rule-id (use `.kavach/tmp/semgrep-rule-drafts/<rule-id>/` if working inside a
target repo's `.kavach/` tree, or any scratch directory otherwise - never write scratch files into
`core/kavach/scanners/assets/`):
```
<rule-id>/
├── <rule-id>.yaml     # Semgrep rule
└── <rule-id>.<ext>    # Test file with ruleid/ok annotations
```

## KAVACH ruleset conventions (read before landing a rule)

`core/kavach/scanners/assets/semgrep-kavach.yml` is KAVACH's dependency-free SAST floor - it fires
even when `semgrep scan --config auto` can't reach the registry, so the scanner never silently
returns zero. It is deliberately small and high-signal. Match its existing conventions exactly;
`core/kavach/scanners/sast.py` parses `severity` with a fixed mapping, so deviating breaks
ingestion silently:

- **Id prefix**: every rule id is `kavach-<language-or-area>-<pattern>`, e.g.
  `kavach-node-child-process-exec`, `kavach-python-yaml-load`. Lowercase, hyphens, no version
  suffix.
- **Severity values**: `ERROR`, `WARNING`, or `INFO` only - these are the **legacy** Semgrep
  severity names, not `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`. `core/kavach/scanners/sast.py` maps
  `ERROR -> Severity.HIGH`, `WARNING -> Severity.MEDIUM`, `INFO -> Severity.LOW` (see
  `_SEMGREP_SEV` in that file) - there is no `CRITICAL` mapping, so never emit a severity above
  `ERROR` for this file. If a pattern is genuinely Critical (e.g. it's a Critical-band kill-chain
  primitive per `skill/references/severity-model.md`), that judgment belongs to the domain agent
  that confirms the finding at the sink, not to the scanner-level severity here - the scanner hit
  is a lead, never a verdict (`skill/references/finding-schema.md`).
- **Metadata shape**: `metadata: {cwe: "CWE-XXX", owasp: "AXX:2021"}` - a flat inline map with
  exactly these two keys, matching every existing rule.
- **Message style**: one sentence, hyphen (`-`) not em/en dash, ends without a period is fine but
  stay terse - match the tone of the existing messages (e.g. `"eval() on a non-literal - code
  injection risk."`).
- **File header banner**: do not touch the file's top comment block explaining the offline-floor
  rationale; only ever append new `- id:` entries after the existing ones, separated by one blank
  line, matching the existing block style (`pattern:`/`patterns:`/`pattern-either:` indentation as
  already used).
- **No `mode: taint` yet in the bundled file**: every existing rule is plain pattern-matching
  (`pattern`/`patterns`/`pattern-either` + `pattern-not`). Taint-mode rules are still a valid
  *authoring* choice (they may well be more precise), but confirm they run cleanly under whatever
  semgrep version `SemgrepScanner` invokes before landing one in the bundled file, and prefer
  pattern-matching for this specific file unless taint mode is the only way to keep the false-
  positive rate low - the offline floor's whole design goal is "never zero, always precise."

### Landing the rule

Once a new rule passes its own scratch test suite (below):

1. Append the verified `- id: kavach-...` block to the end of
   `core/kavach/scanners/assets/semgrep-kavach.yml`, following the conventions above.
2. Re-run `semgrep --validate --config core/kavach/scanners/assets/semgrep-kavach.yml` to confirm
   the merged file is still valid YAML/rule syntax.
3. Re-run the scratch test file's cases against the merged file too:
   `semgrep --test --config core/kavach/scanners/assets/semgrep-kavach.yml <rule-id>.<ext>` - a
   rule that passed alone can still regress once it sits next to 20+ other rules (id collisions,
   an earlier rule's `pattern-not` unexpectedly matching your test fixture, etc.).
4. If `core/tests/test_core.py` has a `test_semgrep_normalize`-style unit test asserting on a
   specific severity/category mapping, leave it untouched unless your new rule is what it's
   testing - it exercises `SemgrepScanner.normalize()`, not the ruleset content, so it should be
   unaffected by an added rule.
5. Clean up the scratch directory - it is authoring scaffolding, not a durable KAVACH artifact.

## Quick Start

```yaml
rules:
  - id: kavach-python-insecure-eval
    languages: [python]
    severity: ERROR
    message: "eval() on Flask request data - code injection risk."
    metadata: {cwe: "CWE-95", owasp: "A03:2021"}
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: eval(...)
```

Test file (`kavach-python-insecure-eval.py`):
```python
# ruleid: kavach-python-insecure-eval
eval(request.args.get('code'))

# ok: kavach-python-insecure-eval
eval("print('safe')")
```

Run tests (from the rule directory): `semgrep --test --config <rule-id>.yaml <rule-id>.<ext>`

## Quick Reference

- For commands, pattern operators, and taint mode syntax, see `references/quick-reference.md`.
- For the detailed workflow and examples, you MUST see `references/workflow.md`.

## Workflow

Copy this checklist and track progress:

```
Semgrep Rule Progress:
- [ ] Step 1: Analyze the Problem
- [ ] Step 2: Write Tests First
- [ ] Step 3: Analyze AST structure
- [ ] Step 4: Write the rule
- [ ] Step 5: Iterate until all tests pass (semgrep --test)
- [ ] Step 6: Optimize the rule (remove redundancies, re-test)
- [ ] Step 7: Final Run
- [ ] Step 8: Land the rule in semgrep-kavach.yml (maintainer path only - see above)
```

## Documentation

**REQUIRED**: Before writing any rule, use WebFetch to read **all** of these links with Semgrep
documentation:

1. [Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax)
2. [Pattern Syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax)
3. [ToB Testing Handbook - Semgrep](https://appsec.guide/docs/static-analysis/semgrep/advanced/)
4. [Constant propagation](https://semgrep.dev/docs/writing-rules/data-flow/constant-propagation)
5. [Writing Rules Index](https://github.com/semgrep/semgrep-docs/tree/main/docs/writing-rules/)
