# Completeness Checklist

Before finalizing spec-to-code compliance analysis, verify:

---

## Spec-IR Completeness

- [ ] Extracted ALL explicit invariants from specification
- [ ] Extracted ALL implicit invariants (deduced from context, examples, diagrams)
- [ ] Extracted ALL formulas and mathematical relationships
- [ ] Extracted ALL actor definitions, roles, and trust boundaries
- [ ] Extracted ALL state machine transitions and workflows
- [ ] Extracted ALL security requirements (MUST/NEVER/ALWAYS keywords)
- [ ] Extracted ALL preconditions and postconditions
- [ ] Every Spec-IR item has `source_section` citation
- [ ] Every Spec-IR item has a confidence score (0-1)
- [ ] Minimum threshold met: 10+ items for non-trivial spec

---

## Code-IR Completeness

- [ ] Analyzed ALL public and external functions (no gaps)
- [ ] Analyzed ALL internal functions called by public/external functions
- [ ] Documented ALL state reads with variable names and line numbers
- [ ] Documented ALL state writes with operations and line numbers
- [ ] Documented ALL external calls with target, type, return handling, line numbers
- [ ] Documented ALL revert conditions with exact require/revert statements (or the equivalent
      error path for a non-Solidity codebase)
- [ ] Documented ALL modifiers and their enforcement logic
- [ ] Captured storage layout, initialization logic, authorization graph
- [ ] Every Code-IR claim has a line number citation
- [ ] Minimum threshold met: 3+ invariants per function

---

## Alignment-IR Completeness

- [ ] EVERY Spec-IR item has a corresponding Alignment record (complete 1:1 mapping)
- [ ] EVERY Alignment record has a match_type classification (one of the 6 types)
- [ ] EVERY match_type has reasoning explaining WHY that classification was chosen
- [ ] EVERY Alignment record has evidence with exact quotes (spec_quote AND code_quote)
- [ ] EVERY divergence (`mismatch`, `missing_in_code`, `partial_match`, `code_weaker_than_spec`)
      has a Divergence Finding
- [ ] Undocumented code behavior explicitly flagged as `code_stronger_than_spec`
- [ ] Ambiguities classified (not guessed): confidence < 0.8 or ambiguity_notes populated
- [ ] No placeholder confidence scores (1.0 for everything) - scores reflect actual certainty

---

## Divergence Finding Quality

- [ ] EVERY finding at CVSS High or above has a detailed exploit scenario (prerequisites,
      sequence, impact)
- [ ] Impact quantified with concrete numbers ($X loss, Y% ROI, Z transactions/day, or the
      domain-appropriate equivalent)
- [ ] Remediation includes code examples (not just "fix this")
- [ ] Testing requirements specified (unit, integration, fuzz, fork tests as applicable)
- [ ] Breaking changes documented (migration path, backward compatibility)
- [ ] Evidence includes exhaustive search results (e.g., "searched for 'slippage' → 0 results")
- [ ] `severity` is a computed CVSS band with the vector shown, justified with exploitability
      reasoning (not just "this is critical because...")
- [ ] `kavach_confidence` is set to `confirmed` or `suspected`, and every `suspected` finding names
      the exact runtime test that would confirm it

---

## Phase 6 Final Report

- [ ] All 16 sections present (Executive Summary through Final Risk Assessment)
- [ ] Full Alignment Matrix included (table showing all spec→code mappings with status)
- [ ] All IR artifacts embedded or linked (Spec-IR, Code-IR, Alignment-IR, Divergence Findings)
- [ ] Divergence Findings prioritized by CVSS-derived severity (Critical → High → Medium → Low)
- [ ] Recommended remediations prioritized by risk reduction
- [ ] Documentation update suggestions provided (if spec needs clarification)
- [ ] Report written to `.kavach/attack-surface/spec-compliance-report.md` if `.kavach/` exists,
      else `<repo-or-dir-name>-spec-compliance-report.md` at the repo root
