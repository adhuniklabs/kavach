> Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.

# Deep Probe Protocol - Layer-Trust-Chain Analysis & Bayesian Stop Loop

Governs the **deep-probe team**: `kavach-probe` (coordinator), `kavach-reasoner-backward` and
`kavach-reasoner-contradiction` (parallel hypothesis generators), and `kavach-harvester` (rapid
tracer + Pearl-style causal challenge). The team interrogates a single high-risk component in more
depth than a domain agent's first pass affords, and hands validated hypotheses to
`kavach-chamber` (`chamber-protocol.md`) as a running start instead of a cold one.

**Light vs. full run.** Some modes run `kavach-probe` as a light single-pass: the coordinator may
do Steps 1-2 itself and go straight to one reasoning pass plus one harvester call, stopping after
loop 1 regardless of what the Bayesian questions in Step 6 say. Other modes run the full team below
- both reasoners in parallel, the Bayesian loop up to 3 iterations. This file specifies the full
form; the light form is Steps 1, 2, 3 (one reasoner only, or both but without waiting for
cross-pollination), 5, and a single pass of Step 7 - no Step 6 looping.

## Workspace

```
.kavach/tmp/probe-workspace/<component>/
  attack-surface-map.md
  code-anatomy.md
  round-1-hypotheses.md      # kavach-reasoner-backward
  round-2-hypotheses.md      # kavach-reasoner-contradiction
  cross-model-seeds.md
  round-1-evidence.md        # kavach-harvester
  probe-state.json
  probe-summary.md
```

Transient (`tmp/`) - wiped by the invoking mode's cleanup once `probe-summary.md`'s content is
promoted into the durable gate artifact (`attack-surface/manual-attack-surface-inventory.md` for a
light single-pass run, `attack-surface/deep-probe-summary.md` for a full run, or
`attack-surface/revisit-probe-summary.md` for a revisit pass - see `docs/phase-reference.md` for
which filename the invoking mode expects; none of these are phase ids).

## Step 1: attack surface + layer trust chain mapping

`kavach-probe` reads `attack-surface/knowledge-base-report.md` (architecture model, attack surface,
domain attack research sections) and, if it exists, `attack-surface/intent-corpus.json`'s
`acknowledged_risks[]` array - a soft prioritization hint for which entry points to probe deepest,
never a restriction on which ones are in scope. It also reads any `agent-<domain>.json` already
emitted for this component - prior findings and controls the relevant domain agent already proved.

Then `Glob`/`Grep`/`Read` every source file for the component and write
`attack-surface-map.md`:

```markdown
# Attack Surface Map: <component>

## Entry Points
- `<file:line>` - <function> - <what input it accepts>

## Trust Boundary Crossings
- <where attacker-controlled data crosses into privileged execution>

## Auth / AuthZ Decision Points
- `<file:line>` - <function> - <what it decides>

## Validation / Sanitization Functions
- `<file:line>` - <function> - <what it validates>

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|-----------|---------|-----------------|:---:|---|
| Middleware | Handler | Input is validated JSON | HTTP: YES | WebSocket: NO, Queue consumer: NO |

## Trust Chain Gaps (rows above where "Alternate Paths" is non-empty)
- <description of each gap - feed these to the reasoners as priority targets>
```

## Step 2: code anatomy

`kavach-probe` reads every source file listed above (batch the reads; for files over ~300 lines,
read the first 300 and note the truncation) and writes `code-anatomy.md` itself - a structured
**observation** document, not analysis:

```markdown
# Code Anatomy: <component>

Generated: <ISO timestamp>
Files read: <count>

## Functions
For each function/method: `<Name>(<params>)` - `<file>:<line>`
- Returns, Params, Calls (with file:line), Side effects

## Defensive Patterns
Every piece of code that looks cautious, protective, or handles an edge case, with the EXACT
behavior on the defensive path.

| Location | Pattern | Trigger condition | Exact behavior when triggered |

## External Calls
Every call to a database, external API, filesystem, cache, or queue.

| Location | Target | Input | Parameterized? | Error handling |

## Trust Assumptions
What the code implicitly assumes about callers, inputs, or environment.

| Location | Assumption | Evidence |

## Layer Transitions

| Direction | From | To | Data passed | Validation before handoff? |
```

Do not analyze or interpret here - observe and document. Include every defensive pattern, even
ones that look safe; the reasoners decide what matters. For "exact behavior when triggered," read
the actual code - never guess.

## Step 3: dispatch the reasoners (parallel)

`kavach-probe` sends both of these via `Task` in the same message, without waiting for one before
sending the other:

**To `kavach-reasoner-backward`** - uses **Pre-Mortem** reasoning ("assume this component was
already breached - what hypothesis explains it, working backward from the compromise to the
input?") and **Abductive** reasoning ("given this defensive pattern from the code anatomy, what is
the simplest explanation for why it exists - what specific attack was it built to stop, and does
it fully stop it, or only the case the author imagined?"). Tags each hypothesis
`Reasoning-Model: Pre-Mortem` or `Reasoning-Model: Abductive`.

**To `kavach-reasoner-contradiction`** - uses **TRIZ** reasoning (find the engineering contradiction
the code resolves - "must be fast" vs. "must validate," "must accept flexible input" vs. "must
reject malformed input" - and check which side of the contradiction lost) and **Game-Theory**
reasoning (model the code as a two-player game between the developer's stated assumption and the
attacker's best response; find the developer's dominant assumption and the move that breaks it).
Tags each hypothesis `Reasoning-Model: TRIZ` or `Reasoning-Model: Game-Theory`.

Each reasoner receives: the attack surface map, the code anatomy, and the Trust Chain Gaps section.
Each writes hypotheses (`PH-<NN>`) to its own output file - `round-1-hypotheses.md` for the
backward reasoner, `round-2-hypotheses.md` for the contradiction reasoner. `kavach-probe` waits for
both files to exist, then reads both.

## Step 4: cross-pollination

`kavach-probe` reads both hypothesis files and, for each pair (one from each reasoner), checks:

1. Do they reference the same file or function?
2. Do they reference the same trust boundary?
3. Does one hypothesis's attack input flow through the other's vulnerable path?
4. Does one hypothesis's "assumption broken" invalidate the other's identified protection?

For each concrete match, write a cross-model seed to `cross-model-seeds.md`:

```markdown
## CROSS-<NN>: <title>

Source-A: PH-<NN> from kavach-reasoner-backward
Source-B: PH-<NN> from kavach-reasoner-contradiction
Connection: <why these interact - shared code path / shared boundary / one breaks the other's control>
Combined hypothesis: <the stronger hypothesis combining both insights>
Test direction for harvester causal challenge: <what counterfactual or intervention test would confirm/deny it>
```

Only write seeds with a **concrete** connection (same file, same trust boundary, same data flow) -
never a speculative one.

## Step 5: dispatch kavach-harvester

`kavach-probe` collects every hypothesis from both rounds plus the cross-model seeds and sends them
to `kavach-harvester` via `Task`, with the component's source paths and the output file
(`round-1-evidence.md`).

### Tracing protocol (kavach-harvester)

For each hypothesis:

1. **Locate the target.** Verify the `Target` field's `file:line` with `Grep`/`Read`. If wrong,
   find the correct location.
2. **Trace the code path.** From the entry point, follow the call chain to where the input is used
   or processed. Document every step: `<file:line> -> <file:line> -> ... -> sink`. Note every
   transformation (cast, encoding, normalization, parsing, filtering) and every sanitizer/validator
   on the path.
3. **Assess bypassability** of each sanitizer/validator found: **Blocks** (definitively prevents
   the attack), **Partial** (reduces surface but may be bypassable), **Bypassable** (state exactly
   why - "only checks length, not type"; "checks after use"; "only applies in this branch").
4. **Causal challenge** - before declaring any hypothesis INVALIDATED, apply Pearl-style causal
   reasoning to the apparent blocking protection from Step 3:
   - **Intervention** - if this protection were forcibly bypassed, does the attacker input still
     reach the dangerous operation? If yes, the protection is not causally necessary - flip to
     VALIDATED and emit a hypothesis about the deeper vulnerability the original one didn't fully
     surface.
   - **Counterfactual (dormant protection)** - what input would trigger this protection? Does
     normal, non-adversarial traffic ever send that? If no, the protection is dormant - never
     battle-tested. Mark NEEDS-DEEPER with reason `dormant-protection`, describing the real risk
     the developer skipped because they assumed "this is already handled."
   - **Confounder** - does the protection live in this code, or upstream (middleware, proxy, WAF,
     deployment constraint)? If upstream, is there a path that bypasses it (direct access, internal
     service-to-service call, background worker, test harness)? If such a path exists, flip to
     VALIDATED with reason `confounded-by-environment`.

   If the protection survives all three tests, proceed to INVALIDATED with a Fragility Score. If
   any test reveals a gap, emit a short `Causal-Followup: PH-<NN+K>` hypothesis alongside the
   verdict so `kavach-probe` can decide whether to extend the probe.
5. **Issue verdict:**
   - **VALIDATED** - the attack input can realistically reach the sink with no blocking
     protection, OR a blocking protection is demonstrably bypassable, OR the causal challenge
     flipped an apparent protection.
   - **INVALIDATED** - a clear, complete blocking protection exists, survives all three causal
     tests, and cannot be bypassed by the stated attack input.
   - **NEEDS-DEEPER** - the path is too complex for a quick trace to resolve confidently (deep call
     chains, conditional protections, dynamic dispatch, or a dormant protection from Step 4).
6. **Assign a Fragility Score** (INVALIDATED verdicts only):
   - **Fragile** - only ONE protection blocks the attack, and at least one of: it's
     configuration-dependent; it has a known bypass pattern for similar systems; it's a single
     value check with no defense-in-depth; it's in external infra (WAF/proxy), not the code.
   - **Moderate** - two or more independent protections block it, but at least one is partially
     bypassable or configuration-dependent.
   - **Robust** - two or more independent, code-level protections block it, none with an obvious
     bypass.

Output format:

```markdown
# Evidence - <component>

## [HARVESTER] PH-<NN>: <title>

**Verdict**: VALIDATED | INVALIDATED | NEEDS-DEEPER

**Code path**:
1. `<file:line>` - <description>
2. `<file:line>` - <description>
3. `<file:line>` - sink: <description>

**Sanitizers on path**:
- `<file:line>` - `<function>` - Blocks / Partial / Bypassable: <reason>

**Verdict rationale**: <1-3 sentences>

**Fragility Score** (INVALIDATED only): Fragile | Moderate | Robust
- **Reason**: <what protection(s) exist, how many, how bypassable>

**Causal challenge** (required before INVALIDATED):
- Intervention: <result>
- Counterfactual: <result>
- Confounder: <result - code-level, or confounded by <upstream component>>
- Causal-Followup: <PH-<NN> if emitted, else "none">

**Deepening note** (NEEDS-DEEPER only): <specific ambiguity, including `dormant-protection` when relevant>
```

**Rules for kavach-harvester**: use actual `file:line` references from reading the code - never
guess. Fragility Score is required for every INVALIDATED verdict. Do not research whether similar
vulnerabilities exist elsewhere (that's `kavach-variant`'s job). Do not search for additional
protections beyond the direct path or challenge findings further (that's `kavach-advocate`'s job
inside the chamber). Do not issue NEEDS-DEEPER just to avoid a verdict - if reachability can be
determined, determine it.

## Step 6: Bayesian / Socratic decision loop

After reading the evidence file, `kavach-probe` initializes `probe-state.json`:

```json
{
  "component": "<name>",
  "loop": 1,
  "total_validated": 0,
  "total_needs_deeper": 0,
  "loops": []
}
```

Answer five questions, recorded into `probe-state.json`:

- **Coverage gap.** Which entry points in the attack surface map have zero VALIDATED or
  NEEDS-DEEPER hypotheses?
- **Chain seeding.** Which VALIDATED findings have code paths that could chain into a
  higher-severity outcome? (A finding is a chain seed if its impact is a precondition for a more
  severe attack.)
- **Fragile safety.** Which INVALIDATED findings got a **Fragile** score? Candidates for
  re-investigation with a different approach.
- **Model coverage.** Which entry points were reached by neither reasoner? Any trust-chain gaps
  left unaddressed?
- **Impact multiplication.** Which NEEDS-DEEPER items, if validated, would change the severity of
  other findings?

**Decision**: if the coverage-gap check has uncovered entry points, OR the fragile-safety check has
Fragile items, OR the model-coverage check has untouched areas → **run another loop** (maximum 3
loops total, full-run mode only). Otherwise → proceed to the summary. A new loop directs the
reasoners at the specific gaps those three checks identified - not a fresh full pass.

## Step 7: write probe-summary.md

```markdown
# Deep Probe Summary: <component>

Status: complete
Loops: <N>
Total hypotheses: <N>
Validated: <N>
Needs-Deeper: <N>
Stop reason: <covered all entry points / max loops / no significant gaps>

## Validated Hypotheses

### PH-<NN>: <title>
- Reasoning-Model: <Pre-Mortem | Abductive | TRIZ | Game-Theory | Causal-Followup>
- Target: `<file:line>` - `<function>`
- Attack input: <specific input>
- Code path: `<file:line>` -> sink at `<file:line>`
- Sanitizers on path: <none | <function> - bypassable: <reason>>
- Security consequence: <what happens>
- Severity estimate: <rough band, resolved to a full CVSS vector per severity-model.md once this
  becomes a finding draft - this is a working estimate for triage priority, not the final score>
- Evidence file: round-1-evidence.md

## NEEDS-DEEPER

### PH-<NN>: <title>
- Why unresolved: <ambiguity; include `dormant-protection` when applicable>
- Suggested follow-up: <what the chamber debate should investigate>

## Coverage Summary
| Entry Point | backward-reasoner | contradiction-reasoner | harvester causal-followups |
|------------|:-:|:-:|:-:|
| <entry> | <PH-NNs or NONE> | <PH-NNs or NONE> | <PH-NNs or NONE> |
```

## Handoff to kavach-chamber

`kavach-chamber` reads `probe-summary.md` (or the promoted durable copy under `attack-surface/`) at
its Initialize step - see `chamber-protocol.md`. Every VALIDATED hypothesis is pre-seeded into the
chamber's `debate.md` as an `H-00` entry, tagged with its origin `Reasoning-Model`, before
`kavach-ideator`'s first round starts. The Ideator builds on these instead of regenerating them;
the Tracer verifies and extends the probe team's existing evidence for these entries rather than
re-tracing from zero. NEEDS-DEEPER items with a `dormant-protection` note are handed to the Ideator
as priority targets for fresh hypothesis generation - the probe team flagged the gap but couldn't
resolve it; the chamber's adversarial debate is the next tool for it.

## Cross-reference

Where a probe hypothesis's ambiguity resembles a specific verification-gate failure mode (a math
bounds question, a dormant-protection question that mirrors Gate 6's environment question), escalate
using `verification-gates.md`'s checklist rather than looping the probe team further - the gates
give a sharper answer than a fourth Bayesian loop would.
