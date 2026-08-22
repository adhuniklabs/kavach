# KAVACH Modes - when to use which

KAVACH runs one of 8 modes per invocation (`/kavach <mode>`). Each is a different tradeoff between
speed, depth, and what state it needs. Phase-by-phase detail lives in `docs/phase-reference.md`;
this page is the "which one do I actually run" decision guide.

## lite - fast triage

Run this when you want a signal in minutes, not a verdict: a pre-commit check, a quick sanity pass
on a repo you've never seen, or a CI gate that can't afford a long audit. It walks recon + a secret
sweep + a light static pass, builds PoCs for what it finds, and consolidates straight into the
findings tree - no knowledge base, no chamber, no adversarial review. Expect it to catch the loud,
obvious stuff (hardcoded keys, unparameterized queries, missing auth on an endpoint) and miss
anything that needs architectural context or a debate to confirm. Use `lite` as a first pass before
committing to `balanced` or `deep`, not as a substitute for either.

## balanced - the default full audit

This is the audit to run when someone asks "is this secure" and you have no other constraint. It
builds the real knowledge base (architecture, threat model, unauthenticated surface), fans the 8
domain hunters out against it, runs a single adversarial-review chamber to kill false positives,
then builds PoCs and disclosure-ready reports for every survivor. It produces the full
`reports/final-audit-report.md` (plus HTML, PDF, JSON and SARIF) with kill-chain fill, VAPT verdict,
and certification. Default choice for:
pre-launch review, periodic full audits, a new codebase with no prior KAVACH history, or anytime
you want one clean deliverable and don't need deep's extra adversarial machinery.

## deep - full adversarial audit

Run this when balanced isn't enough - high-stakes targets (payment rails, auth systems, anything
handling real money or PII at scale), a compliance-driven engagement, or a target you suspect has
subtle logic bugs that a single chamber pass won't surface. Deep adds patch-history/bypass review,
authz-matrix construction, state/concurrency and spec-gap analysis, cross-service taint tracing, a
full multi-agent adversarial chamber (ideator → tracer → advocate, with a background variant
scout), cold zero-context re-verification of every survivor, and a dedicated variant search per
finding before PoC/report. It costs meaningfully more time and budget than balanced. Use it when
the target justifies the cost, not by default.

## diff - incremental re-audit

Run this against a PR or a small set of changed files when you already have a completed prior
audit on this repo. It resolves the last complete audit's commit, scopes to `git diff
--name-only PRIOR...HEAD` (capped at 200 changed files), runs static analysis + a git-blame
regression detector only on what changed, and classifies findings as new/fixed/unchanged against
the prior fingerprint set. If there's no prior audit or the diff is empty, diff mode skips itself
rather than pretending to have scanned anything. Use this for CI-gating pull requests once you have
a baseline; don't use it as your first audit of a repo.

## confirm - live PoC validation (opt-in, gated)

Run this only when you need a finding proven against a real running instance, not just a static
read of the vulnerable line - and only with the explicit live-validation opt-in and its sandbox
rails (isolated container, never production, operator confirms before anything executes, no
persistent artifacts left behind). It discovers and provisions an environment, executes PoCs
against it, falls back to generated reproducer tests where live execution isn't viable, and
aggregates a 9-state confirmation verdict per finding. Absent the opt-in flag, KAVACH stays
static-only and confirm mode simply doesn't run live anything. Use this to harden a `findings/`
tree you already trust before it goes to a client or a bug bounty, not as a routine step.

## revisit - re-run against known findings

Run this when a target has already been audited and you want a fresh look without re-litigating
what's already confirmed: think a follow-up engagement, a re-audit after remediation claims, or a
periodic re-check on a system that changes slowly. It mines fresh intent from docs, re-probes with
prior findings held out as a negative list, reclassifies via SAST, runs fresh chambers, re-verifies
false positives, and hunts both new and known-finding variants before rebuilding the report. Use
`revisit` instead of a fresh `deep` when you want continuity with a prior audit's findings rather
than starting from zero.

## merge - consolidate multiple audits

Run this when you have two or more independent `findings.json`/`findings/` sets for the same target
- multiple auditors, multiple tool runs, or a KAVACH run plus an external scan - and need one
de-duplicated, coherently-numbered result. It copies and indexes each source, runs a chamber pass
for semantic deduplication, auto-fixes metadata, quarantines anything unfixable, renumbers by
severity, applies the renames, and assembles one `reports/final-audit-report.md` with a
`merge-summary.md` provenance trail. Requires at least 2 sources; it has nothing to merge with just one.

## longshot - hail-mary swarm hunt

Run this after balanced/deep have already done the careful work and you want one more low-cost pass
looking for something everyone missed. It enumerates targets (usually per-file), swarms a
hail-mary hunter across each with a strict evidence bar and a per-file timeout, then aggregates,
dedupes, ranks, and curates whatever survives - with no auto-confirm; everything it surfaces still
needs a human or a follow-up mode to validate. Use this as a supplementary, budget-capped pass, not
as your primary audit - it optimizes for coverage breadth over rigor per finding.

## Budget - every mode has a dispatch ceiling

A mode is a depth tradeoff, so it is also a cost tradeoff. Each one seeds a dispatch ledger at
`kavach state init`, and the audit spends its fan-outs against it:

| Mode | Default max dispatches |
|---|---|
| `lite` | 15 |
| `balanced` | 60 |
| `deep` | 120 |
| `diff` | 10 |
| `confirm` | 30 |
| `revisit` | 80 |
| `merge` | 20 |
| `longshot` | 40 |

Plus a 3-hour wall-clock ceiling. Override either with `--budget N` / `--max-wall-seconds S`; `0`
means unlimited, for CI runs that manage their own ceiling. When a ceiling makes the run drop planned
work, that is **recorded and printed** in the report's "Limits of this run" section - so a
budget-constrained audit reads as a budget-constrained audit, not as a clean one. `kavach budget
show` prints the ledger at any point.

Deep on a mid-size repo plans roughly 800 dispatches without a ceiling, and a non-fork sub-agent
does not share the parent's prompt cache. If you want deep's machinery but not its bill, run it with
a smaller `--budget` and read the Limits section - that is a more honest result than running
`balanced` and calling it deep.

### How the ceilings are sized, and when to raise them

The per-finding phases are what consume a ceiling, and they cost **two dispatches per individually
promoted finding** - one `kavach-poc`, one `kavach-reporter`. So the arithmetic that matters is:

```
per-finding dispatches ≈ 2 × (individually promoted findings)   # the G* aggregates cost nothing
```

**Deep's 120 is sized for roughly 25-40 individually promoted findings**, which leaves room for the
20-odd phase-level dispatches deep runs before it ever reaches DP13. Balanced's 60 assumes about
half that. Those are the common cases, not a limit on what KAVACH will audit.

A repo with more genuine Critical/High findings than that will hit the ceiling, and it should: the
measured example is a backend whose 310 findings include 110 at critical/high, 55 of them
individually promotable. That is 110 per-finding dispatches against a ceiling of 120, so the very
next fan-out sheds. Two honest responses, and no third:

- **Raise it** - `--budget 240` (or `0` for unlimited, if you are managing cost another way). Do
  this when you intend to pay for full per-finding coverage of a large finding set.
- **Let it shed** - run at the default and read §2.3 of the report, which names the phase, the count
  dropped and the reason. A shed run is a real result with a stated boundary; it is not a failed one.

What you must not do is treat a silently-truncated audit as a complete one. That is why the shed is
recorded at decision time and printed in the deliverable rather than logged and forgotten.

---

For the exact phases, agents, and gate artifacts behind each mode, see `docs/phase-reference.md`.
For how the engine and the skill divide the work of actually running a mode, see
`docs/orchestration.md`. For the layout every mode writes into, see `docs/output-structure.md`.
