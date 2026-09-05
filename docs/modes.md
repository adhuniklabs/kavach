# KAVACH Modes - when to use which

KAVACH runs **one 26-phase pipeline**. An invocation picks an intensity preset - `lite`, `balanced`
or `deep` (`/kavach <preset>`) - and the preset is a *subset* of that pipeline, not a pipeline of its
own. The three are strictly nested: every phase `lite` schedules, `balanced` schedules, and every
phase `balanced` schedules, `deep` schedules. Moving up a preset only ever adds work. On top of any
of them, `--live` appends the six-phase live-validation tail.

Phase-by-phase detail lives in `docs/phase-reference.md`; this page is the "which one do I actually
run" decision guide.

## lite - fast triage (6 phases)

`recon → sweep → hunt → poc → render → cleanup`.

Run this when you want a signal in minutes, not a verdict: a pre-commit check, a quick sanity pass on
a repo you've never seen, or a CI gate that can't afford a long audit. It walks recon and the secret
sweep, runs `hunt` with a **single-agent roster** (`kavach-sast` alone - the other seven domain
hunters are balanced's and deep's), builds PoCs for what consolidation promotes, and assembles
`reports/final-audit-report.md`. No knowledge base, no intent corpus, no chamber, no adversarial
review.

`lite` schedules `render`, so it now ends in a report rather than in a bare findings tree. It does
**not** schedule `report`, the per-finding drafting phase - that costs one `kavach-reporter` dispatch
per promoted finding, which is most of a 15-dispatch ceiling on its own. So lite's deliverable is the
assembled audit report, not a disclosure-ready write-up per finding.

Expect it to catch the loud, obvious stuff (hardcoded keys, unparameterized queries, missing auth on
an endpoint) and miss anything that needs architectural context or a debate to confirm. Use `lite` as
a first pass before committing to `balanced` or `deep`, not as a substitute for either.

## balanced - the default full audit (13 phases)

Adds `intent`, `intel`, `kb`, `probe`, `chamber`, `crosscheck` and `report` to lite's six.

This is the audit to run when someone asks "is this secure" and you have no other constraint. It
builds the real knowledge base (`kb`: architecture, threat model, unauthenticated surface), fans all
**eight domain hunters** out against it at `hunt`, probes by hand what the scanners cannot reason
about, runs a single adversarial-review chamber to kill false positives, cross-checks every surviving
draft against the documented-intent corpus `intent` mined, then builds PoCs and disclosure-ready
per-finding reports for every survivor. It produces the full `reports/final-audit-report.md` (plus
HTML, PDF, JSON and SARIF) with kill-chain fill, VAPT verdict, and certification. Default choice for:
pre-launch review, periodic full audits, a new codebase with no prior KAVACH history, or anytime you
want one clean deliverable and don't need deep's extra adversarial machinery.

## deep - full adversarial audit (20 phases)

Adds `history`, `authz`, `state`, `spec`, `crossservice`, `verify` and `variant` to balanced's
thirteen - the whole audit half of the pipeline.

Run this when balanced isn't enough - high-stakes targets (payment rails, auth systems, anything
handling real money or PII at scale), a compliance-driven engagement, or a target you suspect has
subtle logic bugs that a single chamber pass won't surface. Deep adds patch-history/bypass review
(`history`, which runs `kavach-history` then `kavach-patch` in sequence), authz-matrix construction,
state/concurrency and spec-gap analysis, cross-service taint tracing, cold zero-context
re-verification of every survivor (`verify`), and a dedicated variant search (`variant`) before
PoC/report. Its `chamber` is the same phase balanced runs, reached with far more attack surface
underneath it. It costs meaningfully more time and budget than balanced. Use it when the target
justifies the cost, not by default.

A plain `deep` run writes `reports/final-audit-report.md` and nothing else under `reports/`. The
confirmation report is `certify`'s gate artifact, and `certify` is a `--live` phase, so `deep` alone
never schedules it.

## `--live` - live PoC validation (6 phases, opt-in, gated)

`inventory → envscan → provision → exploit → testgen → certify`, appended to whichever preset you
ran. `--live` is a flag, not a preset: `kavach plan --mode lite --live` and
`kavach plan --mode deep --live` are both legal, and `cleanup` moves behind `certify` so the tail
finishes before the transient workspaces go.

Use it when you need a finding proven against a real running instance, not just a static read of the
vulnerable line - and only with the explicit live-validation opt-in and its sandbox rails (isolated
container, never production, operator confirms before anything executes, no persistent artifacts left
behind). It indexes the findings tree, discovers and provisions an environment, executes each PoC
against it, falls back to generated reproducer tests where live execution isn't viable, and
aggregates a 9-state confirmation verdict per finding into `reports/confirmation-report.md`. Absent
the opt-in, KAVACH stays static-only and none of these six phases are scheduled at all.

This is how you harden a `findings/` tree you already trust before it goes to a client or a bug
bounty. It is not a routine step, and it is the only way to get a confirmation report.

## Where the removed modes went

KAVACH shipped eight modes until 0.3.0. Five are gone; passing one to any mode-taking verb exits
non-zero and names the replacement rather than reporting an unknown mode:

| Removed | What to run instead |
|---|---|
| `diff` | the **`kavach diff`** verb - resolves the prior commit, scopes to `git diff --name-only PRIOR...HEAD`, and drift-diffs against the baseline. A verb, so it composes with any preset. |
| `confirm` | **`--live`** on any preset. Same six phases, same charter, same rails. |
| `revisit` | re-run any preset **against the existing audit dir**. Completion is gate-driven, so what already has its artifact is not re-run and prior findings stay in the tree. |
| `merge` | the **`kavach merge-run`** verb - `--dir` per source audit dir, two or more. |
| `longshot` | nothing. The per-file hail-mary swarm and its two agents were removed. |

`kavach inventory` also survives as a verb, and it is `inventory`'s executor under `--live`.

## Budget - every preset has a dispatch ceiling

A preset is a depth tradeoff, so it is also a cost tradeoff. Each one seeds a dispatch ledger at
`kavach state init`, and the audit spends its fan-outs against it:

| Mode | Default max dispatches |
|---|---|
| `lite` | 15 |
| `balanced` | 60 |
| `deep` | 120 |
| `--live` | +30 on top of the preset |

The live delta is added, not substituted: `deep --live` seeds 150. Live validation provisions an
environment and executes per finding, so it is priced separately from audit depth.

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

The per-finding phases are what consume a ceiling, and under `balanced`/`deep` they cost **two
dispatches per individually promoted finding** - one `kavach-poc` at `poc`, one `kavach-reporter` at
`report`. So the arithmetic that matters is:

```
per-finding dispatches ≈ 2 × (individually promoted findings)   # the G* aggregates cost nothing
```

`lite` schedules `poc` without `report`, so it pays one, not two.

**Deep's 120 is sized for roughly 25-40 individually promoted findings**, which leaves room for the
22 phase-level dispatches deep runs before it ever reaches `poc`. Balanced's 60 assumes about half
that, over 14 phase-level dispatches. Those are the common cases, not a limit on what KAVACH will
audit.

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

For the exact phases, agents, and gate artifacts behind each preset, see `docs/phase-reference.md`.
For how the engine and the skill divide the work of actually running one, see
`docs/orchestration.md`. For the layout every run writes into, see `docs/output-structure.md`.
