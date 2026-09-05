# KAVACH Architecture - data flow

A KAVACH audit is one data flow, regardless of preset. Presets differ only in which phases of the
one pipeline run, and so in which agents reach each stage (see `docs/modes.md` for the tradeoff and
`docs/phase-reference.md` for the exact phases); the shape below is constant.

```
recon ──▶ sweep ──▶ drafts ──▶ chamber ──▶ triage ──▶ promote ──▶ report
  │          │          │          │           │          │           │
recon.json  sweep-    findings-  tmp/chamber- finding_   findings/   reports/
            summary   draft/     workspace/   class      C*/H*/G*/   final-audit-report.md
            .json     runs/                              coverage    .html .pdf .json .sarif
                      <phase>/                           .json       confirmation-report.md
```

Triage is where the audit stops treating a scanner row and a
reasoned judgement as the same kind of object - see stage 4b.

## 1. Recon - zero-input stack map

`core:recon` walks the entire target repo with no configuration and no prior knowledge, producing
`recon.json`: the stack map (languages, frameworks, datastores, auth mechanism, LLM/payment
integrations if present) plus `file-manifest.txt` - proof every file was seen (Appendix B
coverage). Every later stage reads `recon.json` instead of rediscovering the codebase; `kavach-kb`
in particular treats it as the seed for the architecture model rather than starting from scratch.
This stage never fails closed by skipping a file - a file recon can't classify still shows up in
the manifest as unclassified, not silently dropped.

## 2. Sweep - deterministic scanner baseline

`core:sweep` runs KAVACH's Docker-first (native-fallback) scanner fleet - secrets scanners
(builtin-secrets, gitleaks, trufflehog, and trivy's secret rows), SAST (semgrep, bandit/gosec), and
the rest of the built-in scanners - against the whole tree, deduplicates hits, and writes `sweep-summary.json`
(per-scanner ok/unavailable/error) plus a first cut of `findings.json`. Every scanner hit here is a
**lead**, never a verdict - nothing in `findings.json` at this stage is `confirmed` until a later
agent reads the actual line. Where `deep` needs more than a single detection pass - patch
history, authz matrices, state/concurrency, spec-gap analysis - those specialist agents run in
parallel with or after sweep and write their own `attack-surface/*.md` artifacts, but the mechanism
is the same: deterministic-or-scripted signal in, `findings.json`/`attack-surface/` out.

## 3. Drafts - domain hunters produce per-finding units

The 8 domain hunters (sast, api, llm, billing, crypto, supply, config, logic) at `hunt` - joined
from `balanced` up by the probe team, and under `deep` by the authz/state/spec/cross-service
specialists - fan out against the attack surface recon+sweep built. (`lite` cuts `hunt`'s roster to
`kavach-sast` alone.) Each confirms or refutes its slice of scanner leads at the actual sink, hunts
what scanners structurally can't reason about (reachability, intent, business logic), and emits both
a machine handoff at the engine-named `runs/<phase>/<agent>[-<index>].json` and, via
`dispatch.ingest`, a per-finding draft under `findings-draft/<phase>-NNN-<slug>.md`. The engine names that result path in the dispatch
prompt precisely so a fan-out cannot invent filenames or clobber itself. This is the stage where "a scanner found something"
becomes "VAJRA confirmed this at file:line" or "flagged as suspected, here's the runtime test that
would confirm it" - the confirmed/suspected discipline is enforced here, not retrofitted later.

## 4. Chamber - adversarial review before anything is trusted

Every draft goes through an adversarial-review pass before it's allowed to become a promoted
finding: `kavach-chamber` (the judge) orchestrates `kavach-ideator` (creative attack-mode
hypotheses), `kavach-tracer` (reachability evidence), and `kavach-advocate` (the devil's-advocate
false-positive hunt), with `kavach-variant-scout` running in the background to front-load variant
discovery. `chamber` is one phase with one gate whichever preset scheduled it - what differs is how
much attack surface is underneath it, since `deep` reaches it with `authz`, `state`, `spec`,
`crossservice` and `history` already done. Survivors get zero-context re-verification by
`kavach-verifier` at `verify`, which only `deep` schedules - a cold read with no access to the
chamber's reasoning, specifically to catch anchoring. This stage writes to
`tmp/chamber-workspace/` (transient) and is where a finding's severity gets calibrated, not just
proposed.

## 4b. Triage - a scanner row is not a finding

`kavach triage` (`triage.classify_all`) assigns every finding a `finding_class` - `reasoned` (a
`kavach-*` agent or the reconciler judged it), `code`, `secret`, `dependency` or `iac` - from its
`source`, `category` and `rule_id`. First match wins, deterministic and model-free, idempotent, and
excluded from `fingerprint()` so classifying an existing finding set changes no id.

The class is what makes the rest of the flow affordable and honest. On the audited run, 217 of 310
findings were raw scanner output, and the promotion rule ("everything at `severity >= medium`") sent
each one into its own directory with a `kavach-poc` **and** a `kavach-reporter` sub-agent scheduled
against it. `reasoned` is checked first and unconditionally: a VAJRA judgement about a dependency is
judgement, not a scanner row, and stays promotable. `secret` is checked before `dependency`, keying
on `category == "A07:Secrets"` exactly - because trivy emits its secret rows with `source="trivy"`,
and under a source-only rule a committed credential would have been rolled into the dependency
aggregate and missed by the tracker export's redaction guard.

Two live rewriters mutate `Finding.source` before this point - `sweep.dedupe` joins them with `+` on
every scan, and `merge-run` prefixes a per-source alias - so `classify` matches on **any segment**
of the source rather than the whole string. `triage.sources()` is the one place that rule is written down.

## 5. Promote - the findings tree

Once a finding survives the chamber (and, in deep, cold verification + variant search), PoC
construction (`kavach-poc`) and report drafting (`kavach-reporter`) run per finding, and
`findings_tree.consolidate()` promotes **critical/high `reasoned`/`code`/`secret`** findings from
`findings.json` into `findings/<C1|H1>-<slug>/` - assigning the band-prefixed display id, scaffolding
`draft.md`/`metadata.json`/`evidence/`, and stamping the stable `fingerprint()` as the machine id in
`metadata.json.kavach_id`. The scanner classes roll up instead, into at most two `findings/G*/`
aggregate directories carrying `rows.json`, a core-written `report.md`, and
`metadata.json.is_aggregate: true`. `G` is a distinct band on purpose: a reader must never mistake a
rolled-up CVE table for a cold-verified Critical. False positives caught this late get their
directory renamed `FP-<id>-<slug>/` rather than deleted. Everything else stays table-only in the
report - counted, never dropped. This is the one stage where "a finding" stops being a JSON object
and becomes a directory with its own evidence.

Because the per-finding phases used to gate on `findings/` existing - which `consolidate` creates
unconditionally - a run could promote 238 findings, build **zero** PoCs, and still report `complete`.
`coverage.py` closes that: `kavach coverage --phase poc|report` walks the promoted tree, exempts the
aggregates, and writes an artifact that only satisfies its gate when it says `complete: true`.

## 6. Report - the deliverable

Final report assembly is always VAJRA-lead work, but the *document* is the renderer's. Every format
is built from one `render.model.AuditReport` - assembled from `findings.json`, `recon.json`,
`controls.json`, the `GateResult`, the budget ledger, the coverage artifacts and the promoted tree -
so markdown, HTML, PDF, JSON and SARIF cannot disagree about a number, and section numbering belongs
to `model.outline()` rather than to prose. `core:render` writes them all into `reports/`:
`final-audit-report.md`, `audit-report.html`, `audit-report.pdf` (real page numbers, six figures;
needs the optional `[report]` extra), `report.json`, `report.sarif`.

VAJRA's contribution is the prose, written once to `attack-surface/narrative.json` under six keys
and spliced at six anchors - a missing key renders as `_Not supplied by the reconciler._`, visible
rather than silent. Findings are **tiered** in the document (full block for Critical/High, a table
row for Medium, a roll-up row for the scanner classes, a count for Low/Info), which is what takes a
310-finding report from 3,144 lines to roughly 450 without dropping anything. A deterministic
six-axis scorecard (`scoring.py`) prints alongside the gate, with Annex A showing every deduction -
and it is explicitly *not* the gate: one open Critical fails the gate outright while costing its axis
three points.

`AuditReport.limits` - the budget's shed records, the coverage gaps, and every `suspected` finding -
prints in §2.3 of every format. **A dropped tail must appear in the deliverable**; that is the single
most important honesty property of the design.

VAJRA still fills all 6 kill chains leaf-by-leaf in `attack-surface/kill-chains.md`, writes
`controls.json` fail-closed, and renders the GRANTED/WITHHELD certification block - `score.py`'s gate and exit-code contract (`0` clean, `2`
open Critical, `3` open High, `4` gate/controls unmet, `5` tooling error, `130` interrupt) reads
`controls.json` and the findings tree, unchanged across every preset. `--live` adds `certify`, whose
`confirmation-report.md` (9-state per-finding verdicts against a live environment) is a parallel
deliverable rather than a replacement for the static report. The `cleanup` phase every preset ends
on then removes every transient artifact (`tmp/`, `findings-draft/`, `live-workspace/`) and writes
`attack-surface/cleanup-summary.json`, leaving only the durable tree described in
`docs/output-structure.md`.

## Cross-cutting: the engine/skill seam

None of these stages runs as engine-spawned code. At every stage boundary the Python engine
(`core/kavach/`) is the planner + state manager + renderer - it decides what's next, composes the
prompt, and folds results back in - while `SKILL.md` is the only thing that ever issues a `Task`
call to actually run a sub-agent. See `docs/orchestration.md` for the plan → phase-prompt → Task →
ingest → consolidate loop that drives every one of these stages, and `docs/phase-reference.md`
for exactly which phase id and which agent sits at each point in the flow, and which of the three
presets schedules it.

## Source of truth

- Code: `core/kavach/recon.py`, `core/kavach/sweep.py`, `core/kavach/dispatch.py`,
  `core/kavach/triage.py`, `core/kavach/findings_tree.py`, `core/kavach/coverage.py`,
  `core/kavach/budget.py`, `core/kavach/report_finding.py`, `core/kavach/score.py`,
  `core/kavach/scoring.py`, `core/kavach/render/`, `core/kavach/issues.py`.
