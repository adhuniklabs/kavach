# KAVACH Output Structure

Every audit lands under one durable root in the target repo: **`.kavach/`**. This is the
equivalent of piolium's `piolium/` output dir, and it replaces KAVACH's old single jargon-heavy
`KAVACH_SECURITY_REPORT.md` with a structured artifact tree: a durable knowledge base, a
per-finding tree with disclosure-ready reports, machine renders, and resumable run state.

## What to read first

If you only read one file after an audit, read **`reports/final-audit-report.md`** - it is the
primary human deliverable: executive summary, six-axis scorecard, attacker/kill-chain matrix,
per-axis chapters, prioritized remediation roadmap, residual risk, the limits of the run, and the
certification block (GRANTED/WITHHELD). **`reports/audit-report.pdf`** is the same document with
real page numbers and figures, for sending to someone; **`reports/audit-report.html`** is the same
document again, self-contained and printable.

Read **§2.3 Limits of this run** before you read anything else in it. That section names what the
audit did *not* do - dispatches the budget shed, promoted findings with no proof of concept, every
finding still marked `suspected`. A report with a clean verdict and a long Limits section is a
different claim from one with a clean verdict and an empty one.

If you're triaging one specific finding, go straight to **`findings/<id>-<slug>/report.md`** - it
is self-contained (no pointers back to a draft, a debate, or a phase id) and carries every
`file:line` needed to reproduce the read. A `findings/G*/` directory is different: it is a
**roll-up** of one scanner class, and its `rows.json` holds every member.

If you're integrating KAVACH into CI or another tool, consume **`reports/report.json`** or
**`reports/report.sarif`**, not the markdown - they're the stable machine contract.

If a run got interrupted and you want to know where it stopped, read **`audit-state.json`** (or
run `kavach state show`) before touching anything else in the tree. `kavach budget show` prints
what the run has spent and everything it decided to drop.

## The full tree

```
<target>/.kavach/
├── audit-state.json                # resumable run state. NEVER cleaned, NEVER hand-edited.
├── recon.json                      # Phase-0 stack map. Feeds the KB + scanner selection.
├── file-manifest.txt               # Appendix B coverage - every file KAVACH walked.
├── sweep-summary.json              # per-scanner status (ok / unavailable / error).
├── findings.json                   # {meta, findings[]} - deterministic + merged machine baseline.
├── controls.json                   # 8 gate-control booleans (fail-closed). Drives certification.
├── attack-surface/                 # DURABLE knowledge base - survives cleanup
│   ├── knowledge-base-report.md    #   master project model: classification, arch, DFD/CFD,
│   │                               #   threat model, domain attack research, spec-gap candidates
│   ├── unauthenticated-surface.md  #   anon-reachable entry points
│   ├── authz-matrix.md             #   per-endpoint guard matrix (deep DP5)
│   ├── architecture-entrypoints.md
│   ├── sbom.json                   #   9-category component inventory (kavach-intel)
│   ├── advisory-summary.md         #   3-tier CVE/GHSA/OSV advisory intel + heatmap
│   ├── commit-recon-report.md      #   git-history security forensics (kavach-history)
│   ├── patch-bypass-summary.md     #   prior-fix bypass verdicts (kavach-patch)
│   ├── state-concurrency-summary.md
│   ├── spec-gap-summary.md
│   ├── manual-attack-surface-inventory.md
│   ├── deep-probe-summary.md
│   ├── cross-service-edges.json / .md
│   ├── variant-summary.md
│   ├── diff-summary.md             #   diff mode only
│   ├── findings-baseline-<commit>.json.gz  # commit-keyed drift baseline, gzipped, written by
│   │                               #   `state complete`. A plain .json from 0.2.x still loads.
│   ├── poc-coverage.json           #   per-finding PoC coverage - THE GATE for LT3/BL6/DP13/RV11
│   ├── report-coverage.json        #   per-finding report coverage - the gate for BL6b/DP14/RV11b
│   ├── promoted-index.json         #   kavach_id -> dir for every dir consolidate wrote. The
│   │                               #   live set the coverage gates are scoped to.
│   ├── narrative.json              #   VAJRA's prose for the six render anchors
│   ├── merge-index.json  merge-dedup-decisions.json  merge-rename-map.json   # merge-mode gates
│   ├── confirm-findings-inventory.json  confirm-intent-crosscheck.json       # confirm-mode gates
│   ├── confirm-env-strategies.json  confirm-env-connection.json             #   (redacted - see below)
│   ├── confirm-poc-results.json  confirm-test-mapping.json                  #   (redacted - see below)
│   ├── deep-chamber-summary.md  adversarial-verification.md  # deep DP10 / DP11 gates
│   ├── longshot-hunt-summary.json  #   per-file swarm roll-up (longshot LS2 gate)
│   ├── longshot-targets.json       #   SIDECAR per-file swarm state (longshot LS1/LS2)
│   ├── longshot-summary.md
│   ├── intent-corpus.json          #   documented-intent corpus (kavach-intent; FP suppression)
│   ├── attack-pattern-registry.json
│   ├── kill-chains.md              #   the 6 KAVACH kill chains filled leaf-by-leaf (VAJRA)
│   ├── merge-summary.md            #   merge mode only
│   └── <mode>-cleanup-summary.json #   written by the mode's final cleanup phase
├── findings-draft/                 # TRANSIENT per-phase drafts (removed by cleanup)
│   └── <prefix>-NNN-<slug>.md      #   prefix = phase id lowercased, e.g. bl3-001-sqli.md
├── findings/                       # DURABLE promoted findings - the deliverable core
│   ├── <C1|H1>-<slug>/             #   individually promoted; see "The finding-dir contract" below
│   ├── G1-vulnerable-dependencies/ #   AGGREGATE: every dependency-class finding, rolled up
│   ├── G2-infrastructure-misconfiguration/  #   AGGREGATE: every iac-class finding, rolled up
│   └── FP-<C1|H1>-<slug>/          #   false positives, renamed not deleted (auditable)
├── findings-deferred/              # valid-but-triage-skipped drafts (appendix only, not action items)
├── findings-stale/                 # DURABLE - dirs `consolidate --prune-stale` MOVED out of
│                                   #   findings/ because they belong to an earlier promoted set
├── reports/                        # DURABLE - every rendered deliverable lives here
│   ├── final-audit-report.md       #   PRIMARY human deliverable. REPLACES KAVACH_SECURITY_REPORT.md.
│   ├── audit-report.html           #   self-contained, print-styled, inline SVG figures
│   ├── audit-report.pdf            #   real page numbers + Contents; needs the [report] extra
│   ├── report.json                 #   machine render (aggregate)
│   ├── report.sarif                #   SARIF 2.1.0, for code-scanning integrations
│   ├── confirmation-report.md      #   confirm mode only - 9-state per-finding verdicts
│   └── issues.json                 #   `kavach issues plan` export plan (operator verb only)
├── runs/                           # DURABLE (prunable) - per-phase sub-agent machine results
│   └── <phase>/<agent>[-<index>].json      #   e.g. runs/dp4/kavach-sast-3.json
├── reinvest-report.md              # deferred mode, not shipped - listed for completeness only
└── tmp/                            # TRANSIENT workspaces (removed by cleanup)
    ├── runs/<run_id>/               #   per-sub-agent: prompt.md, transcript.jsonl, result.md, error.txt
    ├── chamber-workspace/<cluster>/ #   debate.md, variant-candidates/
    ├── probe-workspace/<component>/ #   attack-surface-map.md, code-anatomy.md, probe-state.json
    ├── merge-workspace/              #   per-source aliases (a, b, …) for merge mode
    ├── verifier-reviews/             #   cold-verifier full per-finding reviews
    ├── confirm/                      #   confirm-mode working state INCLUDING credentials
    └── real-env-evidence/<slug>/     #   confirm-mode live reproduction artifacts (gated)
```

`runs/<phase>/` is a **different directory** from the transient `tmp/runs/<run_id>/`. The former is
the engine's durable result contract (`dispatch.result_path`); the latter is one sub-agent
invocation's scratch space. The `<phase>` component is lowercased and slugified with the same rule
as the `findings-draft/` prefix - `DP4` -> `dp4`, `CF1_5` -> `cf1-5`, `RV10k` -> `rv10k` - so any
glob over it uses the lowercase form.

A root-level `agent-<domain>.json` is **legacy**. Cleanup still recognises it so it is not reported
as unexpected, but the engine-issued path is `runs/<phase>/<agent>.json`, named in the
runtime header the sub-agent is dispatched with. That is the whole point: there is exactly one place
a result filename can come from.

## Durable vs transient

Durable artifacts are the deliverable - they survive every mode's cleanup phase (LT4/BL7/DP17/
CF7/etc.) and are never touched by anything except the phase that authored them:

- `audit-state.json`, `recon.json`, `file-manifest.txt`, `sweep-summary.json`, `findings.json`,
  `controls.json`
- `attack-surface/` (the whole dir)
- `findings/` (the whole dir, including `G*` aggregates and `FP-` renamed entries)
- `findings-stale/` (the whole dir - pruned evidence from an earlier promoted set)
- `reports/` (the whole dir) and `runs/` (the whole dir)
- `final-audit-report.md`, `report.json`, `report.sarif`, `confirmation-report.md` at the audit root
  are kept durable for **legacy trees**; nothing writes them there any more

Transient artifacts are working state for a single run and are wiped by the mode's cleanup phase
once the durable artifacts they fed are written:

- `findings-draft/`
- `tmp/` (all of it: `runs/`, `chamber-workspace/`, `probe-workspace/`, `merge-workspace/`,
  `adversarial-reviews/`, `real-env-evidence/`)
- mode-specific workspaces (`confirm-workspace/`) once `CF7`/equivalent has run

**No phase gate may resolve under a transient path.** A gate the mode's own cleanup deletes makes
its phase eligible again on every resume, so the run pays for the same fan-out twice; a test
(`test_modes.py::test_no_gate_under_transient`) enforces it for every phase in every mode. That is
why the confirm, merge, chamber, verification and longshot gate artifacts all live under
`attack-surface/` now.

Cleanup writes a `<mode>-cleanup-summary.json` under `attack-surface/` recording what it removed,
what it retained, what it expected but didn't find, and what it did not recognise:
`{removed, retained, missing, unexpected}`. That summary itself is durable, so a later audit can
see what the previous cleanup did.

`unexpected` is a **report, never a deletion**: any file at the `.kavach` root that is neither
durable, nor transient, nor a known pattern (`agent-*.json`, `*-baseline-*.json`,
`audit-state.json.lock`). The 2026-08-21 audit found four invented root files, one of them a 949 KB
`findings.raw-backup.json` in no doc and no code. Deleting an unknown file in someone's repo is not
the engine's call - making it visible is. Cleanup also removes a stale `audit-state.json.lock`, but
only when it can acquire the lock first; a live run's lock survives.

## The `findings/<id>-<slug>/` contract

Every promoted finding is a directory, not a file, so its evidence stays attached to it:

```
findings/C1-sql-injection-in-login/
├── draft.md              # promoted draft: verdict, severity, evidence, triage notes
├── report.md             # disclosure-ready: Summary / Details / Root Cause / PoC / Impact
├── poc.py                # runnable PoC (substitution vars + last-line JSON verdict)
│   └── poc.theoretical.md    # OR: a theoretical PoC when Confidence is suspected / static-only
├── metadata.json          # kavach_id, severity, cvss_vector, kill_chain, is_variant, confirm_status
└── evidence/               # setup/exploit/impact logs; real-env evidence under confirm mode
```

`report.md` must satisfy the vuln-report contract enforced by `report_finding.py`: exactly the
five H2 sections `## Summary`, `## Details`, `## Root Cause`, `## Proof of Concept`, `## Impact`,
every `file:line` cited, larger than 500 bytes, and **self-contained** - it may never point back
to a draft, a debate, or a phase id ("see draft", "see debate", "phase X", "above finding" are
banned pointer phrases). A report is idempotent: if the existing `report.md` already satisfies
every one of those checks, nothing re-renders it.

A finding that turns out to be a false positive is not deleted - its directory is renamed with an
`FP-` prefix (`findings/FP-C1-sql-injection-in-login/`) so the audit trail stays intact and
auditable.

## Promotion policy - which findings get a directory

Promotion keys on **two** things: severity and `finding_class`. `kavach triage` assigns
the class (`reasoned`, `code`, `secret`, `dependency`, `iac`); it is deterministic, model-free, and
excluded from `fingerprint()`, so classifying an existing `findings.json` changes no id.

| Outcome | Rule |
|---|---|
| Promoted individually (`C*`, `H*`) | `severity ∈ {critical, high}` **and** class ∈ {`reasoned`, `code`, `secret`} |
| Rolled into an aggregate (`G*`) | class ∈ {`dependency`, `iac`} **and** `severity ∈ {critical, high, medium}` |
| Table-only in the report | everything else |

The old rule was "promote every `severity >= medium`", which on the audited run promoted 238
directories - 70% of them raw scanner rows - and then scheduled a `kavach-poc` **and** a
`kavach-reporter` sub-agent against each one. The same finding set now yields roughly 14 individual
directories plus 2 aggregates. **Nothing is dropped**: a table-only finding is still in
`findings.json`, still in `reports/report.json` and `reports/report.sarif`, and still counted in the
report.

`G` is a deliberately distinct band, not another `C`/`H`. A reader must never mistake a rolled-up
CVE table for a cold-verified Critical.

## Stale promoted directories, and upgrading a legacy tree

`consolidate` never deletes. So a `findings/` tree carries directories that are no longer part of
the audit whenever the promoted set changes - and it changes in three ordinary ways:

- **You upgraded a legacy tree.** The old rule promoted every `severity >= medium`; the new one
  promotes critical/high `reasoned`/`code`/`secret` and rolls the scanner classes up. On the audited
  tree that is 238 old directories against 55 new ones.
- **A finding moved.** It dropped critical/high → medium between runs, or was reclassified from
  `reasoned` to a scanner class. It is still in `findings.json`, it is just no longer promoted
  individually.
- **Display ids renumbered.** `C1`/`H1`/`G1` are not stable across runs (see the display-id section
  below), so a re-audit writes `C11-<slug>` where the previous run wrote `C10-<slug>` **for the same
  fingerprint**. Both directories now exist and only one of them is live.

That last one is why the live set is **recorded, not re-derived**. `consolidate` writes
`attack-surface/promoted-index.json` as it goes:

```json
{"written_at": "2026-08-21T…Z", "audit_id": "…", "count": 57,
 "entries": [{"kavach_id": "KAVACH-7e3c775628", "dir": "findings/C1-…",
              "display_id": "C1", "is_aggregate": false}]}
```

It is a full snapshot per pass, not an append - `consolidate` re-promotes the whole finding set on
every call, so the manifest always describes exactly what is live right now. One writer, one reader:
two code paths inferring the live set independently is how it drifted in the first place.

### What "stale" means, and why it is not "missing"

A promoted directory outside that manifest is **stale**. `kavach coverage` counts it separately,
names it, and excludes it from the gate:

| `reason` | Meaning |
|---|---|
| `not_in_manifest_legacy_run` | promoted by an earlier run, under a different display id |
| `de_promoted` | id is still in `findings.json`, but the current policy no longer promotes it individually |
| `gone` | id is no longer in `findings.json` at all |
| `no_metadata` | `metadata.json` is missing or unreadable |

This distinction is the difference between a working gate and a wedged one. Before it, coverage
counted every directory on disk, so an upgraded tree read **291 total, 2 satisfied, 289 missing** -
and 289 of those would never receive a proof of concept, because they are not findings this audit
promotes. The gate could not close, ever. Scoped, the same tree reads `57 total, 2 satisfied,
55 missing, 234 stale`, and the 55 are real work a run can actually do.

A stale directory is **reported, never silently ignored**: the count is on stderr as well as in the
JSON, `stale_dirs[]` carries every one with its reason, and the report's Limits section names the
total. Same principle as cleanup's `unexpected` list - making it visible is the engine's job,
deciding what to do about it is the operator's.

### Tidying up: `--prune-stale` moves, it does not delete

```bash
kavach consolidate --out .kavach --prune-stale
```

Relocates every stale directory to **`findings-stale/`**, keeping its name and its whole contents -
`draft.md`, `report.md`, `poc.*`, `evidence/`. Nothing is removed. A name collision gets a
`--<reason>` suffix rather than an overwrite, and `findings-stale/` is in `cleanup.DURABLE`, so a
later cleanup does not eat it.

**The default is off.** Without the flag, `consolidate` leaves everything exactly where it is and
only the stale count tells the story. That is deliberate: `findings/` is audit evidence, an `FP-`
rename is the established precedent for "wrong but keep it", and moving somebody's directories is
not something a tool should do unasked.

If you would rather not migrate at all, start a fresh audit against a target whose
`.kavach/findings/` has been moved aside. Both routes work; neither deletes anything.

### The `findings/G*/` aggregate contract

```
findings/G1-vulnerable-dependencies/
├── rows.json        # {"finding_class": "dependency", "count": 136, "rows": [<Finding>, …]}
├── report.md        # rendered by the CORE, never by an agent
├── metadata.json    # + is_aggregate: true, member_count, member_ids[], finding_class
└── evidence/        # created empty, for symmetry with a promoted finding
```

`kavach_id` is `KAVACH-AGG-<class>` - stable by construction, and it can never collide with a sha1
fingerprint. `report.md` satisfies the same five-H2-section contract as any other finding report,
because the coverage gate checks every promoted directory uniformly.

An aggregate is **never** dispatched to `kavach-poc` or `kavach-reporter`, and both coverage gates
treat `is_aggregate: true` as already satisfied. `kavach report-finding G1` is a deliberate no-op.

## The budget ledger

`audit-state.json` carries the audit's dispatch ledger at `audits[].budget`:

```json
"budget": {"max_dispatches": 120, "max_wall_seconds": 10800, "dispatches": 47,
           "started_at": "…", "by_phase": {"DP4": 8, "DP13": 22},
           "shed": [{"phase": "DP13", "planned": 40, "allowed": 22, "dropped": 18,
                     "reason": "dispatch ceiling", "at": "…"}]}
```

`0` means **unlimited** for either ceiling - for CI runs that manage their own - and is deliberately
distinct from an exhausted budget, which allows 0 with reason `"dispatch ceiling"`. `shed[]` is
appended at *decision* time, not at charge time, because a coordinator that crashes after shedding
still owes the reader an honest note. Every shed record reaches §2.3 of the report.

Read it with `kavach budget show`; it is the same file the resumable phase state lives in, so it
survives resume and needs no second file.

## `C1`/`H1`/`G1` display id vs `fingerprint()` machine id

KAVACH carries **two** ids per finding, deliberately never conflated:

- **Display id / directory name** - band-prefixed, sequential within its band: `C1`, `C2`, `H1`, …
  (`C` = critical, `H` = high) plus `G1`, `G2` for the two class aggregates (`G` = grouped, and it
  sorts after `C` and `H`). Assigned by `findings_tree.consolidate()` in severity order (critical
  first, then by descending CVSS score within a band). This id is **not stable across runs** -
  rerun the audit and a finding's number can shift if the finding mix changes. It exists purely to
  be short, sortable, and readable in a report; humans reference "C1" in conversation, not the
  fingerprint.

  An aggregate's machine id is not a fingerprint at all: it is the constructed
  `KAVACH-AGG-<class>`, which is stable by definition and cannot collide with a sha1 form.

- **Machine id** - `Finding.fingerprint()`, the format `KAVACH-<sha1[:10]>`, derived from
  `category + normalized primary file path + rule_id + lowercased title` and **deliberately
  excluding the line number**, so it survives the surrounding code shifting. This is the id stored
  in `metadata.json.kavach_id`, in `findings.json`, in `reports/report.sarif`'s `kavachId` field,
  and in a tracker issue body (which is how a re-audit comments instead of filing a duplicate). It is
  what cross-run drift-diffing (`diffing.py`, diff mode's new/fixed/unchanged classification) and
  any external SARIF consumer key off.

Rule of thumb: use the display id (`C1`) when talking to a person about a specific finding in this
report; use the fingerprint (`KAVACH-a1b2c3d4e5`) when a machine, a diff, or a cross-run comparison
needs a stable handle. Never treat a shifted display id as a "new" finding without checking whether
the fingerprint underneath is unchanged.

## How today's root artifacts map in

- `recon.json` stays at the root; it seeds `attack-surface/knowledge-base-report.md` (`kavach-kb`
  reads recon instead of rediscovering the stack) and drives scanner `applicable_scanners()`.
- `findings.json` stays at the root as the deterministic + merged **machine baseline** - the input
  `findings_tree.consolidate()` reads to build `findings/`. Table-only findings live here and in
  the renders, and never get promoted.
- `controls.json` stays at the root; VAJRA writes it fail-closed during report assembly, and
  `score.py`'s gate/exit-code contract reads it unchanged.
- `runs/<phase>/<agent>[-<index>].json` is each sub-agent's machine handoff, at the path the engine
  named in its dispatch prompt. `kavach ingest <phase>` with no `--result` folds every result of a
  phase in one call. Root-level `agent-<domain>.json` is legacy but still recognised.
- `KAVACH_SECURITY_REPORT.md` is retired, and **no code path writes it** -
  `kavach scan --format md` prints to stdout, or to `--output` if you name one. `reports/` is the
  replacement; there is no compatibility alias.

## What `.kavach/` holds that must not leave the machine

`.kavach/` is raw evidence, and one scanner stores a credential verbatim: trivy's secret rows come
through `scanners/deps.py` with `snippet` set to the **raw matched value**, where gitleaks and
trufflehog pass a redacted one. Those rows classify as `secret`, so the tracker export redacts them
and carries `file:line` only - but `findings.json`, and an aggregate's `rows.json`, still hold the
raw value on disk.

Consequences, and they are not optional:

- **Gitignore `.kavach/` in the target repo.** It is audit working state, not a deliverable to
  commit. The deliverables are in `reports/`, and you choose which of those to share.
- **Never copy a finding's `snippet` into anything that leaves the machine** - an issue body, a
  Slack paste, a shared render. Nothing in the engine does; keep it that way.
- `reports/report.json` and `report.sarif` carry the finding set, snippets included. Treat them as
  sensitive, not as generic CI artifacts to publish.

This is pre-existing scanner behaviour, recorded here as a property of the local audit tree rather
than changed, because the redaction that matters - the one on the outbound path - is in place.

## Source of truth

- Code: `core/kavach/findings_tree.py` (`slugify`, `write_draft`, `partition`, `consolidate`,
  `write_aggregate`, `mark_false_positive`, and the live-set contract:
  `write_promoted_index`/`scope_promoted`/`prune_stale`/`STALE_REASONS`),
  `core/kavach/triage.py` (`classify`, the class table),
  `core/kavach/report_finding.py` (the vuln-report contract), `core/kavach/coverage.py` (the two
  coverage artifacts), `core/kavach/budget.py` (the ledger), `core/kavach/dispatch.py`
  (`result_path`/`result_glob` - the `runs/` contract), `core/kavach/cleanup.py`
  (`DURABLE`/`TRANSIENT`/`KNOWN_ROOT`), `core/kavach/finding.py` (`Finding.fingerprint()`).
