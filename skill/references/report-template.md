# Report Template - how the reconciler writes the narrative

**Division of labour.** `report-structure.md` is the authority on *what the renderers emit* - the
sections, their numbering, the figures, the annexes, the finding tiers. This file is the authority
on *how to write the prose that fills them*. If the two ever disagree about structure,
`report-structure.md` wins, because it describes code. Read it first.

The deliverable is **not one file**:

- `reports/final-audit-report.md` - the narrative + machine document. Also
  `reports/audit-report.html`, `reports/audit-report.pdf`, `reports/report.json`,
  `reports/report.sarif`. Every one of them is built from the same `AuditReport` model, so a number
  in one is the same number in all of them.
- `findings/<id>-<slug>/report.md` - one self-contained write-up per **individually promoted**
  finding (`<id>` = the display id, `C1`, `H2`). Contract in §6b below.
- `findings/G*/report.md` - one roll-up per scanner class, **written by the core, never by an
  agent**. Do not draft these and do not dispatch an agent at a `G*` directory.

The narrative must not contradict the promotion policy: only **critical/high** findings
of class `reasoned`/`code`/`secret` get their own directory. `dependency` and `iac` findings roll up
into `findings/G1-vulnerable-dependencies/` and `findings/G2-infrastructure-misconfiguration/` at any
severity. Medium promotable findings are a table row; Low/Info are a count. Nothing is dropped - but
"every Critical, High and Medium gets a directory" is no longer true, so never write it.

## You write exactly six things

Everything you author goes into **`attack-surface/narrative.json`**, keyed by the render anchor.
Nothing else you write reaches the report, and hand-edits to a rendered file are lost on the next
render.

| Key | Anchor | Lands at | Written up in |
|---|---|---|---|
| `exec-summary` | `<!-- KAVACH:exec-summary -->` | §1 Executive summary | §2 below |
| `attacker-matrix` | `<!-- KAVACH:attacker-matrix -->` | §1.5 Attacker matrix | §3 below |
| `attack-trees` | `<!-- KAVACH:attack-trees -->` | §5 Attack-tree findings | §5 below |
| `roadmap` | `<!-- KAVACH:roadmap -->` | §12 Remediation plan | §7 below |
| `residual` | `<!-- KAVACH:residual -->` | §14 Residual risk | §9 below |
| `limits` | `<!-- KAVACH:limits -->` | §15 Limits of this assessment | §10 below |

A key you leave out renders as `_Not supplied by the reconciler._` - visible, never silent. The
section numbers are the renderer's, not yours: it owns numbering so a report can no longer come out
as "§1, §2, §0, §5, §7". The headings below keep the old narrative numbering for continuity; the
table above maps each to where it actually lands.

Two sections that used to be yours are now the core's, and you must not duplicate them:

- **Detailed findings.** The renderer tiers them (full block for Critical/High, table row for
  Medium, roll-up row for scanner classes, a count for Low/Info) - see §6 below for the fields it
  reads out of each finding, which is what you make sure are populated.
- **Limits of this run** (§2.3). Assembled from the budget ledger's shed records, the coverage
  artifacts' `missing[]`, and every `suspected` finding. It is the honesty property of the whole
  report: do not soften it, do not restate it, and do not skip `kavach coverage` to keep it short.

Rule the narrative obeys everywhere: **prove it or flag it.** Every claim of a present control cites
the `file:line` that enforces it; every gap is named as a gap. No hedging to dodge a determination.

---

## 2 - Executive Summary  (`exec-summary`, lands at §1, 8-15 lines)

Founder-facing plain language, no jargon. It must, in this order:
- **Open with the production-readiness verdict** (READY / NOT PRODUCTION-READY) and the count of
  open Critical + High blockers.
- **Lead with the three nightmares** in one sentence each: can keys be stolen, can billing be
  bypassed / the chatbot run free, can the AI be hijacked - each YES/NO/UNVERIFIED with the single
  most important controlling or missing line.
- One line on the next-tier risks (IDOR/tenant isolation, free-token minting, encryption posture).
- Close with the one structural theme (e.g. "auth is solid; the money wall is the whole exposure").
Keep it to 8-15 lines. No finding IDs dumped here - that's the dashboard's job. No softening a
Critical to reassure the founder; calibration is the signature's value.

## 3 - Attacker Matrix  (`attacker-matrix`, lands at §1.5, under the core scorecard + dashboard)

A six-row table answering the operator's named nightmares. Each verdict is **YES** (attacker
succeeds - a kill chain reached EXPLOITABLE), **NO** (blocked - cite the controlling `file:line`),
or **UNVERIFIED** (needs the runtime test named in the adjacent cell). Derived from the reconciled
kill chains, not guessed.

| # | Can an attacker… | Verdict | Controlling / missing line |
|---|---|---|---|
| a | Steal & reuse the operator's API/LLM keys | YES/NO/UNVERIFIED | `file:line` |
| b | Run the paid chatbot(s) for free, at scale | … | … |
| c | Bypass the billing wall (any plan/add-on unpaid) | … | … |
| d | Mint or reset free-tier tokens indefinitely | … | … |
| e | Read/alter another user's or tenant's data | … | … |
| f | Hijack the AI (leak prompt, exfiltrate, act) | … | … |

## 5 - Attack-Tree Findings  (`attack-trees`, lands at §5, from `attack-trees.md`)

Render the **six kill chains** defined in `attack-trees.md` (steal-keys, free-chatbot,
bypass-billing, mint-tokens, read-others-data, hijack-ai). For each, walk root goal → branches →
leaf techniques, and mark every leaf **EXPLOITABLE** / **BLOCKED (cite `file:line`)** /
**UNKNOWN - needs runtime test (name it)**. A goal reachable with zero blocking control is Critical
regardless of perceived likelihood. Cross-reference each EXPLOITABLE leaf to its display id (the
same id as its `findings/<id>-<slug>/` directory, e.g. `C1`) so the roadmap and the tree agree. Per chain:

```
### Kill chain <letter> - <goal, e.g. "Bypass the billing wall">
Root goal: <one line>
- Branch: <attacker sub-goal>
  - <leaf technique> → EXPLOITABLE (C1) | BLOCKED (src/webhook.js:40 verifies signature) | UNKNOWN (test: replay a captured webhook)
Chain verdict: EXPLOITABLE / BLOCKED / UNKNOWN  ·  Overall this chain is <Critical/…>
```

## 6 - Detailed Findings  (core render, tiered - the fields you must populate)

**You do not write this section.** The renderer emits it per axis chapter (§6-§11), tiered by
`model.tier()`: a full boxed block for Critical/High, one table row for Medium, one roll-up row for
any `dependency`/`iac` finding whatever its severity, and a count by category for Low/Info. Your job
is to make sure every field below is populated in `findings.json` (per `finding-schema.md`) so the
block renders complete - an empty field renders as an empty field, in public.

The code snippet comes from the first populated `Location.snippet`. Populate it in the finding; the
renderer will not go and read the file. Rendered layout of a full block:

```
### [<id>] <Concise title>
- **Severity:** <CRITICAL|HIGH|MEDIUM|LOW|INFO> · **CVSS:** <score> (<vector>) · **Confidence:** <Confirmed-in-code|Suspected>
- **Category:** <A01 | API1:BOLA | LLM01 | Billing-Bypass | A07:Secrets | …>
- **Location(s):** `path/to/file.ext:line` (every location listed)
- **What it is:** <plain-language description of the flaw>
- **How it's exploited:** <concrete step-by-step attacker path; minimal PoC as evidence, not a weaponized kit>
- **Business impact:** <cost to the operator: stolen keys / free usage / lost revenue / breach / fines / trust>
- **Remediation - HOW TO FIX:** <copy-pasteable fix / diff for THIS codebase; numbered if multi-step>
- **Impact of the fix:** <what changes, side effects, migration/rollout notes, what it does NOT cover>
- **Effort:** <S|M|L> · **References:** <OWASP/CWE ids>
- **Full report:** `findings/<id>-<slug>/report.md` (Critical/High/Medium only)
```

Field mapping from the JSON: `title, severity, cvss_score, cvss_vector, confidence, category,
locations[], what_it_is, how_exploited, business_impact, remediation, fix_impact, effort,
references[]`. `Confidence` renders `Suspected` unless `confidence == "confirmed"`. `<id>` is the
severity-prefixed display id (`C1`, `H2`, `M3`, …) assigned by `findings_tree.consolidate` in
severity order after de-dup and kill-chain merge (a SAST hit that chains into a billing bypass is
one Critical, not two Mediums); the stable cross-run machine id (`kavach_id`, the finding's
fingerprint) rides alongside it in `metadata.json` but is never the reader-facing id.

## 6b - Per-Finding Report Contract (`findings/<id>-<slug>/report.md`)  (adapts piolium's vuln-report per-finding contract)

Every **individually promoted** finding - critical/high, class `reasoned`/`code`/`secret` - gets one
self-contained report at `findings/<id>-<slug>/report.md`. Medium and below stay table-only per §6,
and a `G*` aggregate's `report.md` is written by the core. One bug per report; never combine two
findings into one file even if they share a root cause (cross-link them instead). This contract is
machine-checked by `report_finding.is_complete`, and `kavach coverage --phase report` gates the
report phase on it - a write-up that fails it leaves the phase open. Required section order, exactly:

```
# [<id>] <Concise title>

## Summary
[One paragraph: vulnerable behavior, attacker control, outcome.]

## Details
[Walk input → sink: the exact branch/handler/validation gate that fails, and why the protection
doesn't hold. Include the decisive code snippet(s), each introduced with a sentence explaining what
it proves, and `path/to/file.ext:line` citations for every claim.]

## Root Cause
[Name the specific implementation or design flaw - the fault, not the symptom - tied back to the
exploit path above.]

## Proof of Concept (PoC)
1. [Setup step]
2. [Exploit step]
3. [Observed/expected result]
[Minimal reproducible command, request, or script - the shortest reliable path, not a weaponized kit.]

## Impact
[Who is affected, under what conditions, what the attacker gains. Practical consequence first;
severity labels second.]
```

Optional sections (add only when they carry real triage value, in this position - after Impact):
`Vulnerability Type`, `CWE`, `CVSS v3.1` (already computed per `severity-model.md` - restate it
here, don't recompute), `Authentication Reality`, `Affected Surfaces`, `Exploit Constraints`,
`Patch Commit`, `Scope`. Do not add `Affected Components` or `Remediation` sections here -
remediation lives in the §6 summary block and the roadmap (§7); this file is the disclosure-ready
exploit story, not the fix ticket.

**Self-contained rule (non-negotiable).** The reader must understand the vulnerability, the trace,
the impact, and the reproduction without opening any sibling file. Banned: "See draft.md", "See
metadata.json", "see evidence/ for the full trace", or any reference to an internal phase/run id.
If content from `draft.md` or a chamber transcript is needed to make the case, **inline it** - copy
the decisive lines in, don't point at them. The only sibling files a `report.md` may reference are
runnable evidence artefacts shipped alongside it (`poc.<ext>` or `poc.theoretical.md`,
`evidence/<file>`), and only from inside the PoC or Impact sections. Cite `file:line` directly
(GitHub-style permalinks pinned to a commit SHA are a welcome addition when the target repo is
GitHub-hosted, but `path:line` citation is the floor and always required).

## 7 - Prioritized Remediation Roadmap  (`roadmap`, lands at §12)

The renderer prints its own three-horizon table under your prose, derived from the finding set. Yours
is the argument - why this order, what depends on what, which item is a quick win. Do not just
restate the table.

An ordered fix list, grouped into exactly three buckets, each item citing its display id (`C1`,
`H2`, …) and marked **[quick win]** or **[structural]**:
- **Before any production traffic** - every open Critical + High; key exposure, IDOR/BOLA, unauth
  LLM proxy, missing webhook verification. Nothing ships until these clear.
- **Before billing goes live** - money-path items that can wait for real traffic but not for the
  first paid user: idempotency, double-spend locking, free-token rate limits, coupon logic.
- **Hardening backlog** - Medium/Low defense-in-depth: headers, logging hygiene, dependency
  upgrades, field-level encryption, abuse monitoring.
Order within each bucket by severity then effort (quick wins first at equal severity).

## 8 - Production-Readiness Verdict  (core gate, lands at §13 - no anchor of yours)

`kavach gate` renders the §6 checklist from `controls.json` - **eight boxes**, each ✅ only when its
control boolean is `true` (unset = unproven = ❌, fail-closed):

- ☐ Zero open Critical findings
- ☐ Zero open High findings
- ☐ `no_client_reachable_secret` - no key reachable by the client; LLM/payment keys server-side, proxy auth-gated + quota-limited
- ☐ `billing_server_side_enforced` - server-side price/entitlement + verified, idempotent webhooks + atomic credits
- ☐ `authz_on_every_object_and_function` - no open IDOR/BOLA/BFLA
- ☐ `ai_guardrails_present` - injection/jailbreak guardrails, non-leaking system prompt, authorized+rate-limited AI actions, sanitized output
- ☐ `encryption_tls_and_at_rest` - TLS enforced; sensitive data + secrets encrypted at rest; named field-level encryption applied
- ☐ `rate_limits_on_expensive_endpoints` - rate/abuse controls on all expensive + money + AI endpoints
- ☐ `no_debug_or_secret_leak_in_prod`

If any box is ❌ the verdict is **NOT PRODUCTION-READY**. There is no anchor in §13, so put the
one-line-per-❌ blocker prose in `exec-summary` (§1.1 prints the machine list right under it). No
softening.

Note the scorecard is **not** the gate. One open Critical fails the gate outright while costing its
axis three points, which can still leave that axis above the 5.0 threshold. If you find yourself
explaining a green-looking scorecard next to a failed gate, that is the correct reading, not a bug -
say so.

## 9 - Residual Risk & What Static Analysis Cannot Certify  (`residual`, lands at §14)

Honest scope statement: this is SAST + architecture + manual code review, not a live pen test.
List what still requires **live DAST / penetration testing** before external sign-off - runtime
authz under real sessions, real payment-flow exploitation against the processor, live infra/cloud
config in the operator's account, DDoS/rate-limit resilience under load, and every finding marked
`Suspected` (each with the runtime test that would confirm it). State plainly that a green gate
certifies the code and architecture, not the running deployment.

The renderer prints the full table of `suspected` findings under your prose. Do not enumerate them
again; explain what class of assurance is missing and what would close it.

## 10 - Limits of This Assessment  (`limits`, lands at §15)

The scope statement static analysis cannot derive, for **this** run specifically. §2.3 already
prints the machine-known gaps (dispatches the budget shed, promoted findings with no PoC, every
suspected finding) - this is the part only you know:

- What you chose not to pursue, and why (a subsystem out of scope, a vendored tree skipped, a
  language with no scanner coverage on this machine).
- Which scanners were unavailable on this run (`sweep-summary.json` marks them `unavailable`) and
  what that blinds the audit to.
- Any finding you judged real but could not prove to the confirmed bar, and the runtime test that
  would settle it.
- What a reader must **not** conclude from a green gate.

If the budget shed work, name it here in your own words as well - the machine line says how many
dispatches were dropped; you say what that means for confidence in the result.
