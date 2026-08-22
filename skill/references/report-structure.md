# Report Structure - what the renderers emit, and what the reconciler fills

`report-template.md` specifies the *narrative* VAJRA writes. This file specifies the
*document* the core renders around it: the sections, their numbering, the figures, the
annexes, and the exact anchors the narrative is spliced into. Everything here is emitted by
`kavach.render`, so it is the same in markdown, HTML and PDF and cannot drift between them.

Read this before writing narrative. If a section is not listed here, no renderer emits it.

---

## 1. One model, five formats

Every renderer builds a `kavach.render.model.AuditReport` first and reads only that:

```
findings.json + recon.json + controls.json + GateResult
  + audit-state.json (budget.shed) + attack-surface/*-coverage.json + findings/*/metadata.json
        │
        └─> AuditReport ──> markdown · HTML · PDF · JSON · SARIF
```

Consequences worth knowing:

- A number that appears in two formats is the same number. There is no per-format arithmetic.
- Section numbering is owned by `model.outline()`, not by prose. It is dense and starts at 1;
  a report can no longer come out as "§1, §2, §0, §5, §7".
- The reader-facing reference for a finding is its promoted display id (`C1`, `H2`, `G1`) when
  `findings/<id>-<slug>/metadata.json` exists, and its stable `KAVACH-<sha1>` id otherwise.
  Renderers call `report.ref(finding)`; never hand-write an id.

## 2. Emitted structure

| # | Section | Owner | Contents |
|---|---|---|---|
| - | Cover | core | Title, auditor, and a metadata table: scope, volume, date, commit, method, reference standards, scorecard, conclusion |
| - | Contents | core | Every section below. Real page numbers in the PDF; links in the HTML; a plain list in markdown |
| - | Glossary | core | ASVS, aggregate finding, CVSS, CWE, confirmed, display id, finding class, gate, KAVACH id, kill chain, suspected |
| 1 | Executive summary | **narrative** + core | `exec-summary` anchor, then 1.1 Verdict · 1.2 Scorecard (Figure 1) · 1.3 Risk dashboard (Figure 2) · 1.4 Finding classes (Figures 3, 4) · 1.5 Attacker matrix (`attacker-matrix` anchor) |
| 2 | Scope, method and limits | core | 2.1 Scope and stack · 2.2 The five-step method · 2.3 Limits of this run (see §4 below) |
| 3 | Scoring reference | core | The scoring method verbatim, 3.1 the six axes, 3.2 every sub-characteristic (Figure 5) |
| 4 | Framework mapping | core | One row per category present: OWASP · ASVS 4.0 · CWE · GDPR |
| 5 | Attack-tree findings | **narrative** | `attack-trees` anchor - the six kill chains |
| 6-11 | One chapter per axis | core | Security · Data protection · Secrets & supply chain · Architecture · Reliability · Maintainability. Findings are tiered, see §3 below |
| 12 | Remediation plan | **narrative** + core | `roadmap` anchor, then the three-horizon table derived from the finding set |
| 13 | Production-readiness verdict | core | The eight controls (Figure 6), blockers, certification wording |
| 14 | Residual risk | **narrative** + core | `residual` anchor, then every `suspected` finding |
| 15 | Limits of this assessment | **narrative** | `limits` anchor |
| - | Annex A - Score justification | core | Every axis's arithmetic, term by term |
| - | Annex B - Findings inventory | core | The promoted tree, then every finding at every severity |
| - | Annex C - Reproducing the figures | core | One command per quantified claim |
| - | Appendix B - Coverage | core | Total files walked, pointer to `file-manifest.txt` |

### The six anchors

Emitted in exactly this order, and asserted by a test:

```
<!-- KAVACH:exec-summary -->      §1
<!-- KAVACH:attacker-matrix -->   §1.5
<!-- KAVACH:attack-trees -->      §5
<!-- KAVACH:roadmap -->           §12
<!-- KAVACH:residual -->          §14
<!-- KAVACH:limits -->            §15
```

Each renders the reconciler's prose when supplied, and the single line
`_Not supplied by the reconciler._` when not. **A missing anchor is visible, never silent.**

The prose is read from `attack-surface/narrative.json`:

```json
{"exec-summary": "…", "attacker-matrix": "…", "attack-trees": "…",
 "roadmap": "…", "residual": "…", "limits": "…"}
```

Blank-line-separated paragraphs become separate paragraphs in HTML and PDF. Unknown keys are
ignored. A caller can pass the same dict as `meta["narrative"]` instead, which wins over the
file.

## 3. Detailed findings are tiered

The old renderer dumped every finding as a full block, which is how a 310-finding run became
a 3,144-line report where the narrative was 6% of the file. Each axis chapter now emits:

| Tier | Applies to | Treatment |
|---|---|---|
| Full block | Critical, High | Boxed: reference · title · severity chip · facts line · location · what it is · how it is exploited · code snippet · **Consequence** · **Proposed fix** · impact of the fix · effort · kill chain · references · KAVACH id |
| Compact | Medium | One row in a table: reference · title · location · category · source |
| Rolled up | any severity, `finding_class` in `dependency` / `iac` | One row in a table: severity · class · title · advisory · location, with a pointer to the aggregate's `rows.json` |
| Counted | Low, Info | A count by category, plus a pointer to `reports/report.json` and `reports/report.sarif` |

`model.tier()` owns the split, so the three renderers cannot disagree, and every finding lands
in exactly one tier - nothing is dropped.

Severity picks the tier for the promotable classes only. **Scanner classes roll up whatever
their severity**, because a rolled-up advisory that reads like a cold-verified Critical is the
exact confusion the `G`-banded aggregate directories exist to prevent. A rolled-up row still
names its severity and its advisory id; it just does not get a write-up.

The code snippet comes from the first `Location.snippet` that is populated. Populate it in
the finding, not in prose - the renderer will not go read the file.

## 4. Limits: the honesty property

`AuditReport.limits` is assembled from three sources, in this order:

1. **`budget.shed`** from the audit's record in `audit-state.json` - every phase where planned
   dispatches were dropped, with the count and the reason.
2. **`missing[]`** from `attack-surface/poc-coverage.json` and
   `attack-surface/report-coverage.json` - every promoted finding with no proof of concept or
   no write-up, named by display id.
3. Every finding still at **`confidence: suspected`**.

It appears in §2.3 of every rendering. **A dropped tail must reach the deliverable.** All
three artifacts are read defensively-by-absence: an audit directory that never had them
yields an empty list, not an exception, so an old audit dir still renders.

The `limits` list is core data. The `<!-- KAVACH:limits -->` anchor in §15 is separate - it is
where the reconciler writes the scope statement that static analysis cannot derive.

## 5. Scoring

`kavach.scoring` produces the six-axis scorecard. It is arithmetic, not judgement:

- Every **assessed** axis starts at **10.0**.
- Each mapped finding deducts **3.0** critical, **1.5** high, **0.75** medium, **0.25** low.
  Info deducts nothing.
- Each control proven in `controls.json` adds **0.5**.
- The result is clamped to **[1.0, 10.0]** and rounded to one decimal.
- An axis is **acceptable at 5.0**. The scorecard is acceptable only when every *assessed* axis
  clears it - a 9.0 elsewhere does not buy off a 2.0.
- **There is no evaluator override and no fudge factor.** Where a human auditor would apply
  judgement, KAVACH does not. If a score looks wrong, argue with `scoring.AXIS_MAP`, which is
  one table for exactly that reason.

### Absence of evidence is not evidence of a control

An axis or sub-characteristic with **no mapped finding and no proving control is `not assessed`,
not 10.0**. It never starts at the baseline, `Clears 5.0` reads `-`, Annex A prints no
arithmetic for it, it is excluded from the overall figure, and it gets no radar spoke and no
sub-characteristic bar. The cover line names the denominator - `2.5 / 10 across 5 assessed axes
(1 not assessed: Maintainability)` - so an average over a varying number of axes is readable.

This is the same fail-closed rule the gate applies to controls: `controls.json` defaults every
control to false and certification is withheld on an unproven one, because an unsupplied control
is an unproven control. A scorecard that read silence as success would contradict the gate on
the same page. **Absence of a finding is not evidence of a control**, and `scoring.METHOD` says
so in every rendering.

Three states, not two: `not assessed` (nothing mapped, no control), *assessed and clean* (a
proven control or an info-only finding, so the number is a result), and *scored down* (findings
deducted). The sub-characteristic table's `Determined by` cell distinguishes all three.

`maintainability` is the axis this bites. KAVACH is a security auditor - neither the scanner
sweep nor the subagent brief reads code for maintainability, and only `API9` and `LLM09` map
there - so expect it to be **not assessed on every run**. The axis is kept rather than deleted
so a reader comparing against a reference audit format still finds the row, with the reason it
is empty stated in its reading.

**The scorecard is not the gate.** One critical finding costs one axis three points and can
leave that axis above the threshold, while the gate fails outright on one open critical. The
gate is the ship decision; the scorecard shows where the debt sits. Both are printed.

A finding's axis is decided by `class:secret`, then `category`, then `finding_class`, then
`kill_chain` - first match wins. The category is the only field that names the control family
that failed; a kill chain names what the attacker *gets*, which is a consequence, so it decides
only findings whose category is unmapped. Within the resolved axis the sub is decided by
`finding_class`, then `category`, then `kill_chain` - the reverse, because inside one axis the
class is the more specific statement. Annex A prints every term.

## 6. Figures

Six figures, numbered in emission order. One implementation each: a
`reportlab.graphics.Drawing` that the PDF draws natively and the HTML exports through
`renderSVG`.

| Figure | Chart | Shows |
|---|---|---|
| 1 | `axis_radar` | The **assessed** axes against the 5.0 threshold ring; a not-assessed axis has no spoke and reads `n/a` in the legend |
| 2 | `severity_bars` | Finding distribution by severity |
| 3 | `class_bars` | Findings by class - how much of the set is raw scanner output |
| 4 | `risk_scatter` | Exploitability against business impact, bubble area ∝ finding count |
| 5 | `sub_bars` | Every **assessed** sub-characteristic; the fallback table lists all eighteen with their state |
| 6 | `control_status` | The eight gate controls, fail-closed |

**reportlab is an optional extra.** `pip install 'kavach-audit[report]'`. Without it:

- `--format md`, `json`, `sarif` are unaffected.
- `--format html` renders every figure as its data table plus a one-line note naming the
  install command. The HTML report never fails because reportlab is missing.
- `--format pdf` raises `ReportlabMissing` carrying the exact install command - not a
  traceback.

`renderPM` is never imported: it needs PIL. `renderSVG` builds its document with the standard
library only, which is the reason it was chosen.

One PDF-only constraint: a page is a fixed height and a table cell cannot split across one,
so every table cell and every field of a boxed finding is clipped at 1,200 characters with a
visible `… (truncated; full text in reports/report.json)`. Markdown and HTML clip nothing.
If a write-up needs more than that, it belongs in `findings/<id>-<slug>/report.md`.

## 7. Annex C - reproducing the figures

Every quantified claim carries the command that recomputes it. Populated from the scanners
that actually produced a finding in this run, plus the `kavach` verbs:

```
kavach render --out .kavach --format json | jq '.gate.counts'      # §3 severity counts
kavach render --out .kavach --format json | jq '.class_counts'     # §1.4 class counts
kavach render --out .kavach --format json | jq '.scorecard'        # Annex A arithmetic
kavach gate   --out .kavach --controls .kavach/controls.json       # §13 the eight controls
```

An assertion is worth what would refute it. Do not write a number into the narrative that
Annex C cannot reproduce.

## 8. The PDF asymmetry

`render()` returns the document as a `str` for every format **except `pdf`**. A PDF is bytes,
so `pdf.render()` writes the file named by `meta["output"]` and returns a one-line summary:

```
KAVACH PDF report → .kavach/reports/audit-report.pdf (23 page(s), 187,432 bytes)
```

Print that line as progress; do not treat it as the document. The PDF carries a running
header, a footer with the target, date and page number, and a Contents page with real page
numbers (built by `multiBuild`, so the numbers are the ones the reader will turn to).
