"""final-audit-report.md - the deterministic report backbone.

Section numbering is owned here (see :func:`model.outline`), so the shipped report can no
longer come out as "§1, §2, §0, §5, §7". The six anchors
``skill/references/report-template.md`` documents are emitted in a fixed order, and each one
renders either the reconciler's prose or an explicit "not supplied" line - never a silently
missing section.

The detailed findings are tiered inside each axis chapter by :func:`model.tier`: critical and
high get the full block, medium a compact table, scanner-class rows a rolled-up table, low and
informational a count by category with a pointer to ``report.json``. Markdown is a text format,
so every figure renders as its caption plus the data table behind it - the same numbers the
HTML and PDF plot, and no dependency on reportlab.
"""

from __future__ import annotations

from ..finding import Confidence, Finding
from ..score import GATE_CONTROLS, GateResult
from ..scoring import ACCEPTABLE, BASE, FLOOR
from . import charts, model
from .model import NOT_SUPPLIED, SEVERITY_ORDER


def render(findings: list[Finding], recon: dict, gate: GateResult, meta: dict) -> str:
    report = model.build(findings, recon, gate, meta)
    return render_report(report)


def render_report(report) -> str:
    out: list[str] = []
    w = out.append
    sections = {s.key: s for s in model.outline(report)}

    _cover(w, report)
    _contents(w, report)
    _glossary(w, sections["glossary"])
    _executive_summary(w, report, sections["exec"])
    _scope(w, report, sections["scope"])
    _scoring(w, report, sections["scoring"])
    _frameworks(w, report, sections["frameworks"])
    _attack_trees(w, report, sections["attack-trees"])
    for chapter in report.chapters:
        _chapter(w, report, sections[f"chapter:{chapter.key}"], chapter)
    _remediation(w, report, sections["remediation"])
    _verdict(w, report, sections["verdict"])
    _residual(w, report, sections["residual"])
    _limits(w, report, sections["limits"])
    _annex_a(w, report)
    _annex_b(w, report)
    _annex_c(w, report)
    _appendix_b(w, report)
    return "\n".join(out)


# --------------------------------------------------------------------------- helpers


def _table(w, headers: list, rows: list) -> None:
    w("| " + " | ".join(headers) + " |")
    w("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        w("| " + " | ".join(_cell(c) for c in row) + " |")
    w("")


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ") or "-"


def _anchor(w, key: str, report) -> None:
    w(f"<!-- KAVACH:{key} -->")
    w("")
    w(report.anchor_text(key) or NOT_SUPPLIED)
    w("")


def _figure(w, name: str, report) -> None:
    fig = charts.FIGURE_NUMBER[name]
    d = charts.data(name, report)
    w(f"**Figure {fig} - {charts.CHART_TITLES[name]}.** {d.caption}")
    w("")
    _table(w, d.headers, d.rows)


def _loc(f: Finding) -> str:
    return ", ".join(f"`{l.file}:{l.line}`" if l.line else f"`{l.file}`"
                     for l in f.locations) or "-"


# --------------------------------------------------------------------------- front matter


def _cover(w, report) -> None:
    m = report.meta
    verdict = "PRODUCTION-READY" if report.gate.passed else "NOT PRODUCTION-READY"
    w("# KAVACH Security Report")
    w("")
    w("Adversarial application security audit · Arvind Saraf (VAJRA) · KAVACH Engine "
      f"{m.get('version') or 'dev'}")
    w("")
    _table(w, ["Field", "Value"], [
        ["Scope", f"`{m.get('target') or 'unspecified target'}`"],
        ["Volume", m.get("volume", "")],
        ["Date", m.get("date") or "not recorded"],
        ["Commit", m.get("commit") or "not recorded"],
        ["Method", f"Deterministic recon and scanner sweep, adversarial subagent review, "
                   f"reconciliation{' (' + m['mode'] + ' mode)' if m.get('mode') else ''}"],
        ["Reference standards", "; ".join(m.get("reference_standards") or [])],
        ["Scorecard", report.scorecard.summary],
        ["Conclusion", f"**{verdict}** - "
                       + (", ".join(report.gate.blockers[:3]) + (
                           f" and {len(report.gate.blockers) - 3} further blocker(s)"
                           if len(report.gate.blockers) > 3 else "")
                          if report.gate.blockers else
                          "no open critical or high finding and every control proven")],
    ])


def _contents(w, report) -> None:
    w("## Contents")
    w("")
    for s in model.outline(report):
        if s.key == "contents":
            continue
        w(f"- {s.heading}")
    w("")
    w("_Page numbers are carried by the PDF rendering (`kavach render --format pdf`); "
      "markdown has no pagination._")
    w("")


def _glossary(w, section) -> None:
    w(f"## {section.heading}")
    w("")
    _table(w, ["Term", "Meaning"], [[term, meaning] for term, meaning in model.GLOSSARY])


# --------------------------------------------------------------------------- body


def _executive_summary(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    _anchor(w, "exec-summary", report)

    verdict = "✅ PRODUCTION-READY" if report.gate.passed else "⛔ NOT PRODUCTION-READY"
    w(f"### {section.number}.1 Verdict")
    w("")
    w(f"**{verdict}**")
    if report.gate.blockers:
        w("")
        w("Blockers:")
        for b in report.gate.blockers:
            w(f"- {b}")
    w("")

    w(f"### {section.number}.2 Scorecard")
    w("")
    _table(w, ["Axis", f"Score / {BASE:.0f}", "Reading"],
           [[a.label, a.score_text, a.reading] for a in report.axes])
    w(f"Overall: **{report.scorecard.summary}**. "
      f"An axis is acceptable at {ACCEPTABLE:.1f} or above. An axis with no mapped finding and "
      f"no proving control is not assessed rather than scored, and is left out of the figure.")
    w("")
    _figure(w, "axis_radar", report)

    w(f"### {section.number}.3 Risk dashboard")
    w("")
    _table(w, ["Severity", "Count"],
           [[s.value.capitalize(), report.counts.get(s.value, 0)] for s in SEVERITY_ORDER])
    _figure(w, "severity_bars", report)

    w(f"### {section.number}.4 Finding classes")
    w("")
    _figure(w, "class_bars", report)
    _figure(w, "risk_scatter", report)

    w(f"### {section.number}.5 Attacker matrix")
    w("")
    _anchor(w, "attacker-matrix", report)


def _scope(w, report, section) -> None:
    m = report.meta
    w(f"## {section.heading}")
    w("")
    w(f"### {section.number}.1 Scope")
    w("")
    w(f"Target `{m.get('target') or 'unspecified'}` at commit "
      f"{m.get('commit') or 'unrecorded'}. {m.get('volume', '')}.")
    w("")
    for label, key in [("Languages", "languages"), ("Frameworks", "frameworks"),
                       ("Datastores", "datastores"), ("ORMs", "orms"), ("Auth", "auth"),
                       ("LLM providers", "llm_providers"),
                       ("Payment processors", "payment_processors"), ("Cloud", "cloud")]:
        vals = report.recon.get(key) or []
        if vals:
            w(f"- **{label}:** {', '.join(vals)}")
    w("")

    w(f"### {section.number}.2 Method")
    w("")
    w("1. Deterministic recon: every file walked and fingerprinted, no model in the loop.")
    w("2. Containerised scanner sweep, deduplicated into the canonical finding model.")
    w("3. Triage into finding classes; scanner classes roll up, reasoned findings promote.")
    w("4. Adversarial subagent review of the promoted set against six attacker kill chains.")
    w("5. Reconciliation into one finding set, then this render. The score is arithmetic "
      "over that set - see §" + model.section(report, "scoring").number + ".")
    w("")
    w("This is static analysis plus architecture and code review. It is not a live "
      "penetration test; see the residual-risk section.")
    w("")

    w(f"### {section.number}.3 Limits of this run")
    w("")
    if report.limits:
        w("Every gap below is a claim this report does **not** make:")
        w("")
        for limit in report.limits:
            w(f"- {limit}")
    else:
        w("No dispatch was shed, every promoted finding carries a proof of concept and a "
          "write-up, and no finding is left at `suspected` confidence.")
    w("")


def _scoring(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    w(report.scorecard.method)
    w("")
    w("The scorecard is not the gate. A single critical finding costs one axis three points "
      "and can still leave that axis above the threshold, while the gate fails outright on "
      "one open critical. Read them together: the gate is the ship/no-ship decision, the "
      "scorecard is where the debt sits.")
    w("")
    w(model.FAIL_CLOSED_NOTE)
    w("")
    w(f"### {section.number}.1 Axes")
    w("")
    _table(w, ["Axis", f"Score / {BASE:.0f}", f"Clears {ACCEPTABLE:.1f}", "Findings mapped"],
           [[a.label, a.score_text, a.clears_text,
             len(report.chapter(a.key).findings)] for a in report.axes])

    w(f"### {section.number}.2 Sub-characteristics")
    w("")
    _figure(w, "sub_bars", report)


def _frameworks(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    w("One row per category present in the finding set. An empty cell means the mapping is "
      "not derivable from the finding's `category` or `references[]` - it does not mean the "
      "requirement is met.")
    w("")
    if report.frameworks:
        _table(w, ["Category", "Findings", "OWASP", "ASVS 4.0", "CWE", "GDPR"],
               [list(row) for row in report.frameworks])
    else:
        w("_No findings, so nothing to map._")
        w("")


def _attack_trees(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    _anchor(w, "attack-trees", report)


def _chapter(w, report, section, chapter) -> None:
    w(f"## {section.heading}")
    w("")
    w(chapter.narrative)
    w("")
    if not chapter.findings:
        w("_No finding maps to this axis._")
        w("")
        return

    tiers = model.tier(chapter.findings)
    n = 0

    if tiers["full"]:
        n += 1
        w(f"### {section.number}.{n} Critical and high findings ({len(tiers['full'])})")
        w("")
        for f in tiers["full"]:
            _finding_block(w, report, f)
    if tiers["compact"]:
        n += 1
        w(f"### {section.number}.{n} Medium findings ({len(tiers['compact'])})")
        w("")
        _table(w, ["Ref", "Title", "Location", "Category", "Source"],
               [[report.ref(f), f.title, _loc(f), f.category or "-", f.source or "-"]
                for f in tiers["compact"]])
    if tiers["rolled"]:
        n += 1
        w(f"### {section.number}.{n} Rolled-up scanner findings ({len(tiers['rolled'])})")
        w("")
        w("Scanner rows of an aggregate class. They are tabled rather than written up "
          "individually so a rolled-up advisory is never mistaken for a cold-verified "
          "finding; the full set lives in the aggregate's `rows.json`.")
        w("")
        _table(w, ["Severity", "Class", "Title", "Advisory", "Location"],
               [[f.severity.value, f.finding_class, f.title, f.rule_id or "-", _loc(f)]
                for f in tiers["rolled"]])
    if tiers["counted"]:
        n += 1
        w(f"### {section.number}.{n} Low and informational findings "
          f"({len(tiers['counted'])})")
        w("")
        by_category: dict = {}
        for f in tiers["counted"]:
            by_category[f.category or "uncategorized"] = \
                by_category.get(f.category or "uncategorized", 0) + 1
        _table(w, ["Category", "Count"],
               [[c, n] for c, n in sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0]))])
        w("Each of these is carried in full in `reports/report.json` and "
          "`reports/report.sarif`; they are counted rather than narrated here so the "
          "deliverable stays readable.")
        w("")


def _finding_block(w, report, f: Finding) -> None:
    cvss = f" · **CVSS** {f.cvss_score:.1f}" if f.cvss_score else ""
    w(f"#### [{report.ref(f)}] {f.title}")
    w("")
    w(f"`{f.severity.value.upper()}`{cvss} · **{f.confidence.value}** · "
      f"class `{f.finding_class or 'unclassified'}` · source `{f.source or 'unknown'}` · "
      f"category {f.category or '-'}" + (f" · rule `{f.rule_id}`" if f.rule_id else ""))
    w("")
    w(f"- **Location(s):** {_loc(f)}")
    if f.what_it_is:
        w(f"- **What it is:** {f.what_it_is}")
    if f.how_exploited:
        w(f"- **How it is exploited:** {f.how_exploited}")
    w("")
    snippet = next((l.snippet for l in f.locations if l.snippet), "")
    if snippet:
        w("```")
        w(snippet.rstrip())
        w("```")
        w("")
    w(f"**Consequence.** {f.business_impact or f.how_exploited or 'Not stated by the reconciler.'}")
    w("")
    w(f"**Proposed fix.** {f.remediation or 'Not stated by the reconciler.'}")
    if f.fix_impact:
        w("")
        w(f"**Impact of the fix.** {f.fix_impact}")
    tail = []
    if f.effort:
        tail.append(f"**Effort** {f.effort}")
    if f.kill_chain:
        tail.append(f"**Kill chain** {f.kill_chain}")
    if f.references:
        tail.append("**References** " + ", ".join(f.references))
    tail.append(f"**KAVACH id** `{f.id}`")
    w("")
    w(" · ".join(tail))
    w("")


def _remediation(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    _anchor(w, "roadmap", report)
    w("The three horizons below are derived from the finding set, not from prose: "
      "everything critical or high blocks production traffic, money-path findings block the "
      "first paid user, and the rest is the hardening backlog.")
    w("")
    if report.remediation:
        _table(w, ["#", "Horizon", "Action", "Addresses", "Severity", "Effort"],
               [[r["n"], r["horizon"], r["action"],
                 ", ".join(r["addresses"][:8]) + (
                     f" (+{len(r['addresses']) - 8})" if len(r["addresses"]) > 8 else ""),
                 r["severity"], r["effort"] or "-"] for r in report.remediation])
    else:
        w("_Nothing to remediate._")
        w("")


def _verdict(w, report, section) -> None:
    verdict = "✅ PRODUCTION-READY" if report.gate.passed else "⛔ NOT PRODUCTION-READY"
    w(f"## {section.heading}")
    w("")
    w(f"**{verdict}**")
    w("")
    _table(w, ["Control", "Status"],
           [[c, "✅ proven" if report.controls.get(c) is True else "❌ unproven"]
            for c in GATE_CONTROLS])
    _figure(w, "control_status", report)
    if report.gate.blockers:
        w("Blockers:")
        w("")
        for b in report.gate.blockers:
            w(f"- {b}")
        w("")
    w("Certification: a green gate certifies this codebase and its architecture at the "
      f"commit named on the cover page. It does not certify the running deployment.")
    w("")


def _residual(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    _anchor(w, "residual", report)
    suspected = [f for f in report.findings if f.confidence == Confidence.SUSPECTED]
    if suspected:
        w(f"{len(suspected)} finding(s) are marked suspected and need a runtime test before "
          "external sign-off:")
        w("")
        _table(w, ["Ref", "Title", "Category", "Location"],
               [[report.ref(f), f.title, f.category or "-", _loc(f)] for f in suspected[:40]])
        if len(suspected) > 40:
            w(f"_{len(suspected) - 40} further suspected finding(s) in `reports/report.json`._")
            w("")


def _limits(w, report, section) -> None:
    w(f"## {section.heading}")
    w("")
    _anchor(w, "limits", report)


# --------------------------------------------------------------------------- back matter


def _annex_a(w, report) -> None:
    section = model.section(report, "annex-a")
    w(f"## {section.heading}")
    w("")
    w("The arithmetic behind every axis, term by term. Sum the effects, clamp to "
      f"[{FLOOR:.1f}, {BASE:.1f}], round to one decimal - that is the score. No evaluator "
      "override.")
    w("")
    for axis in report.axes:
        rows = report.scorecard.axis_rows(axis.key)
        if not rows:
            w(f"### {axis.label} - {axis.score_text}")
            w("")
            w(model.NOT_ASSESSED_NOTE)
            w("")
            continue
        w(f"### {axis.label} - {axis.score:.1f} / {BASE:.0f}")
        w("")
        _table(w, ["Item", "Effect", "Justification"],
               [[r.item, f"{r.effect:+.2f}", r.justification] for r in rows])
        w(f"Total: **{axis.score:.1f}**")
        w("")


def _annex_b(w, report) -> None:
    section = model.section(report, "annex-b")
    w(f"## {section.heading}")
    w("")
    if report.promoted:
        w("Promoted finding directories:")
        w("")
        _table(w, ["Ref", "Directory", "Severity", "Kind"],
               [[p["display_id"], f"`{p['dir']}`", p["severity"],
                 f"aggregate of {p['member_count']}" if p["is_aggregate"] else "individual"]
                for p in report.promoted])
    else:
        w("No promoted finding directory was found in this audit directory.")
        w("")
    w("Full inventory, every severity:")
    w("")
    if report.findings:
        _table(w, ["Ref", "Severity", "Class", "Category", "Title", "Location", "Source"],
               [[report.ref(f), f.severity.value, f.finding_class or "-", f.category or "-",
                 f.title, _loc(f), f.source or "-"] for f in report.findings])
    else:
        w("_No findings._")
        w("")


def _annex_c(w, report) -> None:
    section = model.section(report, "annex-c")
    w(f"## {section.heading}")
    w("")
    w("Every quantified claim in this report is recomputable. Run from the audited "
      "repository root, with the audit directory at `.kavach`:")
    w("")
    _table(w, ["Claim", "Command"],
           [[caption, f"`{command}`"] for caption, command in report.figure_commands])


def _appendix_b(w, report) -> None:
    section = model.section(report, "appendix-b")
    totals = report.recon.get("totals") or {}
    w(f"## {section.heading}")
    w("")
    w(f"Total files walked: **{totals.get('files', 0)}** "
      f"({totals.get('code_files', 0)} code files). "
      "Full file manifest emitted alongside this report as `file-manifest.txt`.")
    w("")
