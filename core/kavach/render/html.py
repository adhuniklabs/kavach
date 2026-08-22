"""Self-contained HTML audit report - one file, no external asset, no dependency.

Same structure and same numbers as the markdown and PDF renderings, because all three read
:class:`~kavach.render.model.AuditReport`. Charts are inlined as SVG exported from the one
reportlab ``Drawing`` per figure; when reportlab is not installed every figure degrades to
the data table behind it plus a one-line note, and the document still renders. That is the
hard requirement - the HTML report must never fail because an optional extra is missing.

Styled for screen, dark mode and print from the same sheet.
"""

from __future__ import annotations

import html as _h

from ..finding import Confidence, Finding
from ..score import GATE_CONTROLS, GateResult
from ..scoring import ACCEPTABLE, BASE, FLOOR
from . import charts, model
from .model import NOT_SUPPLIED, SEVERITY_ORDER

_CSS = """
:root{--ink:#1f2933;--muted:#616e7c;--rule:#d3d9e2;--paper:#ffffff;--panel:#f7f9fc;
--accent:#1d4ed8;--good:#2e7d32;--bad:#b00020;--code:#eef1f6}
@media (prefers-color-scheme:dark){:root{--ink:#e4e7eb;--muted:#9aa5b1;--rule:#3e4c59;
--paper:#12181f;--panel:#1a212b;--accent:#7f9cf5;--good:#68d391;--bad:#fc8181;--code:#1f2731}}
*{box-sizing:border-box}
body{font:15px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;
margin:0;color:var(--ink);background:var(--paper)}
main{max-width:960px;margin:0 auto;padding:3rem 1.5rem 6rem}
h1{font-size:2.1rem;line-height:1.2;margin:0 0 .3rem}
h2{font-size:1.4rem;margin:3rem 0 .8rem;padding-bottom:.35rem;border-bottom:2px solid var(--rule)}
h3{font-size:1.08rem;margin:2rem 0 .6rem}
h4{font-size:.98rem;margin:0 0 .4rem}
p,ul,ol{margin:.6rem 0}
a{color:var(--accent)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:.1rem .32rem;border-radius:3px;font-size:.86em}
pre{background:var(--code);padding:.7rem .85rem;border-radius:5px;overflow-x:auto;
font-size:.82rem;line-height:1.5;border-left:3px solid var(--rule)}
table{border-collapse:collapse;width:100%;margin:.9rem 0;font-size:.86rem}
th,td{border:1px solid var(--rule);padding:.42rem .6rem;text-align:left;vertical-align:top}
th{background:var(--panel);font-weight:600}
.tablewrap{overflow-x:auto}
.cover{border:1px solid var(--rule);border-radius:6px;padding:1.4rem 1.6rem;background:var(--panel)}
.cover .kicker{color:var(--muted);font-size:.85rem;letter-spacing:.04em;text-transform:uppercase}
.cover table{margin:1.1rem 0 0;background:var(--paper)}
.chip{display:inline-block;color:#fff;padding:.1rem .5rem;border-radius:999px;
font-size:.7rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;
vertical-align:.08em}
.verdict{font-weight:700;font-size:1.1rem}
.pass{color:var(--good)} .fail{color:var(--bad)}
.finding{border:1px solid var(--rule);border-left:4px solid var(--rule);border-radius:5px;
padding:.9rem 1.1rem;margin:1.1rem 0;background:var(--panel);break-inside:avoid}
.finding.critical{border-left-color:#b00020} .finding.high{border-left-color:#d84315}
.finding.medium{border-left-color:#f9a825} .finding.low{border-left-color:#2e7d32}
.finding .facts{color:var(--muted);font-size:.8rem;margin:.15rem 0 .7rem}
.finding dl{margin:.5rem 0;display:grid;grid-template-columns:auto 1fr;gap:.2rem .7rem}
.finding dt{font-weight:600;color:var(--muted);font-size:.82rem}
.finding dd{margin:0;font-size:.9rem}
.figure{margin:1.3rem 0;break-inside:avoid}
.figure svg{max-width:100%;height:auto;display:block;background:#fff;border:1px solid var(--rule);
border-radius:5px;padding:.5rem}
.figure figcaption{color:var(--muted);font-size:.82rem;margin-top:.45rem}
.note{color:var(--muted);font-size:.82rem;border-left:3px solid var(--rule);
padding:.2rem 0 .2rem .7rem;margin:.6rem 0}
.contents ol{columns:2;column-gap:2.5rem;padding-left:1.2rem}
.contents li{break-inside:avoid;margin:.15rem 0}
.limits li{margin:.35rem 0}
.arith td:nth-child(2){text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.unsupplied{color:var(--muted);font-style:italic}
@media print{
:root{--ink:#111;--muted:#555;--rule:#bbb;--paper:#fff;--panel:#f6f6f6;--code:#f1f1f1}
body{font-size:10.5pt}
main{max-width:none;padding:0}
h2{page-break-before:always;page-break-after:avoid}
h2:first-of-type{page-break-before:avoid}
h3,h4{page-break-after:avoid}
.finding,.figure,table{page-break-inside:avoid}
@page{margin:18mm 16mm}
}
"""


def render(findings: list[Finding], recon: dict, gate: GateResult, meta: dict) -> str:
    report = model.build(findings, recon, gate, meta)
    return render_report(report)


def render_report(report) -> str:
    out: list[str] = []
    w = out.append
    sections = {s.key: s for s in model.outline(report)}
    target = _h.escape(report.meta.get("target") or "unspecified target")

    w("<!doctype html>")
    w('<html lang="en"><head><meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width,initial-scale=1">')
    w(f"<title>KAVACH Security Report - {target}</title>")
    w(f"<style>{_CSS}</style>")
    w("</head><body><main>")

    _cover(w, report)
    _contents(w, report)
    _glossary(w, sections["glossary"])
    _executive_summary(w, report, sections["exec"])
    _scope(w, report, sections["scope"])
    _scoring(w, report, sections["scoring"])
    _frameworks(w, report, sections["frameworks"])
    _anchor_section(w, report, sections["attack-trees"], "attack-trees")
    for chapter in report.chapters:
        _chapter(w, report, sections[f"chapter:{chapter.key}"], chapter)
    _remediation(w, report, sections["remediation"])
    _verdict(w, report, sections["verdict"])
    _residual(w, report, sections["residual"])
    _anchor_section(w, report, sections["limits"], "limits")
    _annex_a(w, report, sections["annex-a"])
    _annex_b(w, report, sections["annex-b"])
    _annex_c(w, report, sections["annex-c"])
    _appendix_b(w, report, sections["appendix-b"])

    w("</main></body></html>")
    return "\n".join(out)


# --------------------------------------------------------------------------- helpers


def _slug(key: str) -> str:
    return "s-" + key.replace(":", "-")


def _h2(w, section) -> None:
    w(f'<h2 id="{_slug(section.key)}">{_h.escape(section.heading)}</h2>')


def _table(w, headers: list, rows: list, css: str = "") -> None:
    cls = f' class="{css}"' if css else ""
    w('<div class="tablewrap">')
    w(f"<table{cls}><thead><tr>"
      + "".join(f"<th>{_h.escape(str(x))}</th>" for x in headers)
      + "</tr></thead><tbody>")
    for row in rows:
        w("<tr>" + "".join(f"<td>{_cell(c)}</td>" for c in row) + "</tr>")
    w("</tbody></table></div>")


def _cell(value) -> str:
    text = str(value)
    if not text:
        return "&mdash;"
    if text.startswith("`") and text.endswith("`") and len(text) > 2:
        return f"<code>{_h.escape(text[1:-1])}</code>"
    return _h.escape(text)


def _chip(severity: str) -> str:
    return (f'<span class="chip" style="background:{charts.SEVERITY_COLOR[severity]}">'
            f"{_h.escape(severity)}</span>")


def _anchor(w, key: str, report) -> None:
    w(f"<!-- KAVACH:{key} -->")
    text = report.anchor_text(key)
    if not text:
        w(f'<p class="unsupplied">{_h.escape(NOT_SUPPLIED.strip("_"))}</p>')
        return
    for para in [p.strip() for p in text.split("\n\n") if p.strip()]:
        w(f"<p>{_h.escape(para)}</p>")


def _anchor_section(w, report, section, key: str) -> None:
    _h2(w, section)
    _anchor(w, key, report)


def _figure(w, name: str, report) -> None:
    fig = charts.FIGURE_NUMBER[name]
    d = charts.data(name, report)
    caption = (f"<strong>Figure {fig} &mdash; {_h.escape(charts.CHART_TITLES[name])}.</strong> "
               f"{_h.escape(d.caption)}")
    svg = charts.svg(name, report)
    w('<figure class="figure">')
    if svg:
        w(svg)
        w(f"<figcaption>{caption}</figcaption>")
    else:
        w(f"<figcaption>{caption}</figcaption>")
        _table(w, d.headers, d.rows)
        w(f'<p class="note">Figure {fig} is shown as its data table: reportlab is not '
          f"installed, so no vector figure could be drawn. "
          f"<code>{_h.escape(charts.PIP_HINT)}</code> enables the plotted version.</p>")
    w("</figure>")


def _loc(f: Finding) -> str:
    return ", ".join(f"<code>{_h.escape(l.file)}:{l.line}</code>" if l.line
                     else f"<code>{_h.escape(l.file)}</code>"
                     for l in f.locations) or "&mdash;"


def _loc_text(f: Finding) -> str:
    return ", ".join(f"{l.file}:{l.line}" if l.line else l.file for l in f.locations)


# --------------------------------------------------------------------------- front matter


def _cover(w, report) -> None:
    m = report.meta
    passed = report.gate.passed
    verdict = "PRODUCTION-READY" if passed else "NOT PRODUCTION-READY"
    conclusion = (", ".join(report.gate.blockers[:3])
                  + (f" and {len(report.gate.blockers) - 3} further blocker(s)"
                     if len(report.gate.blockers) > 3 else "")) if report.gate.blockers else \
        "no open critical or high finding and every control proven"
    scorecard = report.scorecard.summary

    w('<section class="cover">')
    w('<p class="kicker">Adversarial application security audit</p>')
    w("<h1>KAVACH Security Report</h1>")
    w(f'<p class="kicker">Arvind Saraf (VAJRA) &middot; KAVACH Engine '
      f"{_h.escape(m.get('version') or 'dev')}</p>")
    _table(w, ["Field", "Value"], [
        ["Scope", f"`{m.get('target') or 'unspecified target'}`"],
        ["Volume", m.get("volume", "")],
        ["Date", m.get("date") or "not recorded"],
        ["Commit", m.get("commit") or "not recorded"],
        ["Method", "Deterministic recon and scanner sweep, adversarial subagent review, "
                   "reconciliation"
                   + (f" ({m['mode']} mode)" if m.get("mode") else "")],
        ["Reference standards", "; ".join(m.get("reference_standards") or [])],
        ["Scorecard", scorecard],
        ["Conclusion", f"{verdict} - {conclusion}"],
    ])
    w(f'<p class="verdict {"pass" if passed else "fail"}">{verdict}</p>')
    w("</section>")


def _contents(w, report) -> None:
    w('<section class="contents">')
    w('<h2 id="s-contents">Contents</h2>')
    w("<ol>")
    for s in model.outline(report):
        if s.key == "contents":
            continue
        w(f'<li><a href="#{_slug(s.key)}">{_h.escape(s.heading)}</a></li>')
    w("</ol>")
    w('<p class="note">Page numbers are carried by the PDF rendering '
      "(<code>kavach render --format pdf</code>); this document is paginated by the "
      "browser at print time.</p>")
    w("</section>")


def _glossary(w, section) -> None:
    _h2(w, section)
    _table(w, ["Term", "Meaning"], [[t, m] for t, m in model.GLOSSARY])


# --------------------------------------------------------------------------- body


def _executive_summary(w, report, section) -> None:
    _h2(w, section)
    _anchor(w, "exec-summary", report)

    passed = report.gate.passed
    w(f"<h3>{section.number}.1 Verdict</h3>")
    w(f'<p class="verdict {"pass" if passed else "fail"}">'
      f'{"PRODUCTION-READY" if passed else "NOT PRODUCTION-READY"}</p>')
    if report.gate.blockers:
        w("<ul>" + "".join(f"<li>{_h.escape(b)}</li>" for b in report.gate.blockers) + "</ul>")

    w(f"<h3>{section.number}.2 Scorecard</h3>")
    _table(w, ["Axis", f"Score / {BASE:.0f}", "Reading"],
           [[a.label, a.score_text, a.reading] for a in report.axes])
    _figure(w, "axis_radar", report)

    w(f"<h3>{section.number}.3 Risk dashboard</h3>")
    _table(w, ["Severity", "Count"],
           [[s.value.capitalize(), report.counts.get(s.value, 0)] for s in SEVERITY_ORDER])
    _figure(w, "severity_bars", report)

    w(f"<h3>{section.number}.4 Finding classes</h3>")
    _figure(w, "class_bars", report)
    _figure(w, "risk_scatter", report)

    w(f"<h3>{section.number}.5 Attacker matrix</h3>")
    _anchor(w, "attacker-matrix", report)


def _scope(w, report, section) -> None:
    m = report.meta
    _h2(w, section)
    w(f"<h3>{section.number}.1 Scope</h3>")
    w(f"<p>Target <code>{_h.escape(m.get('target') or 'unspecified')}</code> at commit "
      f"{_h.escape(m.get('commit') or 'unrecorded')}. {_h.escape(m.get('volume', ''))}.</p>")
    stack = [(label, report.recon.get(key) or []) for label, key in
             [("Languages", "languages"), ("Frameworks", "frameworks"),
              ("Datastores", "datastores"), ("ORMs", "orms"), ("Auth", "auth"),
              ("LLM providers", "llm_providers"),
              ("Payment processors", "payment_processors"), ("Cloud", "cloud")]]
    stack = [(label, vals) for label, vals in stack if vals]
    if stack:
        _table(w, ["Layer", "Detected"], [[label, ", ".join(v)] for label, v in stack])

    w(f"<h3>{section.number}.2 Method</h3>")
    w("<ol>")
    for step in ("Deterministic recon: every file walked and fingerprinted, no model in "
                 "the loop.",
                 "Containerised scanner sweep, deduplicated into the canonical finding model.",
                 "Triage into finding classes; scanner classes roll up, reasoned findings "
                 "promote.",
                 "Adversarial subagent review of the promoted set against six attacker "
                 "kill chains.",
                 "Reconciliation into one finding set, then this render. The score is "
                 "arithmetic over that set."):
        w(f"<li>{_h.escape(step)}</li>")
    w("</ol>")
    w("<p>This is static analysis plus architecture and code review. It is not a live "
      "penetration test; see the residual-risk section.</p>")

    w(f"<h3>{section.number}.3 Limits of this run</h3>")
    if report.limits:
        w("<p>Every gap below is a claim this report does <strong>not</strong> make:</p>")
        w('<ul class="limits">'
          + "".join(f"<li>{_h.escape(x)}</li>" for x in report.limits) + "</ul>")
    else:
        w("<p>No dispatch was shed, every promoted finding carries a proof of concept and a "
          "write-up, and no finding is left at suspected confidence.</p>")


def _scoring(w, report, section) -> None:
    _h2(w, section)
    w(f"<p>{_h.escape(report.scorecard.method)}</p>")
    w("<p>The scorecard is not the gate. A single critical finding costs one axis three "
      "points and can still leave that axis above the threshold, while the gate fails "
      "outright on one open critical. The gate is the ship decision; the scorecard shows "
      "where the debt sits.</p>")
    w(f"<p>{_h.escape(model.FAIL_CLOSED_NOTE)}</p>")
    w(f"<h3>{section.number}.1 Axes</h3>")
    _table(w, ["Axis", f"Score / {BASE:.0f}", f"Clears {ACCEPTABLE:.1f}", "Findings mapped"],
           [[a.label, a.score_text, a.clears_text,
             len(report.chapter(a.key).findings)] for a in report.axes])
    w(f"<h3>{section.number}.2 Sub-characteristics</h3>")
    _figure(w, "sub_bars", report)


def _frameworks(w, report, section) -> None:
    _h2(w, section)
    w("<p>One row per category present in the finding set. An empty cell means the mapping "
      "is not derivable from the finding&rsquo;s category or references &mdash; it does not "
      "mean the requirement is met.</p>")
    if report.frameworks:
        _table(w, ["Category", "Findings", "OWASP", "ASVS 4.0", "CWE", "GDPR"],
               [list(row) for row in report.frameworks])
    else:
        w('<p class="unsupplied">No findings, so nothing to map.</p>')


def _chapter(w, report, section, chapter) -> None:
    _h2(w, section)
    w(f"<p>{_h.escape(chapter.narrative)}</p>")
    if not chapter.findings:
        w('<p class="unsupplied">No finding maps to this axis.</p>')
        return

    tiers = model.tier(chapter.findings)
    n = 0

    if tiers["full"]:
        n += 1
        w(f"<h3>{section.number}.{n} Critical and high findings "
          f"({len(tiers['full'])})</h3>")
        for f in tiers["full"]:
            _finding_box(w, report, f)
    if tiers["compact"]:
        n += 1
        w(f"<h3>{section.number}.{n} Medium findings ({len(tiers['compact'])})</h3>")
        _table(w, ["Ref", "Title", "Location", "Category", "Source"],
               [[report.ref(f), f.title, f"`{_loc_text(f)}`", f.category or "",
                 f.source or ""] for f in tiers["compact"]])
    if tiers["rolled"]:
        n += 1
        w(f"<h3>{section.number}.{n} Rolled-up scanner findings "
          f"({len(tiers['rolled'])})</h3>")
        w("<p>Scanner rows of an aggregate class. They are tabled rather than written up "
          "individually so a rolled-up advisory is never mistaken for a cold-verified "
          "finding; the full set lives in the aggregate&rsquo;s <code>rows.json</code>.</p>")
        _table(w, ["Severity", "Class", "Title", "Advisory", "Location"],
               [[f.severity.value, f.finding_class, f.title, f.rule_id or "",
                 f"`{_loc_text(f)}`"] for f in tiers["rolled"]])
    if tiers["counted"]:
        n += 1
        w(f"<h3>{section.number}.{n} Low and informational findings "
          f"({len(tiers['counted'])})</h3>")
        by_category: dict = {}
        for f in tiers["counted"]:
            key = f.category or "uncategorized"
            by_category[key] = by_category.get(key, 0) + 1
        _table(w, ["Category", "Count"],
               [[c, n_] for c, n_ in sorted(by_category.items(),
                                            key=lambda kv: (-kv[1], kv[0]))])
        w("<p>Each of these is carried in full in <code>reports/report.json</code> and "
          "<code>reports/report.sarif</code>; they are counted rather than narrated here so "
          "the deliverable stays readable.</p>")


def _finding_box(w, report, f: Finding) -> None:
    cvss = f" &middot; CVSS {f.cvss_score:.1f}" if f.cvss_score else ""
    w(f'<article class="finding {f.severity.value}">')
    w(f"<h4>[{_h.escape(report.ref(f))}] {_h.escape(f.title)} {_chip(f.severity.value)}</h4>")
    w(f'<p class="facts">{_h.escape(f.confidence.value)}{cvss} &middot; class '
      f"<code>{_h.escape(f.finding_class or 'unclassified')}</code> &middot; source "
      f"<code>{_h.escape(f.source or 'unknown')}</code> &middot; "
      f"{_h.escape(f.category or '-')}"
      + (f" &middot; rule <code>{_h.escape(f.rule_id)}</code>" if f.rule_id else "")
      + f" &middot; <code>{_h.escape(f.id)}</code></p>")
    w(f"<dl><dt>Location</dt><dd>{_loc(f)}</dd>")
    if f.what_it_is:
        w(f"<dt>What it is</dt><dd>{_h.escape(f.what_it_is)}</dd>")
    if f.how_exploited:
        w(f"<dt>How it is exploited</dt><dd>{_h.escape(f.how_exploited)}</dd>")
    w("</dl>")
    snippet = next((l.snippet for l in f.locations if l.snippet), "")
    if snippet:
        w(f"<pre>{_h.escape(snippet.rstrip())}</pre>")
    w(f"<dl><dt>Consequence</dt><dd>{_h.escape(f.business_impact or f.how_exploited or 'Not stated by the reconciler.')}</dd>")
    w(f"<dt>Proposed fix</dt><dd>{_h.escape(f.remediation or 'Not stated by the reconciler.')}</dd>")
    if f.fix_impact:
        w(f"<dt>Impact of the fix</dt><dd>{_h.escape(f.fix_impact)}</dd>")
    if f.effort:
        w(f"<dt>Effort</dt><dd>{_h.escape(f.effort)}</dd>")
    if f.kill_chain:
        w(f"<dt>Kill chain</dt><dd>{_h.escape(f.kill_chain)}</dd>")
    if f.references:
        w("<dt>References</dt><dd>"
          + ", ".join(_h.escape(r) for r in f.references) + "</dd>")
    w("</dl></article>")


def _remediation(w, report, section) -> None:
    _h2(w, section)
    _anchor(w, "roadmap", report)
    w("<p>The three horizons below are derived from the finding set, not from prose: "
      "everything critical or high blocks production traffic, money-path findings block the "
      "first paid user, and the rest is the hardening backlog.</p>")
    if report.remediation:
        _table(w, ["#", "Horizon", "Action", "Addresses", "Severity", "Effort"],
               [[r["n"], r["horizon"], r["action"],
                 ", ".join(r["addresses"][:8]) + (
                     f" (+{len(r['addresses']) - 8})" if len(r["addresses"]) > 8 else ""),
                 r["severity"], r["effort"]] for r in report.remediation])
    else:
        w('<p class="unsupplied">Nothing to remediate.</p>')


def _verdict(w, report, section) -> None:
    passed = report.gate.passed
    _h2(w, section)
    w(f'<p class="verdict {"pass" if passed else "fail"}">'
      f'{"PRODUCTION-READY" if passed else "NOT PRODUCTION-READY"}</p>')
    _table(w, ["Control", "Status"],
           [[c, "proven" if report.controls.get(c) is True else "unproven"]
            for c in GATE_CONTROLS])
    _figure(w, "control_status", report)
    if report.gate.blockers:
        w("<p>Blockers:</p><ul>"
          + "".join(f"<li>{_h.escape(b)}</li>" for b in report.gate.blockers) + "</ul>")
    w("<p>Certification: a green gate certifies this codebase and its architecture at the "
      "commit named on the cover page. It does not certify the running deployment.</p>")


def _residual(w, report, section) -> None:
    _h2(w, section)
    _anchor(w, "residual", report)
    suspected = [f for f in report.findings if f.confidence == Confidence.SUSPECTED]
    if suspected:
        w(f"<p>{len(suspected)} finding(s) are marked suspected and need a runtime test "
          "before external sign-off.</p>")
        _table(w, ["Ref", "Title", "Category", "Source"],
               [[report.ref(f), f.title, f.category or "", f.source or ""]
                for f in suspected[:40]])
        if len(suspected) > 40:
            w(f'<p class="note">{len(suspected) - 40} further suspected finding(s) in '
              "<code>reports/report.json</code>.</p>")


def _annex_a(w, report, section) -> None:
    _h2(w, section)
    w("<p>The arithmetic behind every axis, term by term. Sum the effects, clamp to "
      f"[{FLOOR:.1f}, {BASE:.1f}], round to one decimal &mdash; that is the score. No "
      "evaluator override.</p>")
    for axis in report.axes:
        rows = report.scorecard.axis_rows(axis.key)
        if not rows:
            w(f"<h3>{_h.escape(axis.label)} &mdash; {axis.score_text}</h3>")
            w(f'<p class="unsupplied">{_h.escape(model.NOT_ASSESSED_NOTE)}</p>')
            continue
        w(f"<h3>{_h.escape(axis.label)} &mdash; {axis.score:.1f} / {BASE:.0f}</h3>")
        _table(w, ["Item", "Effect", "Justification"],
               [[r.item, f"{r.effect:+.2f}", r.justification] for r in rows], css="arith")


def _annex_b(w, report, section) -> None:
    _h2(w, section)
    if report.promoted:
        w("<p>Promoted finding directories:</p>")
        _table(w, ["Ref", "Directory", "Severity", "Kind"],
               [[p["display_id"], f"`{p['dir']}`", p["severity"],
                 f"aggregate of {p['member_count']}" if p["is_aggregate"] else "individual"]
                for p in report.promoted])
    else:
        w('<p class="unsupplied">No promoted finding directory was found in this audit '
          "directory.</p>")
    w("<p>Full inventory, every severity:</p>")
    if report.findings:
        _table(w, ["Ref", "Severity", "Class", "Category", "Title", "Source"],
               [[report.ref(f), f.severity.value, f.finding_class or "", f.category or "",
                 f.title, f.source or ""] for f in report.findings])
    else:
        w('<p class="unsupplied">No findings.</p>')


def _annex_c(w, report, section) -> None:
    _h2(w, section)
    w("<p>Every quantified claim in this report is recomputable. Run from the audited "
      "repository root, with the audit directory at <code>.kavach</code>:</p>")
    _table(w, ["Claim", "Command"],
           [[caption, f"`{command}`"] for caption, command in report.figure_commands])


def _appendix_b(w, report, section) -> None:
    totals = report.recon.get("totals") or {}
    _h2(w, section)
    w(f"<p>Total files walked: <strong>{totals.get('files', 0)}</strong> "
      f"({totals.get('code_files', 0)} code files). Full file manifest emitted alongside "
      "this report as <code>file-manifest.txt</code>.</p>")
