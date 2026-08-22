"""Print-ready PDF audit report, built with reportlab Platypus.

**The one asymmetry in the renderer contract.** Every other format in
:data:`kavach.render.RENDERERS` returns the document itself as a ``str``. A PDF is bytes, so
this renderer writes the file to ``meta["output"]`` and returns a one-line human summary of
what it wrote - the path, the page count and the byte size. ``cmd_render`` prints that line
to stderr like any other progress message instead of dumping a binary to stdout. A test
covers the asymmetry so nobody "fixes" it back into a ``str`` of PDF bytes.

reportlab is an optional extra (``pip install 'kavach-audit[report]'``) and is imported
lazily inside :func:`render`, so importing this module on a machine without it costs
nothing. Asking for a PDF without it raises :class:`~kavach.render.charts.ReportlabMissing`,
which carries the install command - never a traceback out of an import.

Only the 14 standard PDF typefaces are used. No font file is registered, no image codec is
touched, and ``renderPM`` is never imported, so this works in a bare VM with nothing but a
pip install behind it.

Contents page numbers are real: ``afterFlowable`` notifies a ``TOCEntry`` for every heading
and ``multiBuild`` runs the layout until the numbers stop moving.

One constraint the text formats do not have: a Platypus table cell cannot split across a
page, so any single field long enough to overflow one would abort the whole build. Every cell
and every field of a boxed finding is therefore clipped at :data:`_FIELD_LIMIT` characters
with a visible pointer to ``reports/report.json``, which carries the untruncated text. The
markdown and HTML renderings clip nothing - they have no pagination to respect.
"""

from __future__ import annotations

import os

from ..finding import Confidence, Finding
from ..score import GATE_CONTROLS
from ..scoring import ACCEPTABLE, BASE, FLOOR
from . import charts, model
from .charts import ReportlabMissing
from .model import NOT_SUPPLIED, SEVERITY_ORDER


def render(findings: list, recon: dict, gate, meta: dict) -> str:
    """Write the PDF named by ``meta["output"]`` and return a one-line summary of the file."""
    if not charts.available():
        raise ReportlabMissing("The PDF report")
    output = (meta or {}).get("output")
    if not output:
        raise ValueError("the pdf renderer writes a file, so it needs a destination: "
                         "pass --output PATH (meta['output'])")
    report = model.build(findings, recon, gate, meta)
    return write(report, output)


def write(report, output: str) -> str:
    """Build the document for an already-assembled :class:`AuditReport`."""
    if not charts.available():
        raise ReportlabMissing("The PDF report")

    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import Frame, PageTemplate

    parent = os.path.dirname(os.path.abspath(output))
    if parent:
        os.makedirs(parent, exist_ok=True)

    styles = _styles()
    doc = _Doc(output, pagesize=A4, title="KAVACH Security Report",
               author="Arvind Saraf (VAJRA) - KAVACH Engine",
               subject=f"Security audit of {report.meta.get('target') or 'unspecified target'}")
    width, height = A4
    frame = Frame(45, 52, width - 90, height - 112, id="body",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=_blank_furniture),
        PageTemplate(id="body", frames=[frame], onPage=_furniture(report)),
    ])

    story = _story(report, styles)
    doc.multiBuild(story)

    size = os.path.getsize(output)
    return (f"KAVACH PDF report → {output} "
            f"({doc.page} page(s), {size:,} bytes)")


# --------------------------------------------------------------------------- document


def _Doc(*args, **kwargs):
    """Build the BaseDocTemplate subclass lazily - its base class lives in reportlab."""
    from reportlab.platypus import BaseDocTemplate

    class KavachDoc(BaseDocTemplate):
        """Notifies a TOCEntry per heading so the Contents page carries real page numbers."""

        def afterFlowable(self, flowable) -> None:
            style = getattr(flowable, "style", None)
            name = getattr(style, "name", "")
            if name not in ("KavachH1", "KavachH2"):
                return
            level = 0 if name == "KavachH1" else 1
            self.notify("TOCEntry", (level, flowable.getPlainText(), self.page))

    return KavachDoc(*args, **kwargs)


def _blank_furniture(canvas, doc) -> None:
    """The cover carries no running header or footer."""
    return None


def _furniture(report):
    """Running header (report title) and footer (target - date - page)."""
    from reportlab.lib.colors import HexColor

    target = report.meta.get("target") or "unspecified target"
    date = report.meta.get("date") or "undated"
    footer = f"{os.path.basename(target.rstrip('/')) or target} audit · {date}"
    rule = HexColor(charts.GRID)
    muted = HexColor(charts.MUTED)

    def draw(canvas, doc) -> None:
        page_width, page_height = canvas._pagesize
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(45, page_height - 40, "KAVACH Security Report")
        canvas.drawRightString(page_width - 45, page_height - 40,
                               report.meta.get("commit") or "")
        canvas.setStrokeColor(rule)
        canvas.setLineWidth(0.4)
        canvas.line(45, page_height - 48, page_width - 45, page_height - 48)
        canvas.line(45, 42, page_width - 45, 42)
        canvas.drawString(45, 32, footer)
        canvas.drawRightString(page_width - 45, 32, f"page {doc.page}")
        canvas.restoreState()

    return draw


def _styles():
    from reportlab.lib.colors import HexColor
    from reportlab.lib.enums import TA_LEFT, TA_RIGHT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    ink = HexColor(charts.INK)
    muted = HexColor(charts.MUTED)
    ss = getSampleStyleSheet()
    add = ss.add

    add(ParagraphStyle("KavachBody", parent=ss["BodyText"], fontName="Helvetica",
                       fontSize=9, leading=13.2, textColor=ink, spaceBefore=0, spaceAfter=6,
                       alignment=TA_LEFT))
    add(ParagraphStyle("KavachSmall", parent=ss["KavachBody"], fontSize=7.6, leading=10.6,
                       textColor=muted))
    add(ParagraphStyle("KavachH1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                       fontSize=15, leading=19, textColor=ink, spaceBefore=2, spaceAfter=8))
    add(ParagraphStyle("KavachH2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                       fontSize=10.5, leading=14, textColor=ink, spaceBefore=10, spaceAfter=4))
    add(ParagraphStyle("KavachH3", parent=ss["Heading3"], fontName="Helvetica-Bold",
                       fontSize=9.2, leading=12.5, textColor=ink, spaceBefore=6, spaceAfter=3))
    add(ParagraphStyle("KavachTitle", parent=ss["Title"], fontName="Helvetica-Bold",
                       fontSize=26, leading=30, textColor=ink, alignment=TA_LEFT,
                       spaceBefore=0, spaceAfter=4))
    add(ParagraphStyle("KavachKicker", parent=ss["KavachSmall"], fontSize=8.4, leading=11.5,
                       textColor=muted, spaceAfter=2))
    add(ParagraphStyle("KavachCell", parent=ss["KavachBody"], fontSize=7.6, leading=10,
                       spaceAfter=0))
    add(ParagraphStyle("KavachCellHead", parent=ss["KavachCell"],
                       fontName="Helvetica-Bold"))
    add(ParagraphStyle("KavachCellNum", parent=ss["KavachCell"], alignment=TA_RIGHT))
    add(ParagraphStyle("KavachCaption", parent=ss["KavachSmall"], spaceBefore=3,
                       spaceAfter=8))
    add(ParagraphStyle("KavachCode", parent=ss["KavachBody"], fontName="Courier",
                       fontSize=7.4, leading=9.6, textColor=ink, backColor=HexColor("#f1f4f9"),
                       borderPadding=4, spaceBefore=3, spaceAfter=5))
    add(ParagraphStyle("KavachUnsupplied", parent=ss["KavachBody"], textColor=muted,
                       fontName="Helvetica-Oblique"))
    add(ParagraphStyle("KavachH1Plain", parent=ss["KavachH1"]))
    add(ParagraphStyle("KavachTOC0", parent=ss["KavachBody"], fontSize=9, leading=15,
                       spaceAfter=0))
    add(ParagraphStyle("KavachTOC1", parent=ss["KavachBody"], fontSize=8, leading=13,
                       leftIndent=16, textColor=muted, spaceAfter=0))
    return ss


# --------------------------------------------------------------------------- flowables


def _esc(text) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _p(text, styles, style: str = "KavachBody"):
    from reportlab.platypus import Paragraph
    return Paragraph(text, styles[style])


def _h1(title: str, styles):
    return _p(_esc(title), styles, "KavachH1")


def _h2(title: str, styles):
    return _p(_esc(title), styles, "KavachH2")


def _table(headers: list, rows: list, styles, widths: list = None, *,
           align_right: list = None):
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import Table, TableStyle

    numeric = set(align_right or [])
    head = [_p(_esc(h), styles, "KavachCellHead") for h in headers]
    # Every cell is clipped: a table cell cannot split across a page, so one unbounded
    # string - a reconciler's remediation paragraph, say - would abort the build.
    body = [[_p(f"<font face='Courier'>{_esc(_clip(str(c)[1:-1]))}</font>" if _is_code(c)
                else _esc(_clip(str(c)) if c else c),
                styles, "KavachCellNum" if i in numeric else "KavachCell")
             for i, c in enumerate(row)] for row in rows]
    table = Table([head] + body, colWidths=widths, repeatRows=1, hAlign="LEFT")
    style = [
        ("GRID", (0, 0), (-1, -1), 0.35, HexColor(charts.GRID)),
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#eef1f6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    table.setStyle(TableStyle(style))
    return table


def _is_code(value) -> bool:
    text = str(value)
    return len(text) > 2 and text.startswith("`") and text.endswith("`")


def _figure(name: str, report, styles) -> list:
    from reportlab.platypus import KeepTogether

    fig = charts.FIGURE_NUMBER[name]
    d = charts.data(name, report)
    drawing = charts.drawing(name, report)
    caption = _p(f"<b>Figure {fig} - {_esc(charts.CHART_TITLES[name])}.</b> {_esc(d.caption)}",
                 styles, "KavachCaption")
    return [KeepTogether([drawing, caption])]


def _anchor(key: str, report, styles) -> list:
    text = report.anchor_text(key)
    if not text:
        return [_p(_esc(NOT_SUPPLIED.strip("_")), styles, "KavachUnsupplied")]
    return [_p(_esc(para), styles) for para in text.split("\n\n") if para.strip()]


def _loc(f: Finding) -> str:
    return ", ".join(f"{l.file}:{l.line}" if l.line else l.file for l in f.locations) or "-"


# A page is a fixed height and a table cell cannot split across one, so a single field long
# enough to overflow a page would abort the whole build. Prose that long belongs in the
# finding's own report.md; the PDF says so and points at the file that has all of it.
_FIELD_LIMIT = 1200
_SNIPPET_LINES = 14


def _clip(text: str, limit: int = _FIELD_LIMIT) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + " … (truncated; full text in reports/report.json)"


def _finding_box(f: Finding, report, styles) -> list:
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import KeepTogether, Table, TableStyle

    inner: list = []
    chip = (f"<font backColor='{charts.SEVERITY_COLOR[f.severity.value]}' "
            f"color='white'> {f.severity.value.upper()} </font>")
    inner.append(_p(f"<b>[{_esc(report.ref(f))}] {_esc(_clip(f.title, 300))}</b> "
                    f"&nbsp;{chip}", styles, "KavachH3"))
    facts = [f.confidence.value]
    if f.cvss_score:
        facts.append(f"CVSS {f.cvss_score:.1f}")
    facts.append(f"class {f.finding_class or 'unclassified'}")
    facts.append(f"source {f.source or 'unknown'}")
    facts.append(f.category or "uncategorized")
    if f.rule_id:
        facts.append(f"rule {f.rule_id}")
    facts.append(f.id)
    inner.append(_p(_esc(_clip(" · ".join(facts), 300)), styles, "KavachSmall"))
    inner.append(_p(f"<b>Location.</b> <font face='Courier'>{_esc(_clip(_loc(f)))}</font>",
                    styles, "KavachCell"))
    if f.what_it_is:
        inner.append(_p(f"<b>What it is.</b> {_esc(_clip(f.what_it_is))}",
                        styles, "KavachCell"))
    if f.how_exploited:
        inner.append(_p(f"<b>How it is exploited.</b> {_esc(_clip(f.how_exploited))}",
                        styles, "KavachCell"))
    snippet = next((l.snippet for l in f.locations if l.snippet), "")
    if snippet:
        lines = "<br/>".join(_esc(_clip(line, 160))
                             for line in snippet.rstrip().splitlines()[:_SNIPPET_LINES])
        inner.append(_p(lines, styles, "KavachCode"))
    inner.append(_p(f"<b>Consequence.</b> {_esc(_clip(f.business_impact or f.how_exploited) or 'Not stated by the reconciler.')}",
                    styles, "KavachCell"))
    inner.append(_p(f"<b>Proposed fix.</b> "
                    f"{_esc(_clip(f.remediation) or 'Not stated by the reconciler.')}",
                    styles, "KavachCell"))
    if f.fix_impact:
        inner.append(_p(f"<b>Impact of the fix.</b> {_esc(_clip(f.fix_impact))}",
                        styles, "KavachCell"))
    tail = []
    if f.effort:
        tail.append(f"effort {f.effort}")
    if f.kill_chain:
        tail.append(f"kill chain {f.kill_chain}")
    if f.references:
        tail.append("references " + ", ".join(f.references))
    if tail:
        inner.append(_p(_esc(_clip(" · ".join(tail))), styles, "KavachSmall"))

    # One row per flowable rather than one cell holding them all: a single-row table cannot
    # split, so a finding whose write-up runs past a page height would abort the whole build
    # with a LayoutError. Row-per-flowable lets the box continue onto the next page.
    box = Table([[flowable] for flowable in inner], colWidths=[505], hAlign="LEFT",
                splitByRow=1, repeatRows=0)
    box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.35, HexColor(charts.GRID)),
        ("LINEBEFORE", (0, 0), (0, -1), 3, HexColor(charts.SEVERITY_COLOR[f.severity.value])),
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#fafbfd")),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
    ]))
    return [KeepTogether([box])]


# --------------------------------------------------------------------------- story


def _story(report, styles) -> list:
    from reportlab.platypus import NextPageTemplate, PageBreak, Spacer

    sections = {s.key: s for s in model.outline(report)}
    story: list = []
    story += _cover(report, styles)
    story += [NextPageTemplate("body"), PageBreak()]
    story += _contents(report, styles)
    story += [PageBreak()]
    story += _glossary(report, styles, sections["glossary"])
    story += _executive_summary(report, styles, sections["exec"])
    story += _scope(report, styles, sections["scope"])
    story += _scoring(report, styles, sections["scoring"])
    story += _frameworks(report, styles, sections["frameworks"])
    story += [_h1(sections["attack-trees"].heading, styles)]
    story += _anchor("attack-trees", report, styles)
    for chapter in report.chapters:
        story += _chapter(report, styles, sections[f"chapter:{chapter.key}"], chapter)
    story += _remediation(report, styles, sections["remediation"])
    story += _verdict(report, styles, sections["verdict"])
    story += _residual(report, styles, sections["residual"])
    story += [_h1(sections["limits"].heading, styles)]
    story += _anchor("limits", report, styles)
    story += [PageBreak()]
    story += _annex_a(report, styles, sections["annex-a"])
    story += [PageBreak()]
    story += _annex_b(report, styles, sections["annex-b"])
    story += [PageBreak()]
    story += _annex_c(report, styles, sections["annex-c"])
    story += _appendix_b(report, styles, sections["appendix-b"])
    story += [Spacer(1, 4)]
    return story


def _cover(report, styles) -> list:
    from reportlab.platypus import Spacer

    m = report.meta
    passed = report.gate.passed
    verdict = "PRODUCTION-READY" if passed else "NOT PRODUCTION-READY"
    conclusion = (", ".join(report.gate.blockers[:3])
                  + (f" and {len(report.gate.blockers) - 3} further blocker(s)"
                     if len(report.gate.blockers) > 3 else "")) if report.gate.blockers else \
        "no open critical or high finding and every control proven"
    colour = charts.GOOD if passed else charts.BAD

    return [
        Spacer(1, 120),
        _p("ADVERSARIAL APPLICATION SECURITY AUDIT", styles, "KavachKicker"),
        _p("KAVACH Security Report", styles, "KavachTitle"),
        _p(_esc(f"Arvind Saraf (VAJRA) · KAVACH Engine {m.get('version') or 'dev'}"),
           styles, "KavachKicker"),
        Spacer(1, 26),
        _table(["Field", "Value"], [
            ["Scope", f"`{m.get('target') or 'unspecified target'}`"],
            ["Volume", m.get("volume", "")],
            ["Date", m.get("date") or "not recorded"],
            ["Commit", m.get("commit") or "not recorded"],
            ["Method", "Deterministic recon and scanner sweep, adversarial subagent review, "
                       "reconciliation"
                       + (f" ({m['mode']} mode)" if m.get("mode") else "")],
            ["Reference standards", "; ".join(m.get("reference_standards") or [])],
            ["Scorecard", report.scorecard.summary],
            ["Conclusion", conclusion],
        ], styles, widths=[110, 395]),
        Spacer(1, 20),
        _p(f"<font size='15' color='{colour}'><b>{verdict}</b></font>", styles),
    ]


def _contents(report, styles) -> list:
    from reportlab.platypus.tableofcontents import TableOfContents

    toc = TableOfContents()
    toc.levelStyles = [styles["KavachTOC0"], styles["KavachTOC1"]]
    toc.dotsMinLevel = 0
    # KavachH1Plain, not KavachH1: the contents page must not list itself.
    return [_p("Contents", styles, "KavachH1Plain"), toc]


def _glossary(report, styles, section) -> list:
    return [_h1(section.heading, styles),
            _table(["Term", "Meaning"], [[t, m] for t, m in model.GLOSSARY], styles,
                   widths=[105, 400])]


def _executive_summary(report, styles, section) -> list:
    passed = report.gate.passed
    colour = charts.GOOD if passed else charts.BAD
    out = [_h1(section.heading, styles)]
    out += _anchor("exec-summary", report, styles)

    out.append(_h2(f"{section.number}.1 Verdict", styles))
    out.append(_p(f"<font color='{colour}'><b>"
                  f"{'PRODUCTION-READY' if passed else 'NOT PRODUCTION-READY'}</b></font>",
                  styles))
    if report.gate.blockers:
        out.append(_table(["Blocker"], [[b] for b in report.gate.blockers], styles,
                          widths=[505]))

    out.append(_h2(f"{section.number}.2 Scorecard", styles))
    out.append(_table(["Axis", f"Score / {BASE:.0f}", "Reading"],
                      [[a.label, a.score_text, a.reading] for a in report.axes],
                      styles, widths=[120, 55, 330], align_right=[1]))
    out += _figure("axis_radar", report, styles)

    out.append(_h2(f"{section.number}.3 Risk dashboard", styles))
    out.append(_table(["Severity", "Count"],
                      [[s.value.capitalize(), report.counts.get(s.value, 0)]
                       for s in SEVERITY_ORDER], styles, widths=[120, 60], align_right=[1]))
    out += _figure("severity_bars", report, styles)

    out.append(_h2(f"{section.number}.4 Finding classes", styles))
    out += _figure("class_bars", report, styles)
    out += _figure("risk_scatter", report, styles)

    out.append(_h2(f"{section.number}.5 Attacker matrix", styles))
    out += _anchor("attacker-matrix", report, styles)
    return out


def _scope(report, styles, section) -> list:
    m = report.meta
    out = [_h1(section.heading, styles), _h2(f"{section.number}.1 Scope", styles)]
    out.append(_p(f"Target <font face='Courier'>{_esc(m.get('target') or 'unspecified')}</font> "
                  f"at commit {_esc(m.get('commit') or 'unrecorded')}. "
                  f"{_esc(m.get('volume', ''))}.", styles))
    stack = [(label, report.recon.get(key) or []) for label, key in
             [("Languages", "languages"), ("Frameworks", "frameworks"),
              ("Datastores", "datastores"), ("ORMs", "orms"), ("Auth", "auth"),
              ("LLM providers", "llm_providers"),
              ("Payment processors", "payment_processors"), ("Cloud", "cloud")]]
    stack = [(label, vals) for label, vals in stack if vals]
    if stack:
        out.append(_table(["Layer", "Detected"], [[label, ", ".join(v)] for label, v in stack],
                          styles, widths=[120, 385]))

    out.append(_h2(f"{section.number}.2 Method", styles))
    for i, step in enumerate((
        "Deterministic recon: every file walked and fingerprinted, no model in the loop.",
        "Containerised scanner sweep, deduplicated into the canonical finding model.",
        "Triage into finding classes; scanner classes roll up, reasoned findings promote.",
        "Adversarial subagent review of the promoted set against six attacker kill chains.",
        "Reconciliation into one finding set, then this render. The score is arithmetic "
        "over that set.",
    ), 1):
        out.append(_p(f"{i}. {_esc(step)}", styles))
    out.append(_p("This is static analysis plus architecture and code review. It is not a "
                  "live penetration test; see the residual-risk section.", styles))

    out.append(_h2(f"{section.number}.3 Limits of this run", styles))
    if report.limits:
        out.append(_p("Every gap below is a claim this report does <b>not</b> make.", styles))
        out.append(_table(["Limit"], [[x] for x in report.limits], styles, widths=[505]))
    else:
        out.append(_p("No dispatch was shed, every promoted finding carries a proof of "
                      "concept and a write-up, and no finding is left at suspected "
                      "confidence.", styles))
    return out


def _scoring(report, styles, section) -> list:
    out = [_h1(section.heading, styles), _p(_esc(report.scorecard.method), styles)]
    out.append(_p("The scorecard is not the gate. A single critical finding costs one axis "
                  "three points and can still leave that axis above the threshold, while the "
                  "gate fails outright on one open critical. The gate is the ship decision; "
                  "the scorecard shows where the debt sits.", styles))
    out.append(_p(_esc(model.FAIL_CLOSED_NOTE), styles))
    out.append(_h2(f"{section.number}.1 Axes", styles))
    out.append(_table(["Axis", f"Score / {BASE:.0f}", f"Clears {ACCEPTABLE:.1f}",
                       "Findings mapped"],
                      [[a.label, a.score_text, a.clears_text,
                        len(report.chapter(a.key).findings)] for a in report.axes],
                      styles, widths=[170, 70, 70, 90], align_right=[1, 3]))
    out.append(_h2(f"{section.number}.2 Sub-characteristics", styles))
    out += _figure("sub_bars", report, styles)
    return out


def _frameworks(report, styles, section) -> list:
    out = [_h1(section.heading, styles)]
    out.append(_p("One row per category present in the finding set. An empty cell means the "
                  "mapping is not derivable from the finding's category or references - it "
                  "does not mean the requirement is met.", styles))
    if report.frameworks:
        out.append(_table(["Category", "n", "OWASP", "ASVS 4.0", "CWE", "GDPR"],
                          [list(row) for row in report.frameworks], styles,
                          widths=[90, 20, 165, 90, 65, 75], align_right=[1]))
    else:
        out.append(_p("No findings, so nothing to map.", styles, "KavachUnsupplied"))
    return out


def _chapter(report, styles, section, chapter) -> list:
    out = [_h1(section.heading, styles), _p(_esc(chapter.narrative), styles)]
    if not chapter.findings:
        out.append(_p("No finding maps to this axis.", styles, "KavachUnsupplied"))
        return out

    tiers = model.tier(chapter.findings)
    n = 0

    if tiers["full"]:
        n += 1
        out.append(_h2(f"{section.number}.{n} Critical and high findings "
                       f"({len(tiers['full'])})", styles))
        for f in tiers["full"]:
            out += _finding_box(f, report, styles)
    if tiers["compact"]:
        n += 1
        out.append(_h2(f"{section.number}.{n} Medium findings "
                       f"({len(tiers['compact'])})", styles))
        out.append(_table(["Ref", "Title", "Location", "Category", "Source"],
                          [[report.ref(f), f.title, f"`{_loc(f)}`", f.category or "",
                            f.source or ""] for f in tiers["compact"]],
                          styles, widths=[75, 165, 135, 70, 60]))
    if tiers["rolled"]:
        n += 1
        out.append(_h2(f"{section.number}.{n} Rolled-up scanner findings "
                       f"({len(tiers['rolled'])})", styles))
        out.append(_p("Scanner rows of an aggregate class. They are tabled rather than "
                      "written up individually so a rolled-up advisory is never mistaken "
                      "for a cold-verified finding; the full set lives in the aggregate's "
                      "rows.json.", styles, "KavachSmall"))
        out.append(_table(["Severity", "Class", "Title", "Advisory", "Location"],
                          [[f.severity.value, f.finding_class, f.title, f.rule_id or "",
                            f"`{_loc(f)}`"] for f in tiers["rolled"]],
                          styles, widths=[50, 60, 175, 100, 120]))
    if tiers["counted"]:
        n += 1
        out.append(_h2(f"{section.number}.{n} Low and informational findings "
                       f"({len(tiers['counted'])})", styles))
        by_category: dict = {}
        for f in tiers["counted"]:
            key = f.category or "uncategorized"
            by_category[key] = by_category.get(key, 0) + 1
        out.append(_table(["Category", "Count"],
                          [[c, v] for c, v in sorted(by_category.items(),
                                                     key=lambda kv: (-kv[1], kv[0]))],
                          styles, widths=[200, 60], align_right=[1]))
        out.append(_p("Each of these is carried in full in reports/report.json and "
                      "reports/report.sarif; they are counted rather than narrated here so "
                      "the deliverable stays readable.", styles, "KavachSmall"))
    return out


def _remediation(report, styles, section) -> list:
    out = [_h1(section.heading, styles)]
    out += _anchor("roadmap", report, styles)
    out.append(_p("The three horizons below are derived from the finding set, not from "
                  "prose: everything critical or high blocks production traffic, money-path "
                  "findings block the first paid user, and the rest is the hardening "
                  "backlog.", styles))
    if report.remediation:
        out.append(_table(["#", "Horizon", "Action", "Addresses", "Sev", "Effort"],
                          [[r["n"], r["horizon"], r["action"],
                            ", ".join(r["addresses"][:6]) + (
                                f" (+{len(r['addresses']) - 6})"
                                if len(r["addresses"]) > 6 else ""),
                            r["severity"], r["effort"]] for r in report.remediation],
                          styles, widths=[18, 105, 175, 120, 47, 40], align_right=[0]))
    else:
        out.append(_p("Nothing to remediate.", styles, "KavachUnsupplied"))
    return out


def _verdict(report, styles, section) -> list:
    passed = report.gate.passed
    colour = charts.GOOD if passed else charts.BAD
    out = [_h1(section.heading, styles),
           _p(f"<font size='13' color='{colour}'><b>"
              f"{'PRODUCTION-READY' if passed else 'NOT PRODUCTION-READY'}</b></font>", styles)]
    out.append(_table(["Control", "Status"],
                      [[c, "proven" if report.controls.get(c) is True else "unproven"]
                       for c in GATE_CONTROLS], styles, widths=[330, 175]))
    out += _figure("control_status", report, styles)
    if report.gate.blockers:
        out.append(_table(["Blocker"], [[b] for b in report.gate.blockers], styles,
                          widths=[505]))
    out.append(_p("Certification: a green gate certifies this codebase and its architecture "
                  "at the commit named on the cover page. It does not certify the running "
                  "deployment.", styles))
    return out


def _residual(report, styles, section) -> list:
    out = [_h1(section.heading, styles)]
    out += _anchor("residual", report, styles)
    suspected = [f for f in report.findings if f.confidence == Confidence.SUSPECTED]
    if suspected:
        out.append(_p(f"{len(suspected)} finding(s) are marked suspected and need a runtime "
                      "test before external sign-off.", styles))
        out.append(_table(["Ref", "Title", "Category", "Source"],
                          [[report.ref(f), f.title, f.category or "", f.source or ""]
                           for f in suspected[:40]], styles,
                          widths=[80, 245, 100, 80]))
        if len(suspected) > 40:
            out.append(_p(f"{len(suspected) - 40} further suspected finding(s) in "
                          "reports/report.json.", styles, "KavachSmall"))
    return out


def _annex_a(report, styles, section) -> list:
    out = [_h1(section.heading, styles)]
    out.append(_p("The arithmetic behind every axis, term by term. Sum the effects, clamp "
                  f"to [{FLOOR:.1f}, {BASE:.1f}], round to one decimal - that is the score. "
                  "No evaluator override.", styles))
    for axis in report.axes:
        rows = report.scorecard.axis_rows(axis.key)
        if not rows:
            out.append(_p(f"<b>{_esc(axis.label)} - {_esc(axis.score_text)}</b>",
                          styles, "KavachH3"))
            out.append(_p(_esc(model.NOT_ASSESSED_NOTE), styles, "KavachUnsupplied"))
            continue
        out.append(_p(f"<b>{_esc(axis.label)} - {axis.score:.1f} / {BASE:.0f}</b>",
                      styles, "KavachH3"))
        out.append(_table(["Item", "Effect", "Justification"],
                          [[r.item, f"{r.effect:+.2f}", r.justification] for r in rows],
                          styles, widths=[210, 50, 245], align_right=[1]))
    return out


def _annex_b(report, styles, section) -> list:
    out = [_h1(section.heading, styles)]
    if report.promoted:
        out.append(_p("Promoted finding directories:", styles))
        out.append(_table(["Ref", "Directory", "Severity", "Kind"],
                          [[p["display_id"], f"`{p['dir']}`", p["severity"],
                            f"aggregate of {p['member_count']}" if p["is_aggregate"]
                            else "individual"] for p in report.promoted],
                          styles, widths=[45, 275, 90, 95]))
    else:
        out.append(_p("No promoted finding directory was found in this audit directory.",
                      styles, "KavachUnsupplied"))
    out.append(_p("Full inventory, every severity:", styles))
    if report.findings:
        out.append(_table(["Ref", "Sev", "Class", "Category", "Title", "Source"],
                          [[report.ref(f), f.severity.value, f.finding_class or "",
                            f.category or "", f.title, f.source or ""]
                           for f in report.findings],
                          styles, widths=[78, 40, 55, 85, 172, 75]))
    else:
        out.append(_p("No findings.", styles, "KavachUnsupplied"))
    return out


def _annex_c(report, styles, section) -> list:
    return [
        _h1(section.heading, styles),
        _p("Every quantified claim in this report is recomputable. Run from the audited "
           "repository root, with the audit directory at .kavach:", styles),
        _table(["Claim", "Command"],
               [[caption, f"`{command}`"] for caption, command in report.figure_commands],
               styles, widths=[215, 290]),
    ]


def _appendix_b(report, styles, section) -> list:
    totals = report.recon.get("totals") or {}
    return [
        _h1(section.heading, styles),
        _p(f"Total files walked: <b>{totals.get('files', 0)}</b> "
           f"({totals.get('code_files', 0)} code files). Full file manifest emitted "
           "alongside this report as file-manifest.txt.", styles),
    ]
