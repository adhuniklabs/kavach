"""Figures for the report - one definition, two outputs.

Each chart has exactly one implementation. :func:`drawing` builds a
``reportlab.graphics.Drawing``; the PDF draws that object natively and the HTML exports the
same object through ``reportlab.graphics.renderSVG``, which is stdlib XML only. ``renderPM``
is deliberately never used - it needs PIL, and the whole point of choosing reportlab was a
pip install with no system libraries behind it.

reportlab is an optional extra. Every import of it happens *inside* a function, so importing
this module costs nothing and :func:`available` can answer honestly. When it is absent,
:func:`data` still returns the numbers behind every figure, which is what lets the HTML
report substitute a table and a one-line note instead of failing. A report that renders
without its figures beats no report.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..finding import Confidence
from ..score import GATE_CONTROLS
from ..scoring import ACCEPTABLE, BASE, NOT_ASSESSED

PIP_HINT = "pip install 'kavach-audit[report]'"

INK = "#1f2933"
MUTED = "#7b8794"
GRID = "#d3d9e2"
PAPER = "#ffffff"
ACCENT = "#1d4ed8"
ACCENT_FILL = "#dbe4ff"
GOOD = "#2e7d32"
BAD = "#b00020"

SEVERITY_COLOR = {"critical": "#b00020", "high": "#d84315", "medium": "#f9a825",
                  "low": "#2e7d32", "info": "#546e7a"}
CLASS_COLOR = {"reasoned": "#1d4ed8", "code": "#5b6b8c", "secret": "#b00020",
               "dependency": "#f9a825", "iac": "#00796b", "unclassified": "#9aa5b1"}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Exploitability/impact proxy when a finding carries no CVSS base score. Documented in the
# figure caption so the axes are never mistaken for a measured CVSS vector.
SEVERITY_PROXY = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}

CHART_TITLES = {
    "axis_radar": "Six-axis scorecard",
    "severity_bars": "Findings by severity",
    "sub_bars": "Score by sub-characteristic",
    "risk_scatter": "Exploitability against business impact",
    "class_bars": "Findings by class",
    "control_status": "Production-readiness controls",
}

# Emission order, and therefore the figure numbering every renderer prints.
CHART_ORDER = ("axis_radar", "severity_bars", "class_bars", "risk_scatter",
               "sub_bars", "control_status")
FIGURE_NUMBER = {name: i + 1 for i, name in enumerate(CHART_ORDER)}


class ReportlabMissing(RuntimeError):
    """Raised when a caller needs reportlab and it is not installed."""

    def __init__(self, what: str = "This output") -> None:
        super().__init__(
            f"{what} needs reportlab, which KAVACH ships as an optional extra so the core "
            f"install stays dependency-light. Install it with:\n\n    {PIP_HINT}\n\n"
            f"Markdown, JSON, SARIF and HTML render without it."
        )


def available() -> bool:
    """True when reportlab can be imported. Never raises."""
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class ChartData:
    """The numbers behind a figure - the HTML fallback table and the drawing read the same one."""

    key: str
    caption: str
    headers: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    note: str = ""


# --------------------------------------------------------------------------- data


def _axis_radar_data(report) -> ChartData:
    rows = [[a.label, a.score_text, a.clears_text] for a in report.axes]
    dropped = [a.label for a in report.axes if not a.assessed]
    caption = (f"Scorecard over the {len(report.axes) - len(dropped)} assessed axes, each out "
               f"of {BASE:.0f}. The dashed ring is the {ACCEPTABLE:.1f} acceptability "
               f"threshold.")
    if dropped:
        caption += (f" {', '.join(dropped)} carr{'ies' if len(dropped) == 1 else 'y'} no spoke: "
                    f"no finding maps there and no control credits it, so there is no "
                    f"measurement to place on one. The legend keeps the row, marked n/a.")
    return ChartData(
        key="axis_radar",
        caption=caption,
        headers=["Axis", f"Score / {BASE:.0f}", f"Clears {ACCEPTABLE:.1f}"],
        rows=rows,
    )


def _severity_bars_data(report) -> ChartData:
    total = sum(report.counts.get(s, 0) for s in SEVERITY_ORDER) or 1
    rows = [[s.capitalize(), str(report.counts.get(s, 0)),
             f"{100.0 * report.counts.get(s, 0) / total:.1f}%"] for s in SEVERITY_ORDER]
    return ChartData(
        key="severity_bars",
        caption="Distribution of the reconciled finding set by severity.",
        headers=["Severity", "Findings", "Share"],
        rows=rows,
    )


def _sub_bars_data(report) -> ChartData:
    rows = []
    for axis in report.axes:
        for sub in axis.subs:
            terms = sub.determined_by
            # Annex A carries the full arithmetic; this cell only has to show what dominates.
            shown = "; ".join(terms[:6]) + (f"; +{len(terms) - 6} more" if len(terms) > 6 else "")
            if not shown:
                # Three states, not two. A sub with a proven control or an info-only finding was
                # assessed and came out clean; a sub with neither was never looked at, and the
                # cell has to say which of the two a reader is looking at.
                shown = (NOT_ASSESSED + " - no finding maps here and no control credits it"
                         if not sub.assessed else "assessed, nothing deducted")
            rows.append([axis.label, sub.label, sub.score_text, shown])
    blank = sum(1 for a in report.axes for s in a.subs if not s.assessed)
    caption = f"Every sub-characteristic out of {BASE:.0f}, with the terms that moved it."
    if blank:
        caption += (f" {blank} of the {len(rows)} were not assessed and carry no bar: absence "
                    f"of a finding is not evidence of a control.")
    return ChartData(
        key="sub_bars",
        caption=caption,
        headers=["Axis", "Sub-characteristic", f"Score / {BASE:.0f}", "Determined by"],
        rows=rows,
    )


def _exploitability(finding) -> float:
    return finding.cvss_score if finding.cvss_score > 0 else \
        SEVERITY_PROXY[finding.severity.value]


def _impact(finding) -> float:
    return SEVERITY_PROXY[finding.severity.value]


def _risk_cells(report) -> list:
    """Bucket findings into integer (exploitability, impact) cells - one bubble per cell.

    Bucketing rather than jittering keeps the figure reproducible: the same finding set
    always draws the same bubbles in the same places.
    """
    cells: dict = {}
    for f in report.findings:
        key = (int(round(_exploitability(f))), int(round(_impact(f))),
               f.confidence == Confidence.CONFIRMED)
        cells.setdefault(key, []).append(f)
    out = []
    for (x, y, confirmed), members in sorted(cells.items()):
        members.sort(key=lambda f: (-f.severity.rank, f.id))
        out.append({
            "x": x, "y": y, "confirmed": confirmed, "count": len(members),
            "severity": members[0].severity.value,
            "examples": [report.ref(f) for f in members[:3]],
        })
    return out


def _risk_scatter_data(report) -> ChartData:
    rows = [[str(c["x"]), str(c["y"]), "confirmed" if c["confirmed"] else "suspected",
             str(c["count"]), ", ".join(c["examples"])] for c in _risk_cells(report)]
    return ChartData(
        key="risk_scatter",
        caption="Exploitability (CVSS base score, or the severity proxy when the finding "
                "carries no vector) against business impact (severity band). Bubble area is "
                "proportional to the number of findings in the cell; filled bubbles are "
                "confirmed in code, hollow ones are suspected.",
        headers=["Exploitability", "Business impact", "Confidence", "Findings", "Examples"],
        rows=rows,
    )


def _class_bars_data(report) -> ChartData:
    total = sum(report.class_counts.values()) or 1
    rows = [[k, str(v), f"{100.0 * v / total:.1f}%"]
            for k, v in sorted(report.class_counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    return ChartData(
        key="class_bars",
        caption="Findings by class. Scanner classes (dependency, iac) are rolled up into "
                "aggregate directories rather than promoted individually, so this is the "
                "figure that shows how much of the set is raw tool output.",
        headers=["Class", "Findings", "Share"],
        rows=rows,
    )


def _control_status_data(report) -> ChartData:
    rows = [[c, "proven" if report.controls.get(c) is True else "unproven"]
            for c in GATE_CONTROLS]
    return ChartData(
        key="control_status",
        caption="The eight production-readiness controls. Unset is unproven, not passing - "
                "the gate is fail-closed.",
        headers=["Control", "Status"],
        rows=rows,
    )


_DATA = {
    "axis_radar": _axis_radar_data,
    "severity_bars": _severity_bars_data,
    "sub_bars": _sub_bars_data,
    "risk_scatter": _risk_scatter_data,
    "class_bars": _class_bars_data,
    "control_status": _control_status_data,
}


def data(name: str, report) -> ChartData:
    """The numbers behind one figure. Works with or without reportlab."""
    try:
        fn = _DATA[name]
    except KeyError:
        raise ValueError(f"unknown chart '{name}'; choose from {list(CHART_ORDER)}") from None
    return fn(report)


# --------------------------------------------------------------------------- drawings


def _shapes():
    """The shape classes every drawing needs, imported at call time so reportlab stays lazy."""
    from reportlab.graphics.shapes import (Circle, Drawing, Group, Line, Polygon, Rect,
                                           String)
    return Drawing, Line, Circle, Polygon, Rect, String, Group


def _color(hexstr: str):
    from reportlab.lib.colors import HexColor
    return HexColor(hexstr)


def _text(String, x, y, label, *, size=7, anchor="start", fill=MUTED, bold=False):
    s = String(x, y, label, fontSize=size, textAnchor=anchor, fillColor=_color(fill))
    s.fontName = "Helvetica-Bold" if bold else "Helvetica"
    return s


def axis_radar(report):
    """Radar over the *assessed* axes, hand-plotted on a fixed 0-10 scale.

    Drawn from shapes rather than ``SpiderChart`` because SpiderChart normalises each spoke
    against the maximum across strands - with a single strand every spoke would peg at the
    outer ring and the figure would be a lie.

    A not-assessed axis gets no spoke at all, rather than a differently-styled one. A radar's
    message is geometry: the polygon has to cross *some* radius on every spoke it has in order
    to close, and any radius is a magnitude nobody measured - so a dashed or hollow marker still
    leaves the shape misstating its own area, and a full-length spoke for an unmeasured axis is
    the exact reading this figure must not support. Dropping the spoke makes the polygon a
    genuine polygon over what was measured; the axis keeps its legend row, marked n/a, so the
    reader loses the false spoke and not the fact.
    """
    Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
    w, h = 470, 290
    d = Drawing(w, h)
    cx, cy, radius = 200, 145, 112
    axes = [a for a in report.axes if a.assessed]
    n = len(axes)
    angles = [math.pi / 2 - i * 2 * math.pi / n for i in range(n)] if n else []

    def point(i, value):
        r = radius * max(0.0, min(1.0, value / BASE))
        return cx + r * math.cos(angles[i]), cy + r * math.sin(angles[i])

    def ring_points(value):
        pts = []
        for i in range(n):
            x, y = point(i, value)
            pts.extend([x, y])
        return pts

    # Two spokes are a line and one is a dot - neither is a radar, and drawing one anyway would
    # be a shape that reads as a measurement of area. Say so instead.
    if n < 3:
        d.add(_text(String, 24, cy, f"Only {n} of {len(report.axes)} axes were assessed; a "
                                   f"radar needs at least three.", size=8, fill=INK))
        d.add(_text(String, 24, cy - 14, "The scores are in the axis table above.", size=7))
    else:
        for ring in (2, 4, 6, 8, 10):
            d.add(Polygon(ring_points(ring), strokeColor=_color(GRID), strokeWidth=0.5,
                          fillColor=None))
        for i in range(n):
            x, y = point(i, BASE)
            d.add(Line(cx, cy, x, y, strokeColor=_color(GRID), strokeWidth=0.5))

        scored = []
        for i, axis in enumerate(axes):
            x, y = point(i, axis.score)
            scored.extend([x, y])
        d.add(Polygon(scored, strokeColor=_color(ACCENT), strokeWidth=1.4,
                      fillColor=_color(ACCENT_FILL)))

        # The threshold ring and the scale labels go on top of the fill, or the fill hides them.
        threshold = Polygon(ring_points(ACCEPTABLE), strokeColor=_color(BAD), strokeWidth=0.8,
                            fillColor=None)
        threshold.strokeDashArray = (2, 2)
        d.add(threshold)
        for i, axis in enumerate(axes):
            x, y = point(i, axis.score)
            d.add(Circle(x, y, 2.6, fillColor=_color(ACCENT), strokeColor=_color(PAPER),
                         strokeWidth=0.6))
        for ring in (2, 4, 6, 8, 10):
            x, y = point(0, ring)
            d.add(_text(String, cx + 3, y - 2, str(ring), size=6))

    # Labels sit in a legend column: six axis names around a 112pt radar would collide. Every
    # axis gets a row, plotted or not, so the figure cannot quietly lose one.
    top = cy + 100
    d.add(_text(String, 330, top + 22, "Axis", size=7, fill=INK, bold=True))
    for i, axis in enumerate(report.axes):
        y = top - i * 17
        plotted = axis.assessed and n >= 3
        d.add(Circle(334, y + 2.4, 2.6,
                     fillColor=_color(ACCENT) if plotted else None,
                     strokeColor=None if plotted else _color(MUTED), strokeWidth=0.7))
        d.add(_text(String, 342, y, axis.label, size=7, fill=INK if axis.assessed else MUTED))
        if axis.assessed:
            d.add(_text(String, 462, y, f"{axis.score:.1f}", size=7, anchor="end",
                        fill=GOOD if axis.acceptable else BAD, bold=True))
        else:
            d.add(_text(String, 462, y, "n/a", size=7, anchor="end", fill=MUTED))
    d.add(_text(String, 330, top - len(report.axes) * 17 - 4,
                "n/a = not assessed, not plotted", size=6))
    return d


def severity_bars(report):
    """Vertical bars, one per severity band, coloured with the report's severity palette."""
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
    d = Drawing(470, 200)
    counts = [report.counts.get(s, 0) for s in SEVERITY_ORDER]
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 40, 30, 410, 145
    chart.data = [counts]
    chart.categoryAxis.categoryNames = [s.capitalize() for s in SEVERITY_ORDER]
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.strokeColor = _color(GRID)
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(counts + [1])
    chart.valueAxis.valueStep = max(1, _step(max(counts + [1])))
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.strokeColor = _color(GRID)
    chart.valueAxis.gridStrokeColor = _color(GRID)
    chart.valueAxis.visibleGrid = 1
    chart.barSpacing = 6
    chart.groupSpacing = 14
    chart.barLabels.fontSize = 7
    chart.barLabelFormat = "%d"
    chart.barLabels.dy = 5
    for i, sev in enumerate(SEVERITY_ORDER):
        chart.bars[(0, i)].fillColor = _color(SEVERITY_COLOR[sev])
        chart.bars[(0, i)].strokeColor = None
    d.add(chart)
    return d


def _step(top: int) -> int:
    for candidate in (1, 2, 5, 10, 20, 25, 50, 100, 200, 500):
        if top / candidate <= 6:
            return candidate
    return max(1, top // 6)


def _hbars(labels: list, values: list, colors: list, *, vmax: float, fmt: str,
           height: int, left: int = 158, step: float = None):
    """Shared horizontal-bar drawing for the two horizontal figures."""
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
    d = Drawing(470, height)
    chart = HorizontalBarChart()
    chart.x, chart.y = left, 24
    chart.width, chart.height = 470 - left - 46, height - 40
    chart.data = [list(values)]
    chart.categoryAxis.categoryNames = list(labels)
    chart.categoryAxis.labels.fontSize = 6.5
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.boxAnchor = "e"
    chart.categoryAxis.labels.dx = -3
    chart.categoryAxis.strokeColor = _color(GRID)
    chart.categoryAxis.reverseDirection = 1
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = vmax
    if step:
        chart.valueAxis.valueStep = step
    chart.valueAxis.labels.fontSize = 6.5
    chart.valueAxis.strokeColor = _color(GRID)
    chart.valueAxis.gridStrokeColor = _color(GRID)
    chart.valueAxis.visibleGrid = 1
    chart.barSpacing = 2
    chart.groupSpacing = 4
    chart.barLabels.fontSize = 6.5
    chart.barLabelFormat = fmt
    chart.barLabels.dx = 6
    chart.barLabels.boxAnchor = "w"
    for i, colour in enumerate(colors):
        chart.bars[(0, i)].fillColor = _color(colour)
        chart.bars[(0, i)].strokeColor = None
    d.add(chart)
    return d


def sub_bars(report):
    """One bar per *assessed* sub-characteristic, grouped by axis, on the radar's 0-10 scale.

    A not-assessed sub is left out for the same reason it gets no radar spoke: a bar length is a
    magnitude, and a zero-length bar reads as 0.0 just as a full one reads as 10.0. The caption
    says how many were dropped and the figure's fallback table lists all eighteen with their
    state, so the omission is stated rather than silent.
    """
    labels, values, colors = [], [], []
    for axis in report.axes:
        for sub in axis.subs:
            if not sub.assessed:
                continue
            labels.append(f"{axis.label} · {sub.label}")
            values.append(sub.score)
            colors.append(GOOD if sub.score >= ACCEPTABLE else BAD)
    if not labels:
        Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
        d = Drawing(470, 60)
        d.add(_text(String, 24, 30, "No sub-characteristic was assessed, so there is nothing "
                                    "to plot.", size=8, fill=INK))
        return d
    return _hbars(labels, values, colors, vmax=BASE, fmt="%0.1f",
                  height=42 + 15 * len(labels))


def class_bars(report):
    """One bar per finding class - the figure that makes the scanner-noise share visible."""
    items = sorted(report.class_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if not items:
        items = [("no findings", 0)]
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    colors = [CLASS_COLOR.get(k, MUTED) for k in labels]
    top = max(values + [1])
    return _hbars(labels, values, colors, vmax=top, fmt="%d",
                  height=44 + 18 * len(labels), left=110, step=_step(top))


def risk_scatter(report):
    """Bubble plot of exploitability against business impact, one bubble per integer cell."""
    Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
    w, h = 470, 300
    d = Drawing(w, h)
    x0, y0, x1, y1 = 46, 42, 440, 268

    for v in range(0, 11, 2):
        gx = x0 + (x1 - x0) * v / 10.0
        gy = y0 + (y1 - y0) * v / 10.0
        d.add(Line(gx, y0, gx, y1, strokeColor=_color(GRID), strokeWidth=0.4))
        d.add(Line(x0, gy, x1, gy, strokeColor=_color(GRID), strokeWidth=0.4))
        d.add(_text(String, gx, y0 - 11, str(v), size=6.5, anchor="middle"))
        d.add(_text(String, x0 - 6, gy - 2.5, str(v), size=6.5, anchor="end"))

    d.add(Line(x0, y0, x1, y0, strokeColor=_color(INK), strokeWidth=0.6))
    d.add(Line(x0, y0, x0, y1, strokeColor=_color(INK), strokeWidth=0.6))
    d.add(_text(String, (x0 + x1) / 2, y0 - 24, "Exploitability (CVSS base or severity proxy)",
                size=7, anchor="middle", fill=INK))
    ylabel = Group(_text(String, 0, 0, "Business impact (severity band)", size=7,
                         anchor="middle", fill=INK))
    ylabel.translate(x0 - 30, (y0 + y1) / 2)
    ylabel.rotate(90)
    d.add(ylabel)

    for cell in _risk_cells(report):
        cx = x0 + (x1 - x0) * min(10, cell["x"]) / 10.0
        cy = y0 + (y1 - y0) * min(10, cell["y"]) / 10.0
        r = 3.0 + 2.2 * math.sqrt(cell["count"])
        colour = _color(SEVERITY_COLOR[cell["severity"]])
        circle = Circle(cx, cy, min(r, 20), strokeColor=colour, strokeWidth=1.1)
        circle.fillColor = colour if cell["confirmed"] else None
        d.add(circle)
        if cell["count"] > 1:
            d.add(_text(String, cx, cy + min(r, 20) + 3, str(cell["count"]), size=6,
                        anchor="middle", fill=INK))

    d.add(_text(String, x0, y1 + 14, "filled = confirmed in code · hollow = suspected · "
                                     "area ∝ finding count", size=6.5, fill=MUTED))
    return d


def control_status(report):
    """The eight gate controls as a status list - fail-closed, so unset draws red."""
    Drawing, Line, Circle, Polygon, Rect, String, Group = _shapes()
    row_h = 19
    d = Drawing(470, 26 + row_h * len(GATE_CONTROLS))
    top = 26 + row_h * (len(GATE_CONTROLS) - 1)
    for i, control in enumerate(GATE_CONTROLS):
        y = top - i * row_h
        proven = report.controls.get(control) is True
        colour = GOOD if proven else BAD
        d.add(Rect(0, y - 4, 470, row_h - 3, fillColor=_color("#f7f9fc" if i % 2 else PAPER),
                   strokeColor=None))
        d.add(Rect(4, y - 1, 9, 9, fillColor=_color(colour), strokeColor=None))
        d.add(_text(String, 20, y + 1, control, size=7.5, fill=INK))
        d.add(_text(String, 466, y + 1, "proven" if proven else "unproven", size=7.5,
                    anchor="end", fill=colour, bold=True))
    return d


_DRAW = {
    "axis_radar": axis_radar,
    "severity_bars": severity_bars,
    "sub_bars": sub_bars,
    "risk_scatter": risk_scatter,
    "class_bars": class_bars,
    "control_status": control_status,
}


def drawing(name: str, report):
    """The ``Drawing`` for one figure. Raises :class:`ReportlabMissing` without reportlab."""
    try:
        fn = _DRAW[name]
    except KeyError:
        raise ValueError(f"unknown chart '{name}'; choose from {list(CHART_ORDER)}") from None
    if not available():
        raise ReportlabMissing(f"The '{name}' figure")
    return fn(report)


def svg(name: str, report) -> str:
    """The figure as an inline SVG fragment, or ``""`` when reportlab is absent.

    Exported through ``renderSVG``, which builds the document with ``xml.dom.minidom`` -
    no PIL, no C extension, nothing a VM has to install first.
    """
    if not available():
        return ""
    from reportlab.graphics import renderSVG
    body = renderSVG.drawToString(_DRAW[name](report))
    cut = body.find("<svg")
    return body[cut:] if cut >= 0 else body
