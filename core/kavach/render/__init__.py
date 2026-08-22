"""Report renderers over the one canonical Finding[] - formats never drift.

Every renderer builds a :class:`~kavach.render.model.AuditReport` first and reads only that,
so markdown, HTML, JSON, SARIF and PDF cannot disagree about a number.

One asymmetry: :func:`render` returns a ``str`` for every format except ``"pdf"``, which
writes the file named by ``meta["output"]`` and returns a one-line human summary of what it
wrote. See :mod:`kavach.render.pdf` for why, and ``ReportlabMissing`` for what happens when
the optional ``[report]`` extra is not installed.
"""

from __future__ import annotations

from ..finding import Finding
from ..score import GateResult
from ..triage import classify_all
from . import html as _html
from . import json_out as _json
from . import markdown as _md
from . import pdf as _pdf
from . import sarif as _sarif
from .charts import PIP_HINT, ReportlabMissing  # noqa: F401  (re-exported for callers)
from .model import AuditReport, build  # noqa: F401

RENDERERS = {
    "json": _json.render,
    "md": _md.render,
    "markdown": _md.render,
    "sarif": _sarif.render,
    "html": _html.render,
    "pdf": _pdf.render,
}

# The formats that return the document itself. "pdf" writes a file and returns a summary line.
TEXT_FORMATS = tuple(k for k in RENDERERS if k != "pdf")


def render(fmt: str, findings: list[Finding], recon: dict, gate: GateResult,
           meta: dict | None = None) -> str:
    try:
        fn = RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"unknown format '{fmt}'; choose from {sorted(RENDERERS)}") from None
    # Classify at the subsystem boundary as well as in model.build, because sarif is the one
    # renderer that never builds an AuditReport - it reads Finding.finding_class straight off
    # the argument, so the model's call cannot reach it. classify_all is idempotent, so for the
    # four formats that do build a model this is the no-op that makes the assumption unnecessary
    # rather than a second place that has to be kept in step. See model.build for the why.
    return fn(classify_all(findings), recon, gate, meta or {})
