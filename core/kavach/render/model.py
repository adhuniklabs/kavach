"""The one report model every renderer consumes.

``AuditReport`` is assembled once from ``findings.json`` + ``recon.json`` +
``controls.json`` + the ``GateResult`` + the run's budget/coverage artifacts. Markdown,
HTML, JSON, SARIF and PDF all read *this*, never raw findings, which is what stops five
output formats from drifting into five different reports.

Two properties matter more than the rest:

* :attr:`AuditReport.limits` carries every honesty debt of the run - the dispatches the
  budget shed, the promoted findings with no PoC or no write-up, and every finding still
  marked ``suspected``. A dropped tail must appear in the deliverable.
* :attr:`AuditReport.figure_commands` carries the command that recomputes each quantified
  claim, which Annex C prints. An assertion is worth what would refute it.

Both are read defensively-by-absence: an audit directory from an older run simply yields
empty lists rather than an exception, because a report that cannot render is worth less
than a report that says "not measured".
"""

from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field

from ..finding import Confidence, Finding, Severity
from ..score import GATE_CONTROLS, GateResult
from ..scoring import (Axis, Scorecard, SubScore, axis_for,  # noqa: F401 (re-exported)
                       class_counts, score)
from ..triage import AGGREGATE_CLASSES, classify_all
from ..triage import sources as source_segments

SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)

# How a chapter presents its findings. Severity picks the tier for the promotable classes;
# the scanner classes are rolled up whatever their severity, because a CVE table that reads
# like a cold-verified Critical is the exact confusion the aggregate directories exist to
# prevent (§A3). Nothing is dropped - a rolled-up row still names its severity and advisory.
FULL_BLOCK = (Severity.CRITICAL, Severity.HIGH)
COMPACT = (Severity.MEDIUM,)
COUNTED = (Severity.LOW, Severity.INFO)

# The six narrative anchors skill/references/report-template.md documents, in emitted order.
ANCHORS = ("exec-summary", "attacker-matrix", "attack-trees", "roadmap", "residual", "limits")
NOT_SUPPLIED = "_Not supplied by the reconciler._"

# Annex A's stand-in for an axis that has no arithmetic to show. Shared so four renderers
# cannot word the same absence four different ways.
NOT_ASSESSED_NOTE = ("Not assessed - no finding maps to this axis and no control in "
                     "controls.json credits it, so there is no arithmetic to show. Absence of "
                     "a finding is not evidence of a control, and this axis is left out of the "
                     "overall figure rather than counted as a ten.")

# The fail-closed rule, stated wherever a rendering explains the scale. Sourced here for the
# same reason: the sentence is the fix, and three renderers wording it three ways would let one
# of them drift back into reading silence as success.
FAIL_CLOSED_NOTE = ("Both halves of this report read silence the same way. The gate withholds "
                    "certification on a control that was never proven, because an unsupplied "
                    "control is an unproven one - the paranoia mandate. The scorecard reports "
                    "an axis or sub-characteristic with no mapped finding and no proving "
                    "control as not assessed rather than scoring it, and excludes it from the "
                    "overall figure and from the radar. Absence of a finding is not evidence "
                    "of a control: an axis with no coverage is reported as not assessed, and it "
                    "moves the headline number in neither direction.")

HORIZONS = ("Before any production traffic", "Before billing goes live", "Hardening backlog")

# Categories on the money path: a Medium here cannot wait for the hardening backlog.
MONEY_PATH_CATEGORIES = ("BILLING", "BILLING-BYPASS", "API4", "API6", "A09")
MONEY_PATH_CHAINS = ("bypass-billing", "free-chatbot", "mint-tokens")

EFFORT_RANK = {"S": 0, "M": 1, "L": 2, "": 3}

GLOSSARY = (
    ("ASVS", "OWASP Application Security Verification Standard 4.0 - the requirement "
             "catalogue this report maps findings onto."),
    ("Aggregate finding", "A rolled-up set of scanner rows of one class (dependency, IaC) "
                          "published under a G-banded directory. Never a cold-verified Critical."),
    ("CVSS", "Common Vulnerability Scoring System v3.1 base score, 0.0-10.0."),
    ("CWE", "Common Weakness Enumeration - the weakness class behind a finding."),
    ("Confirmed", "A line of code was read that proves the flaw."),
    ("Display id", "The reader-facing finding id (C1, H2, G1). Renumbers between runs."),
    ("Finding class", "How the signal was produced: reasoned, code, secret, dependency, iac. "
                      "Only the first three are promoted individually."),
    ("Gate", "The eight-control production-readiness check. Unset control = unproven = fail."),
    ("KAVACH id", "The stable machine fingerprint of a finding, constant across runs."),
    ("Kill chain", "One of the six attacker goals the findings are reconciled against."),
    ("Suspected", "The flaw is indicated but needs a runtime test to confirm. Named in Limits."),
)

# Framework mapping, keyed on the category token before the first ':'. Only rows that are
# genuinely derivable are populated - an empty cell reads as "not derivable", never as "clean".
FRAMEWORK_MAP = {
    "A01": ("OWASP Top 10 2021 A01 Broken Access Control", "V4 Access Control",
            "CWE-284", "Art. 5(1)(f), Art. 32"),
    "A02": ("OWASP Top 10 2021 A02 Cryptographic Failures", "V6 Stored Cryptography",
            "CWE-311", "Art. 32(1)(a)"),
    "A03": ("OWASP Top 10 2021 A03 Injection", "V5 Validation & Encoding", "CWE-74", ""),
    "A04": ("OWASP Top 10 2021 A04 Insecure Design", "V1 Architecture", "CWE-657", ""),
    "A05": ("OWASP Top 10 2021 A05 Security Misconfiguration", "V14 Configuration",
            "CWE-16", ""),
    "A06": ("OWASP Top 10 2021 A06 Vulnerable & Outdated Components",
            "V14.2 Dependency", "CWE-1104", ""),
    "A07": ("KAVACH A07 Secrets", "V6.4 Secret Management", "CWE-798", "Art. 32(1)(a)"),
    "A08": ("OWASP Top 10 2021 A08 Software & Data Integrity Failures",
            "V10 Malicious Code", "CWE-494", ""),
    "A09": ("OWASP Top 10 2021 A09 Logging & Monitoring Failures",
            "V7 Error Handling & Logging", "CWE-778", "Art. 33 (breach notification)"),
    "A10": ("OWASP Top 10 2021 A10 SSRF", "V5.2 Sanitization", "CWE-918", ""),
    "API1": ("OWASP API Top 10 2023 API1 BOLA", "V4 Access Control", "CWE-639",
             "Art. 5(1)(f), Art. 32"),
    "API2": ("OWASP API Top 10 2023 API2 Broken Authentication", "V2 Authentication",
             "CWE-287", ""),
    "API3": ("OWASP API Top 10 2023 API3 Object Property Level Authorization",
             "V4 Access Control", "CWE-915", "Art. 5(1)(c) data minimisation"),
    "API4": ("OWASP API Top 10 2023 API4 Unrestricted Resource Consumption",
             "V11 Business Logic", "CWE-770", ""),
    "API5": ("OWASP API Top 10 2023 API5 BFLA", "V4 Access Control", "CWE-285", ""),
    "API6": ("OWASP API Top 10 2023 API6 Sensitive Business Flows", "V11 Business Logic",
             "CWE-840", ""),
    "API7": ("OWASP API Top 10 2023 API7 SSRF", "V5.2 Sanitization", "CWE-918", ""),
    "API8": ("OWASP API Top 10 2023 API8 Security Misconfiguration", "V14 Configuration",
             "CWE-16", ""),
    "API9": ("OWASP API Top 10 2023 API9 Improper Inventory Management", "V1 Architecture",
             "CWE-1059", ""),
    "API10": ("OWASP API Top 10 2023 API10 Unsafe Consumption of APIs",
              "V13 API & Web Service", "CWE-1104", ""),
    "LLM01": ("OWASP LLM Top 10 LLM01 Prompt Injection", "V5 Validation & Encoding",
              "CWE-1427", ""),
    "LLM02": ("OWASP LLM Top 10 LLM02 Insecure Output Handling", "V5 Validation & Encoding",
              "CWE-79", ""),
    "LLM03": ("OWASP LLM Top 10 LLM03 Training Data Poisoning", "V10 Malicious Code",
              "CWE-1395", ""),
    "LLM04": ("OWASP LLM Top 10 LLM04 Model Denial of Service", "V11 Business Logic",
              "CWE-770", ""),
    "LLM05": ("OWASP LLM Top 10 LLM05 Supply Chain", "V14.2 Dependency", "CWE-1104", ""),
    "LLM06": ("OWASP LLM Top 10 LLM06 Sensitive Information Disclosure",
              "V8 Data Protection", "CWE-200", "Art. 5(1)(f), Art. 32"),
    "LLM07": ("OWASP LLM Top 10 LLM07 Insecure Plugin Design", "V1 Architecture",
              "CWE-1427", ""),
    "LLM08": ("OWASP LLM Top 10 LLM08 Excessive Agency", "V1 Architecture", "CWE-250", ""),
    "LLM09": ("OWASP LLM Top 10 LLM09 Overreliance", "V1 Architecture", "", ""),
    "LLM10": ("OWASP LLM Top 10 LLM10 Model Theft", "V8 Data Protection", "CWE-200",
              "Art. 32"),
}

REFERENCE_STANDARDS = (
    "OWASP Top 10 2021",
    "OWASP API Security Top 10 2023",
    "OWASP Top 10 for LLM Applications",
    "OWASP ASVS 4.0",
    "CWE / CVSS v3.1",
    "GDPR Art. 5 & Art. 32",
)

# Reproduction command per scanner source, for Annex C. Only sources that actually produced
# a finding in this run are printed. Keyed on a bare scanner id, so every lookup goes through
# triage.sources - the raw Finding.source may carry a merge alias or a dedupe concatenation.
SOURCE_COMMANDS = {
    "trivy": "trivy fs --scanners vuln,secret,misconfig .",
    "trivy-secret": "trivy fs --scanners secret .",
    "pip-audit": "pip-audit -r requirements.txt",
    "npm-audit": "npm audit --json",
    "osv-scanner": "osv-scanner -r .",
    "guarddog": "guarddog pypi scan .",
    "gitleaks": "gitleaks detect --source . --no-git",
    "trufflehog": "trufflehog filesystem . --json",
    "semgrep": "semgrep --config auto .",
    "bandit": "bandit -r .",
    "gosec": "gosec ./...",
    "checkov": "checkov -d .",
    "kics": "kics scan -p .",
    "hadolint": "hadolint Dockerfile",
    "builtin-secrets": "python3 -m kavach sweep . --out .kavach",
}


@dataclass
class Chapter:
    key: str
    title: str
    narrative: str
    findings: list[Finding] = field(default_factory=list)


@dataclass
class Section:
    """One entry in the contents. ``number`` is "" for the unnumbered front and back matter."""

    key: str
    number: str
    title: str

    @property
    def heading(self) -> str:
        return f"{self.number}. {self.title}" if self.number else self.title


@dataclass
class AuditReport:
    """Everything every renderer needs, and nothing a renderer has to re-derive."""

    meta: dict
    gate: GateResult
    counts: dict
    axes: list[Axis]
    findings: list[Finding]
    promoted: list[dict]
    chapters: list[Chapter]
    remediation: list[dict]
    limits: list[str]
    narrative: dict
    figure_commands: list = field(default_factory=list)
    scorecard: Scorecard | None = None
    controls: dict = field(default_factory=dict)
    recon: dict = field(default_factory=dict)
    frameworks: list = field(default_factory=list)
    class_counts: dict = field(default_factory=dict)
    display_ids: dict = field(default_factory=dict)

    def anchor_text(self, key: str) -> str:
        return (self.narrative.get(key) or "").strip()

    def ref(self, finding: Finding) -> str:
        """Reader-facing reference: the promoted display id when there is one, else the id."""
        return self.display_ids.get(finding.id, finding.id)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def chapter(self, key: str) -> Chapter:
        for c in self.chapters:
            if c.key == key:
                return c
        raise KeyError(key)

    def to_dict(self) -> dict:
        return {
            "meta": self.meta,
            "gate": self.gate.to_dict(),
            "counts": self.counts,
            "class_counts": self.class_counts,
            "scorecard": self.scorecard.to_dict() if self.scorecard else {},
            "promoted": self.promoted,
            "remediation": self.remediation,
            "limits": self.limits,
            "frameworks": [
                {"category": c, "count": n, "owasp": o, "asvs": a, "cwe": w, "gdpr": g}
                for c, n, o, a, w, g in self.frameworks
            ],
            "figure_commands": [{"caption": c, "command": cmd}
                                for c, cmd in self.figure_commands],
            "narrative": {k: self.narrative.get(k, "") for k in ANCHORS},
        }


def tier(findings: list[Finding]) -> dict:
    """Split a chapter's findings into the four presentation tiers.

    Returns ``{"full": [...], "compact": [...], "counted": [...], "rolled": [...]}``. Every
    finding lands in exactly one bucket, so a renderer that walks all four has shown the
    whole chapter.
    """
    rolled = [f for f in findings if f.finding_class in AGGREGATE_CLASSES]
    rest = [f for f in findings if f.finding_class not in AGGREGATE_CLASSES]
    return {
        "full": [f for f in rest if f.severity in FULL_BLOCK],
        "compact": [f for f in rest if f.severity in COMPACT],
        "counted": [f for f in rest if f.severity in COUNTED],
        "rolled": sorted(rolled, key=lambda f: (-f.severity.rank, -f.cvss_score, f.title)),
    }


def outline(report: "AuditReport") -> list:
    """The document's section list, numbered by the renderer.

    Section numbering is owned here so markdown, HTML and PDF cannot disagree, and so the
    shipped report can no longer come out as "§1, §2, §0, §5, §7" with 3, 4 and 6 missing.
    """
    front = [Section("contents", "", "Contents"), Section("glossary", "", "Glossary")]
    fixed_head = [
        ("exec", "Executive summary"),
        ("scope", "Scope, method and limits"),
        ("scoring", "Scoring reference"),
        ("frameworks", "Framework mapping"),
        ("attack-trees", "Attack-tree findings"),
    ]
    body = [Section(key, str(i), title) for i, (key, title) in enumerate(fixed_head, 1)]
    n = len(fixed_head)
    for chapter in report.chapters:
        n += 1
        body.append(Section(f"chapter:{chapter.key}", str(n), chapter.title))
    for key, title in (("remediation", "Remediation plan"),
                       ("verdict", "Production-readiness verdict"),
                       ("residual", "Residual risk"),
                       ("limits", "Limits of this assessment")):
        n += 1
        body.append(Section(key, str(n), title))
    back = [
        Section("annex-a", "", "Annex A - Score justification"),
        Section("annex-b", "", "Annex B - Findings inventory"),
        Section("annex-c", "", "Annex C - Reproducing the figures"),
        Section("appendix-b", "", "Appendix B - Coverage"),
    ]
    return front + body + back


def section(report: "AuditReport", key: str) -> Section:
    for s in outline(report):
        if s.key == key:
            return s
    raise KeyError(f"no section '{key}'")


def _read_json(path: str):
    """Read a JSON artifact, or return None. Absence is a normal state, not an error."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _category_token(category: str) -> str:
    return (category or "").strip().upper().split(":", 1)[0].strip()


def load_promoted(audit_dir: str) -> list[dict]:
    """The promoted finding tree as the report sees it: display_id, dir, severity, aggregate."""
    if not audit_dir:
        return []
    out = []
    pattern = os.path.join(audit_dir, "findings", "*", "metadata.json")
    for path in sorted(glob.glob(pattern)):
        meta = _read_json(path)
        if not isinstance(meta, dict) or not meta.get("display_id"):
            continue
        fdir = os.path.dirname(path)
        out.append({
            "display_id": meta["display_id"],
            "dir": os.path.join("findings", os.path.basename(fdir)),
            "severity": meta.get("severity", ""),
            "is_aggregate": bool(meta.get("is_aggregate")),
            "kavach_id": meta.get("kavach_id", ""),
            "member_count": meta.get("member_count", 0),
            "finding_class": meta.get("finding_class", ""),
        })
    out.sort(key=lambda p: (p["display_id"][:1], _display_n(p["display_id"])))
    return out


def _display_n(display_id: str) -> int:
    digits = "".join(ch for ch in display_id if ch.isdigit())
    return int(digits) if digits else 0


def budget_shed(audit_dir: str, audit_id: str = "") -> list[dict]:
    """The shed records from ``audit-state.json``, newest audit last.

    Read out of the raw JSON rather than through ``budget.py`` so the report model stays
    independent of the ledger's own module - the on-disk key is the contract (§A5).
    """
    if not audit_dir:
        return []
    raw = _read_json(os.path.join(audit_dir, "audit-state.json"))
    if not isinstance(raw, dict):
        return []
    out = []
    for audit in raw.get("audits") or []:
        if not isinstance(audit, dict):
            continue
        if audit_id and audit.get("audit_id") != audit_id:
            continue
        ledger = audit.get("budget")
        if not isinstance(ledger, dict):
            continue
        for record in ledger.get("shed") or []:
            if isinstance(record, dict):
                out.append(record)
    return out


def coverage_gaps(audit_dir: str) -> list[dict]:
    """The two ``*-coverage.json`` artifacts, in the order the report names them."""
    if not audit_dir:
        return []
    out = []
    for kind in ("poc", "report"):
        doc = _read_json(os.path.join(audit_dir, "attack-surface", f"{kind}-coverage.json"))
        if isinstance(doc, dict):
            out.append(doc)
    return out


def load_narrative(audit_dir: str) -> dict:
    """VAJRA's prose per anchor, from ``attack-surface/narrative.json``.

    Shape: ``{"exec-summary": "...", ...}``. Unknown keys are ignored; missing anchors
    render as NOT_SUPPLIED rather than vanishing.
    """
    doc = _read_json(os.path.join(audit_dir, "attack-surface", "narrative.json")) if audit_dir \
        else None
    if not isinstance(doc, dict):
        return {}
    return {k: str(v) for k, v in doc.items() if k in ANCHORS and str(v).strip()}


def _limits(findings: list[Finding], audit_dir: str, audit_id: str) -> list[str]:
    out: list[str] = []

    for record in budget_shed(audit_dir, audit_id):
        phase = record.get("phase", "?")
        planned = record.get("planned", 0)
        dropped = record.get("dropped", 0)
        reason = record.get("reason", "budget")
        out.append(f"Phase {phase}: {dropped} of {planned} planned subagent dispatches were "
                   f"dropped ({reason}). Those findings were not investigated.")

    for doc in coverage_gaps(audit_dir):
        kind = doc.get("kind", "?")
        missing = [m for m in (doc.get("missing") or []) if isinstance(m, dict)]
        if not missing:
            continue
        label = "proof of concept" if kind == "poc" else "per-finding write-up"
        ids = ", ".join(m.get("display_id", "?") for m in missing[:12])
        tail = f" and {len(missing) - 12} more" if len(missing) > 12 else ""
        out.append(f"{len(missing)} of {doc.get('total', len(missing))} promoted findings have "
                   f"no {label}: {ids}{tail}.")

    stale = max((doc.get("stale") or 0 for doc in coverage_gaps(audit_dir)), default=0)
    if stale:
        out.append(f"{stale} promoted directory(ies) from an earlier run are no longer part of "
                   "this audit and were excluded from the coverage gates - see "
                   "attack-surface/poc-coverage.json `stale_dirs` for each one and why.")

    suspected = [f for f in findings if f.confidence == Confidence.SUSPECTED]
    if suspected:
        ids = ", ".join(f.id for f in suspected[:12])
        tail = f" and {len(suspected) - 12} more" if len(suspected) > 12 else ""
        out.append(f"{len(suspected)} finding(s) are marked suspected - indicated by static "
                   f"analysis but not confirmed by a runtime test: {ids}{tail}.")

    return out


def _horizon(finding: Finding) -> int:
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return 0
    token = _category_token(finding.category)
    chain = (finding.kill_chain or "").strip().lower()
    if token in MONEY_PATH_CATEGORIES or chain in MONEY_PATH_CHAINS:
        return 1
    return 2


def _remediation(findings: list[Finding], display_ids: dict) -> list[dict]:
    """One action row per (horizon, category), ordered by horizon then severity then effort."""
    buckets: dict = {}
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        buckets.setdefault((_horizon(f), f.category or "uncategorized"), []).append(f)

    rows = []
    for (horizon, category), members in buckets.items():
        members.sort(key=lambda f: (-f.severity.rank, EFFORT_RANK.get(f.effort, 3), f.id))
        top = members[0]
        action = top.remediation.strip() or f"Remediate the {category} findings"
        rows.append({
            "horizon": HORIZONS[horizon],
            "_sort": (horizon, -top.severity.rank,
                      EFFORT_RANK.get(top.effort, 3), category),
            "category": category,
            "action": action,
            "addresses": [display_ids.get(f.id, f.id) for f in members],
            "effort": max((f.effort for f in members if f.effort),
                          key=lambda e: EFFORT_RANK.get(e, 3), default=""),
            "severity": top.severity.value,
        })
    rows.sort(key=lambda r: r["_sort"])
    for n, row in enumerate(rows, 1):
        row.pop("_sort")
        row["n"] = n
    return rows


def _frameworks(findings: list[Finding]) -> list:
    """(category, count, owasp, asvs, cwe, gdpr) per distinct category in the finding set."""
    seen: dict = {}
    for f in findings:
        cat = f.category or "uncategorized"
        entry = seen.setdefault(cat, {"n": 0, "cwe": []})
        entry["n"] += 1
        for candidate in list(f.references) + [f.rule_id]:
            token = (candidate or "").strip().upper()
            if token.startswith("CWE-") and token not in entry["cwe"]:
                entry["cwe"].append(token)

    rows = []
    for cat in sorted(seen):
        mapped = FRAMEWORK_MAP.get(_category_token(cat), ("", "", "", ""))
        cwes = seen[cat]["cwe"] or ([mapped[2]] if mapped[2] else [])
        rows.append((cat, seen[cat]["n"], mapped[0], mapped[1],
                     ", ".join(sorted(set(cwes))[:4]), mapped[3]))
    return rows


def _figure_commands(findings: list[Finding], audit_dir: str) -> list:
    out = [
        ("Severity counts in §3 Risk dashboard",
         "kavach render --out .kavach --format json | jq '.gate.counts'"),
        ("Findings by class in §1 Executive summary",
         "kavach render --out .kavach --format json | jq '.class_counts'"),
        ("Six-axis scorecard and every deduction in Annex A",
         "kavach render --out .kavach --format json | jq '.scorecard'"),
        ("Gate verdict and the eight controls in §8",
         "kavach gate --out .kavach --controls .kavach/controls.json"),
        ("File coverage in Appendix B",
         "wc -l .kavach/file-manifest.txt"),
    ]
    # Match on normalised source *segments*, never on the raw field. `Finding.source` is
    # rewritten by merge (`a:trivy`) and by dedupe (`trivy+semgrep`), so a literal lookup
    # misses every corroborated finding - which shortens Annex C instead of breaking it, and
    # a quietly shrinking annex is the worst failure mode this report has. triage.sources is
    # the one place that understands both rewrites; do not parse them here.
    present = sorted({s for f in findings for s in source_segments(f) if s in SOURCE_COMMANDS})
    for source in present:
        n = sum(1 for f in findings if source in source_segments(f))
        out.append((f"{n} finding(s) attributed to {source}", SOURCE_COMMANDS[source]))
    if audit_dir and os.path.isdir(os.path.join(audit_dir, "findings")):
        out.append(("Promoted finding tree in Annex B",
                    "find .kavach/findings -maxdepth 1 -mindepth 1 -type d | sort"))
    out.append(("This document",
                "kavach render --out .kavach --format pdf "
                "--output .kavach/reports/audit-report.pdf"))
    return out


def _volume(recon: dict) -> str:
    totals = recon.get("totals") or {}
    files = totals.get("files", 0)
    code = totals.get("code_files", 0)
    languages = len(recon.get("languages") or [])
    return f"{files:,} files walked ({code:,} code files, {languages} language(s))"


def build(findings: list[Finding], recon: dict, gate: GateResult,
          meta: dict | None = None) -> AuditReport:
    """Assemble the report model.

    ``meta`` is the renderer's one input channel, so the integrator has exactly one place
    to add a key. Recognised keys: ``version``, ``date``, ``commit``, ``mode``,
    ``audit_dir`` (unlocks limits/promoted/narrative/controls), ``controls`` (dict override),
    ``narrative`` (dict override), ``output`` (destination path, required by the PDF).
    """
    meta = dict(meta or {})
    audit_dir = meta.get("audit_dir") or ""
    audit_id = meta.get("audit_id") or ""

    controls = meta.get("controls")
    if not isinstance(controls, dict):
        controls = _read_json(os.path.join(audit_dir, "controls.json")) if audit_dir else None
        controls = controls if isinstance(controls, dict) else {}
    controls = {k: v for k, v in controls.items() if k in GATE_CONTROLS}

    narrative = meta.get("narrative")
    if not isinstance(narrative, dict):
        narrative = load_narrative(audit_dir)
    narrative = {k: str(v) for k, v in narrative.items() if k in ANCHORS and str(v).strip()}

    promoted = load_promoted(audit_dir)
    display_ids = {p["kavach_id"]: p["display_id"] for p in promoted if p.get("kavach_id")}

    # Classify on load, exactly as findings_tree.consolidate does (findings_tree.py:204, :293),
    # so a findings.json that never went through `kavach triage` upgrades transparently here
    # too. The renderer is the second consumer of finding_class and it must not assume an
    # upstream verb ran: SKILL.md sequences triage before render, but README documents the core
    # as usable standalone and `kavach render --out .kavach` is what an operator reaches for on
    # an existing tree. Un-triaged, every row read as `unclassified` - Figure 3 showed one bar
    # instead of the scanner-noise share it exists to show, the `class:` keys in AXIS_MAP were
    # inert, and the aggregate rollup never fired, so 141 dependency rows deducted one-by-one
    # instead of once per severity band. classify_all returns a new list and is idempotent, so
    # this is free on the normal path. Rendering stays read-only: findings.json is not rewritten.
    ordered = sorted(classify_all(findings), key=lambda f: (-f.severity.rank, -f.cvss_score, f.id))
    card = score(ordered, controls)

    chapters = [
        Chapter(key=axis.key, title=axis.label, narrative=axis.reading,
                findings=[f for f in ordered if axis_for(f) == axis.key])
        for axis in card.axes
    ]

    report_meta = {
        "target": recon.get("root", ""),
        "commit": meta.get("commit", ""),
        "date": meta.get("date", ""),
        "mode": meta.get("mode", ""),
        "version": meta.get("version", ""),
        "files_walked": (recon.get("totals") or {}).get("files", 0),
        "volume": _volume(recon),
        "reference_standards": list(REFERENCE_STANDARDS),
    }

    return AuditReport(
        meta=report_meta,
        gate=gate,
        counts=dict(gate.counts),
        axes=card.axes,
        findings=ordered,
        promoted=promoted,
        chapters=chapters,
        remediation=_remediation(ordered, display_ids),
        limits=_limits(ordered, audit_dir, audit_id),
        narrative=narrative,
        figure_commands=_figure_commands(ordered, audit_dir),
        scorecard=card,
        controls=controls,
        recon=recon,
        frameworks=_frameworks(ordered),
        class_counts=class_counts(ordered),
        display_ids=display_ids,
    )
