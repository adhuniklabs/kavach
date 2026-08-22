"""Canonical KAVACH finding model.

Every signal - whether it comes from a Docker scanner, a domain subagent, or the
VAJRA reconciler - is normalized into a single ``Finding``. One model in means one
model out: scoring, gating, and every renderer consume the exact same shape, so the
report can never drift between formats.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # a line was read that proves the flaw
    SUSPECTED = "suspected"   # needs runtime verification / DAST


@dataclass
class Location:
    file: str
    line: int | None = None
    snippet: str | None = None


@dataclass
class Finding:
    """A single security finding in KAVACH's canonical form.

    ``id`` is derived (see :meth:`fingerprint`) and stays stable across line moves,
    which is what lets a later cut diff runs for drift.
    """

    title: str
    severity: Severity
    category: str                       # e.g. "A01" / "API1:BOLA" / "LLM01" / "Billing-Bypass"
    source: str                         # scanner id | subagent name | "reconciler"
    locations: list[Location] = field(default_factory=list)
    what_it_is: str = ""
    how_exploited: str = ""
    business_impact: str = ""
    remediation: str = ""
    fix_impact: str = ""
    effort: str = ""                    # S | M | L
    confidence: Confidence = Confidence.SUSPECTED
    cvss_vector: str = ""
    cvss_score: float = 0.0
    rule_id: str = ""                   # underlying scanner rule / CWE / OWASP id
    references: list[str] = field(default_factory=list)
    kill_chain: str | None = None       # which of the 6 attack trees this belongs to
    finding_class: str = ""             # "" until triage.classify() labels it
    id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        self.locations = [
            loc if isinstance(loc, Location) else Location(**loc) for loc in self.locations
        ]
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable id: category + normalized primary path + rule + title.

        Deliberately excludes the raw line number so a finding keeps its identity when
        surrounding code shifts.
        """
        primary = self.locations[0].file if self.locations else ""
        primary = os.path.normpath(primary).replace(os.sep, "/") if primary else ""
        basis = "\x1f".join([self.category, primary, self.rule_id, self.title.strip().lower()])
        digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10]
        return f"KAVACH-{digest}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        d = dict(d)
        d.pop("id", None)  # always re-derive
        return cls(**d)


def load_findings(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows = data["findings"] if isinstance(data, dict) else data
    return [Finding.from_dict(r) for r in rows]


def dump_findings(findings: list[Finding], path: str, meta: dict[str, Any] | None = None) -> None:
    payload = {"meta": meta or {}, "findings": [f.to_dict() for f in findings]}
    tmp = f"{path}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    os.replace(tmp, path)
