"""Phase 1 orchestration - run applicable scanners and merge their findings.

Each scanner is independent, so a missing Docker image or a broken tool degrades to an
``unavailable``/``error`` outcome without aborting the sweep. The dedupe step collapses
the same defect reported by two tools (e.g. gitleaks + trivy both finding one secret)
into a single finding while remembering which sources corroborated it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .finding import Finding
from .scanners import ScanOutcome, applicable_scanners


@dataclass
class SweepResult:
    findings: list[Finding]
    outcomes: list[ScanOutcome] = field(default_factory=list)

    @property
    def unavailable(self) -> list[str]:
        return [o.scanner_id for o in self.outcomes if o.status == "unavailable"]

    def summary(self) -> dict[str, Any]:
        return {
            "scanners_run": [o.to_dict() for o in self.outcomes],
            "unavailable": self.unavailable,
            "total_findings": len(self.findings),
        }


def run_sweep(target: str, recon: dict) -> SweepResult:
    scanners = applicable_scanners(recon)
    outcomes: list[ScanOutcome] = []
    collected: list[Finding] = []
    for scanner in scanners:
        outcome = scanner.run(target, recon)
        outcomes.append(outcome)
        collected.extend(outcome.findings)
    return SweepResult(findings=dedupe(collected), outcomes=outcomes)


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_id: dict[str, Finding] = {}
    for f in findings:
        existing = by_id.get(f.id)
        if existing is None:
            by_id[f.id] = f
            continue
        # keep the higher-severity representation; record corroborating source
        keep, drop = (existing, f) if existing.severity.rank >= f.severity.rank else (f, existing)
        if drop.source not in keep.source:
            keep.source = f"{keep.source}+{drop.source}"
        by_id[f.id] = keep
    return sorted(by_id.values(), key=lambda f: (-f.severity.rank, f.category, f.title))
