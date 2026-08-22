"""Pure scoring and the production-readiness gate.

No I/O, no rendering - just functions over ``Finding`` lists so the same numbers back
the terminal summary, the JSON report, and the CI exit code.
"""

from __future__ import annotations

from dataclasses import dataclass

from .finding import Finding, Severity

# The eight control booleans of KAVACH Section 6. Deterministic scanning can only
# assert a subset; the rest are supplied by the reconciler after the subagents run.
GATE_CONTROLS = [
    "no_client_reachable_secret",
    "billing_server_side_enforced",
    "authz_on_every_object_and_function",
    "ai_guardrails_present",
    "encryption_tls_and_at_rest",
    "rate_limits_on_expensive_endpoints",
    "no_debug_or_secret_leak_in_prod",
    "webhooks_verified_and_idempotent",
]


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {s.value: 0 for s in Severity}
    for f in findings:
        out[f.severity.value] += 1
    return out


@dataclass
class GateResult:
    passed: bool
    blockers: list[str]
    counts: dict[str, int]

    def to_dict(self) -> dict:
        return {"passed": self.passed, "blockers": self.blockers, "counts": self.counts}


def gate(findings: list[Finding], controls: dict[str, bool] | None = None,
         *, require_controls: bool = True) -> GateResult:
    """Production-readiness gate (KAVACH Section 6).

    Passes only if there are zero open Critical and zero open High findings *and* every
    supplied control boolean is true. Unsupplied controls are treated as unproven
    (fail-closed - the paranoia mandate).

    ``require_controls=False`` gates on severity counts alone - used for the deterministic
    scan before the subagents have supplied the control verdicts.
    """
    counts = counts_by_severity(findings)
    blockers: list[str] = []

    if counts["critical"]:
        blockers.append(f"{counts['critical']} open Critical finding(s)")
    if counts["high"]:
        blockers.append(f"{counts['high']} open High finding(s)")

    if require_controls:
        controls = controls or {}
        for control in GATE_CONTROLS:
            if controls.get(control) is not True:
                blockers.append(f"control unverified: {control}")

    return GateResult(passed=not blockers, counts=counts, blockers=blockers)


def exit_code(gate_result: GateResult) -> int:
    """CLI exit-code contract (stable API for CI)."""
    if gate_result.counts["critical"]:
        return 2
    if gate_result.counts["high"]:
        return 3
    if not gate_result.passed:
        return 4
    return 0
