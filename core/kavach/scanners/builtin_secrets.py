"""Dependency-free secret scanner - the deterministic floor.

gitleaks/trivy are better, but they need Docker or a native binary. This pure-Python
scanner always runs so the operator's #1 nightmare (a committed key) is never missed just
because no tool was installed. High-signal patterns only - precision over recall; the
richer tools and the SAST subagent widen the net.
"""

from __future__ import annotations

import os
import re

from ..finding import Confidence, Finding, Location, Severity
from .base import ScanOutcome, Scanner

# (rule id, human name, compiled pattern). Anchored on provider-specific shapes to keep
# false positives low.
_PATTERNS = [
    ("anthropic-key", "Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", "OpenAI API key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("aws-access-key", "AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("gcp-key", "Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe-secret", "Stripe live secret key", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("github-pat", "GitHub personal access token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("slack-token", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("razorpay-secret", "Razorpay key secret", re.compile(r"rzp_live_[0-9A-Za-z]{14,}")),
    ("private-key", "Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("db-url", "Database connection string with credentials",
     re.compile(r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@")),
    ("generic-bearer", "Hardcoded bearer/authorization secret",
     re.compile(r"(?i)authorization[\"'\s:=]+bearer\s+[A-Za-z0-9._\-]{20,}")),
]

_IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "target", "__pycache__",
    ".venv", "venv", "vendor", ".terraform", "coverage", ".mypy_cache", ".pytest_cache",
}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".lock",
             ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mp3", ".min.js", ".map"}
_MAX_BYTES = 1_000_000


class BuiltinSecretsScanner(Scanner):
    id = "builtin-secrets"
    title = "Built-in secret scanner (no dependencies)"
    image = None
    native_binary = None

    def applies(self, recon: dict) -> bool:
        return True

    def docker_args(self, recon: dict) -> list[str]:
        return []

    def normalize(self, result, target, recon):  # pragma: no cover - run() overridden
        return []

    def run(self, target: str, recon: dict) -> ScanOutcome:
        findings: list[Finding] = []
        seen: set[str] = set()
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
            for name in filenames:
                _, ext = os.path.splitext(name.lower())
                if ext in _SKIP_EXT:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > _MAX_BYTES:
                        continue
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        lines = fh.readlines()
                except OSError:
                    continue
                rel = os.path.relpath(path, target)
                for lineno, line in enumerate(lines, 1):
                    for rule_id, human, pattern in _PATTERNS:
                        m = pattern.search(line)
                        if not m:
                            continue
                        key = f"{rel}:{rule_id}:{_redact(m.group(0))}"
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(_finding(human, rule_id, rel, lineno, m.group(0)))
        return ScanOutcome(self.id, "ok", findings=findings, runner="native")


def _finding(human: str, rule_id: str, rel: str, lineno: int, match: str) -> Finding:
    return Finding(
        title=f"Hardcoded secret: {human}",
        severity=Severity.CRITICAL,
        category="A07:Secrets",
        source="builtin-secrets",
        rule_id=rule_id,
        confidence=Confidence.CONFIRMED,
        cvss_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        locations=[Location(file=rel, line=lineno, snippet=_redact(match))],
        what_it_is=f"A {human} is committed in source.",
        how_exploited="Anyone with repo read access, a shipped bundle, or git history lifts "
                      "the key and uses it directly on the operator's account.",
        business_impact="Key theft: attacker runs the operator's paid LLM/API for free, "
                        "exfiltrates data, or racks up cloud spend.",
        remediation="Remove the literal, rotate the credential now, and load it from a secret "
                    "manager or deploy-time env injection. Purge it from git history.",
        references=["CWE-798", "OWASP-A07"],
    )


def _redact(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:3] + "…"
    return f"{secret[:6]}…{secret[-4:]}"
