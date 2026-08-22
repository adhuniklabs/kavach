"""Fail-open insecure-defaults scanner - dependency-free, always on.

A fail-open default (``SECRET = env.get('KEY') or 'default'``) lets the app run
insecurely when configuration is simply missing, instead of refusing to start
(fail-secure). High-signal patterns only, same precision-over-recall philosophy as
builtin_secrets.py: an explicit sensitive-sounding name (secret/password/token/key)
or a known security-relevant flag (auth/debug/CORS), never a bare generic default.
"""

from __future__ import annotations

import os
import re

from ..finding import Confidence, Finding, Location, Severity
from .base import ScanOutcome, Scanner

# (rule id, human name, severity, compiled pattern, what/how/impact/remediation)
_PATTERNS = [
    (
        "fallback-secret", "Fallback secret from environment default", Severity.CRITICAL,
        re.compile(
            r"(?i)"
            r"(?:os\.(?:environ\.get|getenv)\(\s*['\"]\w*(?:secret|password|token|api_?key|credential)\w*['\"]\s*,\s*['\"][^'\"]{4,}['\"]\s*\)"
            r"|process\.env\.\w*(?:secret|password|token|api_?key|credential)\w*\s*\|\|\s*['\"][^'\"]{4,}['\"]"
            r"|env\.fetch\(\s*['\"]\w*(?:secret|password|token|api_?key|credential)\w*['\"]\s*,\s*['\"][^'\"]{4,}['\"]\s*\)"
            # `<something>.get(<sensitive key>) or '<literal>'` - the .get()-or idiom, key side
            r"|\w+(?:\.\w+)*\.get\(\s*['\"]\w*(?:secret|password|token|api_?key|credential)\w*['\"]\s*\)\s*or\s*['\"][^'\"]{4,}['\"]"
            # `SENSITIVE_NAME = os.environ.get(...) or '<literal>'` - same idiom, assignment side
            r"|\w*(?:secret|password|token|api_?key|credential)\w*\s*=\s*"
            r"(?:os\.environ\.get|os\.getenv|\w+(?:\.\w+)*\.get)\(\s*['\"][^'\"]*['\"]\s*\)\s*or\s*['\"][^'\"]{4,}['\"])"
        ),
        "The app runs with a hardcoded fallback secret when the environment variable is unset.",
        "An attacker who can prevent the real secret from being configured (missing "
        "deploy var, stripped container env, misconfigured CI) gets the app running "
        "with a known, public value - forging tokens or reusing the fallback directly.",
        "Key theft / auth bypass: anyone who reads this source knows the fallback and "
        "can sign valid credentials or authenticate as the app itself.",
        "Read the value with no default (crash on missing config) or validate it "
        "explicitly at startup. Never let a secret silently fall back to a literal.",
    ),
    (
        "fail-open-flag", "Fail-open security flag defaults to disabled", Severity.HIGH,
        re.compile(
            r"(?i)"
            r"(?:os\.(?:environ\.get|getenv)\(\s*['\"](?:require_auth|auth_required|auth_enabled|verify_ssl|ssl_verify)['\"]\s*,\s*['\"]?false['\"]?\s*\)"
            r"|process\.env\.(?:REQUIRE_AUTH|AUTH_REQUIRED|AUTH_ENABLED|VERIFY_SSL|SSL_VERIFY)\s*\|\|\s*['\"]?false['\"]?)"
        ),
        "A security-relevant flag (auth requirement, TLS verification) defaults to "
        "disabled/false when its environment variable is unset.",
        "Missing configuration silently disables authentication or certificate "
        "verification instead of crashing - the app runs open by default.",
        "Authentication bypass or MITM exposure whenever the flag isn't explicitly set.",
        "Default security flags to their secure value, or better, require them "
        "explicitly and crash on missing config.",
    ),
    (
        "debug-default-true", "Debug mode defaults to enabled", Severity.MEDIUM,
        re.compile(
            r"(?i)"
            r"(?:os\.(?:environ\.get|getenv)\(\s*['\"]debug['\"]\s*,\s*['\"]?true['\"]?\s*\)"
            r"|process\.env\.(?:DEBUG|NODE_DEBUG)\s*\|\|\s*['\"]?true['\"]?)"
        ),
        "Debug mode is enabled by default when the environment variable is unset.",
        "Stack traces, verbose errors, or introspection endpoints leak internal "
        "implementation details to any client that triggers an error.",
        "Information disclosure - internal paths, library versions, query structure.",
        "Default debug mode to disabled; only enable it via an explicit, "
        "environment-scoped flag.",
    ),
    (
        "cors-wildcard", "CORS defaults to allow-all origin", Severity.HIGH,
        re.compile(
            r"(?i)"
            r"(?:access-control-allow-origin['\"\]]*\s*[:=]\s*['\"]\*['\"]"
            r"|origin\s*:\s*['\"]\*['\"]"
            r"|process\.env\.\w*ORIGINS?\w*\s*\|\|\s*['\"]\*['\"])"
        ),
        "CORS is configured (or defaults) to allow requests from any origin.",
        "Any site can make credentialed cross-origin requests against this API on "
        "behalf of a logged-in victim, exfiltrating session data or triggering actions.",
        "Cross-origin data theft / CSRF-style abuse of authenticated endpoints.",
        "Require an explicit allow-list of origins; never default or fall back to '*' "
        "on an endpoint that accepts credentials.",
    ),
]

_IGNORE_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "target", "__pycache__",
    ".venv", "venv", "vendor", ".terraform", "coverage", ".mypy_cache", ".pytest_cache",
}
_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".lock",
             ".woff", ".woff2", ".ttf", ".ico", ".mp4", ".mp3", ".map"}
_SKIP_SUFFIXES = (".min.js",)  # multi-part extensions splitext() can't match via _SKIP_EXT
_MAX_BYTES = 1_000_000


class FailOpenDefaultsScanner(Scanner):
    id = "fail-open-defaults"
    title = "Fail-open insecure defaults (no dependencies)"
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
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
            for name in filenames:
                low = name.lower()
                _, ext = os.path.splitext(low)
                if ext in _SKIP_EXT or low.endswith(_SKIP_SUFFIXES):
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
                    stripped = line.strip()
                    if stripped.startswith(("//", "#")):
                        continue
                    for rule_id, human, severity, pattern, what, how, impact, fix in _PATTERNS:
                        m = pattern.search(line)
                        if not m:
                            continue
                        findings.append(_finding(rule_id, human, severity, rel, lineno,
                                                 line.strip(), what, how, impact, fix))
        return ScanOutcome(self.id, "ok", findings=findings, runner="native")


_CVSS = {
    Severity.CRITICAL: ("9.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    Severity.HIGH: ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.MEDIUM: ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}


def _finding(rule_id, human, severity, rel, lineno, snippet, what, how, impact, fix) -> Finding:
    score, vector = _CVSS[severity]
    return Finding(
        title=f"Fail-open default: {human}",
        severity=severity,
        category="A05:Misconfig",
        source="fail-open-defaults",
        rule_id=rule_id,
        confidence=Confidence.SUSPECTED,
        cvss_score=float(score),
        cvss_vector=vector,
        locations=[Location(file=rel, line=lineno, snippet=snippet[:200])],
        what_it_is=what,
        how_exploited=how,
        business_impact=impact,
        remediation=fix,
        references=["CWE-1188", "OWASP-A05"],
    )
