"""Infrastructure-as-code and container hardening - checkov (IaC) and hadolint (Dockerfile)."""

from __future__ import annotations

import json
import os

from ..dockerutil import ToolResult
from ..finding import Confidence, Finding, Location, Severity
from .base import Scanner

_CHECKOV_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
_HADOLINT_SEV = {"error": Severity.MEDIUM, "warning": Severity.LOW,
                 "info": Severity.INFO, "style": Severity.INFO}


class CheckovScanner(Scanner):
    id = "checkov"
    title = "Checkov (IaC misconfiguration)"
    image = "bridgecrew/checkov:latest"
    native_binary = "checkov"
    network = "none"

    def applies(self, recon: dict) -> bool:
        caps = recon.get("capabilities", {})
        iac = recon.get("iac", {})
        return caps.get("has_iac") or caps.get("has_dockerfile") or bool(iac.get("compose"))

    def docker_args(self, recon: dict) -> list[str]:
        return ["-d", "/src", "-o", "json", "--compact", "--quiet"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["checkov", "-d", ".", "-o", "json", "--compact", "--quiet"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        payload = _load_any(result.stdout)
        blocks = payload if isinstance(payload, list) else [payload]
        findings: list[Finding] = []
        for block in blocks:
            checks = ((block.get("results", {}) or {}).get("failed_checks", []) or []) \
                if isinstance(block, dict) else []
            for c in checks:
                sev = _CHECKOV_SEV.get(str(c.get("severity", "")).upper(), Severity.MEDIUM)
                rng = c.get("file_line_range", []) or []
                findings.append(Finding(
                    title=str(c.get("check_name", c.get("check_id", "IaC misconfig")))[:140],
                    severity=sev, category="A05:Misconfiguration", source=self.id,
                    rule_id=c.get("check_id", ""), confidence=Confidence.CONFIRMED,
                    locations=[Location(file=str(c.get("file_path", "")).lstrip("/"),
                                        line=rng[0] if rng else None)],
                    what_it_is=str(c.get("check_name", "")),
                    remediation=str(c.get("guideline", "") or "See the Checkov policy guideline."),
                    references=[u for u in [c.get("guideline")] if u],
                ))
        return findings


class HadolintScanner(Scanner):
    id = "hadolint"
    title = "Hadolint (Dockerfile hardening)"
    image = "hadolint/hadolint:latest"
    native_binary = "hadolint"
    network = "none"

    def applies(self, recon: dict) -> bool:
        return bool(recon.get("iac", {}).get("dockerfiles"))

    def docker_args(self, recon: dict) -> list[str]:
        dockerfiles = recon.get("iac", {}).get("dockerfiles", [])
        return ["hadolint", "-f", "json", *[f"/src/{d}" for d in dockerfiles]]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        dockerfiles = recon.get("iac", {}).get("dockerfiles", [])
        return ["hadolint", "-f", "json", *dockerfiles]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        raw = _load_any(result.stdout)
        rows = raw if isinstance(raw, list) else []
        findings: list[Finding] = []
        for r in rows:
            sev = _HADOLINT_SEV.get(str(r.get("level", "")).lower(), Severity.INFO)
            code = r.get("code", "")
            findings.append(Finding(
                title=f"Dockerfile: {code} {r.get('message','')}"[:140],
                severity=sev, category="A05:Misconfiguration", source=self.id,
                rule_id=code, confidence=Confidence.CONFIRMED,
                locations=[Location(file=str(r.get("file", "")).replace("/src/", ""),
                                    line=r.get("line"))],
                what_it_is=str(r.get("message", "")),
                remediation=f"See hadolint rule {code}.",
                references=[f"https://github.com/hadolint/hadolint/wiki/{code}"] if code else [],
            ))
        return findings


class KicsScanner(Scanner):
    """KICS (Checkmarx) - broadest IaC coverage (Terraform, K8s, Ansible, Helm, OpenAPI,
    CDK, Dockerfile, and more), beyond checkov/trivy. Writes its report to a file."""

    id = "kics"
    title = "KICS (IaC misconfiguration)"
    image = "checkmarx/kics:latest"
    native_binary = "kics"
    network = "none"
    needs_writable_out = True

    def applies(self, recon: dict) -> bool:
        caps = recon.get("capabilities", {})
        iac = recon.get("iac", {})
        return caps.get("has_iac") or caps.get("has_dockerfile") or bool(iac.get("compose"))

    def docker_args(self, recon: dict) -> list[str]:
        return ["scan", "-p", "/src", "--report-formats", "json", "-o", "/out",
                "--output-name", "kics", "--no-progress", "--ci"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return None  # KICS needs its bundled query assets; use the image

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        text = result.stdout
        if result.workdir:
            report = os.path.join(result.workdir, "kics.json")
            if os.path.exists(report):
                with open(report, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
        data = _load_any(text)
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        for q in data.get("queries", []) or []:
            sev = _CHECKOV_SEV.get(str(q.get("severity", "")).upper(), Severity.MEDIUM)
            for f in q.get("files", []) or []:
                findings.append(Finding(
                    title=str(q.get("query_name", "IaC misconfig"))[:140],
                    severity=sev, category="A05:Misconfiguration", source=self.id,
                    rule_id=str(q.get("query_id", "")), confidence=Confidence.CONFIRMED,
                    locations=[Location(file=str(f.get("file_name", "")).replace("/src/", ""),
                                        line=f.get("line"))],
                    what_it_is=str(q.get("description", "")),
                    remediation=str(f.get("expected_value", "") or q.get("query_url", "")),
                    references=[u for u in [q.get("query_url")] if u],
                ))
        return findings


def _load_any(text: str):
    text = text.strip()
    if not text:
        return {}
    # pick the EARLIEST opener - that is the real top-level container, not an inner array
    candidates = [(text.find(c), c) for c in "[{" if text.find(c) != -1]
    if not candidates:
        return {}
    start, opener = min(candidates)
    closer = "]" if opener == "[" else "}"
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        end = text.rfind(closer)
        if end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return {}
    return {}
