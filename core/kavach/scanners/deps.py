"""Dependency & vulnerability scanners - trivy (fs: vuln+secret+misconfig), pip-audit,
npm audit, osv-scanner. These supply *real, current* CVE ids so the model never invents
one (a KAVACH banned behavior, made structurally impossible)."""

from __future__ import annotations

import json
import os

from ..dockerutil import ToolResult
from ..finding import Confidence, Finding, Location, Severity
from .base import Scanner
from .sast import _load_json_obj

_TRIVY_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
              "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "UNKNOWN": Severity.INFO}


class TrivyScanner(Scanner):
    id = "trivy"
    title = "Trivy (deps, secrets, IaC misconfig)"
    image = "aquasec/trivy:latest"
    native_binary = "trivy"
    network = "default"  # downloads the vulnerability DB

    def applies(self, recon: dict) -> bool:
        return True

    def docker_args(self, recon: dict) -> list[str]:
        return ["fs", "--scanners", "vuln,secret,misconfig", "--format", "json",
                "--quiet", "/src"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["trivy", "fs", "--scanners", "vuln,secret,misconfig",
                "--format", "json", "--quiet", "."]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        findings: list[Finding] = []
        for res in data.get("Results", []) or []:
            target_file = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                sev = _TRIVY_SEV.get(str(v.get("Severity", "")).upper(), Severity.INFO)
                fixed = v.get("FixedVersion")
                findings.append(Finding(
                    title=f"{v.get('PkgName','')} {v.get('InstalledVersion','')}: "
                          f"{v.get('VulnerabilityID','')}",
                    severity=sev, category="A06:Vulnerable-Components", source=self.id,
                    rule_id=v.get("VulnerabilityID", ""), confidence=Confidence.CONFIRMED,
                    cvss_score=_trivy_cvss(v),
                    locations=[Location(file=target_file)],
                    what_it_is=str(v.get("Title", v.get("Description", "")))[:300],
                    remediation=(f"Upgrade {v.get('PkgName','')} to {fixed}."
                                 if fixed else "No fixed version yet - assess exposure / pin / mitigate."),
                    references=[u for u in [v.get("PrimaryURL")] if u],
                ))
            for s in res.get("Secrets", []) or []:
                findings.append(Finding(
                    title=f"Secret in {target_file}: {s.get('Title', s.get('RuleID',''))}",
                    severity=Severity.CRITICAL, category="A07:Secrets", source=self.id,
                    rule_id=s.get("RuleID", ""), confidence=Confidence.CONFIRMED, cvss_score=9.1,
                    locations=[Location(file=target_file, line=s.get("StartLine"),
                                        snippet=s.get("Match"))],
                    what_it_is="Trivy matched a committed secret.",
                    remediation="Remove, rotate, and load from a secret manager.",
                    references=["CWE-798"],
                ))
            for m in res.get("Misconfigurations", []) or []:
                sev = _TRIVY_SEV.get(str(m.get("Severity", "")).upper(), Severity.MEDIUM)
                findings.append(Finding(
                    title=f"Misconfig: {m.get('Title', m.get('ID',''))}",
                    severity=sev, category="A05:Misconfiguration", source=self.id,
                    rule_id=m.get("ID", ""), confidence=Confidence.CONFIRMED,
                    locations=[Location(file=target_file,
                                        line=(m.get("CauseMetadata", {}) or {}).get("StartLine"))],
                    what_it_is=str(m.get("Description", "")),
                    remediation=str(m.get("Resolution", "")),
                    references=[u for u in [m.get("PrimaryURL")] if u],
                ))
        return findings


class PipAuditScanner(Scanner):
    id = "pip-audit"
    title = "pip-audit (Python dependency CVEs)"
    image = None
    native_binary = "pip-audit"
    network = "default"

    def applies(self, recon: dict) -> bool:
        return recon.get("capabilities", {}).get("has_python", False)

    def docker_args(self, recon: dict) -> list[str]:
        return []

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["pip-audit", "-f", "json", "--progress-spinner", "off"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        deps = data.get("dependencies", data) if isinstance(data, dict) else data
        deps = deps if isinstance(deps, list) else []
        findings: list[Finding] = []
        for dep in deps:
            for v in dep.get("vulns", []) or []:
                findings.append(Finding(
                    title=f"{dep.get('name','')} {dep.get('version','')}: {v.get('id','')}",
                    severity=Severity.HIGH, category="A06:Vulnerable-Components", source=self.id,
                    rule_id=v.get("id", ""), confidence=Confidence.CONFIRMED,
                    locations=[Location(file="requirements/pyproject")],
                    what_it_is=str(v.get("description", ""))[:300],
                    remediation=("Upgrade to " + ", ".join(v.get("fix_versions", []))
                                 if v.get("fix_versions") else "No fix released - assess exposure."),
                    references=v.get("aliases", []),
                ))
        return findings


class NpmAuditScanner(Scanner):
    id = "npm-audit"
    title = "npm audit (Node dependency CVEs)"
    image = None
    native_binary = "npm"
    network = "default"

    def applies(self, recon: dict) -> bool:
        caps = recon.get("capabilities", {})
        return caps.get("has_node", False) and caps.get("has_lockfiles", False)

    def docker_args(self, recon: dict) -> list[str]:
        return []

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["npm", "audit", "--json"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        findings: list[Finding] = []
        for name, v in (data.get("vulnerabilities", {}) or {}).items():
            sev = _TRIVY_SEV.get(str(v.get("severity", "")).upper(), Severity.MEDIUM)
            via = v.get("via", [])
            cves = [x.get("url") for x in via if isinstance(x, dict) and x.get("url")]
            title = next((x.get("title") for x in via if isinstance(x, dict) and x.get("title")),
                         f"Vulnerable dependency: {name}")
            findings.append(Finding(
                title=str(title)[:140], severity=sev, category="A06:Vulnerable-Components",
                source=self.id, rule_id=name, confidence=Confidence.CONFIRMED,
                locations=[Location(file="package-lock.json")],
                what_it_is=f"npm audit flagged '{name}' ({v.get('range','')}).",
                remediation="Run `npm audit fix` or upgrade to a non-vulnerable version.",
                references=cves[:4],
            ))
        return findings


class OsvScanner(Scanner):
    id = "osv-scanner"
    title = "OSV-Scanner (lockfile CVEs, all ecosystems)"
    image = "ghcr.io/google/osv-scanner:latest"
    native_binary = "osv-scanner"
    network = "default"

    def applies(self, recon: dict) -> bool:
        return recon.get("capabilities", {}).get("has_lockfiles", False)

    def docker_args(self, recon: dict) -> list[str]:
        return ["--format", "json", "-r", "/src"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["osv-scanner", "--format", "json", "-r", "."]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        findings: list[Finding] = []
        for res in data.get("results", []) or []:
            src = (res.get("source", {}) or {}).get("path", "")
            for pkg in res.get("packages", []) or []:
                pinfo = pkg.get("package", {}) or {}
                for v in pkg.get("vulnerabilities", []) or []:
                    sev = _osv_severity(v)
                    findings.append(Finding(
                        title=f"{pinfo.get('name','')}: {v.get('id','')}",
                        severity=sev, category="A06:Vulnerable-Components", source=self.id,
                        rule_id=v.get("id", ""), confidence=Confidence.CONFIRMED,
                        locations=[Location(file=os.path.basename(src) or src)],
                        what_it_is=str(v.get("summary", v.get("details", "")))[:300],
                        remediation="Upgrade to a patched version per the advisory.",
                        references=v.get("aliases", []),
                    ))
        return findings


def _trivy_cvss(v: dict) -> float:
    for src in (v.get("CVSS", {}) or {}).values():
        if isinstance(src, dict) and src.get("V3Score"):
            return float(src["V3Score"])
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0}.get(
        str(v.get("Severity", "")).upper(), 0.0)


def _osv_severity(v: dict) -> Severity:
    ds = (v.get("database_specific", {}) or {}).get("severity", "")
    return {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW}.get(str(ds).upper(), Severity.MEDIUM)
