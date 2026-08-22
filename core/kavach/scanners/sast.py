"""Static application security testing - semgrep (multi-language) and bandit (Python)."""

from __future__ import annotations

import json
import os
import subprocess

from ..dockerutil import (
    ScannerUnavailable, ToolResult, docker_available, native_available, run_docker, run_native,
)
from ..finding import Confidence, Finding, Location, Severity
from .base import ScanOutcome, Scanner, _strip_mount_prefix

_SEMGREP_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_BANDIT_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

_ASSETS = os.path.join(os.path.dirname(__file__), "assets")
_KAVACH_RULES = os.path.join(_ASSETS, "semgrep-kavach.yml")
_BASE_ARGS = ["--json", "--quiet", "--timeout", "0", "--metrics", "off"]


class SemgrepScanner(Scanner):
    """Multi-language SAST. Always runs KAVACH's bundled offline ruleset (so it can never
    silently return zero when the registry is unreachable) plus `--config auto` for breadth.
    Falls back to offline-only if the registry fetch aborts the run."""

    id = "semgrep"
    title = "Semgrep (multi-language SAST)"
    image = "semgrep/semgrep:latest"
    native_binary = "semgrep"
    network = "default"  # --config auto fetches the rule registry

    def applies(self, recon: dict) -> bool:
        return bool(recon.get("languages"))

    def extra_mounts(self, recon: dict) -> list[tuple[str, str]]:
        return [(_ASSETS, "/kavach-rules")]

    def docker_args(self, recon: dict) -> list[str]:  # full run: offline floor + registry
        return ["semgrep", "scan", "--config", "/kavach-rules/semgrep-kavach.yml",
                "--config", "auto", *_BASE_ARGS, "/src"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["semgrep", "scan", "--config", _KAVACH_RULES,
                "--config", "auto", *_BASE_ARGS, "."]

    def run(self, target: str, recon: dict) -> ScanOutcome:
        try:
            result = self._invoke(target, recon)
        except ScannerUnavailable as exc:
            return ScanOutcome(self.id, "unavailable", message=str(exc))
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ScanOutcome(self.id, "error", message=f"{type(exc).__name__}: {exc}")

        data = _load_json_obj(result.stdout)
        note = ""
        if not data:
            # the registry (--config auto) likely aborted the run - retry offline-only
            try:
                result = self._invoke_offline(target, recon)
            except (ScannerUnavailable, subprocess.TimeoutExpired, OSError) as exc:
                return ScanOutcome(self.id, "error", message=f"offline retry failed: {exc}")
            data = _load_json_obj(result.stdout)
            note = "registry ruleset unreachable - ran KAVACH offline rules only"

        try:
            findings = self._parse(data)
        except Exception as exc:  # noqa: BLE001
            return ScanOutcome(self.id, "error", runner=result.runner,
                               message=f"normalize failed: {type(exc).__name__}: {exc}")
        if result.runner == "docker":
            _strip_mount_prefix(findings)
        errs = data.get("errors") or []
        if errs and not findings and not note:
            note = f"{len(errs)} semgrep config error(s); only offline rules matched"
        return ScanOutcome(self.id, "ok", findings=findings, runner=result.runner, message=note)

    def _invoke_offline(self, target: str, recon: dict) -> ToolResult:
        if self.image and docker_available():
            return run_docker(self.image,
                              ["semgrep", "scan", "--config", "/kavach-rules/semgrep-kavach.yml",
                               *_BASE_ARGS, "/src"],
                              target, network="none", timeout=self.timeout,
                              extra_ro_mounts=self.extra_mounts(recon))
        if self.native_binary and native_available(self.native_binary):
            return run_native(["semgrep", "scan", "--config", _KAVACH_RULES, *_BASE_ARGS, "."],
                              cwd=target, timeout=self.timeout)
        raise ScannerUnavailable(f"{self.id}: no docker/native for offline retry")

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        return self._parse(_load_json_obj(result.stdout))

    def _parse(self, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        for r in data.get("results", []):
            extra = r.get("extra", {}) or {}
            meta = extra.get("metadata", {}) or {}
            sev = _SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM)
            owasp = _as_list(meta.get("owasp"))
            cwe = _as_list(meta.get("cwe"))
            findings.append(Finding(
                title=str(extra.get("message", r.get("check_id", "semgrep finding")))[:140],
                severity=sev,
                category=(owasp[0] if owasp else (cwe[0] if cwe else "SAST")),
                source=self.id,
                rule_id=r.get("check_id", ""),
                confidence=Confidence.SUSPECTED,
                locations=[Location(file=r.get("path", ""),
                                    line=(r.get("start", {}) or {}).get("line"),
                                    snippet=(extra.get("lines") or None))],
                what_it_is=str(extra.get("message", "")),
                remediation=str((meta.get("fix") or extra.get("fix") or "")),
                references=[*cwe, *owasp, *_as_list(meta.get("references"))][:6],
            ))
        return findings


class BanditScanner(Scanner):
    id = "bandit"
    title = "Bandit (Python SAST)"
    image = None  # no reliable official image; prefer native
    native_binary = "bandit"
    network = "none"

    def applies(self, recon: dict) -> bool:
        return recon.get("capabilities", {}).get("has_python", False)

    def docker_args(self, recon: dict) -> list[str]:
        return []

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["bandit", "-r", ".", "-f", "json", "-q"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        findings: list[Finding] = []
        for r in data.get("results", []):
            sev = _BANDIT_SEV.get(str(r.get("issue_severity", "")).upper(), Severity.LOW)
            cwe = (r.get("issue_cwe") or {}).get("id")
            findings.append(Finding(
                title=str(r.get("issue_text", r.get("test_name", "bandit finding")))[:140],
                severity=sev,
                category=f"CWE-{cwe}" if cwe else "SAST",
                source=self.id,
                rule_id=r.get("test_id", ""),
                confidence=Confidence.SUSPECTED,
                locations=[Location(file=r.get("filename", ""), line=r.get("line_number"),
                                    snippet=r.get("code"))],
                what_it_is=str(r.get("issue_text", "")),
                references=[f"CWE-{cwe}"] if cwe else [],
            ))
        return findings


class GosecScanner(Scanner):
    """Go SAST - closes the gap bandit (Python-only) leaves. Catches SQLi, command
    injection, path traversal, SSRF, hardcoded creds, and weak crypto in Go source."""

    id = "gosec"
    title = "gosec (Go SAST)"
    image = "ghcr.io/securego/gosec:latest"
    native_binary = "gosec"
    network = "default"  # may resolve module type info

    def applies(self, recon: dict) -> bool:
        return recon.get("capabilities", {}).get("has_go", False)

    def docker_args(self, recon: dict) -> list[str]:
        return ["-fmt=json", "-quiet", "-no-fail", "/src/..."]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["gosec", "-fmt=json", "-quiet", "-no-fail", "./..."]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        data = _load_json_obj(result.stdout)
        findings: list[Finding] = []
        for r in data.get("Issues", []) or []:
            sev = _BANDIT_SEV.get(str(r.get("severity", "")).upper(), Severity.MEDIUM)
            cwe = (r.get("cwe") or {}).get("id")
            findings.append(Finding(
                title=str(r.get("details", r.get("rule_id", "gosec finding")))[:140],
                severity=sev, category=f"CWE-{cwe}" if cwe else "SAST", source=self.id,
                rule_id=r.get("rule_id", ""), confidence=Confidence.SUSPECTED,
                locations=[Location(file=str(r.get("file", "")).replace("/src/", ""),
                                    line=_as_int(r.get("line")), snippet=r.get("code"))],
                what_it_is=str(r.get("details", "")),
                references=[f"CWE-{cwe}"] if cwe else [],
            ))
        return findings


def _as_int(v):
    try:
        return int(str(v).split(",")[0])
    except (TypeError, ValueError):
        return None


def _load_json_obj(text: str) -> dict:
    text = text.strip()
    start = text.find("{")
    if start == -1:
        return {}
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        end = text.rfind("}")
        if end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return {}
        return {}


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]
