"""Secret detection - always-on. A hardcoded provider/payment/DB key is the operator's
#1 nightmare (KAVACH §3.4), so this runs on every target regardless of stack."""

from __future__ import annotations

import json
import os

from ..dockerutil import ToolResult
from ..finding import Confidence, Finding, Location, Severity
from .base import Scanner


class GitleaksScanner(Scanner):
    id = "gitleaks"
    title = "Gitleaks (hardcoded secrets)"
    image = "zricethezav/gitleaks:latest"
    native_binary = "gitleaks"
    network = "none"
    needs_writable_out = True  # gitleaks writes its JSON report to a file, not stdout

    def applies(self, recon: dict) -> bool:
        return True

    def docker_args(self, recon: dict) -> list[str]:
        return ["detect", "--source", "/src", "--no-git", "-f", "json",
                "-r", "/out/gitleaks.json", "--exit-code", "0", "--redact"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["gitleaks", "detect", "--source", ".", "--no-git", "-f", "json",
                "-r", "/dev/stdout", "--exit-code", "0", "--redact"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        text = result.stdout
        if result.workdir:
            report = os.path.join(result.workdir, "gitleaks.json")
            if os.path.exists(report):
                with open(report, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
        raw = _first_json_array(text)
        findings: list[Finding] = []
        for hit in raw:
            rule = hit.get("RuleID", "secret")
            findings.append(Finding(
                title=f"Hardcoded secret: {hit.get('Description', rule)}",
                severity=Severity.CRITICAL,
                category="A07:Secrets",
                source=self.id,
                rule_id=rule,
                confidence=Confidence.CONFIRMED,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                locations=[Location(file=hit.get("File", ""), line=hit.get("StartLine"),
                                    snippet=hit.get("Match"))],
                what_it_is=f"Gitleaks matched rule '{rule}' - a credential committed in source.",
                how_exploited="Anyone with read access to the repo, a leaked bundle, or git "
                              "history can lift the key and use it directly.",
                business_impact="Stolen API/LLM/payment/DB key used in attackers' own projects; "
                                "runaway spend on the operator's account.",
                remediation="Remove the secret, rotate it immediately, and load it from a secret "
                            "manager or deploy-time env injection. Purge from git history.",
                references=["CWE-798", "OWASP-A07"],
            ))
        return findings


class TruffleHogScanner(Scanner):
    """Verified secrets: TruffleHog can call the provider to confirm a leaked key is *live*.
    A verified hit is a confirmed incident, not a suspicion - the sharpest signal for the
    key-theft nightmare. Detection is offline; only verification needs network."""

    id = "trufflehog"
    title = "TruffleHog (verified secrets)"
    image = "trufflesecurity/trufflehog:latest"
    native_binary = "trufflehog"
    network = "default"  # verification calls providers; detection still works offline

    def applies(self, recon: dict) -> bool:
        return True

    def docker_args(self, recon: dict) -> list[str]:
        return ["filesystem", "/src", "--json", "--no-update"]

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        return ["trufflehog", "filesystem", ".", "--json", "--no-update"]

    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "DetectorName" not in rec:
                continue
            fs = (((rec.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
            verified = bool(rec.get("Verified"))
            detector = rec.get("DetectorName", "secret")
            findings.append(Finding(
                title=f"{'Verified' if verified else 'Unverified'} secret: {detector}",
                severity=Severity.CRITICAL if verified else Severity.HIGH,
                category="A07:Secrets", source=self.id, rule_id=str(detector),
                confidence=Confidence.CONFIRMED if verified else Confidence.SUSPECTED,
                cvss_score=9.3 if verified else 7.5,
                locations=[Location(file=str(fs.get("file", "")).replace("/src/", ""),
                                    line=_to_int(fs.get("line")),
                                    snippet=rec.get("Redacted"))],
                what_it_is=(f"TruffleHog {'verified against the provider that this is a LIVE ' if verified else 'detected a '}"
                            f"{detector} credential in source."),
                how_exploited="A live credential is used directly on the operator's account - "
                              "run paid APIs for free, exfiltrate data, rack up spend.",
                business_impact="Key theft / account takeover.",
                remediation="Rotate the credential now, remove the literal, load from a secret "
                            "manager, and purge from git history.",
                references=["CWE-798", "OWASP-A07"],
            ))
        return findings


def _to_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _first_json_array(text: str) -> list:
    text = text.strip()
    start = text.find("[")
    if start == -1:
        return []
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        # tolerate trailing log lines after the array
        depth, in_str, esc = 0, False, False
        for i, ch in enumerate(text[start:], start):
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return []
        return []
