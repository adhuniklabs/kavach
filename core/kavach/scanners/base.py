"""Scanner adapter contract.

A scanner is KAVACH's replacement for AgentShield's hand-written TypeScript rules: a
thin adapter around an external security tool. Adding a tool is one file - declare when
it ``applies``, how to invoke it (Docker image and/or native binary), and how to
``normalize`` its raw output into canonical ``Finding`` objects.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..dockerutil import (
    ScannerUnavailable,
    ToolResult,
    docker_available,
    native_available,
    run_docker,
    run_native,
)
from ..finding import Finding


@dataclass
class ScanOutcome:
    scanner_id: str
    status: str            # "ok" | "unavailable" | "error"
    findings: list[Finding] = field(default_factory=list)
    runner: str = ""       # "docker" | "native"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_id": self.scanner_id,
            "status": self.status,
            "runner": self.runner,
            "message": self.message,
            "findings": len(self.findings),
        }


class Scanner(ABC):
    id: str = ""
    title: str = ""
    image: str | None = None          # Docker image (preferred)
    native_binary: str | None = None  # fallback native command name
    network: str = "none"             # "none" for offline tools, "default" for advisory-DB tools
    timeout: int = 600
    needs_writable_out: bool = False  # mount a writable /out for tools that emit a report file

    @abstractmethod
    def applies(self, recon: dict) -> bool:
        """Whether this scanner is relevant to the detected stack."""

    @abstractmethod
    def docker_args(self, recon: dict) -> list[str]:
        """Arguments passed to the Docker image (target mounted read-only at /src)."""

    def native_cmd(self, target: str, recon: dict) -> list[str] | None:
        """Native invocation, if a fallback binary exists. Return None to disable."""
        return None

    def extra_mounts(self, recon: dict) -> list[tuple[str, str]]:
        """Extra read-only (host, container) mounts - e.g. bundled offline rulesets."""
        return []

    @abstractmethod
    def normalize(self, result: ToolResult, target: str, recon: dict) -> list[Finding]:
        """Parse tool output into canonical findings. Tolerate non-zero exit codes -
        most scanners exit non-zero simply because they found something."""

    def run(self, target: str, recon: dict) -> ScanOutcome:
        try:
            result = self._invoke(target, recon)
        except ScannerUnavailable as exc:
            return ScanOutcome(self.id, "unavailable", message=str(exc))
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ScanOutcome(self.id, "error", message=f"{type(exc).__name__}: {exc}")
        try:
            findings = self.normalize(result, target, recon)
        except Exception as exc:  # noqa: BLE001 - a broken parser must not abort the sweep
            return ScanOutcome(
                self.id, "error", runner=result.runner,
                message=f"normalize failed: {type(exc).__name__}: {exc}",
            )
        finally:
            if result.workdir:
                shutil.rmtree(result.workdir, ignore_errors=True)
        if result.runner == "docker":
            _strip_mount_prefix(findings)
        return ScanOutcome(self.id, "ok", findings=findings, runner=result.runner)

    mount_at = "/src"

    def _invoke(self, target: str, recon: dict) -> ToolResult:
        if self.image and docker_available():
            return run_docker(
                self.image, self.docker_args(recon), target,
                network=self.network, timeout=self.timeout,
                writable_out=self.needs_writable_out,
                extra_ro_mounts=self.extra_mounts(recon),
            )
        native = self.native_cmd(target, recon)
        if native and self.native_binary and native_available(self.native_binary):
            return run_native(native, cwd=target, timeout=self.timeout)
        raise ScannerUnavailable(
            f"{self.id}: no Docker daemon/image and no native '{self.native_binary}' binary"
        )


def _strip_mount_prefix(findings: list[Finding], prefix: str = "/src/") -> None:
    for f in findings:
        for loc in f.locations:
            if loc.file.startswith(prefix):
                loc.file = loc.file[len(prefix):]
            elif loc.file == prefix.rstrip("/"):
                loc.file = ""
