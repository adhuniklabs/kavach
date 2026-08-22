"""Docker-first scanner execution with graceful fallback.

Strategy (the user's chosen model): prefer a pinned Docker image so the host needs
nothing installed; fall back to a native binary if the image can't run; otherwise mark
the scanner unavailable so the caller degrades to model-only review instead of crashing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


class ScannerUnavailable(Exception):
    """Raised when neither a Docker image nor a native binary can run a scanner."""


@dataclass
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    runner: str  # "docker" | "native"
    workdir: str = ""  # host path mounted writable at /out, for tools that emit a report file


_docker_ok: bool | None = None


def docker_available() -> bool:
    global _docker_ok
    if _docker_ok is None:
        if shutil.which("docker") is None:
            _docker_ok = False
        else:
            try:
                r = subprocess.run(
                    ["docker", "info"], capture_output=True, timeout=15, check=False
                )
                _docker_ok = r.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                _docker_ok = False
    return _docker_ok


def run_docker(
    image: str,
    args: list[str],
    target: str,
    *,
    network: str = "none",
    timeout: int = 600,
    mount_at: str = "/src",
    writable_out: bool = False,
    extra_ro_mounts: list[tuple[str, str]] | None = None,
) -> ToolResult:
    out_dir = tempfile.mkdtemp(prefix="kavach-out-") if writable_out else ""
    # realpath both mounts: on macOS the temp dir lives under a /var/folders symlink
    # that Docker Desktop's file sharing refuses to bind.
    target = os.path.realpath(target)
    cmd = ["docker", "run", "--rm", f"--network={network}",
           "-v", f"{target}:{mount_at}:ro"]
    for host, container in (extra_ro_mounts or []):
        cmd += ["-v", f"{os.path.realpath(host)}:{container}:ro"]
    if out_dir:
        cmd += ["-v", f"{os.path.realpath(out_dir)}:/out"]
    cmd += ["-w", mount_at, image, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return ToolResult(proc.returncode, proc.stdout, proc.stderr, "docker", workdir=out_dir)


def run_native(cmd: list[str], *, cwd: str | None = None, timeout: int = 600) -> ToolResult:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd
    )
    return ToolResult(proc.returncode, proc.stdout, proc.stderr, "native")


def native_available(binary: str) -> bool:
    return shutil.which(binary) is not None
