"""Optional code-graph index, the same way scanners are optional.

Every hunter spends most of its budget on discovery: grep for a symbol, open the file,
follow the import, repeat, until it finally reaches the line it will cite. A pre-built
symbol graph answers those structural questions in one call instead - who calls this, what
does changing it reach, where is it defined - which is exactly the question a source-to-sink
trace asks over and over.

The engine does not query the graph and does not ship one. It only *establishes* whether one
exists and records that in `attack-surface/graph-status.json`, so `dispatch.phase_prompt` can
tell an agent to reach for it - or tell it plainly that there is none, which matters more: an
agent that assumes a tool it does not have wastes a turn discovering that.

Absent binary, failed index and unindexable target are all the same outcome here: a status
file saying `available: false` with the reason. Nothing raises, nothing blocks a phase. This
is a scanner, not a prerequisite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

BINARY = "codegraph"
STATUS_ARTIFACT = os.path.join("attack-surface", "graph-status.json")
DEFAULT_TIMEOUT = 20 * 60      # the Linux kernel indexes in under 12 minutes on 2 cores


def binary_path(binary: str = BINARY) -> str | None:
    return shutil.which(binary)


def _run(argv: list[str], *, timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


def _version(binary: str, timeout: int = 30) -> str:
    code, out, _ = _run([binary, "version"], timeout=timeout)
    return out.strip().splitlines()[0] if code == 0 and out.strip() else ""


def _statistics(binary: str, target: str, timeout: int = 60) -> dict:
    """Best-effort. `status` is documented without `--json`, so a non-JSON answer is the
    expected case, not an error - the graph is still usable, we just cannot count it."""
    code, out, _ = _run([binary, "status", target, "--json"], timeout=timeout)
    if code != 0:
        return {}
    try:
        parsed = json.loads(out)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def status_path(audit_dir: str) -> str:
    return os.path.join(os.path.abspath(audit_dir), STATUS_ARTIFACT)


def write_status(audit_dir: str, payload: dict) -> str:
    path = status_path(audit_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def read_status(audit_dir: str) -> dict:
    try:
        with open(status_path(audit_dir), encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return {"available": False, "reason": "not established"}
    return payload if isinstance(payload, dict) else {"available": False, "reason": "malformed"}


def available(audit_dir: str) -> bool:
    return bool(read_status(audit_dir).get("available"))


def index(target: str, audit_dir: str, *, binary: str = BINARY, force: bool = False,
          timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Build (or refresh) the target's graph and record what happened."""
    target = os.path.abspath(target)
    found = binary_path(binary)
    if found is None:
        return write_and_return(audit_dir, {
            "available": False, "reason": f"{binary} is not installed",
            "hint": "https://github.com/colbymchenry/codegraph - hunters fall back to grep",
        })

    argv = [found, "index", target, "--quiet"] + (["--force"] if force else [])
    started = time.time()
    code, _, err = _run(argv, timeout=timeout, cwd=target)
    elapsed = round(time.time() - started, 1)
    if code != 0:
        return write_and_return(audit_dir, {
            "available": False, "reason": f"{binary} index exited {code}",
            "detail": err.strip()[:500], "elapsed_seconds": elapsed,
        })

    stats = _statistics(found, target)
    return write_and_return(audit_dir, {
        "available": True, "tool": binary, "cli": found, "version": _version(found),
        "root": target, "elapsed_seconds": elapsed,
        "indexed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **({"statistics": stats} if stats else {}),
    })


def write_and_return(audit_dir: str, payload: dict) -> dict:
    write_status(audit_dir, payload)
    return payload


def prompt_section(audit_dir: str) -> str:
    """What an agent is told about the graph. Both halves matter: a hunter that does not know
    the graph is there greps anyway and the index was wasted, and one that assumes a graph it
    does not have burns a turn finding out."""
    status = read_status(audit_dir)
    if not status.get("available"):
        return ("## Code graph\n\n"
                "No pre-built code graph is available for this repository"
                f" ({status.get('reason', 'unknown')}). Use grep and file reads, and expect "
                "structural questions to cost you several calls each.\n")
    cli = status.get("cli", status.get("tool", BINARY))
    return (
        "## Code graph\n\n"
        "This repository is indexed, so **answer structural questions from the graph before "
        "you grep**. Reaching for grep first is the single most expensive habit on a large "
        "repo - one graph call replaces the find/read/follow-the-import loop.\n"
        f"  - `{cli} explore \"<question>\"` - relevant symbols' source plus the call paths "
        "between them, in one call\n"
        f"  - `{cli} callers <symbol> --json` / `{cli} callees <symbol> --json` - who reaches "
        "this, and what it reaches. This is a reachability trace: it is how you prove an "
        "unauthenticated route touches a sink\n"
        f"  - `{cli} impact <symbol> --json` - the blast radius of one symbol\n"
        f"  - `{cli} query <name> --json` - where a symbol is defined\n"
        "The graph resolves dynamic-dispatch hops (callbacks, interface to impl) that grep "
        "cannot follow. Open a file to read the exact lines you will cite - never to discover "
        "structure the graph already holds.\n"
    )
