"""Corpus self-validation gate.

Runs the dependency-free path (recon + built-in secret scan) against hand-authored
vulnerable fixtures and checks each fixture's ``expected.json`` - the regression firewall
AgentShield proved valuable. Deliberately avoids Docker/network so it can gate in any CI.
Grow the fixtures alongside detectors.
"""

from __future__ import annotations

import json
import os
import sys

from .recon import run_recon
from .scanners.builtin_secrets import BuiltinSecretsScanner

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "corpus", "fixtures")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def check_fixture(path: str) -> list[str]:
    """Return a list of failure messages ([] means the fixture passed)."""
    failures: list[str] = []
    with open(os.path.join(path, "expected.json"), encoding="utf-8") as fh:
        expected = json.load(fh)

    recon, _ = run_recon(path)
    for key, wanted in (expected.get("stack") or {}).items():
        found = set(recon.get(key, []))
        for item in wanted:
            if item not in found:
                failures.append(f"stack.{key}: expected '{item}', got {sorted(found) or '[]'}")

    secrets = BuiltinSecretsScanner().run(path, recon).findings
    min_secrets = expected.get("min_secrets", 0)
    if len(secrets) < min_secrets:
        failures.append(f"secrets: expected >= {min_secrets}, found {len(secrets)}")
    return failures


def run_corpus_gate() -> int:
    if not os.path.isdir(FIXTURES_DIR):
        _log(f"corpus: no fixtures at {FIXTURES_DIR}")
        return 6
    fixtures = sorted(
        d for d in os.listdir(FIXTURES_DIR)
        if os.path.isfile(os.path.join(FIXTURES_DIR, d, "expected.json"))
    )
    _log(f"KAVACH corpus gate → {len(fixtures)} fixture(s)")
    total_failures = 0
    for name in fixtures:
        failures = check_fixture(os.path.join(FIXTURES_DIR, name))
        if failures:
            total_failures += len(failures)
            _log(f"  ✗ {name}")
            for f in failures:
                _log(f"      {f}")
        else:
            _log(f"  ✓ {name}")
    if total_failures:
        _log(f"corpus gate FAILED with {total_failures} issue(s)")
        return 6
    _log("corpus gate PASSED")
    return 0
