# Adapted from piolium (github.com/vigolium/piolium) - MIT License, (c) j3ssie.
"""Dependency-free Rust secret-zeroization scanner.

Ported from zeroize-audit's find_dangerous_apis.py: pure source-text grep for Rust
APIs that quietly defeat a secret's zeroization guarantee - no compilation required.
Only reports a hit when a sensitive-sounding name (key/secret/password/token/...) is
within reach, since the whole point of this scanner is secret hygiene, not generic
Rust memory-safety linting. Every finding lands on the key-theft kill chain: a secret
that's never wiped is a secret that outlives its owner in memory.
"""

from __future__ import annotations

import os
import re

from ..finding import Confidence, Finding, Location, Severity
from .base import ScanOutcome, Scanner

_SENSITIVE_NAME = re.compile(
    r"(?i)(?:\b(?:Key|PrivateKey|SecretKey|SigningKey|MasterKey|HmacKey|"
    r"Password|Passphrase|Pin|Token|AuthToken|BearerToken|ApiKey|"
    r"Secret|SharedSecret|PreSharedKey|Nonce|Seed|Entropy|"
    r"Credential|SessionKey|DerivedKey)\b"
    r"|(?<![a-zA-Z])(?:key|secret|password|token|nonce|seed|private|master|credential)(?![a-zA-Z]))"
)

# (rule id, human name, exploit tier, compiled pattern, what/how/remediation)
# Tier feeds _CVSS below; severity is derived from the resulting score (Severity.from_cvss),
# never hardcoded - see the vector/score note above _CVSS.
_PATTERNS = [
    (
        "mem-forget", "mem::forget() suppresses the secret's Drop/ZeroizeOnDrop", "direct",
        re.compile(r"\bmem::forget\s*\("),
        "mem::forget() prevents the value's Drop (and therefore ZeroizeOnDrop) from "
        "ever running, so the secret bytes are never wiped from memory.",
        "The forgotten allocation's bytes remain readable for the process lifetime - a "
        "core dump, swap file, or heap-inspection primitive lifts the live secret.",
        "Do not call mem::forget on secret-holding values. If ownership genuinely must "
        "be relinquished, wipe the bytes first (zeroize crate) before forgetting.",
    ),
    (
        "manually-drop", "ManuallyDrop::new() suppresses automatic drop", "direct",
        re.compile(r"\bManuallyDrop\s*::\s*new\s*\("),
        "ManuallyDrop::new() opts the value out of automatic Drop; the secret is only "
        "wiped if something later calls ManuallyDrop::drop() explicitly.",
        "Any path that returns, panics, or is refactored without that explicit drop() "
        "call leaves the secret un-zeroized for the rest of the process's life.",
        "Avoid ManuallyDrop for secret material, or pair every ManuallyDrop::new with "
        "a guaranteed (e.g. Drop-guard or catch-unwind-safe) call to zeroize + drop.",
    ),
    (
        "box-leak", "Box::leak() never drops or zeroes the allocation", "direct",
        re.compile(r"\bBox\s*::\s*leak\s*\("),
        "Box::leak() intentionally leaks the allocation for the program's lifetime - "
        "it is never dropped, so a secret inside it is never zeroized.",
        "The leaked secret sits in the heap for as long as the process runs, "
        "recoverable from a core dump or a heap-read primitive.",
        "Never leak secret-holding allocations. Use a scoped, droppable owner (Zeroizing<T> "
        "or ZeroizeOnDrop) instead.",
    ),
    (
        "box-into-raw", "Box::into_raw() escapes Drop until reclaimed", "conditional",
        re.compile(r"\bBox\s*::\s*into_raw\s*\("),
        "Box::into_raw() hands out a raw pointer and disables Drop for the boxed "
        "value until Box::from_raw() reclaims it.",
        "If the matching Box::from_raw() + zeroize is missing on any path (error, "
        "panic, early return), the secret is silently never wiped.",
        "Always pair Box::into_raw() with a Box::from_raw() + explicit zeroize on "
        "every exit path, or avoid raw pointers for secret material entirely.",
    ),
    (
        "non-volatile-wipe", "ptr::write_bytes() is a non-volatile wipe LLVM may elide", "conditional",
        re.compile(r"\bptr\s*::\s*write_bytes\s*\("),
        "ptr::write_bytes() is a plain (non-volatile) store. If the compiler can prove "
        "the memory is never read again, it is free to optimize the wipe away as dead "
        "code - the 'zeroization' never actually happens at runtime.",
        "The secret bytes may still be present after the 'wipe' call returns, "
        "recoverable from memory even though the source claims to have cleared it.",
        "Use the zeroize crate's volatile write (or core::ptr::write_volatile + a "
        "compiler_fence(Ordering::SeqCst)) so the compiler cannot eliminate the wipe.",
    ),
]

_BLOCK_COMMENT_START = re.compile(r"/\*")
_BLOCK_COMMENT_END = re.compile(r"\*/")
_CONTEXT_WINDOW = 15


class RustSecretApisScanner(Scanner):
    id = "rust-secret-apis"
    title = "Rust secret-zeroization API scanner (no dependencies)"
    image = None
    native_binary = None

    def applies(self, recon: dict) -> bool:
        return "Rust" in (recon.get("languages") or [])

    def docker_args(self, recon: dict) -> list[str]:
        return []

    def normalize(self, result, target, recon):  # pragma: no cover - run() overridden
        return []

    def run(self, target: str, recon: dict) -> ScanOutcome:
        findings: list[Finding] = []
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in ("target", ".git")]
            for name in filenames:
                if not name.endswith(".rs"):
                    continue
                path = os.path.join(dirpath, name)
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        source = fh.read()
                except OSError:
                    continue
                rel = os.path.relpath(path, target)
                findings.extend(_scan_file(rel, source))
        return ScanOutcome(self.id, "ok", findings=findings, runner="native")


def _comment_mask(lines: list[str]) -> list[bool]:
    """Per-line "is this line commented out" mask (// and /* ... */)."""
    mask = []
    in_block = False
    for line in lines:
        stripped = line.strip()
        if in_block:
            mask.append(True)
            if _BLOCK_COMMENT_END.search(line):
                in_block = False
            continue
        if stripped.startswith("//"):
            mask.append(True)
            continue
        if stripped.startswith("/*"):
            mask.append(True)
            if not _BLOCK_COMMENT_END.search(line):
                in_block = True
            continue
        mask.append(False)
        if _BLOCK_COMMENT_START.search(stripped) and not _BLOCK_COMMENT_END.search(stripped):
            in_block = True
    return mask


def _has_sensitive_context(lines: list[str], center_idx: int) -> bool:
    start = max(0, center_idx - _CONTEXT_WINDOW)
    end = min(len(lines), center_idx + _CONTEXT_WINDOW + 1)
    return bool(_SENSITIVE_NAME.search("\n".join(lines[start:end])))


def _scan_file(rel: str, source: str) -> list[Finding]:
    lines = source.splitlines()
    commented = _comment_mask(lines)
    findings: list[Finding] = []
    for lineno, line in enumerate(lines, start=1):
        if commented[lineno - 1]:
            continue
        if not _has_sensitive_context(lines, lineno - 1):
            continue
        for rule_id, human, tier, pattern, what, how, fix in _PATTERNS:
            if pattern.search(line):
                findings.append(_finding(rule_id, human, tier, rel, lineno, line.strip(),
                                         what, how, fix))
    return findings


# Both tiers are local, low-privilege reads of unwiped memory (C:H/I:N/A:N) - real exposure,
# but conditional on a separate primitive (core dump, swap, heap read) to actually recover the
# bytes, not itself remotely exploitable. "direct" (AC:L) suppresses the wipe outright; "conditional"
# (AC:H) only defeats it if something else - a missing reclaim, an optimizer decision - also goes
# wrong. Scores are the real CVSS 3.1 base-score computation for each vector, not a guess: both land
# in the Medium band, which is what Severity.from_cvss derives - never hardcode a Severity here.
_CVSS = {
    "direct": ("6.2", "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "conditional": ("5.1", "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
}


def _finding(rule_id, human, tier, rel, lineno, snippet, what, how, fix) -> Finding:
    score, vector = _CVSS[tier]
    severity = Severity.from_cvss(float(score))
    return Finding(
        title=f"Secret zeroization bypass: {human}",
        severity=severity,
        category="A02:Crypto",
        source="rust-secret-apis",
        rule_id=rule_id,
        confidence=Confidence.SUSPECTED,
        cvss_score=float(score),
        cvss_vector=vector,
        locations=[Location(file=rel, line=lineno, snippet=snippet[:200])],
        what_it_is=what,
        how_exploited=how,
        business_impact="A secret (key, token, password, or credential) that outlives its "
                        "intended scope in memory is recoverable via core dump, swap, or a "
                        "heap-read primitive - direct key theft.",
        remediation=fix,
        references=["CWE-316", "CWE-1258"],
        kill_chain="steal-keys",
    )
