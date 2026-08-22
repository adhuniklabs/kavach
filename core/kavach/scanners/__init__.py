"""Scanner registry. Adding a tool = write an adapter and list it here."""

from __future__ import annotations

from .base import Scanner, ScanOutcome
from .builtin_secrets import BuiltinSecretsScanner
from .deps import NpmAuditScanner, OsvScanner, PipAuditScanner, TrivyScanner
from .fail_open_defaults import FailOpenDefaultsScanner
from .iac import CheckovScanner, HadolintScanner, KicsScanner
from .malware import GuardDogScanner
from .rust_secret_apis import RustSecretApisScanner
from .sast import BanditScanner, GosecScanner, SemgrepScanner
from .secrets import GitleaksScanner, TruffleHogScanner

ALL_SCANNERS: list[Scanner] = [
    BuiltinSecretsScanner(),
    FailOpenDefaultsScanner(),
    GitleaksScanner(),
    TruffleHogScanner(),
    SemgrepScanner(),
    TrivyScanner(),
    BanditScanner(),
    GosecScanner(),
    RustSecretApisScanner(),
    PipAuditScanner(),
    NpmAuditScanner(),
    OsvScanner(),
    GuardDogScanner(),
    CheckovScanner(),
    HadolintScanner(),
    KicsScanner(),
]


def applicable_scanners(recon: dict) -> list[Scanner]:
    return [s for s in ALL_SCANNERS if s.applies(recon)]


__all__ = ["Scanner", "ScanOutcome", "ALL_SCANNERS", "applicable_scanners"]
