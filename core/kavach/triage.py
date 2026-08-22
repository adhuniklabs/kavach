"""Finding classification - which signals are judgement and which are scanner rows.

70% of a deep run's finding set is raw scanner output. Promoting each row as a
first-class finding buys 800 dispatches and a 3,000-line report. ``classify`` sorts a
finding into one of five classes from its ``source``/``category``/``rule_id`` alone:
deterministic, model-free, and idempotent, so an old ``findings.json`` upgrades on load
and two runs never disagree. ``findings_tree.consolidate`` then promotes only the
classes a human would want a per-finding report for, and rolls the rest up.
"""

from __future__ import annotations

import re
from dataclasses import replace

from .finding import Finding

CLASSES = ("reasoned", "code", "secret", "dependency", "iac")
AGGREGATE_CLASSES = ("dependency", "iac")     # never promoted individually
PROMOTABLE_CLASSES = ("reasoned", "code", "secret")

# Exact match, never a startswith: A07 also spells several non-secret
# identification/authentication categories, and one of those must not be redacted as a
# credential. rust-secret-apis files its zeroization findings under A02:Crypto, so the
# source list still earns its place beside the category.
_SECRET_CATEGORY = "A07:Secrets"
_SECRET_SOURCES = frozenset({"gitleaks", "trufflehog", "builtin-secrets", "rust-secret-apis"})
# "deps"/"malware"/"iac" name the scanner modules rather than any scanner id - inert
# today, kept so an ingested finding that labels itself by module still lands right.
_DEPENDENCY_SOURCES = frozenset({
    "trivy", "pip-audit", "npm-audit", "osv-scanner", "guarddog", "deps", "malware",
})
_IAC_SOURCES = frozenset({"checkov", "kics", "hadolint", "iac"})

_ADVISORY_RULE = re.compile(r"^(CVE|GHSA|OSV)-")
_IAC_RULE = re.compile(r"^(CKV|DL|AVD)")
# merge_findings._alias emits "a".."z" then "s26", "s27", ...; index_sources prefixes
# every source with it. Anchored and repeated so a merge of a merge resolves too, and
# narrow enough that no scanner id can match it.
_MERGE_ALIAS = re.compile(r"^(?:(?:[a-z]|s\d+):)+")


def sources(finding: Finding) -> list[str]:
    """The normalised scanner-id *segments* of a finding, lowercased and hyphenated.

    ``Finding.source`` starts out as one scanner id, but exactly two places in the tree
    rewrite it afterwards, and both forms reach anything that reads the field:

    - ``merge_findings.py:54`` prefixes each source with its per-audit alias, so ``trivy``
      becomes ``a:trivy`` (aliases are ``a``..``z`` then ``s26``, ``s27``, ...).
    - ``sweep.py:56`` concatenates the sources of two findings that share a fingerprint,
      so a corroborated row reads ``gitleaks+builtin-secrets``. Which id lands first is
      decided by severity rank, not by authority, so neither position is dependable.

    Merge applies both, in that order - ``index_sources`` aliases and *then* calls
    ``sweep.dedupe`` - so ``a:kavach-api+b:kavach-api`` is a shape that occurs today.

    Callers matching a source against a set must therefore ask **does any segment match**
    rather than comparing the whole string; a whole-string comparison matches none of the
    rewritten forms and fails silently, which is how a merged VAJRA finding was being
    classified as ``code`` and how a merged scanner drops out of the report's Annex C.
    """
    raw = finding.source.strip().lower().replace("_", "-")
    return [_MERGE_ALIAS.sub("", part) for part in raw.split("+") if part]


_sources = sources     # retained: the name this helper had before it grew a second caller


def classify(finding: Finding) -> str:
    """Return the ``finding_class`` for one finding. First match wins.

    ``reasoned`` is tested first and unconditionally: a VAJRA-authored finding about a
    dependency is judgement, not a scanner row, and has to stay promotable.

    ``secret`` is tested before ``dependency`` and keys on the category, because trivy
    files committed secrets under its own ``trivy`` source id. A secret that classifies
    as ``dependency`` is rolled into an aggregate instead of being promoted, and the
    issue exporter's redaction guard keys on this field - so the misclassification ends
    with a live credential in a public tracker.

    Every branch reads the normalised source list (see :func:`sources`), so one merged
    or corroborated source id is enough to hold the class.
    """
    ids = sources(finding)
    if any(s.startswith("kavach-") or s == "reconciler" for s in ids):
        return "reasoned"
    if finding.category == _SECRET_CATEGORY or _SECRET_SOURCES.intersection(ids):
        return "secret"
    if (_DEPENDENCY_SOURCES.intersection(ids)
            or finding.category.startswith("A06")
            or _ADVISORY_RULE.match(finding.rule_id)):
        return "dependency"
    if _IAC_SOURCES.intersection(ids) or _IAC_RULE.match(finding.rule_id):
        return "iac"
    return "code"


def classify_all(findings: list[Finding]) -> list[Finding]:
    return [replace(f, finding_class=classify(f)) for f in findings]


__all__ = ["sources", "classify", "classify_all", "CLASSES", "AGGREGATE_CLASSES",
           "PROMOTABLE_CLASSES"]
