"""findings-draft → findings/<id>-<slug>/ promotion.

Adapted from piolium (github.com/vigolium/piolium) - MIT License, © j3ssie.
Display ids are severity-prefixed (C1/H1/G1) and stable within an audit directory: a
fingerprint keeps the id, and the directory, that the first pass gave it. The stable machine
id is still finding.fingerprint(), stored in metadata.json.

Only ``triage.PROMOTABLE_CLASSES`` at critical/high get their own directory. Scanner
classes roll up into one ``G``-banded aggregate directory per class, whose report.md is
written here by the core - a rolled-up CVE table must never read as a cold-verified
Critical, which is why it carries its own band letter.

``consolidate`` never deletes, so a tree re-consolidated after the finding mix changed - or
after a legacy ``severity >= medium`` policy - holds directories that are no longer part of
the audit. It therefore records exactly which directory it wrote for which fingerprint in
``attack-surface/promoted-index.json``, and :func:`scope_promoted` reads that manifest back.
One writer, one reader: the live set is inspectable rather than inferred, which matters
because two code paths re-deriving it is how it drifted in the first place.

Numbering from scratch used to make that set grow on its own. A second pass over a larger
finding set slid every id down a place, wrote a fresh directory beside each old one, and
``scope_promoted`` correctly reported half the tree as stale: a balanced audit measured 35
directories for 24 findings, and ``render`` built the deliverable over the duplicates. Ids
are now assigned from what is already on disk, so a live finding cannot be handed a second
directory. That is the fix rather than pruning afterwards, because pruning has to move a
directory that may hold a proof of concept somebody paid for.
"""

from __future__ import annotations

import json
import os
import re
import time

import yaml

from . import triage
from .finding import Finding, Severity, load_findings

AGGREGATE_ID_PREFIX = "KAVACH-AGG-"
_INDEX_REL = ("attack-surface", "promoted-index.json")

# What consolidate writes itself. Anything else in a promoted directory was paid for - a
# proof of concept, a write-up, a captured request - and it decides which directory a
# fingerprint keeps when an older engine left it more than one.
_CORE_WRITES = {"draft.md", "metadata.json", "rows.json"}

# Why a promoted directory is not part of the current audit. A stale directory is reported
# and skipped, never deleted and never counted as missing work - demanding a PoC for a
# finding that is no longer promoted is what wedged the gate shut.
STALE_REASONS = {
    "no_metadata": "metadata.json is missing or unreadable",
    "gone": "kavach_id is no longer in findings.json",
    "de_promoted": "no longer individually promoted under the current policy",
    "not_in_manifest_legacy_run": "promoted by an earlier run, under a different display id",
}

_BAND = {Severity.CRITICAL: "C", Severity.HIGH: "H"}
_AGGREGATE_BAND = "G"
_AGGREGATE_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

_AGGREGATE_SLUG = {
    "dependency": "vulnerable-dependencies",
    "iac": "infrastructure-misconfiguration",
}
_AGGREGATE_TITLE = {
    "dependency": "Vulnerable dependencies",
    "iac": "Infrastructure misconfiguration",
}
_AGGREGATE_CAUSE = {
    "dependency": (
        "The dependency set is not pinned to patched releases. Manifests and lockfiles "
        "carry versions that shipped with published advisories, and no upgrade gate runs "
        "in CI, so each new advisory lands in the running image unnoticed."
    ),
    "iac": (
        "Infrastructure templates rely on the provider's insecure defaults rather than "
        "declaring the hardened value explicitly. Nothing in CI fails the build when a "
        "template omits encryption, network scoping, or a non-root runtime user."
    ),
}
_AGGREGATE_REPRO = {
    "dependency": "trivy fs .",
    "iac": "checkov -d .",
}
_AGGREGATE_NO_FIX = {
    "dependency": "No member reported a fixed version; assess exposure per row.",
    "iac": "Apply each row's remediation in the template it cites - there is no class-wide fix.",
}
_AGGREGATE_EXPOSURE = {
    "dependency": ("Every path listed above ships code the operator did not write and cannot "
                   "audit."),
    "iac": ("Every template listed above provisions running infrastructure, so each row is a "
            "live property of the deployed environment rather than a source-level defect."),
}

_VERSION = re.compile(r"^v?\d")
_ADVISORY_ID = re.compile(r"^(CVE|GHSA|OSV|CKV|DL|AVD)", re.IGNORECASE)
_FIXED_IN = re.compile(r"[Uu]pgrade(?: \S+?)? to ([\w.+-]*\d[\w.+-]*)")


def slugify(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return s[:50].strip("-")


def write_draft(audit_dir: str, finding: Finding, phase: str, n: int) -> str:
    slug = slugify(finding.title)
    prefix = phase.lower()
    rel = f"{prefix}-{n:03d}-{slug}.md"
    draft_dir = os.path.join(audit_dir, "findings-draft")
    os.makedirs(draft_dir, exist_ok=True)
    fm = {
        "id": f"{prefix}-{n:03d}", "phase": phase, "slug": slug,
        "severity": finding.severity.value, "confidence": finding.confidence.value,
        "kavach_id": finding.fingerprint(),
    }
    path = os.path.join(draft_dir, rel)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n")
        fh.write(f"# {finding.title}\n\n{finding.what_it_is}\n")
    return path


def partition(findings: list[Finding]) -> tuple[list[Finding], dict[str, list[Finding]]]:
    """Split a classified finding set into (individually promoted, aggregates by class)."""
    promoted, grouped = [], {}
    for f in findings:
        if f.severity in _BAND and f.finding_class in triage.PROMOTABLE_CLASSES:
            promoted.append(f)
        elif f.finding_class in triage.AGGREGATE_CLASSES and f.severity in _AGGREGATE_SEVERITIES:
            grouped.setdefault(f.finding_class, []).append(f)
    promoted.sort(key=lambda f: (-f.severity.rank, -f.cvss_score))
    return promoted, grouped


def promoted_index_path(audit_dir: str) -> str:
    return os.path.join(audit_dir, *_INDEX_REL)


def write_promoted_index(audit_dir: str, created: list[str]) -> str:
    """Record the directories this consolidate pass wrote. A full snapshot, not an append:
    consolidate re-promotes the whole finding set on every call, so the manifest mirrors
    exactly what is live right now."""
    entries = []
    for fdir in created:
        meta = read_metadata(fdir) or {}
        entries.append({
            "kavach_id": meta.get("kavach_id", ""),
            "dir": os.path.relpath(fdir, audit_dir),
            "display_id": meta.get("display_id", ""),
            "is_aggregate": bool(meta.get("is_aggregate")),
        })
    path = promoted_index_path(audit_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "audit_id": _audit_id(audit_dir), "count": len(entries),
                   "entries": entries}, fh, indent=2)
        fh.write("\n")
    return path


def read_promoted_index(audit_dir: str) -> dict | None:
    """None when no pass has written one - a legacy tree, or one never consolidated."""
    try:
        with open(promoted_index_path(audit_dir), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc.get("entries"), list) else None


def _audit_id(audit_dir: str) -> str:
    from . import state
    run = state.latest_audit(audit_dir)
    return "" if run is None else run.audit_id


def promoted_dirs(audit_dir: str) -> list[str]:
    """Every directory under findings/ that is not an FP- rename. Includes ones with no
    metadata.json, so they can be reported as stale rather than silently ignored."""
    root = os.path.join(audit_dir, "findings")
    if not os.path.isdir(root):
        return []
    return sorted(os.path.join(root, name) for name in os.listdir(root)
                  if os.path.isdir(os.path.join(root, name)) and not name.startswith("FP-"))


def read_metadata(finding_dir: str) -> dict | None:
    try:
        with open(os.path.join(finding_dir, "metadata.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def is_aggregate(meta: dict) -> bool:
    """An aggregate's kavach_id is the pinned KAVACH-AGG-<class> form, never a fingerprint,
    so it is never checked against findings.json."""
    return bool(meta.get("is_aggregate")) or \
        str(meta.get("kavach_id", "")).startswith(AGGREGATE_ID_PREFIX)


def _current_ids(audit_dir: str, findings: list[Finding] | None) -> tuple[set | None, set | None]:
    """(every fingerprint in findings.json, the subset promoted individually today), or
    (None, None) when there is no finding set to scope against."""
    if findings is None:
        path = os.path.join(audit_dir, "findings.json")
        if not os.path.exists(path):
            return None, None
        findings = load_findings(path)
    findings = triage.classify_all(findings)
    return ({f.fingerprint() for f in findings},
            {f.fingerprint() for f in partition(findings)[0]})


def scope_promoted(audit_dir: str, findings: list[Finding] | None = None):
    """Split findings/ into (live dirs, stale entries, how it was scoped).

    ``scoped_by`` is ``promoted-index`` when consolidate's manifest is on disk (exact),
    ``promotion-policy`` when it is not but findings.json is (misses renumbered duplicates
    from an earlier run), and ``unscoped`` when neither exists (every directory counts, the
    legacy behaviour). A reader must be able to tell which of the three it got.
    """
    index = read_promoted_index(audit_dir)
    live_names = None if index is None else {e.get("dir") for e in index["entries"]}
    all_ids, promoted_ids = _current_ids(audit_dir, findings)
    scoped_by = ("promoted-index" if live_names is not None
                 else "promotion-policy" if promoted_ids is not None else "unscoped")

    live: list[str] = []
    stale: list[dict] = []
    for fdir in promoted_dirs(audit_dir):
        rel = os.path.relpath(fdir, audit_dir)
        meta = read_metadata(fdir)
        if meta is None:
            stale.append({"display_id": os.path.basename(fdir).split("-", 1)[0], "dir": rel,
                          "kavach_id": "", "reason": "no_metadata",
                          "detail": STALE_REASONS["no_metadata"]})
            continue
        reason = _stale_reason(rel, meta, live_names, all_ids, promoted_ids)
        if reason is None:
            live.append(fdir)
        else:
            stale.append({"display_id": meta.get("display_id", ""), "dir": rel,
                          "kavach_id": meta.get("kavach_id", ""), "reason": reason,
                          "detail": STALE_REASONS[reason]})
    return live, stale, scoped_by


def _stale_reason(rel: str, meta: dict, live_names, all_ids, promoted_ids) -> str | None:
    """None when the directory is live.

    The manifest is the authority when it exists: consolidate wrote that directory for this
    finding set, so nothing re-derived overrides it. The id checks then serve two purposes -
    they name *why* an unlisted directory fell out, and they are the whole predicate when
    there is no manifest to read.
    """
    if live_names is not None:
        if rel in live_names:
            return None
        return _absence_reason(meta, all_ids, promoted_ids) or "not_in_manifest_legacy_run"
    return _absence_reason(meta, all_ids, promoted_ids)


def _absence_reason(meta: dict, all_ids, promoted_ids) -> str | None:
    """Why the current finding set no longer promotes this directory, most specific first,
    so a de-promotion reads as a de-promotion rather than as a bookkeeping miss."""
    if is_aggregate(meta):
        return None
    kavach_id = meta.get("kavach_id", "")
    if all_ids is not None and kavach_id not in all_ids:
        return "gone"
    if promoted_ids is not None and kavach_id not in promoted_ids:
        return "de_promoted"
    return None


def prune_stale(audit_dir: str, findings: list[Finding] | None = None) -> list[str]:
    """Relocate every stale directory to findings-stale/, keeping its name. A move, never a
    delete: this tree is audit evidence, and the FP- rename is the established precedent for
    "wrong but keep it". Returns the new paths."""
    _, stale, _ = scope_promoted(audit_dir, findings)
    dest_root = os.path.join(audit_dir, "findings-stale")
    moved = []
    for entry in stale:
        src = os.path.join(audit_dir, entry["dir"])
        dest = os.path.join(dest_root, os.path.basename(src))
        os.makedirs(dest_root, exist_ok=True)
        if os.path.exists(dest):
            dest = f"{dest}--{entry['reason']}"
        os.replace(src, dest)
        moved.append(dest)
    return moved


def _display_n(display_id: str) -> int:
    digits = "".join(ch for ch in display_id if ch.isdigit())
    return int(digits) if digits else 0


def _has_evidence(finding_dir: str) -> bool:
    """Whether the directory holds anything a run paid for. consolidate writes draft.md,
    metadata.json, rows.json and an empty evidence/; a proof of concept, a written report or
    a captured artifact is everything else."""
    for name in os.listdir(finding_dir):
        if name in _CORE_WRITES:
            continue
        if name == "evidence" and not os.listdir(os.path.join(finding_dir, "evidence")):
            continue
        return True
    return False


def _supersedes(candidate: tuple[str, str], held: tuple[str, str]) -> bool:
    """Which of two directories carrying one fingerprint the next pass writes into: the one
    holding evidence, then the lower display id. A tree an older engine already doubled is
    adopted by its proof of concept rather than by whichever name sorts first."""
    candidate_evidence, held_evidence = _has_evidence(candidate[1]), _has_evidence(held[1])
    if candidate_evidence != held_evidence:
        return candidate_evidence
    return _display_n(candidate[0]) < _display_n(held[0])


def _existing_placements(audit_dir: str) -> tuple[dict[str, tuple[str, str]], dict[str, int]]:
    """(kavach_id -> the (display id, directory) it already holds, band -> highest id in use).

    Read off the directories rather than out of ``promoted-index.json``: a tree written by an
    older engine carries directories the manifest never described, and those are exactly the
    ones whose numbers must not be issued a second time.
    """
    placements: dict[str, tuple[str, str]] = {}
    highest: dict[str, int] = {}
    for fdir in promoted_dirs(audit_dir):
        meta = read_metadata(fdir)
        if meta is None:
            continue
        display_id = str(meta.get("display_id", ""))
        n = _display_n(display_id)
        if not n:
            continue
        band = display_id[0]
        highest[band] = max(highest.get(band, 0), n)
        kavach_id = str(meta.get("kavach_id", ""))
        held = placements.get(kavach_id)
        if kavach_id and (held is None or _supersedes((display_id, fdir), held)):
            placements[kavach_id] = (display_id, fdir)
    return placements, highest


def _assign(band: str, held: tuple[str, str] | None, counters: dict[str, int]) -> str:
    """The id this finding already holds, or the next one free in its band. A new id is issued
    above every id on disk and never into a gap a de-promoted finding left, so a fresh
    directory cannot land on the name a stale one is still using."""
    if held is not None and held[0][0] == band:
        return held[0]
    counters[band] = counters.get(band, 0) + 1
    return f"{band}{counters[band]}"


def consolidate(audit_dir: str, findings: list[Finding]) -> list[str]:
    # Always create findings/, even on a zero-finding run - a phase whose gate is just
    # ["findings"] would otherwise never be satisfiable.
    os.makedirs(os.path.join(audit_dir, "findings"), exist_ok=True)
    findings = triage.classify_all(findings)
    promoted, grouped = partition(findings)

    placements, counters = _existing_placements(audit_dir)
    created = []
    for f in promoted:
        band = _BAND[f.severity]
        held = placements.get(f.fingerprint())
        display_id = _assign(band, held, counters)
        fdir = os.path.join(audit_dir, "findings", f"{display_id}-{slugify(f.title)}")
        if held is not None and held[1] != fdir and not os.path.exists(fdir):
            # A severity that crossed bands takes its directory with it rather than orphaning
            # it: the evidence belongs to the finding, not to the id it used to carry.
            os.replace(held[1], fdir)
        os.makedirs(os.path.join(fdir, "evidence"), exist_ok=True)
        with open(os.path.join(fdir, "draft.md"), "w", encoding="utf-8") as fh:
            fh.write(f"# [{display_id}] {f.title}\n\n{f.what_it_is}\n\n{f.how_exploited}\n")
        meta = {
            "display_id": display_id, "kavach_id": f.fingerprint(),
            "severity": f.severity.value, "cvss_vector": f.cvss_vector,
            "cvss_score": f.cvss_score, "kill_chain": f.kill_chain,
            "finding_class": f.finding_class, "is_aggregate": False,
            "is_variant": False, "confirm_status": "unconfirmed",
        }
        with open(os.path.join(fdir, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        created.append(fdir)

    for cls in triage.AGGREGATE_CLASSES:
        members = grouped.get(cls)
        if not members:
            continue
        display_id = _assign(_AGGREGATE_BAND,
                             placements.get(f"{AGGREGATE_ID_PREFIX}{cls}"), counters)
        created.append(write_aggregate(audit_dir, display_id, cls, members))

    write_promoted_index(audit_dir, created)
    return created


def write_aggregate(audit_dir: str, display_id: str, finding_class: str,
                    members: list[Finding]) -> str:
    """Materialise one aggregate directory: rows.json + report.md + metadata.json."""
    members = sorted(members, key=lambda f: (-f.severity.rank, -f.cvss_score, f.title))
    fdir = os.path.join(audit_dir, "findings", f"{display_id}-{_AGGREGATE_SLUG[finding_class]}")
    os.makedirs(os.path.join(fdir, "evidence"), exist_ok=True)
    rows = {"finding_class": finding_class, "count": len(members),
            "rows": [f.to_dict() for f in members]}
    with open(os.path.join(fdir, "rows.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    top = members[0]
    meta = {
        "display_id": display_id, "kavach_id": f"KAVACH-AGG-{finding_class}",
        "severity": top.severity.value, "cvss_vector": "", "cvss_score": top.cvss_score,
        "kill_chain": None, "finding_class": finding_class, "is_aggregate": True,
        "member_count": len(members), "member_ids": [f.fingerprint() for f in members],
        "is_variant": False, "confirm_status": "unconfirmed",
    }
    with open(os.path.join(fdir, "metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    write_aggregate_report(fdir, display_id, finding_class, members)
    return fdir


def _manifests(members: list[Finding]) -> list[str]:
    seen = []
    for f in members:
        path = f.locations[0].file if f.locations else ""
        if path and path not in seen:
            seen.append(path)
    return seen


def _row(finding: Finding) -> tuple[str, str, str, str, str, str]:
    """(package, installed, advisory, severity, fixed_in, manifest) for one member.

    Scanners spell the package two ways: trivy/pip-audit/osv put it in the title and the
    advisory id in rule_id, npm-audit puts the package name itself in rule_id.
    """
    rule = finding.rule_id.strip()
    if rule and _ADVISORY_ID.match(rule):
        advisory = rule
        head = finding.title.rsplit(":", 1)[0].strip() if ":" in finding.title else finding.title
    else:
        advisory = "-"
        head = rule or finding.title
    parts = head.split()
    if len(parts) > 1 and _VERSION.match(parts[-1]):
        package, installed = " ".join(parts[:-1]), parts[-1]
    else:
        package, installed = head, "-"
    fix = _FIXED_IN.search(finding.remediation)
    manifest = finding.locations[0].file if finding.locations else "-"
    return (package or "-", installed, advisory, finding.severity.value,
            fix.group(1).rstrip(".") if fix else "-", manifest)


def write_aggregate_report(finding_dir: str, display_id: str, finding_class: str,
                           members: list[Finding]) -> str:
    """Render the aggregate's report.md.

    Satisfies the same five-H2-section contract report_finding.py enforces, because the
    coverage gate checks every promoted directory uniformly.
    """
    manifests = _manifests(members)
    top = members[0]
    title = _AGGREGATE_TITLE[finding_class]
    repro = _AGGREGATE_REPRO[finding_class]
    rows = [_row(m) for m in members]
    upgrades = []
    for pkg, _installed, _advisory, _sev, fixed_in, _manifest in rows:
        line = f"- Upgrade `{pkg}` to `{fixed_in}`."
        if fixed_in != "-" and line not in upgrades:
            upgrades.append(line)

    lines = [
        f"# [{display_id}] {title}",
        "",
        f"- **Severity:** {top.severity.value.upper()} (highest member) · "
        f"**Members:** {len(members)} · **Class:** `{finding_class}`",
        f"- **Manifests / templates affected:** {len(manifests)}",
        "",
        "## Summary",
        "",
        f"{len(members)} {title.lower()} findings across {len(manifests)} "
        f"manifest(s), highest severity {top.severity.value.upper()}. This is a rolled-up "
        "scanner class, not a cold-verified finding: each row below is a machine match that "
        "is real but unexploited, and the class is remediated as a set rather than one "
        "vulnerability at a time.",
        "",
        "## Details",
        "",
        "| Package / check | Installed | Advisory | Severity | Fixed in | Path |",
        "|---|---|---|---|---|---|",
    ]
    for pkg, installed, advisory, sev, fixed_in, manifest in rows:
        lines.append(f"| {pkg} | {installed} | {advisory} | {sev} | {fixed_in} | `{manifest}` |")
    lines += [
        "",
        "## Root Cause",
        "",
        _AGGREGATE_CAUSE[finding_class],
        "",
        "## Proof of Concept",
        "",
        "There is no single exploit for a rolled-up set. Reproduce the inventory instead:",
        "",
        "```sh",
        repro,
        "```",
        "",
        *(upgrades or [_AGGREGATE_NO_FIX[finding_class]]),
        "",
        "## Impact",
        "",
        f"{_AGGREGATE_EXPOSURE[finding_class]} "
        f"The highest-severity member is **{top.title}** "
        f"({top.severity.value.upper()}) in `{manifests[0] if manifests else 'unknown path'}`; "
        "an attacker who reaches the affected component inherits whatever that row exposes, "
        "with no application-level control in the way.",
        "",
    ]
    text = "\n".join(lines)
    path = os.path.join(finding_dir, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def mark_false_positive(audit_dir: str, finding_dir: str) -> str:
    base = os.path.basename(finding_dir)
    renamed = os.path.join(os.path.dirname(finding_dir), f"FP-{base}")
    os.replace(finding_dir, renamed)
    return renamed
