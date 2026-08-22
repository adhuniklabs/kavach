"""Tracker export - two-phase, approval-gated, idempotent issue creation.

Filing issues in someone's tracker is outward-facing and hard to reverse, so it is never a
side effect of an audit. There are exactly two phases: ``plan()`` reads the audit tree and
writes ``reports/issues.json`` and nothing else; ``push_github()`` is the only thing that can
reach a tracker, and ``dry_run`` defaults to True here so the unconfigured call is the safe
one. Every gh invocation goes through ``_gh``, the single place that decides whether a command
runs - a mutating command under ``dry_run`` is recorded and never executed.

Idempotency keys on ``kavach_id`` (``Finding.fingerprint()``), never on the title. The
fingerprint deliberately excludes line numbers, so it survives code movement and a re-audit
comments on the existing issue instead of filing a duplicate.

``secret``-class findings never carry their evidence off the machine. Stated precisely, because
the guarantee is structural rather than a filter: the body is synthesized from ``file:line`` +
class + remediation, so no evidence, no snippet and no matched value can reach an issue body; and
``_body_abs`` is ``None`` for such an entry, so the finding's ``report.md`` - which may inline the
credential - is never opened on the export path. The entry does keep the *relative* ``body_path``
as local metadata: it is what tells the operator where the withheld value lives on this machine,
it is inert (nothing reads it), and ``issues.json`` never leaves the machine. See
``_redacted_body``.

GitHub is the only provider in this cut. ``PROVIDERS`` is the seam a Jira adapter drops into;
see ``docs/tracker-export.md``.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Callable, Iterator

from .finding import Severity
from .report_finding import is_complete
from .state import latest_audit

GH_TIMEOUT = 60
PLAN_NAME = "issues.json"
DEFAULT_SEVERITIES = ("critical", "high")

_BASE_LABELS = ("security", "kavach")
_AGG_PREFIX = "KAVACH-AGG-"
_BODY_PLACEHOLDER = "<body-file>"

# gh verbs that only read. Anything not listed is treated as mutating, so a verb added
# later is fail-safe under dry_run rather than silently executable.
_READ_VERBS = ("list", "view", "status")

# triage.classify() fills Finding.finding_class; an un-triaged findings.json leaves it empty.
# Re-deriving the secret row of triage's table here is deliberate - the cost of mistaking a
# secret for a code finding is a live credential published to a tracker.
_SECRET_SOURCES = frozenset({
    "gitleaks", "trufflehog", "builtin-secrets", "trivy-secret", "rust_secret_apis",
})

_WITHHELD = (
    "KAVACH does not copy a matched secret into a tracker: an issue is readable by more people "
    "than the repository, and a pasted credential outlives its rotation. The matched value, its "
    "snippet, and the scanner that found it stay in the local audit tree at `{body_path}` on the "
    "machine that ran the audit. Treat the credential as already compromised: rotate it, then "
    "purge it from git history before closing this issue."
)


class IssuesError(RuntimeError):
    """Operator-facing tracker-export failure. Raised before any tracker call is made."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def plan_path(audit_dir: str) -> str:
    return os.path.join(audit_dir, "reports", PLAN_NAME)


def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _rows_by_id(audit_dir: str) -> dict[str, dict]:
    """findings.json rows keyed by fingerprint, as raw dicts - the plan needs only the
    serialized fields, so it stays readable across a findings.json written by any core."""
    path = os.path.join(audit_dir, "findings.json")
    if not os.path.exists(path):
        return {}
    data = _read_json(path)
    rows = data["findings"] if isinstance(data, dict) else data
    return {row.get("id", ""): row for row in rows}


def _target(audit_dir: str) -> str:
    recon = os.path.join(audit_dir, "recon.json")
    root = _read_json(recon).get("root", "") if os.path.exists(recon) else ""
    return root or os.path.dirname(audit_dir)


def _commit(audit_dir: str) -> str:
    run = latest_audit(audit_dir)
    return (run.commit or "") if run else ""


def _promoted_dirs(audit_dir: str) -> list[str]:
    tree = os.path.join(audit_dir, "findings")
    if not os.path.isdir(tree):
        return []
    return sorted(
        os.path.join(tree, name) for name in os.listdir(tree)
        if os.path.exists(os.path.join(tree, name, "metadata.json"))
    )


def _finding_class(meta: dict, row: dict) -> str:
    kavach_id = meta.get("kavach_id", "")
    if meta.get("is_aggregate") and kavach_id.startswith(_AGG_PREFIX):
        return kavach_id[len(_AGG_PREFIX):]
    return row.get("finding_class") or (
        "secret" if row.get("source", "") in _SECRET_SOURCES else ""
    )


def _locations(row: dict) -> list[str]:
    """file:line only. A secret-class body is built from this, so snippets never come along."""
    out = []
    for loc in row.get("locations", []):
        line = loc.get("line")
        out.append(f"{loc.get('file', '')}:{line}" if line else loc.get("file", ""))
    return [loc for loc in out if loc]


def _scrub(text: str, row: dict) -> str:
    """Strip any matched snippet out of text bound for a tracker. `snippet` is the one field a
    secret scanner fills with the credential itself, so the title and remediation of a
    secret-class finding are checked against it before they leave the machine. Snippets shorter
    than 8 characters are left alone - a credential is not that short, and a 3-character
    replacement would only mangle the sentence."""
    for loc in row.get("locations", []):
        snippet = (loc.get("snippet") or "").strip()
        if len(snippet) >= 8:
            text = text.replace(snippet, "[withheld]")
    return text


def _dir_title(fdir: str) -> str:
    """Title from the directory slug. Nothing inside the finding dir is read, so a redacted
    entry with no findings.json row still cannot pick a secret up out of a report."""
    slug = os.path.basename(fdir).split("-", 1)[-1]
    return slug.replace("-", " ").capitalize()


def _excluded(fdir: str, meta: dict, cls: str, severities: tuple[str, ...],
              include_aggregates: bool) -> str:
    if os.path.basename(fdir).startswith("FP-"):
        return "marked false positive"
    if meta.get("is_aggregate") and not include_aggregates:
        return "aggregate excluded by include_aggregates=False"
    severity = meta.get("severity", "")
    if severity not in severities:
        return f"severity {severity or 'unknown'} not in {list(severities)}"
    if cls == "secret":
        return ""                      # body is synthesized; no report.md is read or needed
    report = os.path.join(fdir, "report.md")
    if not os.path.exists(report):
        return "no report.md - nothing disclosure-ready to post"
    with open(report, encoding="utf-8") as fh:
        if not is_complete(fh.read()):
            return "report.md fails the report_finding contract"
    return ""


def _entry(audit_dir: str, fdir: str, meta: dict, row: dict, cls: str, commit: str) -> dict:
    display_id = meta.get("display_id", os.path.basename(fdir).split("-")[0])
    severity = meta.get("severity", "")
    redacted = cls == "secret"
    report = os.path.join(fdir, "report.md")
    title = row.get("title") or _dir_title(fdir)
    remediation = row.get("remediation", "")
    if redacted:
        title, remediation = _scrub(title, row), _scrub(remediation, row)
    return {
        "kavach_id": meta.get("kavach_id", ""),
        "display_id": display_id,
        "title": f"[KAVACH {display_id}] {title}",
        "labels": [*_BASE_LABELS, f"severity:{severity}"],
        "body_path": os.path.relpath(report, audit_dir),
        "severity": severity,
        "finding_class": cls,
        "existing_issue": None,
        "redacted": redacted,
        "is_aggregate": bool(meta.get("is_aggregate")),
        "member_count": meta.get("member_count", 0),
        "cvss_score": meta.get("cvss_score", 0.0),
        "cvss_vector": meta.get("cvss_vector", ""),
        "kill_chain": meta.get("kill_chain"),
        "locations": _locations(row),
        "remediation": remediation,
        "commit": commit,
        # Hydration-only (never serialized). None for a redacted entry, which is what makes the
        # report.md unreadable on the export path - the relative body_path above stays, as the
        # local pointer to the withheld value.
        "_body_abs": None if redacted else report,
    }


def _sort_key(entry: dict) -> tuple:
    return (-Severity(entry["severity"]).rank, entry["is_aggregate"],
            -entry["cvss_score"], entry["display_id"])


def plan(audit_dir: str, *, severities: tuple[str, ...] = DEFAULT_SEVERITIES,
         include_aggregates: bool = True) -> dict:
    """Read-only. Returns the export plan; writes nothing until write_plan()."""
    audit_dir = os.path.abspath(audit_dir)
    severities = tuple(severities)
    rows = _rows_by_id(audit_dir)
    commit = _commit(audit_dir)
    issues: list[dict] = []
    skipped: list[dict] = []
    for fdir in _promoted_dirs(audit_dir):
        meta = _read_json(os.path.join(fdir, "metadata.json"))
        row = rows.get(meta.get("kavach_id", ""), {})
        cls = _finding_class(meta, row)
        reason = _excluded(fdir, meta, cls, severities, include_aggregates)
        if reason:
            skipped.append({"display_id": meta.get("display_id", os.path.basename(fdir)),
                            "dir": os.path.relpath(fdir, audit_dir), "reason": reason})
            continue
        issues.append(_entry(audit_dir, fdir, meta, row, cls, commit))
    issues.sort(key=_sort_key)
    return {
        "meta": {
            "target": _target(audit_dir), "commit": commit, "generated_at": _now(),
            "provider": "github", "severities": list(severities),
            "include_aggregates": include_aggregates,
        },
        "issues": issues,
        "skipped": skipped,
    }


def write_plan(audit_dir: str, plan: dict) -> str:
    path = plan_path(audit_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {**plan, "issues": [
        {k: v for k, v in entry.items() if not k.startswith("_")}
        for entry in plan.get("issues", [])
    ]}
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)
    return path


def read_plan(audit_dir: str, path: str | None = None) -> dict:
    """Load a written plan and re-hydrate the body paths write_plan() strips. The operator is
    expected to edit issues.json between plan and push - dropping entries, retitling, trimming
    labels - so push always reads the reviewed file rather than re-planning."""
    audit_dir = os.path.abspath(audit_dir)
    loaded = _read_json(path or plan_path(audit_dir))
    for entry in loaded.get("issues", []):
        entry["_body_abs"] = (
            None if entry.get("redacted") else os.path.join(audit_dir, entry["body_path"])
        )
    return loaded


def _report_body(entry: dict) -> str:
    path = entry.get("_body_abs")
    if not path or not os.path.exists(path):
        raise IssuesError(
            f"{entry['display_id']}: no report body at {entry['body_path']} - re-run "
            "`kavach issues plan` against the audit directory that holds the findings tree"
        )
    with open(path, encoding="utf-8") as fh:
        return fh.read().rstrip() + "\n"


def _redacted_body(entry: dict) -> str:
    locations = "\n".join(f"- `{loc}`" for loc in entry["locations"]) or "- _none recorded_"
    return "\n".join([
        "## Summary", "",
        f"A secret-class finding ({entry['severity'].upper()}) was confirmed at the location(s) "
        "below. **The matched value is withheld from this issue.**", "",
        "## Location(s)", "", locations, "",
        "## Remediation", "",
        entry["remediation"] or "Rotate the exposed credential and load it from a secret "
                                "manager or deploy-time env injection.", "",
        "## Why this issue is redacted", "",
        _WITHHELD.format(body_path=entry["body_path"]), "",
    ])


def _footer(entry: dict) -> str:
    lines = [
        "", "---", "",
        f"- **KAVACH id:** `{entry['kavach_id']}` - the stable handle. Leave it in the body: "
        "KAVACH matches on it and will comment here instead of filing a duplicate.",
        f"- **Severity:** {entry['severity'].upper()} · **CVSS:** {entry['cvss_score']} "
        f"(`{entry['cvss_vector'] or 'not scored'}`)",
        f"- **Kill chain:** {entry['kill_chain'] or 'not mapped'}",
        f"- **Finding class:** {entry['finding_class'] or 'unclassified'}",
        f"- **Audit commit:** `{entry['commit'] or 'unknown'}`",
        f"- **Local audit artifact:** `{entry['body_path']}`",
    ]
    if entry["is_aggregate"]:
        lines.append(f"- **Rolled-up members:** {entry['member_count']}")
    lines += ["", "_Filed by KAVACH. Display ids renumber between runs; the KAVACH id does not._"]
    return "\n".join(lines)


def render_issue(entry: dict) -> tuple[str, str]:
    """(title, body_markdown). A redacted entry is synthesized and never reads report.md."""
    body = _redacted_body(entry) if entry.get("redacted") else _report_body(entry)
    return entry["title"], body + _footer(entry)


def render_comment(entry: dict) -> str:
    return "\n".join([
        f"### KAVACH re-audit - still open at `{entry['commit'] or 'unknown'}`", "",
        f"Seen again on {_now()}. No new issue was filed; `{entry['kavach_id']}` matched the "
        "body of this one.", "",
        f"- **Severity this run:** {entry['severity'].upper()} (CVSS {entry['cvss_score']})",
        f"- **Display id this run:** {entry['display_id']}",
        f"- **Local audit artifact:** `{entry['body_path']}`",
    ])


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=GH_TIMEOUT)


def _is_mutating(argv: list[str]) -> bool:
    return argv[2] not in _READ_VERBS


def _gh(argv: list[str], result: dict, *, dry_run: bool) -> subprocess.CompletedProcess | None:
    """The only place a gh command is executed. A mutating command under dry_run is recorded
    with executed=False and never run - that invariant is what makes the plan phase safe."""
    mutating = _is_mutating(argv)
    executed = not (mutating and dry_run)
    result["commands"].append({"argv": argv, "mutating": mutating, "executed": executed})
    if not executed:
        return None
    try:
        return _run(argv)
    except (OSError, subprocess.TimeoutExpired) as exc:
        result["errors"].append(f"gh {' '.join(argv[1:3])} failed to run: {exc}")
        return None


def _gh_ready(result: dict, *, dry_run: bool) -> bool:
    """False when gh cannot be used at all, with the reason recorded. No fallback route
    exists: if gh is missing or unauthenticated, KAVACH does not post by another means."""
    if shutil.which("gh") is None:
        result["errors"].append(
            "gh CLI not found on PATH - install it from https://cli.github.com and run "
            "`gh auth login`.")
        return False
    proc = _gh(["gh", "auth", "status"], result, dry_run=dry_run)
    if proc is None:
        return False
    if proc.returncode != 0:
        result["errors"].append(
            "gh is not authenticated - run `gh auth login`. KAVACH never handles a token "
            "itself.")
        return False
    return True


def _search_argv(kavach_id: str, repo: str) -> list[str]:
    return ["gh", "issue", "list", "--repo", repo, "--search", f"{kavach_id} in:body",
            "--state", "all", "--json", "number,title,state"]


def _create_argv(repo: str, title: str, labels: list[str], body_file: str) -> list[str]:
    argv = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body-file", body_file]
    for label in labels:
        argv += ["--label", label]
    return argv


def _comment_argv(repo: str, number: int, body_file: str) -> list[str]:
    return ["gh", "issue", "comment", str(number), "--repo", repo, "--body-file", body_file]


@contextlib.contextmanager
def _body_file(body: str, *, dry_run: bool) -> Iterator[str]:
    """--body-file keeps a long report out of argv. Under dry_run nothing is written and the
    recorded command carries a placeholder path."""
    if dry_run:
        yield _BODY_PLACEHOLDER
        return
    fd, path = tempfile.mkstemp(prefix="kavach-issue-", suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    try:
        yield path
    finally:
        os.unlink(path)


def _labels(entry: dict, extra: list[str] | None) -> list[str]:
    out = list(entry["labels"])
    for label in extra or []:
        if label not in out:
            out.append(label)
    return out


def _existing(payload: str) -> dict | None:
    """An open match wins; an all-closed match still counts, so a regression comments on the
    closed issue rather than filing a fresh one beside it."""
    hits = json.loads(payload or "[]")
    return next((h for h in hits if h.get("state", "").lower() == "open"), hits[0] if hits else None)


def _push_one(entry: dict, repo: str, labels: list[str] | None, result: dict, *,
              dry_run: bool) -> None:
    title, body = render_issue(entry)
    record = {"kavach_id": entry["kavach_id"], "display_id": entry["display_id"],
              "title": title, "redacted": entry["redacted"],
              "body_bytes": len(body.encode("utf-8"))}

    search = _gh(_search_argv(entry["kavach_id"], repo), result, dry_run=dry_run)
    if search is None or search.returncode != 0:
        detail = (search.stderr or "").strip() if search else "not run"
        result["errors"].append(f"{entry['display_id']}: issue search failed: {detail}")
        return

    hit = _existing(search.stdout)
    if hit:
        entry["existing_issue"] = hit["number"]
        with _body_file(render_comment(entry), dry_run=dry_run) as path:
            proc = _gh(_comment_argv(repo, hit["number"], path), result, dry_run=dry_run)
        if proc is not None and proc.returncode != 0:
            result["errors"].append(
                f"{entry['display_id']}: comment on #{hit['number']} failed: "
                f"{(proc.stderr or '').strip()}")
            return
        result["updated"].append({**record, "number": hit["number"], "state": hit.get("state")})
        return

    with _body_file(body, dry_run=dry_run) as path:
        proc = _gh(_create_argv(repo, title, _labels(entry, labels), path), result,
                   dry_run=dry_run)
    if proc is not None and proc.returncode != 0:
        result["errors"].append(
            f"{entry['display_id']}: create failed: {(proc.stderr or '').strip()}")
        return
    result["created"].append({**record, "url": (proc.stdout or "").strip() if proc else None})


def push_github(audit_dir: str, plan: dict, *, repo: str, dry_run: bool = True,
                labels: list[str] | None = None) -> dict:
    """Create or update one GitHub issue per planned entry. dry_run=True (the default) runs
    the idempotency searches and renders every body, but executes no mutating gh command and
    writes nothing back."""
    result: dict = {"provider": "github", "repo": repo, "dry_run": dry_run,
                    "created": [], "updated": [], "skipped": list(plan.get("skipped", [])),
                    "errors": [], "commands": [], "ok": False}
    if not _gh_ready(result, dry_run=dry_run):
        return result
    for entry in plan.get("issues", []):
        _push_one(entry, repo, labels, result, dry_run=dry_run)
    result["ok"] = not result["errors"]
    if not dry_run:
        result["plan_path"] = write_plan(audit_dir, plan)
    return result


PROVIDERS: dict[str, Callable[..., dict]] = {"github": push_github}


def push(audit_dir: str, plan: dict, *, provider: str = "github", **kwargs) -> dict:
    """Provider dispatch. GitHub is the only adapter in this cut; a Jira adapter is one
    push_jira() plus one row here."""
    adapter = PROVIDERS.get(provider)
    if adapter is None:
        raise IssuesError(f"unsupported tracker provider {provider!r} - supported: "
                          f"{', '.join(sorted(PROVIDERS))}")
    return adapter(audit_dir, plan, **kwargs)
