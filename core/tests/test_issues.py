import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from kavach import issues, report_finding, state
from kavach.finding import Confidence, Finding, Location, Severity

# The literal a gitleaks-class finding carries in Location.snippet. It is written into the
# secret finding's report.md below; no issue title or body may ever contain it.
SECRET_VALUE = "AKIAIOSFODNN7EXAMPLE-live-key-do-not-publish"

_PROSE = (
    "The service reads the identifier straight off the request path and loads the record "
    "without checking ownership, so any authenticated session can walk the whole table. "
    "Every guard on the route is advisory and none of them rejects the request."
)


def _finding(title, severity, source, *, category="A01", secret=False):
    snippet = SECRET_VALUE if secret else "cursor.execute(q)"
    return Finding(
        title=title, severity=severity, category=category, source=source,
        locations=[Location(file="src/app.py", line=42, snippet=snippet)],
        what_it_is=_PROSE, how_exploited=_PROSE, business_impact=_PROSE,
        remediation="Rotate the credential and load it from a secret manager.",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N", cvss_score=9.1,
        confidence=Confidence.CONFIRMED,
    )


def _promote(audit_dir, display_id, finding, *, report=True, extra_meta=None):
    fdir = os.path.join(audit_dir, "findings", f"{display_id}-{display_id.lower()}-slug")
    os.makedirs(os.path.join(fdir, "evidence"), exist_ok=True)
    meta = {
        "display_id": display_id, "kavach_id": finding.fingerprint(),
        "severity": finding.severity.value, "cvss_vector": finding.cvss_vector,
        "cvss_score": finding.cvss_score, "kill_chain": finding.kill_chain,
        "is_aggregate": False, "member_count": 0,
    }
    meta.update(extra_meta or {})
    with open(os.path.join(fdir, "metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    if report:
        body = report_finding.render_report(finding)
        # A reporter subagent inlines the decisive snippet - for a secret that is the value.
        body += f"\n\nMatched value: `{finding.locations[0].snippet}`\n"
        with open(os.path.join(fdir, "report.md"), "w", encoding="utf-8") as fh:
            fh.write(body)
    return fdir


def _aggregate(audit_dir, display_id, cls, severity, count):
    fdir = os.path.join(audit_dir, "findings", f"{display_id}-vulnerable-dependencies")
    os.makedirs(os.path.join(fdir, "evidence"), exist_ok=True)
    meta = {"display_id": display_id, "kavach_id": f"KAVACH-AGG-{cls}", "severity": severity,
            "is_aggregate": True, "member_count": count, "member_ids": []}
    with open(os.path.join(fdir, "metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    with open(os.path.join(fdir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join([
            f"# {count} vulnerable dependencies", "",
            "## Summary", "", _PROSE, "", "## Details", "", _PROSE, "",
            "## Root Cause", "", _PROSE, "", "## Proof of Concept", "", "`trivy fs .`", "",
            "## Impact", "", _PROSE, "",
        ]))
    return fdir


def _audit(audit_dir):
    """One audit tree covering every plan() branch: promotable, secret, aggregate,
    below-threshold, false-positive, and a dir whose report.md is not disclosure-ready."""
    findings = [
        _finding("SQL injection in login", Severity.CRITICAL, "kavach-sast"),
        _finding("Hardcoded secret: AWS Access Key", Severity.CRITICAL, "gitleaks",
                 category="A07:Secrets", secret=True),
        _finding("Reflected XSS in search", Severity.HIGH, "semgrep"),
        _finding("Verbose error page", Severity.MEDIUM, "semgrep"),
        _finding("Missing CSRF token", Severity.HIGH, "semgrep"),
        _finding("Open redirect", Severity.HIGH, "semgrep"),
    ]
    classes = ["code", "secret", "code", "code", "code", "code"]
    rows = []
    for f, cls in zip(findings, classes):
        row = f.to_dict()
        row["finding_class"] = cls
        rows.append(row)
    os.makedirs(audit_dir, exist_ok=True)
    with open(os.path.join(audit_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump({"meta": {"phase": "merge"}, "findings": rows}, fh, indent=2)
    with open(os.path.join(audit_dir, "recon.json"), "w", encoding="utf-8") as fh:
        json.dump({"root": "/repo/target"}, fh)
    state.init_audit(audit_dir, "balanced", ["intel"], commit="deadbeef")

    _promote(audit_dir, "C1", findings[0])
    _promote(audit_dir, "C2", findings[1])
    _promote(audit_dir, "H1", findings[2])
    _promote(audit_dir, "M1", findings[3])
    _promote(audit_dir, "FP-H2", findings[4])
    stub = _promote(audit_dir, "H3", findings[5], report=False)
    with open(os.path.join(stub, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("# Open redirect\n\nTBD\n")
    _aggregate(audit_dir, "G1", "dependency", "high", 136)
    return findings


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _proc(argv, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=argv, returncode=rc, stdout=stdout, stderr=stderr)


class _Gh:
    """Stand-in for issues._run. Records every argv it is handed and fails the test outright
    if a mutating command is ever executed, which is the dry-run guarantee under test."""

    def __init__(self, *, hits=(), allow_mutating=False, auth_rc=0):
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self.hits = list(hits)
        self.allow_mutating = allow_mutating
        self.auth_rc = auth_rc

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        self.kwargs.append(kwargs)
        if issues._is_mutating(argv) and not self.allow_mutating:
            raise AssertionError(f"mutating gh command executed: {argv}")
        if argv[:3] == ["gh", "auth", "status"]:
            return _proc(argv, self.auth_rc, "Logged in to github.com")
        if argv[:3] == ["gh", "issue", "list"]:
            return _proc(argv, 0, json.dumps(self.hits))
        return _proc(argv, 0, "https://github.com/o/n/issues/7")

    def verbs(self):
        return [c[2] for c in self.calls]


class IssuesTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.join(tempfile.mkdtemp(), ".kavach")
        self.findings = _audit(self.dir)

    def _push(self, gh, *, dry_run=True, plan=None, labels=None):
        with patch.object(issues.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(issues, "_run", gh):
            return issues.push_github(self.dir, plan or issues.plan(self.dir),
                                      repo="acme/api", dry_run=dry_run, labels=labels)


class TestPlan(IssuesTestCase):
    def test_meta_and_entry_shape(self):
        p = issues.plan(self.dir)
        self.assertEqual(p["meta"]["provider"], "github")
        self.assertEqual(p["meta"]["target"], "/repo/target")
        self.assertEqual(p["meta"]["commit"], "deadbeef")
        self.assertEqual(p["meta"]["severities"], ["critical", "high"])
        self.assertTrue(p["meta"]["generated_at"].endswith("Z"))

        entry = p["issues"][0]
        for key in ("kavach_id", "display_id", "title", "labels", "body_path", "severity",
                    "finding_class", "existing_issue", "redacted"):
            self.assertIn(key, entry)
        self.assertIsNone(entry["existing_issue"])
        self.assertTrue(entry["title"].startswith(f"[KAVACH {entry['display_id']}] "))
        self.assertFalse(os.path.isabs(entry["body_path"]))
        self.assertEqual(entry["labels"][:2], ["security", "kavach"])
        self.assertIn(f"severity:{entry['severity']}", entry["labels"])

    def test_selects_critical_high_and_aggregate_ordered_by_severity(self):
        ids = [e["display_id"] for e in issues.plan(self.dir)["issues"]]
        self.assertEqual(ids, ["C1", "C2", "H1", "G1"])

    def test_skips_below_threshold_false_positive_and_incomplete_report(self):
        reasons = {s["display_id"]: s["reason"] for s in issues.plan(self.dir)["skipped"]}
        self.assertIn("severity medium", reasons["M1"])
        self.assertEqual(reasons["FP-H2"], "marked false positive")
        self.assertEqual(reasons["H3"], "report.md fails the report_finding contract")

    def test_no_report_md_is_skipped_not_pushed(self):
        os.remove(os.path.join(self.dir, "findings", "H1-h1-slug", "report.md"))
        reasons = {s["display_id"]: s["reason"] for s in issues.plan(self.dir)["skipped"]}
        self.assertEqual(reasons["H1"], "no report.md - nothing disclosure-ready to post")

    def test_aggregate_class_from_kavach_id_and_opt_out(self):
        agg = next(e for e in issues.plan(self.dir)["issues"] if e["display_id"] == "G1")
        self.assertEqual(agg["finding_class"], "dependency")
        self.assertTrue(agg["is_aggregate"])
        self.assertEqual(agg["member_count"], 136)

        p = issues.plan(self.dir, include_aggregates=False)
        self.assertNotIn("G1", [e["display_id"] for e in p["issues"]])
        self.assertIn("aggregate excluded", dict(
            (s["display_id"], s["reason"]) for s in p["skipped"])["G1"])

    def test_severities_widens_the_selection(self):
        ids = [e["display_id"] for e in
               issues.plan(self.dir, severities=("critical", "high", "medium"))["issues"]]
        self.assertIn("M1", ids)

    def test_unclassified_secret_source_still_redacts(self):
        # an un-triaged findings.json (no finding_class) must not lose the secret guard
        path = os.path.join(self.dir, "findings.json")
        data = _load(path)
        for row in data["findings"]:
            row.pop("finding_class", None)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        entry = next(e for e in issues.plan(self.dir)["issues"] if e["display_id"] == "C2")
        self.assertEqual(entry["finding_class"], "secret")
        self.assertTrue(entry["redacted"])

    def test_plan_writes_nothing(self):
        issues.plan(self.dir)
        self.assertFalse(os.path.exists(issues.plan_path(self.dir)))

    def test_write_plan_strips_hydration_keys_and_read_plan_restores(self):
        path = issues.write_plan(self.dir, issues.plan(self.dir))
        self.assertEqual(path, os.path.join(self.dir, "reports", "issues.json"))
        on_disk = _load(path)
        self.assertTrue(all(not k.startswith("_") for e in on_disk["issues"] for k in e))

        loaded = issues.read_plan(self.dir)
        c1 = next(e for e in loaded["issues"] if e["display_id"] == "C1")
        self.assertTrue(os.path.exists(c1["_body_abs"]))
        secret = next(e for e in loaded["issues"] if e["display_id"] == "C2")
        self.assertIsNone(secret["_body_abs"])


class TestRender(IssuesTestCase):
    def _entry(self, display_id):
        return next(e for e in issues.plan(self.dir)["issues"] if e["display_id"] == display_id)

    def test_body_is_report_verbatim_plus_footer(self):
        entry = self._entry("C1")
        report = _read(os.path.join(self.dir, entry["body_path"]))
        title, body = issues.render_issue(entry)
        self.assertEqual(title, entry["title"])
        self.assertIn(report.strip(), body)
        self.assertIn("## Proof of Concept", body)

    def test_footer_carries_the_kavach_id_the_search_matches_on(self):
        for display_id in ("C1", "C2", "G1"):
            entry = self._entry(display_id)
            _, body = issues.render_issue(entry)
            self.assertIn(entry["kavach_id"], body,
                          f"{display_id}: idempotency search would never match its own issue")
            self.assertIn("deadbeef", body)

    def test_secret_body_is_redacted_and_never_carries_the_value(self):
        entry = self._entry("C2")
        self.assertTrue(entry["redacted"])
        self.assertIsNone(entry["_body_abs"])
        title, body = issues.render_issue(entry)

        self.assertNotIn(SECRET_VALUE, body)
        self.assertNotIn(SECRET_VALUE, title)
        self.assertNotIn(SECRET_VALUE, json.dumps(entry))
        report = _read(os.path.join(self.dir, entry["body_path"]))
        self.assertNotIn(report.strip(), body)          # report.md was never read

        self.assertIn("src/app.py:42", body)            # file:line survives
        self.assertIn("withheld", body)
        self.assertIn("secret manager", body)
        self.assertIn(entry["body_path"], body)         # points at the local audit tree

    def test_a_value_quoted_in_the_title_or_remediation_is_scrubbed(self):
        # a kavach-* authored secret finding can quote the credential in its own prose
        path = os.path.join(self.dir, "findings.json")
        data = _load(path)
        secret = next(r for r in data["findings"] if r["finding_class"] == "secret")
        secret["title"] = f"AWS key {SECRET_VALUE} committed to source"
        secret["remediation"] = f"Revoke {SECRET_VALUE} in IAM, then rotate."
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        entry = self._entry("C2")
        title, body = issues.render_issue(entry)
        self.assertNotIn(SECRET_VALUE, json.dumps(entry))
        self.assertNotIn(SECRET_VALUE, title)
        self.assertNotIn(SECRET_VALUE, body)
        self.assertIn("[withheld]", title)
        self.assertIn("Revoke [withheld] in IAM", body)

    def test_secret_entry_needs_no_report_md(self):
        os.remove(os.path.join(self.dir, "findings", "C2-c2-slug", "report.md"))
        entry = self._entry("C2")
        _, body = issues.render_issue(entry)
        self.assertIn("src/app.py:42", body)

    def test_render_issue_raises_when_the_body_is_gone(self):
        entry = self._entry("C1")
        os.remove(entry["_body_abs"])
        with self.assertRaises(issues.IssuesError):
            issues.render_issue(entry)

    def test_comment_is_a_delta_not_a_repost(self):
        entry = self._entry("C1")
        comment = issues.render_comment(entry)
        self.assertIn(entry["kavach_id"], comment)
        self.assertIn("re-audit", comment.lower())
        self.assertNotIn("## Proof of Concept", comment)


class TestGithubAdapter(IssuesTestCase):
    def test_search_is_keyed_on_kavach_id_in_body_over_all_states(self):
        self.assertEqual(
            issues._search_argv("KAVACH-7e3c775628", "acme/api"),
            ["gh", "issue", "list", "--repo", "acme/api",
             "--search", "KAVACH-7e3c775628 in:body",
             "--state", "all", "--json", "number,title,state"],
        )

    def test_mutating_allowlist_is_fail_safe(self):
        self.assertFalse(issues._is_mutating(["gh", "issue", "list"]))
        self.assertFalse(issues._is_mutating(["gh", "auth", "status"]))
        self.assertTrue(issues._is_mutating(["gh", "issue", "create"]))
        self.assertTrue(issues._is_mutating(["gh", "issue", "comment"]))
        self.assertTrue(issues._is_mutating(["gh", "issue", "some-new-verb"]))

    def test_dry_run_executes_no_mutating_command(self):
        gh = _Gh()                                  # raises if a mutating argv is executed
        result = self._push(gh)
        self.assertTrue(result["ok"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(len(result["created"]), 4)
        self.assertEqual(result["updated"], [])

        self.assertEqual(set(gh.verbs()), {"status", "list"})
        planned = [c for c in result["commands"] if c["mutating"]]
        self.assertEqual(len(planned), 4)
        self.assertTrue(all(not c["executed"] for c in planned))
        self.assertTrue(all(c["executed"] for c in result["commands"] if not c["mutating"]))
        self.assertTrue(all(c["argv"][2] == "create" for c in planned))
        self.assertTrue(all(issues._BODY_PLACEHOLDER in c["argv"] for c in planned))

    def test_dry_run_writes_nothing(self):
        self._push(_Gh())
        self.assertFalse(os.path.exists(issues.plan_path(self.dir)))

    def test_every_gh_call_has_a_timeout_and_no_shell(self):
        with patch.object(issues.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(issues.subprocess, "run", _Gh()) as run:
            issues.push_github(self.dir, issues.plan(self.dir), repo="acme/api")
        for kwargs in run.kwargs:
            self.assertEqual(kwargs["timeout"], issues.GH_TIMEOUT)
            self.assertNotIn("shell", kwargs)

    def test_existing_issue_is_commented_not_duplicated(self):
        gh = _Gh(hits=[{"number": 41, "title": "old", "state": "OPEN"}], allow_mutating=True)
        result = self._push(gh, dry_run=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["created"], [])
        self.assertEqual(len(result["updated"]), 4)
        self.assertEqual({u["number"] for u in result["updated"]}, {41})
        self.assertNotIn("create", gh.verbs())
        self.assertEqual(gh.verbs().count("comment"), 4)

    def test_a_closed_match_still_counts_as_existing(self):
        gh = _Gh(hits=[{"number": 9, "title": "old", "state": "CLOSED"}], allow_mutating=True)
        result = self._push(gh, dry_run=False)
        self.assertEqual(result["created"], [])
        self.assertEqual({u["number"] for u in result["updated"]}, {9})

    def test_real_push_records_the_issue_number_in_the_plan(self):
        gh = _Gh(hits=[{"number": 41, "title": "old", "state": "OPEN"}], allow_mutating=True)
        result = self._push(gh, dry_run=False)
        written = _load(result["plan_path"])
        self.assertTrue(all(e["existing_issue"] == 41 for e in written["issues"]))

    def test_operator_labels_are_added_to_the_planned_labels(self):
        gh = _Gh(allow_mutating=True)
        result = self._push(gh, dry_run=False, labels=["triage", "kavach"])
        create = next(c for c in result["commands"] if c["argv"][2] == "create")
        self.assertEqual(create["argv"].count("--label"), 4)     # 3 planned + 1 new, deduped
        self.assertIn("triage", create["argv"])

    def test_search_failure_is_reported_and_nothing_is_created(self):
        class _Failing(_Gh):
            def __call__(self, argv, **kwargs):
                if argv[:3] == ["gh", "issue", "list"]:
                    self.calls.append(argv)
                    return _proc(argv, 1, "", "could not resolve to a Repository")
                return super().__call__(argv, **kwargs)

        result = self._push(_Failing())
        self.assertFalse(result["ok"])
        self.assertEqual(result["created"], [])
        self.assertEqual(len(result["errors"]), 4)
        self.assertIn("could not resolve", result["errors"][0])

    def test_gh_missing_errors_and_writes_nothing(self):
        with patch.object(issues.shutil, "which", return_value=None), \
             patch.object(issues, "_run", _Gh()) as gh:
            result = issues.push_github(self.dir, issues.plan(self.dir), repo="acme/api",
                                        dry_run=False)
        self.assertFalse(result["ok"])
        self.assertIn("gh CLI not found", result["errors"][0])
        self.assertEqual(gh.calls, [])
        self.assertEqual(result["commands"], [])
        self.assertFalse(os.path.exists(issues.plan_path(self.dir)))

    def test_unauthenticated_gh_errors_before_any_issue_call(self):
        gh = _Gh(auth_rc=1)
        result = self._push(gh, dry_run=False)
        self.assertFalse(result["ok"])
        self.assertIn("not authenticated", result["errors"][0])
        self.assertEqual(gh.verbs(), ["status"])
        self.assertFalse(os.path.exists(issues.plan_path(self.dir)))

    def test_gh_binary_failure_is_caught_not_raised(self):
        def _boom(argv, **kwargs):
            raise OSError("Exec format error")

        with patch.object(issues.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(issues, "_run", _boom):
            result = issues.push_github(self.dir, issues.plan(self.dir), repo="acme/api")
        self.assertFalse(result["ok"])
        self.assertIn("Exec format error", result["errors"][0])


class TestProviderDispatch(IssuesTestCase):
    def test_github_is_the_only_provider(self):
        self.assertEqual(sorted(issues.PROVIDERS), ["github"])

    def test_dispatch_routes_to_github(self):
        gh = _Gh()
        with patch.object(issues.shutil, "which", return_value="/usr/bin/gh"), \
             patch.object(issues, "_run", gh):
            result = issues.push(self.dir, issues.plan(self.dir), provider="github",
                                 repo="acme/api")
        self.assertEqual(result["provider"], "github")

    def test_jira_is_an_explicit_error_not_a_silent_no_op(self):
        with self.assertRaises(issues.IssuesError) as ctx:
            issues.push(self.dir, issues.plan(self.dir), provider="jira", repo="acme/api")
        self.assertIn("jira", str(ctx.exception))
        self.assertIn("github", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
