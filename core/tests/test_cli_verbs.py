"""The v0.3 CLI surface: triage, coverage, budget, issues, the pdf/html renders, and the
reports/ deliverable move. One test per contract the skill or a phase gate depends on.
"""

import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from kavach import budget, coverage, flags, modes, runner, state, triage
from kavach.cli import main
from kavach.finding import (Confidence, Finding, Location, Severity, dump_findings,
                            load_findings)
from kavach.findings_tree import consolidate


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _finding(title, severity=Severity.CRITICAL, source="kavach-sast", category="A01",
             **kw) -> Finding:
    return Finding(title=title, severity=severity, category=category, source=source,
                   locations=[Location(file=f"{title.lower()}.py", line=1)],
                   what_it_is="x" * 40, how_exploited="y" * 40, business_impact="z" * 40,
                   remediation="fix it", **kw)


def _mixed_findings() -> list[Finding]:
    return [
        _finding("SQLi"),
        _finding("IDOR", severity=Severity.HIGH, source="kavach-api", category="API1:BOLA"),
        _finding("CVE-2024-1", severity=Severity.HIGH, source="trivy", category="A06:Components"),
        _finding("CVE-2024-2", severity=Severity.HIGH, source="trivy", category="A06:Components"),
        _finding("Root container", severity=Severity.HIGH, source="checkov", category="A05:Misconfig"),
        _finding("AWS key", severity=Severity.CRITICAL, source="gitleaks", category="A07:Secrets"),
        _finding("Verbose error", severity=Severity.LOW, source="semgrep", category="A09:Logging"),
    ]


def _out(dirname: str) -> list[str]:
    return ["--out", dirname]


def _restore_flag_env(case: unittest.TestCase) -> None:
    saved = {env: os.environ.get(env) for env in flags.FLAG_ENV.values()}

    def restore():
        for env, val in saved.items():
            if val is None:
                os.environ.pop(env, None)
            else:
                os.environ[env] = val

    case.addCleanup(restore)
    for env in saved:
        os.environ.pop(env, None)


def _fake_gh(argv, *_a, **_kw) -> subprocess.CompletedProcess:
    """Stand in for the one place issues.py executes gh: authenticated, no existing issue,
    every create/comment succeeds. Keeps the dry-run contract off the network."""
    stdout = "[]" if argv[2] == "list" else "https://github.com/o/r/issues/1"
    return subprocess.CompletedProcess(argv, 0, stdout, "")


class TestTriageVerb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        dump_findings(_mixed_findings(), os.path.join(self.dir, "findings.json"))

    def _run(self):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main(["triage", *_out(self.dir)])
        return rc, json.loads(buf.getvalue()), err.getvalue()

    def test_triage_classifies_in_place_and_reports_counts(self):
        rc, payload, err = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(payload["total"], 7)
        self.assertEqual(payload["by_class"]["dependency"], 2)
        self.assertEqual(payload["by_class"]["iac"], 1)
        self.assertEqual(payload["by_class"]["secret"], 1)
        self.assertEqual(payload["by_class"]["reasoned"], 2)
        self.assertEqual(payload["by_class"]["code"], 1)
        self.assertIn("dependency", err)
        for f in load_findings(os.path.join(self.dir, "findings.json")):
            self.assertIn(f.finding_class, triage.CLASSES)

    def test_triage_is_idempotent(self):
        first = self._run()[1]
        self.assertEqual(self._run()[1], first)

    def test_triage_does_not_change_any_fingerprint(self):
        before = [f.fingerprint() for f in load_findings(os.path.join(self.dir, "findings.json"))]
        self._run()
        after = [f.fingerprint() for f in load_findings(os.path.join(self.dir, "findings.json"))]
        self.assertEqual(before, after)


class TestCoverageVerb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.dirs = consolidate(self.dir, _mixed_findings())

    def _run(self, kind):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main(["coverage", "--phase", kind, *_out(self.dir)])
        return rc, json.loads(buf.getvalue()), err.getvalue()

    def test_cli_choices_match_the_module(self):
        self.assertEqual(coverage.KINDS, ("poc", "report"))

    def test_missing_poc_is_exit_7_and_leaves_the_gate_unsatisfied(self):
        rc, payload, err = self._run("poc")
        self.assertEqual(rc, 7)
        self.assertFalse(payload["complete"])
        self.assertIn("C1", err)
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, "attack-surface", "poc-coverage.json")))
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6"))

    def test_aggregates_are_exempt_and_a_full_sweep_is_exit_0(self):
        for fdir in self.dirs:
            with open(os.path.join(fdir, "metadata.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
            if not meta["is_aggregate"]:
                with open(os.path.join(fdir, "poc.theoretical.md"), "w", encoding="utf-8") as fh:
                    fh.write("static-only reproduction\n")
        rc, payload, _ = self._run("poc")
        self.assertEqual(rc, 0)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["aggregates_exempt"], 2)
        self.assertTrue(runner.gate_satisfied(self.dir, "BL6"))


class TestBudgetVerb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        # --budget mirrors into KAVACH_MAX_DISPATCHES for the whole process (that is the point
        # - a later dispatch reads the same ceiling), so each case starts from a clean env.
        _restore_flag_env(self)

    def _run(self, *argv):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main([*argv, *_out(self.dir)])
        return rc, buf.getvalue(), err.getvalue()

    def test_state_init_seeds_the_ledger_from_the_mode(self):
        self._run("state", "init", "--mode", "deep")
        rc, payload, _ = self._run("budget", "show")
        self.assertEqual(rc, 0)
        ledger = json.loads(payload)
        self.assertEqual(ledger["max_dispatches"], budget.DEFAULT_MAX_DISPATCHES["deep"])
        self.assertEqual(ledger["dispatches"], 0)
        self.assertEqual(ledger["remaining"], budget.DEFAULT_MAX_DISPATCHES["deep"])

    def test_budget_flag_overrides_the_mode_default(self):
        self._run("state", "init", "--mode", "deep", "--budget", "9")
        self.assertEqual(json.loads(self._run("budget", "show")[1])["max_dispatches"], 9)

    def test_check_sheds_and_records_when_planned_exceeds_the_ceiling(self):
        self._run("state", "init", "--mode", "lite", "--budget", "4")
        rc, payload, err = self._run("budget", "check", "--phase", "BL3", "--planned", "8")
        self.assertEqual(rc, 7)
        self.assertEqual(json.loads(payload), {"allowed": 4, "dropped": 4,
                                              "reason": budget.DISPATCH_CEILING})
        self.assertIn("4/8 allowed", err)
        shed = budget.shed_records(self.dir)
        self.assertEqual(len(shed), 1)
        self.assertEqual(shed[0]["dropped"], 4)

    def test_check_within_budget_is_exit_0_and_charge_accounts(self):
        self._run("state", "init", "--mode", "lite", "--budget", "10")
        self.assertEqual(self._run("budget", "check", "--phase", "BL3", "--planned", "6")[0], 0)
        self.assertEqual(self._run("budget", "charge", "--phase", "BL3", "-n", "6")[0], 0)
        ledger = json.loads(self._run("budget", "show")[1])
        self.assertEqual((ledger["dispatches"], ledger["remaining"]), (6, 4))
        self.assertEqual(ledger["by_phase"], {"BL3": 6})

    def test_check_and_charge_need_a_phase(self):
        self._run("state", "init", "--mode", "lite")
        self.assertEqual(self._run("budget", "check", "--planned", "1")[0], 5)
        self.assertEqual(self._run("budget", "charge", "-n", "1")[0], 5)

    def test_budget_verbs_without_an_audit_are_a_tooling_error(self):
        self.assertEqual(self._run("budget", "check", "--phase", "BL3", "--planned", "1")[0], 5)
        self.assertEqual(self._run("budget", "show")[0], 0)


class TestFlagEnvMirroring(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._saved = {k: os.environ.get(k) for k in flags.FLAG_ENV.values()}

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_flags_reach_the_env_readers_a_subagent_sees(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            main(["state", "init", "--mode", "lite", "--out", self.dir,
                  "--budget", "0", "--max-wall-seconds", "60"])
        self.assertEqual(os.environ["KAVACH_MAX_DISPATCHES"], "0")
        self.assertEqual(os.environ["KAVACH_MAX_WALL_SECONDS"], "60")
        self.assertEqual(flags.max_dispatches(120), 0)      # 0 = unlimited, not exhausted
        self.assertEqual(flags.max_wall_seconds(10800), 60)


class TestRenderVerb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        dump_findings(_mixed_findings(), os.path.join(self.dir, "findings.json"))
        self.reports = os.path.join(self.dir, "reports")

    def _run(self, *argv):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main([*argv, "--out", self.dir, "--severity-only"])
        return rc, buf.getvalue(), err.getvalue()

    def test_md_render_creates_the_reports_dir_it_is_told_to_write_into(self):
        path = os.path.join(self.reports, "final-audit-report.md")
        self.assertEqual(self._run("render", "--format", "md", "--output", path)[0], 0)
        self.assertTrue(os.path.exists(path))
        self.assertTrue(runner.gate_satisfied(self.dir, "BL6c"))

    def test_html_render_does_not_need_reportlab(self):
        rc, body, _ = self._run("render", "--format", "html")
        self.assertEqual(rc, 0)
        self.assertIn("<html", body.lower())

    def test_pdf_without_output_is_a_clear_tooling_error(self):
        rc, _, err = self._run("render", "--format", "pdf")
        self.assertEqual(rc, 5)
        self.assertIn("--output", err)

    def test_pdf_writes_bytes_and_logs_a_summary(self):
        try:
            import reportlab  # noqa: F401
        except ImportError:
            self.skipTest("reportlab absent; the html/md paths cover the fallback")
        path = os.path.join(self.reports, "audit-report.pdf")
        rc, stdout, err = self._run("render", "--format", "pdf", "--output", path)
        self.assertEqual(rc, 0)
        self.assertEqual(stdout, "")                     # the document is the file, not stdout
        self.assertIn("page(s)", err)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(5), b"%PDF-")

    def test_audit_dir_reaches_the_limits_section(self):
        """W-C is explicit: without meta["audit_dir"] the report loses budget.shed and the
        coverage gaps. That list is the honesty property of the whole redesign."""
        run = state.init_audit(self.dir, "lite", modes.phases_for("lite"))
        budget.init_budget(self.dir, run.audit_id, "lite", max_dispatches=2)
        budget.check(self.dir, run.audit_id, "LT3", 9)
        consolidate(self.dir, _mixed_findings())
        coverage.write_coverage(self.dir, "poc")

        body = self._run("render", "--format", "md")[1]
        limits = body.split("### 2.3 Limits of this run")[1].split("## 3.")[0]
        self.assertIn("Phase LT3: 7 of 9 planned subagent dispatches were dropped", limits)
        self.assertIn("dispatch ceiling", limits)
        self.assertIn("have no proof of concept", limits)
        self.assertIn("C1", limits)

    def test_suspected_findings_reach_limits_without_an_audit_dir_artifact(self):
        dump_findings([_finding("Maybe SSRF", confidence=Confidence.SUSPECTED)],
                      os.path.join(self.dir, "findings.json"))
        self.assertEqual(self._run("render", "--format", "md")[0], 0)


class TestCoverMetadata(unittest.TestCase):
    """The cover metadata table used to print "not recorded" on both lines, because --date and
    --commit defaulted to empty strings and nothing filled them."""

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.dir = os.path.join(self.repo, ".kavach")
        os.makedirs(self.dir)
        dump_findings(_mixed_findings(), os.path.join(self.dir, "findings.json"))

    def _cover(self, *argv):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main(["render", "--format", "md", "--out", self.dir, "--severity-only", *argv])
        self.assertEqual(rc, 0, err.getvalue())
        rows = {}
        for line in buf.getvalue().splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 2 and cells[0] in ("Date", "Commit"):
                rows[cells[0]] = cells[1]
        return rows

    def test_date_defaults_to_today_in_utc(self):
        self.assertEqual(self._cover()["Date"], time.strftime("%Y-%m-%d", time.gmtime()))

    def test_explicit_date_and_commit_still_win(self):
        rows = self._cover("--date", "2020-01-01", "--commit", "deadbeef")
        self.assertEqual(rows["Date"], "2020-01-01")
        self.assertEqual(rows["Commit"], "deadbeef")

    def _init_git(self) -> str:
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.com")
        _git(self.repo, "config", "user.name", "test")
        _git(self.repo, "commit", "-q", "--allow-empty", "-m", "first")
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_commit_comes_from_the_audited_tree_not_the_process_cwd(self):
        head = self._init_git()
        self.assertEqual(self._cover()["Commit"], head)

    def test_the_recorded_audit_commit_outranks_a_moved_on_working_tree(self):
        """The cover describes the tree the findings came from. A HEAD that moved on since
        `state complete` is a commit this report was never produced against."""
        head = self._init_git()
        state.init_audit(self.dir, "lite", modes.phases_for("lite"))
        state.complete_audit(self.dir, "e47d11f4")
        self.assertNotEqual(head, "e47d11f4")
        self.assertEqual(self._cover()["Commit"], "e47d11f4")

    def test_an_in_progress_run_has_no_recorded_commit_and_gets_live_head(self):
        head = self._init_git()
        state.init_audit(self.dir, "lite", modes.phases_for("lite"))
        self.assertEqual(self._cover()["Commit"], head)

    def test_a_later_null_commit_record_does_not_shadow_a_completed_one(self):
        state.init_audit(self.dir, "deep", modes.phases_for("deep"))
        state.complete_audit(self.dir, "e47d11f4")
        state.init_audit(self.dir, "balanced", modes.phases_for("balanced"))
        self.assertIsNone(state.latest_audit(self.dir).commit)
        self.assertEqual(self._cover()["Commit"], "e47d11f4")

    def test_a_gitless_target_falls_back_to_the_recorded_audit_commit(self):
        state.init_audit(self.dir, "lite", modes.phases_for("lite"))
        state.complete_audit(self.dir, "abc1234")
        self.assertEqual(self._cover()["Commit"], "abc1234")

    def test_no_git_and_no_audit_record_is_honestly_not_recorded(self):
        rows = self._cover()
        self.assertEqual(rows["Commit"], "not recorded")
        self.assertNotEqual(rows["Date"], "not recorded")


class TestScanNoLongerWritesTheRetiredReport(unittest.TestCase):
    """Root cause 11: every doc calls KAVACH_SECURITY_REPORT.<ext> retired; cmd_scan still
    wrote it. recon/sweep are stubbed - the contract under test is scan's render tail, and a
    real sweep pulls docker images."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.repo = tempfile.mkdtemp()
        dump_findings(_mixed_findings(), os.path.join(self.dir, "findings.json"))

    def _scan(self, *extra):
        buf, err = io.StringIO(), io.StringIO()
        with mock.patch("kavach.cli.cmd_recon", return_value=0), \
             mock.patch("kavach.cli.cmd_sweep", return_value=0), \
             redirect_stdout(buf), redirect_stderr(err):
            rc = main(["scan", self.repo, "--out", self.dir, "--format", "md", *extra])
        return rc, buf.getvalue(), err.getvalue()

    def test_scan_prints_the_render_and_writes_no_retired_report(self):
        rc, body, _ = self._scan()
        self.assertEqual(rc, 0)
        self.assertIn("KAVACH Security Report", body)
        for name in os.listdir(self.dir):
            self.assertFalse(name.startswith("KAVACH_SECURITY_REPORT"), name)

    def test_scan_output_flag_writes_where_it_is_told(self):
        path = os.path.join(self.dir, "reports", "scan.md")
        rc, _, _ = self._scan("--output", path)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(path))

    def test_scan_never_pre_satisfies_the_report_gate(self):
        self._scan()
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6c"))


class TestIssuesVerb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        findings = _mixed_findings()
        dump_findings(findings, os.path.join(self.dir, "findings.json"))
        for fdir in consolidate(self.dir, findings):
            with open(os.path.join(fdir, "report.md"), "w", encoding="utf-8") as fh:
                fh.write("# t\n\n## Summary\n\n" + "s" * 200 + "\n\n## Details\n\n" + "d" * 200
                         + "\n\n## Root Cause\n\nrc\n\n## Proof of Concept\n\npoc\n\n"
                         "## Impact\n\nimpact\n")

    def _run(self, *argv):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = main([*argv, *_out(self.dir)])
        return rc, buf.getvalue(), err.getvalue()

    def test_plan_writes_the_plan_under_reports(self):
        rc, _, err = self._run("issues", "plan")
        self.assertEqual(rc, 0)
        path = os.path.join(self.dir, "reports", "issues.json")
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            plan = json.load(fh)
        self.assertTrue(plan["issues"])
        self.assertIn("redacted", err)

    def test_secret_class_entries_are_redacted_and_never_read_their_report(self):
        from kavach import issues
        self._run("issues", "plan")
        with open(os.path.join(self.dir, "reports", "issues.json"), encoding="utf-8") as fh:
            plan = json.load(fh)
        secrets = [e for e in plan["issues"] if e["finding_class"] == "secret"]
        self.assertTrue(secrets)
        hydrated = {e["kavach_id"]: e for e in issues.read_plan(self.dir)["issues"]}
        for e in secrets:
            self.assertTrue(e["redacted"])
            self.assertIsNone(hydrated[e["kavach_id"]]["_body_abs"])
            body = issues.render_issue(hydrated[e["kavach_id"]])[1]
            self.assertIn("withheld from this issue", body)
            self.assertNotIn("hunter2", body)

    def test_push_without_a_plan_is_a_tooling_error(self):
        self.assertEqual(self._run("issues", "push", "--repo", "o/r")[0], 5)

    def test_push_without_repo_is_a_tooling_error(self):
        self._run("issues", "plan")
        self.assertEqual(self._run("issues", "push")[0], 5)

    def test_push_without_yes_is_a_dry_run_that_shows_what_it_would_do(self):
        self._run("issues", "plan")
        with mock.patch("kavach.issues.shutil.which", return_value="/usr/bin/gh"), \
             mock.patch("kavach.issues._run", side_effect=_fake_gh) as run:
            rc, _, err = self._run("issues", "push", "--repo", "o/r")
        self.assertEqual(rc, 0)
        self.assertIn("DRY RUN", err)
        self.assertNotIn("LIVE", err)
        self.assertIn("would run:", err)
        self.assertIn("dry run", err)
        for call in run.call_args_list:
            self.assertNotIn(call.args[0][2], ("create", "comment"))

    def test_push_with_yes_announces_the_repo_and_the_redacted_count_first(self):
        self._run("issues", "plan")
        with mock.patch("kavach.issues.shutil.which", return_value="/usr/bin/gh"), \
             mock.patch("kavach.issues._run", side_effect=_fake_gh):
            rc, _, err = self._run("issues", "push", "--repo", "o/r", "--yes")
        self.assertEqual(rc, 0)
        self.assertIn("LIVE (--yes given)", err)
        self.assertIn("secret-class redacted", err)
        self.assertIn("o/r", err.split("created")[0])


class TestEngineSeamFlags(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _prompt(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(io.StringIO()):
            rc = main(["phase-prompt", *argv, "--out", self.dir, "--mode", "deep"])
        self.assertEqual(rc, 0)
        return buf.getvalue()

    def test_index_gives_each_fan_out_dispatch_its_own_result_path(self):
        """Without --index the eight BL3/DP4 hunters are all told to write one file."""
        paths = {self._prompt("DP4", "--agent", "kavach-sast", "--index", str(i))
                 .split("audit root):\n")[1].splitlines()[0].strip()
                 for i in range(1, 9)}
        self.assertEqual(len(paths), 8)

    def test_agent_overrides_the_phases_default_executor(self):
        body = self._prompt("DP4", "--agent", "kavach-billing")
        self.assertIn("kavach-billing.json", body)

    def test_ingest_folds_every_result_of_a_phase_when_no_result_is_named(self):
        from kavach import dispatch
        for i in (1, 2):
            path = dispatch.result_path(self.dir, "DP4", "kavach-sast", index=i)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [_finding(f"F{i}").to_dict()]}, fh)
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["ingest", "DP4", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertIn("2 draft(s) from 2 result file(s)", buf.getvalue())

    def test_ingest_with_nothing_on_disk_is_a_tooling_error(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["ingest", "DP4", "--out", self.dir]), 5)

    def test_report_finding_on_an_aggregate_is_a_no_op_not_an_error(self):
        findings = _mixed_findings()
        dump_findings(findings, os.path.join(self.dir, "findings.json"))
        consolidate(self.dir, findings)
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["report-finding", "G1", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertIn("aggregate", buf.getvalue())


class TestReportsDeliverableMove(unittest.TestCase):
    """final-audit-report.md and confirmation-report.md live under reports/. Every
    gate that named them must resolve for a new run AND for an audit tree already on disk."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _write(self, rel: str) -> None:
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("KAVACH report\n" + "x" * 600)

    def test_every_report_gate_points_under_reports(self):
        gates = {p: g for p, g in modes.PHASE_GATES.items()
                 if any(n in g[0] for n in ("final-audit-report", "confirmation-report"))}
        self.assertEqual(set(gates), {"BL6c", "DP15", "DP16", "RV11c", "MG7", "CF6"})
        for phase, gate in gates.items():
            self.assertTrue(gate[0].startswith("reports/"), f"{phase}: {gate}")

    def test_the_new_path_satisfies_every_report_gate(self):
        self._write("reports/final-audit-report.md")
        self._write("reports/confirmation-report.md")
        for phase in ("BL6c", "DP15", "DP16", "RV11c", "MG7", "CF6"):
            self.assertTrue(runner.gate_satisfied(self.dir, phase), phase)

    def test_a_pre_0_3_audit_root_report_still_gates_complete(self):
        self._write("final-audit-report.md")
        self._write("confirmation-report.md")
        for phase in ("BL6c", "DP15", "DP16", "RV11c", "MG7", "CF6"):
            self.assertTrue(runner.gate_satisfied(self.dir, phase), phase)

    def test_the_size_rule_still_applies_at_either_path(self):
        for rel in ("reports/final-audit-report.md", "final-audit-report.md"):
            path = os.path.join(self.dir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("truncated")
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6c"))


if __name__ == "__main__":
    unittest.main()
