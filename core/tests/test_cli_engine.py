import gzip
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from kavach import state
from kavach.cli import main
from kavach.finding import Finding, Location, Severity, dump_findings
from kavach.findings_tree import consolidate
from kavach.state import RunStatus


class TestCliEngine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_state_init_and_plan(self):
        rc = main(["state", "init", "--mode", "balanced", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertIsNotNone(state.latest_audit(self.dir))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["plan", "--mode", "balanced", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip().splitlines()[0], "recon")

    def test_phase_prompt_emits_header(self):
        main(["state", "init", "--mode", "balanced", "--out", self.dir])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["phase-prompt", "kb", "--mode", "balanced",
                       "--target", ".", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertIn("Architecture & Threat Model", buf.getvalue())


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


class TestCmdDiff(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.repo = tempfile.mkdtemp()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "test@example.com")
        _git(self.repo, "config", "user.name", "test")
        with open(os.path.join(self.repo, "a.py"), "w") as fh:
            fh.write("print(1)\n")
        _git(self.repo, "add", "a.py")
        _git(self.repo, "commit", "-q", "-m", "first")
        self.first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo,
                                    capture_output=True, text=True, check=True).stdout.strip()
        with open(os.path.join(self.repo, "b.py"), "w") as fh:
            fh.write("print(2)\n")
        _git(self.repo, "add", "b.py")
        _git(self.repo, "commit", "-q", "-m", "second")

    def test_since_scopes_and_writes_scope_not_summary(self):
        rc = main(["diff", self.repo, "--since", self.first, "--out", self.out])
        self.assertEqual(rc, 0)
        scope = os.path.join(self.out, "attack-surface", "diff-scope.md")
        self.assertTrue(os.path.exists(scope))
        with open(scope, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("b.py", body)
        self.assertIn("IN SCOPE", body)

        # diff-summary.md named the DF1 scan gate the mode collapse deleted from the
        # registry; `kavach diff` writes its own scope report under a different name so
        # it doesn't revive that expectation.
        summary = os.path.join(self.out, "attack-surface", "diff-summary.md")
        self.assertFalse(os.path.exists(summary))

    def test_no_prior_commit_is_tooling_error(self):
        rc = main(["diff", self.repo, "--out", self.out])
        self.assertEqual(rc, 5)

    def test_no_durable_baseline_reports_full_scan(self):
        baseline = [Finding(title="SQLi", severity=Severity.HIGH, category="A01", source="s",
                            locations=[Location(file="a.py", line=1)])]
        dump_findings(baseline, os.path.join(self.out, "findings.json"))

        # no `state complete` has ever run for this prior commit, so there is no durable
        # attack-surface/findings-baseline-<prior>.json to diff against
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["diff", self.repo, "--since", self.first, "--out", self.out])
        self.assertEqual(rc, 0)
        self.assertIn("no prior baseline, full-scan", buf.getvalue())

    def test_drift_diffs_against_a_pre_0_3_uncompressed_baseline(self):
        """A legacy audit tree has a plain .json baseline. It must still diff -
        the operator does not re-run a completed audit to upgrade its baseline format."""
        baseline = [Finding(title="SQLi", severity=Severity.HIGH, category="A01", source="s",
                            locations=[Location(file="a.py", line=1)])]
        legacy = os.path.join(self.out, "attack-surface",
                              f"findings-baseline-{self.first}.json")
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        dump_findings(baseline, legacy)
        dump_findings(baseline + [Finding(title="SSRF", severity=Severity.HIGH, category="A01",
                                          source="s", locations=[Location(file="b.py", line=1)])],
                      os.path.join(self.out, "findings.json"))

        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["diff", self.repo, "--since", self.first, "--out", self.out])
        self.assertEqual(rc, 0)
        self.assertIn("new 1", buf.getvalue())

    def test_drift_diffs_against_durable_baseline(self):
        baseline = [Finding(title="SQLi", severity=Severity.HIGH, category="A01", source="s",
                            locations=[Location(file="a.py", line=1)])]
        dump_findings(baseline, os.path.join(self.out, "findings.json"))

        # a prior run completed at `first` and snapshotted the baseline
        main(["state", "init", "--mode", "lite", "--out", self.out])
        main(["state", "complete", "--out", self.out, "--commit", self.first])
        baseline_path = os.path.join(self.out, "attack-surface",
                                     f"findings-baseline-{self.first}.json.gz")
        self.assertTrue(os.path.exists(baseline_path))

        current = baseline + [Finding(title="SSRF", severity=Severity.HIGH, category="A01",
                                      source="s", locations=[Location(file="b.py", line=1)])]
        dump_findings(current, os.path.join(self.out, "findings.json"))
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main(["diff", self.repo, "--since", self.first, "--out", self.out])
        self.assertEqual(rc, 0)
        self.assertIn("drift", buf.getvalue())
        self.assertIn("new 1", buf.getvalue())


class TestCmdStateComplete(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_marks_complete_and_snapshots_baseline(self):
        main(["state", "init", "--mode", "balanced", "--out", self.dir])
        dump_findings([Finding(title="SQLi", severity=Severity.HIGH, category="A01", source="s",
                               locations=[Location(file="a.py", line=1)])],
                      os.path.join(self.dir, "findings.json"))

        rc = main(["state", "complete", "--out", self.dir, "--commit", "deadbeef"])
        self.assertEqual(rc, 0)

        run = state.latest_audit(self.dir)
        self.assertEqual(run.status, RunStatus.COMPLETE)
        self.assertEqual(run.commit, "deadbeef")
        self.assertIsNotNone(run.completed_at)
        # gzipped - the plain copy was byte-identical to findings.json
        baseline = os.path.join(self.dir, "attack-surface", "findings-baseline-deadbeef.json.gz")
        self.assertTrue(os.path.exists(baseline))
        self.assertFalse(os.path.exists(baseline[:-3]))
        with gzip.open(baseline, "rt", encoding="utf-8") as fh:
            self.assertEqual(len(json.load(fh)["findings"]), 1)

    def test_no_in_progress_audit_is_tooling_error(self):
        rc = main(["state", "complete", "--out", self.dir, "--commit", "deadbeef"])
        self.assertEqual(rc, 5)


class TestCmdMergeRun(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp()
        self.src_a = tempfile.mkdtemp()
        self.src_b = tempfile.mkdtemp()

    def test_merge_run_writes_gate_artifacts_and_promotes(self):
        dump_findings([Finding(title="SQLi", severity=Severity.CRITICAL, category="A01",
                               source="kavach-sast", locations=[Location(file="x.py", line=1)])],
                      os.path.join(self.src_a, "findings.json"))
        dump_findings([Finding(title="XSS", severity=Severity.HIGH, category="A01",
                               source="kavach-sast", locations=[Location(file="y.py", line=1)])],
                      os.path.join(self.src_b, "findings.json"))

        rc = main(["merge-run", "--out", self.out, "--dir", self.src_a, "--dir", self.src_b])
        self.assertEqual(rc, 0)

        index_path = os.path.join(self.out, "attack-surface", "merge-index.json")
        rename_path = os.path.join(self.out, "attack-surface", "merge-rename-map.json")
        self.assertTrue(os.path.exists(index_path))
        self.assertTrue(os.path.exists(rename_path))
        self.assertTrue(os.path.exists(os.path.join(self.out, "attack-surface", "merge-summary.md")))

        promoted = os.listdir(os.path.join(self.out, "findings"))
        self.assertEqual(len(promoted), 2)

    def test_merge_run_needs_two_sources(self):
        rc = main(["merge-run", "--out", self.out, "--dir", self.src_a])
        self.assertEqual(rc, 5)

    def test_shared_finding_across_sources_promotes_once(self):
        # same finding (same fingerprint) reported independently by two source audits -
        # MG1's sweep.dedupe must collapse it before MG6 promotes, or the merged set
        # double-counts a single defect.
        shared = Finding(title="SQLi", severity=Severity.HIGH, category="A01",
                         source="kavach-sast", locations=[Location(file="x.py", line=1)])
        dump_findings([shared], os.path.join(self.src_a, "findings.json"))
        dump_findings([shared], os.path.join(self.src_b, "findings.json"))

        rc = main(["merge-run", "--out", self.out, "--dir", self.src_a, "--dir", self.src_b])
        self.assertEqual(rc, 0)

        promoted = os.listdir(os.path.join(self.out, "findings"))
        self.assertEqual(len(promoted), 1)

    def test_merge_run_consumes_dedup_decisions_if_present(self):
        # two DIFFERENT-fingerprint findings that kavach-chamber (MG2) judged to be the
        # same underlying defect described differently - only sweep.dedupe's exact-match
        # can't catch this, so merge-run must read dedup-decisions.json if it exists.
        f_a = Finding(title="SQLi via string concat", severity=Severity.CRITICAL, category="A01",
                     source="kavach-sast", locations=[Location(file="x.py", line=1)])
        f_b = Finding(title="SQLi via f-string", severity=Severity.HIGH, category="A01",
                     source="kavach-sast", locations=[Location(file="y.py", line=1)])
        dump_findings([f_a], os.path.join(self.src_a, "findings.json"))
        dump_findings([f_b], os.path.join(self.src_b, "findings.json"))

        gate_dir = os.path.join(self.out, "attack-surface")
        os.makedirs(gate_dir, exist_ok=True)
        with open(os.path.join(gate_dir, "merge-dedup-decisions.json"), "w", encoding="utf-8") as fh:
            json.dump([{"drop": f_b.fingerprint(), "keep": f_a.fingerprint(),
                       "reason": "same SQLi sink, different string-building style"}], fh)

        rc = main(["merge-run", "--out", self.out, "--dir", self.src_a, "--dir", self.src_b])
        self.assertEqual(rc, 0)

        promoted = os.listdir(os.path.join(self.out, "findings"))
        self.assertEqual(len(promoted), 1)
        with open(os.path.join(self.out, "attack-surface", "merge-summary.md"), encoding="utf-8") as fh:
            self.assertIn("same SQLi sink", fh.read())


class TestMalformedJsonIsToolingError(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_kb_kill_chains_malformed_json_exits_5(self):
        path = os.path.join(self.dir, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        rc = main(["kb", "kill-chains", "--file", path, "--out", self.dir])
        self.assertEqual(rc, 5)

    def test_report_finding_malformed_metadata_json_exits_5(self):
        finding_dir = os.path.join(self.dir, "findings", "H1-x")
        os.makedirs(finding_dir)
        with open(os.path.join(finding_dir, "metadata.json"), "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        rc = main(["report-finding", "H1", "--out", self.dir])
        self.assertEqual(rc, 5)


class TestCmdRenderWithoutRecon(unittest.TestCase):
    """balanced/deep can reach a report phase in an audit dir that never had a core:recon
    pass of its own - render must still produce a report, not crash with FileNotFoundError
    (which would leave `render`'s gate unsatisfiable forever)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_render_with_no_recon_json_still_writes_a_report(self):
        self.assertFalse(os.path.exists(os.path.join(self.dir, "recon.json")))
        dump_findings([Finding(title="SQLi", severity=Severity.HIGH, category="A01", source="s",
                               locations=[Location(file="a.py", line=1)])],
                      os.path.join(self.dir, "findings.json"))

        report_path = os.path.join(self.dir, "final-audit-report.md")
        rc = main(["render", "--out", self.dir, "--format", "md", "--severity-only",
                  "--output", report_path])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("KAVACH Security Report", body)
        self.assertIn("SQLi", body)

    def test_render_with_no_recon_json_and_no_findings(self):
        rc = main(["render", "--out", self.dir, "--format", "json", "--severity-only"])
        self.assertEqual(rc, 5)  # findings.json itself is also absent - a real tooling error

        dump_findings([], os.path.join(self.dir, "findings.json"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["render", "--out", self.dir, "--format", "json", "--severity-only"])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["totals"], {"files": 0, "code_files": 0, "by_language": {}, "by_extension": {}})
        self.assertEqual(report["findings"], [])


class TestCmdResume(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_nothing_to_resume(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["resume", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertIn("nothing to resume", buf.getvalue())

    def test_resumes_latest_in_progress(self):
        state.init_audit(self.dir, "balanced", ["recon", "sweep"], repository="o/r")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["resume", "--out", self.dir])
        self.assertEqual(rc, 0)
        lines = buf.getvalue().splitlines()
        # line 1 is the bare mode token, not "mode: balanced" - SKILL.md's
        # `read -r MODE PHASES < <(K resume ...)` reads only the first line, so a prefix
        # there means MODE ends up as the literal string "mode:".
        self.assertEqual(lines[0], "balanced")
        self.assertIn("recon", lines)

    def test_resume_line_one_is_bare_mode_after_state_init(self):
        main(["state", "init", "--out", self.dir, "--mode", "lite"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["resume", "--out", self.dir])
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().splitlines()[0], "lite")


class TestCmdReportFinding(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_renders_report_for_display_id(self):
        f = Finding(title="IDOR on /orders", severity=Severity.HIGH, category="API1:BOLA",
                   source="kavach-api", locations=[Location(file="src/orders.py", line=42)],
                   what_it_is="details" * 20, how_exploited="steps" * 20,
                   business_impact="impact" * 20, remediation="fix" * 20)
        dump_findings([f], os.path.join(self.dir, "findings.json"))
        dirs = consolidate(self.dir, [f])
        display_id = os.path.basename(dirs[0]).split("-", 1)[0]

        rc = main(["report-finding", display_id, "--out", self.dir])
        self.assertEqual(rc, 0)
        report_path = os.path.join(dirs[0], "report.md")
        self.assertTrue(os.path.exists(report_path))
        with open(report_path, encoding="utf-8") as fh:
            self.assertIn("IDOR on /orders", fh.read())

    def test_unknown_display_id_is_tooling_error(self):
        rc = main(["report-finding", "H99", "--out", self.dir])
        self.assertEqual(rc, 5)


class TestCmdKbKillChains(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_writes_kill_chains_from_file(self):
        chains = [{"letter": "c", "goal": "Bypass the billing wall", "verdict": "EXPLOITABLE",
                  "leaves": [{"technique": "client-trusted price", "status": "EXPLOITABLE",
                             "ref": "C1"}]}]
        path = os.path.join(self.dir, "chains.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(chains, fh)

        rc = main(["kb", "kill-chains", "--file", path, "--out", self.dir])
        self.assertEqual(rc, 0)
        with open(os.path.join(self.dir, "attack-surface", "kill-chains.md"),
                 encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("Bypass the billing wall", body)


if __name__ == "__main__":
    unittest.main()
