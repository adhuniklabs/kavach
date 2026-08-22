import json
import os
import tempfile
import unittest

from kavach import coverage, findings_tree, report_finding, runner
from kavach.finding import Confidence, Finding, Location, Severity


def _reasoned(title="IDOR on /orders"):
    return Finding(
        title=title, severity=Severity.HIGH, category="API1:BOLA", source="kavach-api",
        locations=[Location(file="api/orders.py", line=42)],
        what_it_is="x" * 200, how_exploited="y" * 200, business_impact="z" * 200,
        remediation="w" * 200, confidence=Confidence.CONFIRMED, cvss_score=8.1,
    )


def _scanner_row(title="requests 2.28.1: CVE-2024-35195"):
    return Finding(title=title, severity=Severity.HIGH, category="A06:Vulnerable-Components",
                   source="trivy", rule_id="CVE-2024-35195",
                   locations=[Location(file="requirements.txt", line=3)],
                   remediation="Upgrade requests to 2.31.0.", confidence=Confidence.CONFIRMED)


class TestPocCoverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_promoted_finding_without_a_poc_is_missing(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        report = coverage.poc_coverage(self.dir)
        self.assertFalse(report["complete"])
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["satisfied"], 0)
        self.assertEqual(report["missing"][0]["display_id"], "H1")
        self.assertTrue(report["missing"][0]["dir"].startswith("findings/H1-"))
        self.assertIn("poc", report["missing"][0]["reason"])

    def test_any_poc_file_satisfies(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        with open(os.path.join(dirs[0], "poc.py"), "w", encoding="utf-8") as fh:
            fh.write("import requests\n")
        self.assertTrue(coverage.poc_coverage(self.dir)["complete"])

    def test_theoretical_poc_satisfies(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        with open(os.path.join(dirs[0], "poc.theoretical.md"), "w", encoding="utf-8") as fh:
            fh.write("# Theoretical\n\nNo safe live repro.\n")
        self.assertTrue(coverage.poc_coverage(self.dir)["complete"])

    def test_empty_poc_file_does_not_satisfy(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        open(os.path.join(dirs[0], "poc.py"), "w").close()
        self.assertFalse(coverage.poc_coverage(self.dir)["complete"])

    def test_aggregates_are_exempt_and_counted(self):
        findings_tree.consolidate(self.dir, [_scanner_row()])
        report = coverage.poc_coverage(self.dir)
        self.assertTrue(report["complete"])
        self.assertEqual(report["total"], 1)
        self.assertEqual(report["aggregates_exempt"], 1)
        self.assertEqual(report["satisfied"], 1)

    def test_false_positive_dirs_are_not_counted(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        findings_tree.mark_false_positive(self.dir, dirs[0])
        report = coverage.poc_coverage(self.dir)
        self.assertEqual(report["total"], 0)
        self.assertTrue(report["complete"])

    def test_zero_promoted_findings_is_complete(self):
        findings_tree.consolidate(self.dir, [])
        self.assertTrue(coverage.poc_coverage(self.dir)["complete"])


class TestReportCoverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_missing_report_is_reported(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        report = coverage.report_coverage(self.dir)
        self.assertFalse(report["complete"])
        self.assertEqual(report["missing"][0]["display_id"], "H1")

    def test_report_failing_the_contract_does_not_satisfy(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        with open(os.path.join(dirs[0], "report.md"), "w", encoding="utf-8") as fh:
            fh.write("# IDOR\n\nsee draft for details\n")
        self.assertFalse(coverage.report_coverage(self.dir)["complete"])

    def test_contract_passing_report_satisfies(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        report_finding.write_report(dirs[0], _reasoned())
        self.assertTrue(coverage.report_coverage(self.dir)["complete"])

    def test_core_written_aggregate_report_satisfies_without_an_agent(self):
        findings_tree.consolidate(self.dir, [_scanner_row()])
        self.assertTrue(coverage.report_coverage(self.dir)["complete"])


class TestWriteCoverage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_writes_both_artifacts_where_the_gates_look(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        for kind in coverage.KINDS:
            path = coverage.write_coverage(self.dir, kind)
            self.assertEqual(path, os.path.join(self.dir, "attack-surface",
                                                f"{kind}-coverage.json"))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["kind"], kind)


class TestCoverageGatesThePhase(unittest.TestCase):
    """Acceptance criterion 7: 'complete with 0 PoCs' is now impossible."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_deep_poc_phase_stays_open_until_the_poc_exists(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        coverage.write_coverage(self.dir, "poc")
        self.assertFalse(runner.gate_satisfied(self.dir, "DP13"))

        with open(os.path.join(dirs[0], "poc.theoretical.md"), "w", encoding="utf-8") as fh:
            fh.write("# Theoretical\n\nNo safe live repro.\n")
        coverage.write_coverage(self.dir, "poc")
        self.assertTrue(runner.gate_satisfied(self.dir, "DP13"))

    def test_report_phase_stays_open_until_the_report_passes_the_contract(self):
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        coverage.write_coverage(self.dir, "report")
        self.assertFalse(runner.gate_satisfied(self.dir, "DP14"))

        report_finding.write_report(dirs[0], _reasoned())
        coverage.write_coverage(self.dir, "report")
        self.assertTrue(runner.gate_satisfied(self.dir, "DP14"))

    def test_stale_coverage_artifact_does_not_satisfy_a_new_finding(self):
        # the failure mode this closes: coverage written once, then a phase promotes more
        dirs = findings_tree.consolidate(self.dir, [_reasoned()])
        with open(os.path.join(dirs[0], "poc.theoretical.md"), "w", encoding="utf-8") as fh:
            fh.write("# Theoretical\n\nNo safe live repro.\n")
        coverage.write_coverage(self.dir, "poc")
        self.assertTrue(runner.gate_satisfied(self.dir, "DP13"))

        findings_tree.consolidate(self.dir, [_reasoned(), _reasoned("Mass assignment on /users")])
        coverage.write_coverage(self.dir, "poc")
        self.assertFalse(runner.gate_satisfied(self.dir, "DP13"))


if __name__ == "__main__":
    unittest.main()
