import json
import os
import tempfile
import unittest

from kavach import findings_tree as ft
from kavach import report_finding, triage
from kavach.finding import Finding, Location, Severity, Confidence, load_findings

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "tymewear-findings-reduced.json")


def _f(title, sev, cat="A01", source="kavach-sast", rule_id="", file="src/app.py"):
    return Finding(title=title, severity=sev, category=cat, source=source, rule_id=rule_id,
                   locations=[Location(file=file, line=10)],
                   cvss_vector="CVSS:3.1/AV:N", cvss_score=9.1, confidence=Confidence.CONFIRMED,
                   remediation="Upgrade to 2.31.0.")


def _meta(audit_dir, name):
    with open(os.path.join(audit_dir, "findings", name, "metadata.json"), encoding="utf-8") as fh:
        return json.load(fh)


class TestFindingsTree(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_slugify(self):
        self.assertEqual(ft.slugify("SQL Injection in Login!"), "sql-injection-in-login")

    def test_write_draft_has_frontmatter(self):
        path = ft.write_draft(self.dir, _f("SQLi", Severity.CRITICAL), "hunt", 1)
        self.assertTrue(path.endswith("hunt-001-sqli.md"))
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        self.assertTrue(body.startswith("---\n"))
        self.assertIn("severity: critical", body)

    def test_consolidate_assigns_severity_ids_and_drops_low(self):
        findings = [_f("SQLi", Severity.CRITICAL), _f("XSS", Severity.HIGH),
                    _f("Verbose banner", Severity.LOW)]
        dirs = ft.consolidate(self.dir, findings)
        names = sorted(os.path.basename(d) for d in dirs)
        self.assertEqual(names, ["C1-sqli", "H1-xss"])           # LOW dropped from tree
        meta = _meta(self.dir, "C1-sqli")
        self.assertTrue(meta["kavach_id"].startswith("KAVACH-"))
        self.assertFalse(meta["is_aggregate"])
        self.assertEqual(meta["finding_class"], "reasoned")
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings", "C1-sqli", "evidence")))

    def test_consolidate_creates_findings_dir_on_zero_findings(self):
        # a run with nothing to promote (or nothing above LOW) must still leave findings/
        # on disk - otherwise a gate of just ["findings"] can never be satisfied.
        dirs = ft.consolidate(self.dir, [])
        self.assertEqual(dirs, [])
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings")))

    def test_mark_false_positive(self):
        dirs = ft.consolidate(self.dir, [_f("SQLi", Severity.CRITICAL)])
        renamed = ft.mark_false_positive(self.dir, dirs[0])
        self.assertTrue(os.path.basename(renamed).startswith("FP-C1-"))


class TestPromotionPolicy(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_medium_promotable_finding_is_table_only(self):
        # the old policy promoted every severity >= medium, which is how one run got 238 dirs
        dirs = ft.consolidate(self.dir, [_f("Weak hash", Severity.MEDIUM, source="semgrep")])
        self.assertEqual(dirs, [])

    def test_high_scanner_dependency_never_gets_its_own_dir(self):
        dirs = ft.consolidate(self.dir, [
            _f("requests 2.28.1: CVE-2024-35195", Severity.HIGH, "A06:Vulnerable-Components",
               source="trivy", rule_id="CVE-2024-35195", file="requirements.txt"),
        ])
        self.assertEqual([os.path.basename(d) for d in dirs], ["G1-vulnerable-dependencies"])

    def test_reasoned_finding_about_a_cve_is_still_promoted(self):
        dirs = ft.consolidate(self.dir, [
            _f("The idna advisory is reachable from the public parser", Severity.HIGH,
               "A06:Vulnerable-Components", source="kavach-supply", rule_id="CVE-2024-3651"),
        ])
        self.assertEqual(len(dirs), 1)
        self.assertTrue(os.path.basename(dirs[0]).startswith("H1-"))
        self.assertFalse(_meta(self.dir, os.path.basename(dirs[0]))["is_aggregate"])

    def test_unclassified_findings_are_classified_in_line(self):
        # an old findings.json arrives with finding_class == "" and must upgrade transparently
        f = _f("CKV_AWS_18", Severity.HIGH, "A05:Misconfiguration", source="checkov",
               rule_id="CKV_AWS_18", file="infra/s3.tf")
        self.assertEqual(f.finding_class, "")
        dirs = ft.consolidate(self.dir, [f])
        self.assertEqual([os.path.basename(d) for d in dirs],
                         ["G1-infrastructure-misconfiguration"])

    def test_aggregate_order_is_dependency_then_iac_and_g_sorts_last(self):
        dirs = ft.consolidate(self.dir, [
            _f("CKV_AWS_18", Severity.HIGH, "A05:Misconfiguration", source="checkov",
               rule_id="CKV_AWS_18", file="infra/s3.tf"),
            _f("requests 2.28.1: CVE-2024-35195", Severity.HIGH, "A06:Vulnerable-Components",
               source="trivy", rule_id="CVE-2024-35195", file="requirements.txt"),
            _f("SQLi", Severity.CRITICAL, source="semgrep"),
        ])
        self.assertEqual([os.path.basename(d) for d in dirs],
                         ["C1-sqli", "G1-vulnerable-dependencies",
                          "G2-infrastructure-misconfiguration"])

    def test_aggregate_class_with_no_members_gets_no_directory(self):
        dirs = ft.consolidate(self.dir, [
            _f("CKV_AWS_18", Severity.HIGH, "A05:Misconfiguration", source="checkov",
               rule_id="CKV_AWS_18", file="infra/s3.tf"),
        ])
        self.assertEqual([os.path.basename(d) for d in dirs],
                         ["G1-infrastructure-misconfiguration"])

    def test_low_severity_scanner_row_is_not_aggregated(self):
        dirs = ft.consolidate(self.dir, [
            _f("setuptools 59.6.0: CVE-2022-40897", Severity.LOW, "A06:Vulnerable-Components",
               source="trivy", rule_id="CVE-2022-40897", file="requirements.txt"),
        ])
        self.assertEqual(dirs, [])


class TestAggregateDirectory(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.members = [
            _f("requests 2.28.1: CVE-2024-35195", Severity.HIGH, "A06:Vulnerable-Components",
               source="trivy", rule_id="CVE-2024-35195", file="requirements.txt"),
            _f("idna 3.3: CVE-2024-3651", Severity.CRITICAL, "A06:Vulnerable-Components",
               source="trivy", rule_id="CVE-2024-3651", file="requirements.txt"),
            _f("Prototype pollution in lodash", Severity.MEDIUM, "A06:Vulnerable-Components",
               source="npm-audit", rule_id="lodash", file="package-lock.json"),
        ]
        self.dirs = ft.consolidate(self.dir, self.members)
        self.agg = self.dirs[0]

    def test_rows_json_carries_every_member(self):
        with open(os.path.join(self.agg, "rows.json"), encoding="utf-8") as fh:
            rows = json.load(fh)
        self.assertEqual(rows["finding_class"], "dependency")
        self.assertEqual(rows["count"], 3)
        self.assertEqual(len(rows["rows"]), 3)
        self.assertTrue(all(r["finding_class"] == "dependency" for r in rows["rows"]))

    def test_metadata_marks_the_aggregate_and_lists_members(self):
        meta = _meta(self.dir, os.path.basename(self.agg))
        self.assertTrue(meta["is_aggregate"])
        self.assertEqual(meta["member_count"], 3)
        self.assertEqual(meta["kavach_id"], "KAVACH-AGG-dependency")
        self.assertEqual(meta["severity"], "critical")          # max member severity
        self.assertEqual(sorted(meta["member_ids"]),
                         sorted(f.fingerprint() for f in self.members))

    def test_aggregate_id_never_collides_with_a_member_fingerprint(self):
        meta = _meta(self.dir, os.path.basename(self.agg))
        self.assertNotIn(meta["kavach_id"], meta["member_ids"])

    def test_report_satisfies_the_vuln_report_contract(self):
        with open(os.path.join(self.agg, "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(report_finding.is_complete(text))
        self.assertIn("| requests | 2.28.1 | CVE-2024-35195 | high | 2.31.0 |", text)
        self.assertIn("trivy fs .", text)
        self.assertIn("idna 3.3: CVE-2024-3651", text)          # highest-severity member named
        self.assertIn("`requirements.txt`", text)

    def test_evidence_dir_exists_for_symmetry(self):
        self.assertTrue(os.path.isdir(os.path.join(self.agg, "evidence")))

    def test_iac_report_uses_the_iac_reproduction_command(self):
        d = tempfile.mkdtemp()
        ft.consolidate(d, [
            _f("Container runs as root", Severity.HIGH, "A05:Misconfiguration",
               source="checkov", rule_id="CKV_K8S_23", file="k8s/api-deploy.yaml"),
        ])
        with open(os.path.join(d, "findings", "G1-infrastructure-misconfiguration",
                               "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(report_finding.is_complete(text))
        self.assertIn("checkov -d .", text)


class TestReducedCorpusPromotion(unittest.TestCase):
    """Acceptance criterion 3: the same finding set that promoted 238 dirs now promotes
    a reviewable handful plus exactly two rolled-up classes."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.findings = load_findings(FIXTURE)

    def test_promotion_collapses_to_a_reviewable_set(self):
        dirs = [os.path.basename(d) for d in ft.consolidate(self.dir, self.findings)]
        individual = [d for d in dirs if d[0] in "CH"]
        aggregates = [d for d in dirs if d.startswith("G")]
        self.assertLessEqual(len(individual), 30)
        self.assertEqual(sorted(aggregates),
                         ["G1-vulnerable-dependencies", "G2-infrastructure-misconfiguration"])

    def test_old_policy_would_have_promoted_far_more(self):
        old = [f for f in self.findings
               if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
        new = [d for d in ft.consolidate(self.dir, self.findings)
               if not os.path.basename(d).startswith("G")]
        self.assertGreater(len(old), 2 * len(new))

    def test_every_aggregated_member_stays_in_the_finding_set(self):
        classified = triage.classify_all(self.findings)
        _promoted, grouped = ft.partition(classified)
        aggregated = {f.id for members in grouped.values() for f in members}
        self.assertTrue(aggregated.issubset({f.id for f in classified}))
        self.assertGreater(len(aggregated), 20)


if __name__ == "__main__":
    unittest.main()
