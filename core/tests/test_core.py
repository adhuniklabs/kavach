"""KAVACH core tests - zero dependencies, runnable with `python -m unittest`."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kavach.dockerutil import ToolResult  # noqa: E402
from kavach.finding import Confidence, Finding, Location, Severity  # noqa: E402
from kavach.recon import run_recon  # noqa: E402
from kavach.render import render as render_report  # noqa: E402
from kavach.scanners.builtin_secrets import BuiltinSecretsScanner  # noqa: E402
from kavach.scanners.deps import TrivyScanner  # noqa: E402
from kavach.scanners.iac import KicsScanner  # noqa: E402
from kavach.scanners.malware import GuardDogScanner  # noqa: E402
from kavach.scanners.sast import GosecScanner, SemgrepScanner  # noqa: E402
from kavach.scanners.secrets import GitleaksScanner, TruffleHogScanner  # noqa: E402
from kavach.score import counts_by_severity, exit_code, gate  # noqa: E402
from kavach.sweep import dedupe  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "corpus", "fixtures")


def mk(sev, title="t", cat="X", file="a.py", line=1, source="s", rule=""):
    return Finding(title=title, severity=sev, category=cat, source=source, rule_id=rule,
                   locations=[Location(file=file, line=line)])


class TestFinding(unittest.TestCase):
    def test_fingerprint_stable_across_line_moves(self):
        a = mk(Severity.HIGH, file="src/app.py", line=10)
        b = mk(Severity.HIGH, file="src/app.py", line=99)
        self.assertEqual(a.id, b.id)

    def test_fingerprint_differs_by_category(self):
        a = mk(Severity.HIGH, cat="A01")
        b = mk(Severity.HIGH, cat="A02")
        self.assertNotEqual(a.id, b.id)

    def test_roundtrip(self):
        f = mk(Severity.CRITICAL, source="gitleaks")
        f2 = Finding.from_dict(f.to_dict())
        self.assertEqual(f.id, f2.id)
        self.assertEqual(f2.severity, Severity.CRITICAL)

    def test_severity_from_cvss(self):
        self.assertEqual(Severity.from_cvss(9.8), Severity.CRITICAL)
        self.assertEqual(Severity.from_cvss(7.0), Severity.HIGH)
        self.assertEqual(Severity.from_cvss(4.0), Severity.MEDIUM)
        self.assertEqual(Severity.from_cvss(0.0), Severity.INFO)


class TestScoreGate(unittest.TestCase):
    def test_counts(self):
        c = counts_by_severity([mk(Severity.CRITICAL), mk(Severity.CRITICAL, cat="Y"),
                                mk(Severity.LOW, cat="Z")])
        self.assertEqual(c["critical"], 2)
        self.assertEqual(c["low"], 1)

    def test_gate_blocks_on_critical(self):
        g = gate([mk(Severity.CRITICAL)], require_controls=False)
        self.assertFalse(g.passed)
        self.assertEqual(exit_code(g), 2)

    def test_gate_high_exit_3(self):
        g = gate([mk(Severity.HIGH)], require_controls=False)
        self.assertEqual(exit_code(g), 3)

    def test_gate_clean_severity_only(self):
        g = gate([mk(Severity.LOW)], require_controls=False)
        self.assertTrue(g.passed)
        self.assertEqual(exit_code(g), 0)

    def test_gate_controls_fail_closed(self):
        g = gate([mk(Severity.LOW)])  # controls required, none supplied
        self.assertFalse(g.passed)
        self.assertEqual(exit_code(g), 4)

    def test_gate_controls_all_true(self):
        from kavach.score import GATE_CONTROLS
        g = gate([mk(Severity.LOW)], {c: True for c in GATE_CONTROLS})
        self.assertTrue(g.passed)


class TestDedupe(unittest.TestCase):
    def test_merges_same_finding_records_sources(self):
        a = mk(Severity.CRITICAL, source="gitleaks", rule="k")
        b = mk(Severity.HIGH, source="trivy", rule="k")
        out = dedupe([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.CRITICAL)  # keeps higher
        self.assertIn("gitleaks", out[0].source)
        self.assertIn("trivy", out[0].source)

    def test_sorted_by_severity(self):
        out = dedupe([mk(Severity.LOW, cat="A"), mk(Severity.CRITICAL, cat="B")])
        self.assertEqual(out[0].severity, Severity.CRITICAL)


class TestRecon(unittest.TestCase):
    def test_detects_node_stack(self):
        recon, files = run_recon(os.path.join(FIXTURES, "leaky-node"))
        self.assertIn("JavaScript", recon["languages"])
        self.assertIn("Express", recon["frameworks"])
        self.assertIn("Anthropic", recon["llm_providers"])
        self.assertIn("Stripe", recon["payment_processors"])
        self.assertTrue(recon["capabilities"]["has_llm"])
        self.assertGreater(len(files), 0)

    def test_detects_python_stack(self):
        recon, _ = run_recon(os.path.join(FIXTURES, "py-flask-leak"))
        self.assertIn("Python", recon["languages"])
        self.assertIn("Flask", recon["frameworks"])
        self.assertIn("OpenAI", recon["llm_providers"])
        self.assertIn("Razorpay", recon["payment_processors"])
        self.assertIn("AWS", recon["cloud"])


class TestBuiltinSecrets(unittest.TestCase):
    def test_finds_planted_secrets(self):
        recon, _ = run_recon(os.path.join(FIXTURES, "leaky-node"))
        findings = BuiltinSecretsScanner().run(os.path.join(FIXTURES, "leaky-node"), recon).findings
        self.assertGreaterEqual(len(findings), 3)
        self.assertTrue(all(f.severity == Severity.CRITICAL for f in findings))
        rules = {f.rule_id for f in findings}
        self.assertIn("anthropic-key", rules)
        self.assertIn("stripe-secret", rules)

    def test_redacts(self):
        recon, _ = run_recon(os.path.join(FIXTURES, "leaky-node"))
        findings = BuiltinSecretsScanner().run(os.path.join(FIXTURES, "leaky-node"), recon).findings
        for f in findings:
            self.assertIn("…", f.locations[0].snippet)


class TestNormalizers(unittest.TestCase):
    def test_gitleaks_normalize(self):
        raw = json.dumps([{"RuleID": "aws", "Description": "AWS key", "File": "a.py",
                           "StartLine": 5, "Match": "AKIA...", "Secret": "x"}])
        out = GitleaksScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.CRITICAL)
        self.assertEqual(out[0].locations[0].line, 5)

    def test_gitleaks_tolerates_log_noise(self):
        raw = "12:00 INF loaded\n" + json.dumps([{"RuleID": "x", "File": "f", "StartLine": 1}]) + "\n"
        out = GitleaksScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        self.assertEqual(len(out), 1)

    def test_semgrep_normalize(self):
        raw = json.dumps({"results": [{"check_id": "py.sqli", "path": "a.py",
                          "start": {"line": 3},
                          "extra": {"message": "SQLi", "severity": "ERROR",
                                    "metadata": {"owasp": ["A03"], "cwe": ["CWE-89"]}}}]})
        out = SemgrepScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        self.assertEqual(out[0].severity, Severity.HIGH)
        self.assertEqual(out[0].category, "A03")

    def test_trivy_normalize_vuln_and_secret(self):
        raw = json.dumps({"Results": [
            {"Target": "package-lock.json",
             "Vulnerabilities": [{"VulnerabilityID": "CVE-2021-1", "PkgName": "lodash",
                                  "InstalledVersion": "4.0.0", "Severity": "HIGH",
                                  "FixedVersion": "4.17.21", "Title": "proto pollution"}]},
            {"Target": ".env",
             "Secrets": [{"RuleID": "stripe", "Severity": "CRITICAL", "Title": "Stripe",
                          "StartLine": 2, "Match": "sk_live"}]}]})
        out = TrivyScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        sevs = sorted(f.severity.value for f in out)
        self.assertIn("critical", sevs)
        self.assertIn("high", sevs)
        self.assertTrue(any("CVE-2021-1" in f.rule_id for f in out))


class TestNewScanners(unittest.TestCase):
    def test_trufflehog_verified_is_critical_confirmed(self):
        ndjson = "\n".join([
            json.dumps({"DetectorName": "AWS", "Verified": True, "Redacted": "AKIA...",
                        "SourceMetadata": {"Data": {"Filesystem": {"file": "/src/a.py", "line": 3}}}}),
            json.dumps({"DetectorName": "Slack", "Verified": False,
                        "SourceMetadata": {"Data": {"Filesystem": {"file": "/src/b.py", "line": 9}}}}),
            "some log noise that is not json",
        ])
        out = TruffleHogScanner().normalize(ToolResult(0, ndjson, "", "docker"), ".", {})
        self.assertEqual(len(out), 2)
        verified = [f for f in out if f.rule_id == "AWS"][0]
        self.assertEqual(verified.severity, Severity.CRITICAL)
        self.assertEqual(verified.confidence, Confidence.CONFIRMED)
        self.assertEqual(verified.locations[0].file, "a.py")
        unverified = [f for f in out if f.rule_id == "Slack"][0]
        self.assertEqual(unverified.severity, Severity.HIGH)
        self.assertEqual(unverified.confidence, Confidence.SUSPECTED)

    def test_gosec_normalize(self):
        raw = json.dumps({"Issues": [{"severity": "HIGH", "confidence": "HIGH",
                          "rule_id": "G107", "details": "SSRF via user input",
                          "file": "/src/main.go", "line": "12", "cwe": {"id": "918"}}]})
        out = GosecScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        self.assertEqual(out[0].severity, Severity.HIGH)
        self.assertEqual(out[0].category, "CWE-918")
        self.assertEqual(out[0].locations[0].file, "main.go")
        self.assertEqual(out[0].locations[0].line, 12)

    def test_kics_normalize_from_stdout(self):
        raw = json.dumps({"queries": [{"query_name": "S3 bucket public",
                          "severity": "HIGH", "query_id": "abc",
                          "description": "public bucket",
                          "files": [{"file_name": "/src/main.tf", "line": 5}]}]})
        out = KicsScanner().normalize(ToolResult(0, raw, "", "docker"), ".", {})
        self.assertEqual(out[0].severity, Severity.HIGH)
        self.assertEqual(out[0].category, "A05:Misconfiguration")
        self.assertEqual(out[0].locations[0].file, "main.tf")

    def test_kics_normalize_reads_workdir_report(self):
        # regression: KicsScanner.normalize uses os.path - iac.py must import os
        raw = json.dumps({"queries": [{"query_name": "priv container", "severity": "MEDIUM",
                          "query_id": "x", "files": [{"file_name": "deploy.yaml", "line": 3}]}]})
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "kics.json"), "w") as fh:
                fh.write(raw)
            out = KicsScanner().normalize(ToolResult(0, "", "", "docker", workdir=d), ".", {})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.MEDIUM)

    def test_guarddog_flags_malicious(self):
        raw = json.dumps([
            {"package": "reqeusts", "issues": 2,
             "results": {"exfiltrate-sensitive-data": ["hit"], "typosquatting": ["hit"]}},
            {"package": "flask", "issues": 0, "results": {}},
        ])
        out = GuardDogScanner()._parse(raw, "pypi", "requirements.txt")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, Severity.CRITICAL)  # exfiltrate → malicious
        self.assertEqual(out[0].category, "Supply-Chain-Malware")
        self.assertEqual(out[0].kill_chain, "steal-keys")

    def test_guarddog_manifest_detection(self):
        recon = {"manifests": [{"file": "svc/requirements.txt", "type": "pip", "dependencies": []},
                               {"file": "web/package.json", "type": "npm", "dependencies": []}]}
        pairs = GuardDogScanner()._manifests(recon)
        self.assertIn(("pypi", "svc/requirements.txt"), pairs)
        self.assertIn(("npm", "web/package.json"), pairs)


class TestRender(unittest.TestCase):
    def _fixture(self):
        recon, _ = run_recon(os.path.join(FIXTURES, "leaky-node"))
        findings = [mk(Severity.CRITICAL, title="Hardcoded key", cat="A07",
                       file="server.js", line=6, source="builtin-secrets")]
        g = gate(findings, require_controls=False)
        return findings, recon, g

    def test_markdown(self):
        findings, recon, g = self._fixture()
        md = render_report("md", findings, recon, g, {})
        self.assertIn("KAVACH Security Report", md)
        self.assertIn("NOT PRODUCTION-READY", md)
        self.assertIn("Hardcoded key", md)

    def test_sarif_valid(self):
        findings, recon, g = self._fixture()
        doc = json.loads(render_report("sarif", findings, recon, g, {}))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "error")

    def test_json_and_html(self):
        findings, recon, g = self._fixture()
        doc = json.loads(render_report("json", findings, recon, g, {}))
        self.assertEqual(len(doc["findings"]), 1)
        html = render_report("html", findings, recon, g, {})
        self.assertIn("<title>KAVACH", html)


class TestCorpusGate(unittest.TestCase):
    def test_corpus_passes(self):
        from kavach.corpus import run_corpus_gate
        self.assertEqual(run_corpus_gate(), 0)


if __name__ == "__main__":
    unittest.main()
