"""The v0.3 report model and its four renderings.

The two properties this file exists to protect: the HTML report renders with reportlab
absent, and a dropped tail always reaches ``AuditReport.limits`` and therefore the
deliverable.
"""

import contextlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kavach.finding import Confidence, Finding, Location, Severity  # noqa: E402
from kavach.render import RENDERERS, charts, model, pdf  # noqa: E402
from kavach.render import render as render_report  # noqa: E402
from kavach.score import gate as run_gate  # noqa: E402


class _BlockReportlab:
    """A meta-path finder that makes ``import reportlab`` fail, whatever is installed."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "reportlab" or fullname.startswith("reportlab."):
            raise ImportError("reportlab is blocked by this test")
        return None

    # Python 3.9 still consults the legacy hooks on some paths.
    def find_module(self, fullname, path=None):
        if fullname == "reportlab" or fullname.startswith("reportlab."):
            raise ImportError("reportlab is blocked by this test")
        return None


@contextlib.contextmanager
def reportlab_absent():
    """Simulate a machine where the optional [report] extra was never installed."""
    blocker = _BlockReportlab()
    cached = {k: v for k, v in sys.modules.items() if k.split(".")[0] == "reportlab"}
    for name in cached:
        del sys.modules[name]
    sys.meta_path.insert(0, blocker)
    try:
        yield
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(cached)


RECON = {"root": "/repo", "totals": {"files": 120, "code_files": 80},
         "languages": ["javascript"], "frameworks": ["express"]}


def fixture_findings():
    return [
        Finding(title="Hardcoded Stripe key", severity=Severity.CRITICAL,
                category="A07:Secrets", source="gitleaks", rule_id="stripe-key",
                finding_class="secret", cvss_score=9.1, confidence=Confidence.CONFIRMED,
                kill_chain="steal-keys", what_it_is="A live key is committed.",
                how_exploited="Clone and read.", business_impact="Cards charged as you.",
                remediation="Rotate and move server-side.", effort="S",
                references=["CWE-798"],
                locations=[Location(file="src/pay.js", line=12,
                                    snippet="const k = 'sk_live_x'")]),
        Finding(title="IDOR on orders", severity=Severity.HIGH, category="API1:BOLA",
                source="kavach-api", finding_class="reasoned", cvss_score=7.6,
                remediation="Check ownership.",
                locations=[Location(file="src/orders.js", line=44)]),
        Finding(title="lodash prototype pollution", severity=Severity.MEDIUM,
                category="A06:Vulnerable-Components", source="trivy",
                rule_id="CVE-2019-10744", finding_class="dependency",
                locations=[Location(file="package-lock.json")]),
        Finding(title="Container runs as root", severity=Severity.LOW,
                category="A05:Misconfiguration", source="hadolint", rule_id="DL3002",
                finding_class="iac", locations=[Location(file="Dockerfile", line=3)]),
        Finding(title="Session cookie missing the Secure flag", severity=Severity.MEDIUM,
                category="A05", source="semgrep", rule_id="express-cookie-insecure",
                finding_class="code", locations=[Location(file="src/app.js", line=21)]),
        Finding(title="Verbose stack traces", severity=Severity.INFO, category="A09",
                source="semgrep", finding_class="code",
                locations=[Location(file="src/app.js", line=9)]),
    ]


def build(findings=None, meta=None):
    findings = fixture_findings() if findings is None else findings
    gate = run_gate(findings, (meta or {}).get("controls"), require_controls=True)
    return model.build(findings, RECON, gate, meta or {})


class TestAuditReportModel(unittest.TestCase):
    def test_findings_are_ordered_by_severity_then_cvss(self):
        report = build()
        self.assertEqual([f.severity.value for f in report.findings],
                         ["critical", "high", "medium", "medium", "low", "info"])

    def test_chapters_cover_every_axis_and_partition_the_findings(self):
        report = build()
        self.assertEqual([c.key for c in report.chapters],
                         [a.key for a in report.axes])
        chaptered = sum(len(c.findings) for c in report.chapters)
        self.assertEqual(chaptered, len(report.findings))

    def test_section_numbering_is_dense_and_starts_at_one(self):
        numbers = [int(s.number) for s in model.outline(build()) if s.number]
        self.assertEqual(numbers, list(range(1, len(numbers) + 1)))

    def test_outline_has_no_duplicate_keys(self):
        keys = [s.key for s in model.outline(build())]
        self.assertEqual(len(keys), len(set(keys)))

    def test_frameworks_map_only_from_the_categories_present(self):
        rows = build().frameworks
        self.assertEqual({r[0] for r in rows},
                         {"A07:Secrets", "API1:BOLA", "A06:Vulnerable-Components",
                          "A05:Misconfiguration", "A05", "A09"})
        secrets = next(r for r in rows if r[0] == "A07:Secrets")
        self.assertIn("CWE-798", secrets[4])

    def test_remediation_horizons_are_ordered_and_numbered(self):
        rows = build().remediation
        self.assertEqual([r["n"] for r in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(rows[0]["horizon"], model.HORIZONS[0])
        self.assertTrue(all(r["horizon"] in model.HORIZONS for r in rows))

    def test_info_findings_are_not_scheduled_for_remediation(self):
        addressed = {a for r in build().remediation for a in r["addresses"]}
        info = next(f for f in fixture_findings() if f.severity == Severity.INFO)
        self.assertNotIn(info.id, addressed)

    def test_figure_commands_only_name_sources_that_produced_a_finding(self):
        commands = dict((c, cmd) for c, cmd in build().figure_commands)
        joined = " ".join(commands)
        self.assertIn("gitleaks", joined)
        self.assertIn("trivy", joined)
        self.assertNotIn("osv-scanner", joined)

    def test_annex_c_survives_a_merge_alias_and_a_dedupe_concatenation(self):
        """Annex C must key on source segments, not on the raw field.

        ``Finding.source`` is rewritten in two places - merge_findings aliases it to
        ``a:trivy`` and sweep.dedupe concatenates corroborating scanners into
        ``trivy+semgrep``. A literal ``f.source in SOURCE_COMMANDS`` misses both, so the
        reproduce-the-figures command drops out of the annex and the annex gets *shorter*
        rather than wrong. Annex C is the report's honesty mechanism; a silently shrinking
        annex is its worst failure mode, and it would pass review.
        """
        for source in ("a:trivy", "trivy+semgrep", "s26:trivy+b:semgrep"):
            findings = [Finding(title="dep advisory", severity=Severity.MEDIUM,
                                category="A06", source=source, finding_class="dependency",
                                locations=[Location(file="package-lock.json")])]
            captions = [c for c, _ in build(findings).figure_commands]
            commands = [cmd for _, cmd in build(findings).figure_commands]
            self.assertTrue(any("trivy" in c for c in captions), source)
            self.assertIn(model.SOURCE_COMMANDS["trivy"], commands, source)

    def test_a_stacked_source_counts_toward_every_scanner_it_names(self):
        """``trivy+semgrep`` is one finding attributed to trivy *and* to semgrep.

        Counting it toward neither is the same defect as above, seen in the numbers: the
        per-source totals in Annex C undercount every deduped finding.
        """
        findings = [
            Finding(title="corroborated", severity=Severity.HIGH, category="A03",
                    source="trivy+semgrep", finding_class="code",
                    locations=[Location(file="src/a.js", line=1)]),
            Finding(title="trivy only", severity=Severity.LOW, category="A06",
                    source="a:trivy", finding_class="dependency",
                    locations=[Location(file="package-lock.json")]),
        ]
        captions = dict(zip([c for c, _ in build(findings).figure_commands],
                            [cmd for _, cmd in build(findings).figure_commands]))
        self.assertIn("2 finding(s) attributed to trivy", captions)
        self.assertIn("1 finding(s) attributed to semgrep", captions)

    def test_narrative_override_wins_over_disk(self):
        report = build(meta={"narrative": {"exec-summary": "Three nightmares, all live."}})
        self.assertEqual(report.anchor_text("exec-summary"), "Three nightmares, all live.")
        self.assertEqual(report.anchor_text("residual"), "")

    def test_unknown_narrative_keys_are_dropped(self):
        report = build(meta={"narrative": {"made-up": "x"}})
        self.assertEqual(report.narrative, {})


class TestLimits(unittest.TestCase):
    """A dropped tail must appear in the deliverable - the honesty property of the redesign."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, rel, payload):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

    def test_absent_artifacts_yield_no_crash_and_no_invented_limits(self):
        report = build(meta={"audit_dir": self.dir})
        self.assertEqual(model.budget_shed(self.dir), [])
        self.assertEqual(model.coverage_gaps(self.dir), [])
        self.assertEqual(model.load_promoted(self.dir), [])
        # Only the suspected-findings limit, which comes from the finding set itself.
        self.assertEqual(len(report.limits), 1)
        self.assertIn("suspected", report.limits[0])

    def test_missing_audit_dir_entirely_is_fine(self):
        report = build(meta={"audit_dir": os.path.join(self.dir, "nope")})
        self.assertTrue(all(isinstance(x, str) for x in report.limits))

    def test_budget_shed_reaches_limits(self):
        self._write("audit-state.json", {"audits": [{
            "audit_id": "a1", "mode": "deep",
            "budget": {"max_dispatches": 120, "dispatches": 120,
                       "shed": [{"phase": "DP13", "planned": 40, "allowed": 22,
                                 "dropped": 18, "reason": "dispatch ceiling"}]},
        }]})
        limits = build(meta={"audit_dir": self.dir}).limits
        self.assertTrue(any("DP13" in x and "18 of 40" in x for x in limits), limits)

    def test_budget_shed_can_be_scoped_to_one_audit(self):
        self._write("audit-state.json", {"audits": [
            {"audit_id": "old", "budget": {"shed": [{"phase": "BL6", "planned": 5,
                                                     "dropped": 5, "reason": "wall clock"}]}},
            {"audit_id": "new", "budget": {"shed": [{"phase": "DP13", "planned": 9,
                                                     "dropped": 2, "reason": "ceiling"}]}},
        ]})
        self.assertEqual([r["phase"] for r in model.budget_shed(self.dir, "new")], ["DP13"])
        self.assertEqual([r["phase"] for r in model.budget_shed(self.dir)], ["BL6", "DP13"])

    def test_coverage_missing_reaches_limits(self):
        self._write("attack-surface/poc-coverage.json", {
            "kind": "poc", "complete": False, "total": 25, "satisfied": 18,
            "aggregates_exempt": 2,
            "missing": [{"display_id": "H7", "dir": "findings/H7-x",
                         "reason": "no poc.* or poc.theoretical.md"}],
        })
        limits = build(meta={"audit_dir": self.dir}).limits
        self.assertTrue(any("H7" in x and "proof of concept" in x for x in limits), limits)

    def test_complete_coverage_adds_no_limit(self):
        self._write("attack-surface/report-coverage.json",
                    {"kind": "report", "complete": True, "total": 3, "satisfied": 3,
                     "missing": []})
        limits = build(meta={"audit_dir": self.dir}).limits
        self.assertFalse(any("write-up" in x for x in limits), limits)

    def test_corrupt_artifact_is_treated_as_absent(self):
        path = os.path.join(self.dir, "audit-state.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(model.budget_shed(self.dir), [])

    def test_suspected_findings_reach_limits(self):
        limits = build().limits
        self.assertTrue(any("suspected" in x for x in limits), limits)

    def test_every_limit_reaches_the_markdown_and_html_deliverables(self):
        self._write("audit-state.json", {"audits": [{
            "audit_id": "a1",
            "budget": {"shed": [{"phase": "DP13", "planned": 40, "dropped": 18,
                                 "reason": "dispatch ceiling"}]}}]})
        findings = fixture_findings()
        gate = run_gate(findings, None, require_controls=True)
        meta = {"audit_dir": self.dir}
        md = render_report("md", findings, RECON, gate, meta)
        html = render_report("html", findings, RECON, gate, meta)
        for limit in build(meta=meta).limits:
            self.assertIn(limit, md)
            self.assertIn(limit.replace("&", "&amp;"), html)


class TestPromotedTree(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._promote("C1-hardcoded-stripe-key",
                      {"display_id": "C1", "kavach_id": "KAVACH-aaaa", "severity": "critical",
                       "is_aggregate": False, "finding_class": "secret"})
        self._promote("G1-vulnerable-dependencies",
                      {"display_id": "G1", "kavach_id": "KAVACH-AGG-dependency",
                       "severity": "high", "is_aggregate": True, "member_count": 136,
                       "finding_class": "dependency"})

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _promote(self, name, meta):
        d = os.path.join(self.dir, "findings", name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh)

    def _index(self, *dirs):
        """consolidate's manifest, naming the directories that are live right now."""
        path = os.path.join(self.dir, "attack-surface", "promoted-index.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"count": len(dirs),
                       "entries": [{"dir": d} for d in dirs]}, fh)

    def test_promoted_rows_carry_the_aggregate_keys(self):
        rows = model.load_promoted(self.dir)
        self.assertEqual([r["display_id"] for r in rows], ["C1", "G1"])
        aggregate = rows[1]
        self.assertTrue(aggregate["is_aggregate"])
        self.assertEqual(aggregate["member_count"], 136)
        self.assertEqual(aggregate["dir"], "findings/G1-vulnerable-dependencies")

    def test_display_id_replaces_the_kavach_id_in_the_report(self):
        findings = [Finding(title="Hardcoded Stripe key", severity=Severity.CRITICAL,
                            category="A07", source="gitleaks",
                            locations=[Location(file="src/pay.js", line=1)])]
        self._promote("C2-x", {"display_id": "C2", "kavach_id": findings[0].id,
                               "severity": "critical", "is_aggregate": False})
        report = build(findings, {"audit_dir": self.dir})
        self.assertEqual(report.ref(findings[0]), "C2")

    def test_a_directory_without_metadata_is_skipped(self):
        os.makedirs(os.path.join(self.dir, "findings", "junk"), exist_ok=True)
        self.assertEqual(len(model.load_promoted(self.dir)), 2)

    def test_a_superseded_directory_does_not_reach_the_annex(self):
        """`consolidate` leaves what it supersedes on disk and records the live set in its
        manifest. `coverage` already scopes past the remainder; the report was the last
        consumer reading the raw listing, and it is the copy a client reads."""
        self._promote("C2-hardcoded-stripe-key",
                      {"display_id": "C2", "kavach_id": "KAVACH-aaaa", "severity": "critical",
                       "is_aggregate": False, "finding_class": "secret"})
        self._index("findings/C2-hardcoded-stripe-key",
                    "findings/G1-vulnerable-dependencies")
        self.assertEqual([r["display_id"] for r in model.load_promoted(self.dir)],
                         ["C2", "G1"])

    def test_a_false_positive_rename_does_not_reach_the_annex(self):
        os.rename(os.path.join(self.dir, "findings", "C1-hardcoded-stripe-key"),
                  os.path.join(self.dir, "findings", "FP-C1-hardcoded-stripe-key"))
        self.assertEqual([r["display_id"] for r in model.load_promoted(self.dir)], ["G1"])


class TestMarkdownRender(unittest.TestCase):
    def _md(self, **meta):
        findings = fixture_findings()
        gate = run_gate(findings, meta.get("controls"), require_controls=True)
        return render_report("md", findings, RECON, gate, meta)

    def test_all_six_anchors_appear_in_the_documented_order(self):
        found = re.findall(r"<!-- KAVACH:([a-z-]+) -->", self._md())
        self.assertEqual(found, list(model.ANCHORS))

    def test_unfilled_anchor_says_so_rather_than_vanishing(self):
        md = self._md()
        self.assertEqual(md.count(model.NOT_SUPPLIED), len(model.ANCHORS))

    def test_filled_anchor_renders_the_prose(self):
        md = self._md(narrative={"exec-summary": "The money wall is the whole exposure."})
        self.assertIn("The money wall is the whole exposure.", md)
        self.assertEqual(md.count(model.NOT_SUPPLIED), len(model.ANCHORS) - 1)

    def test_critical_and_high_get_a_full_block(self):
        md = self._md()
        self.assertIn("**Consequence.** Cards charged as you.", md)
        self.assertIn("**Proposed fix.** Rotate and move server-side.", md)
        self.assertIn("const k = 'sk_live_x'", md)

    def test_medium_gets_a_compact_row_not_a_block(self):
        md = self._md()
        chapter = md.split("## 9. Architecture")[1].split("## 10.")[0]
        self.assertIn("Medium findings (1)", chapter)
        self.assertIn("| Session cookie missing the Secure flag |", chapter)
        self.assertNotIn("**Proposed fix.**", chapter)

    def test_scanner_class_rows_roll_up_whatever_their_severity(self):
        md = self._md()
        secrets = md.split("## 8. Secrets & supply chain")[1].split("## 9.")[0]
        architecture = md.split("## 9. Architecture")[1].split("## 10.")[0]
        self.assertIn("Rolled-up scanner findings (1)", secrets)
        self.assertIn("| medium | dependency | lodash prototype pollution |", secrets)
        self.assertIn("Rolled-up scanner findings (1)", architecture)
        self.assertIn("| low | iac | Container runs as root |", architecture)

    def test_low_and_info_are_counted_not_narrated(self):
        reliability = self._md().split("## 10. Reliability")[1].split("## 11.")[0]
        self.assertIn("Low and informational findings (1)", reliability)
        self.assertIn("| A09 | 1 |", reliability)
        # Counted, not narrated: the title never appears in the chapter.
        self.assertNotIn("Verbose stack traces", reliability)

    def test_the_deterministic_sections_the_old_renderer_guaranteed_survive(self):
        md = self._md()
        for heading in ("# KAVACH Security Report", "## Contents", "## Glossary",
                        "Risk dashboard", "Scope, method and limits",
                        "Production-readiness verdict", "Annex A - Score justification",
                        "Annex B - Findings inventory",
                        "Annex C - Reproducing the figures", "## Appendix B - Coverage"):
            self.assertIn(heading, md)
        self.assertIn("NOT PRODUCTION-READY", md)
        self.assertIn("Total files walked: **120**", md)

    def test_annex_a_prints_the_arithmetic(self):
        md = self._md()
        annex = md.split("## Annex A - Score justification")[1]
        self.assertIn("| Baseline | +10.00 |", annex)
        self.assertIn("Effect", annex)

    def test_annex_c_prints_a_command_per_claim(self):
        md = self._md()
        annex = md.split("## Annex C - Reproducing the figures")[1]
        self.assertIn("kavach gate --out .kavach", annex)
        self.assertIn("--format pdf", annex)

    def test_every_figure_is_captioned_and_numbered_once(self):
        md = self._md()
        for name in charts.CHART_ORDER:
            marker = f"**Figure {charts.FIGURE_NUMBER[name]} - {charts.CHART_TITLES[name]}.**"
            self.assertEqual(md.count(marker), 1, name)

    def test_markdown_needs_no_reportlab(self):
        with reportlab_absent():
            self.assertGreater(len(self._md()), 5000)


class TestHtmlRender(unittest.TestCase):
    def _html(self, **meta):
        findings = fixture_findings()
        gate = run_gate(findings, meta.get("controls"), require_controls=True)
        return render_report("html", findings, RECON, gate, meta)

    def test_document_is_self_contained(self):
        html = self._html()
        self.assertIn("<title>KAVACH Security Report", html)
        # No script, no external stylesheet, no remote asset. The only http:// in the
        # document is the SVG namespace declaration, which is a literal, not a fetch.
        for token in ("<script", "<link", "@import", "src=", 'url(http'):
            self.assertNotIn(token, html)

    def test_charts_inline_as_svg_when_reportlab_is_present(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        html = self._html()
        self.assertEqual(html.count("<svg"), len(charts.CHART_ORDER))
        self.assertNotIn("<?xml", html)

    def test_html_renders_with_the_reportlab_import_blocked(self):
        with reportlab_absent():
            self.assertFalse(charts.available())
            html = self._html()
        self.assertNotIn("<svg", html)
        self.assertIn("reportlab is not", html)
        self.assertIn("kavach-audit[report]", html)
        # Every figure still ships its numbers.
        for name in charts.CHART_ORDER:
            self.assertIn(charts.CHART_TITLES[name], html)

    def test_chart_data_is_available_without_reportlab(self):
        report = build()
        with reportlab_absent():
            for name in charts.CHART_ORDER:
                data = charts.data(name, report)
                self.assertTrue(data.headers, name)
                self.assertEqual(charts.svg(name, report), "")

    def test_anchors_are_emitted_in_order_as_comments(self):
        found = re.findall(r"<!-- KAVACH:([a-z-]+) -->", self._html())
        self.assertEqual(found, list(model.ANCHORS))

    def test_findings_are_boxed_with_a_severity_chip(self):
        html = self._html()
        self.assertIn('class="finding critical"', html)
        self.assertIn('class="chip"', html)
        self.assertIn("<pre>const k = &#x27;sk_live_x&#x27;</pre>", html)

    def test_contents_links_resolve_to_emitted_ids(self):
        html = self._html()
        for target in re.findall(r'<a href="#(s-[a-z0-9:._-]+)">', html):
            self.assertIn(f'id="{target}"', html, target)


class TestPdfRender(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.out = os.path.join(self.dir, "reports", "audit-report.pdf")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _render(self, **meta):
        findings = fixture_findings()
        gate = run_gate(findings, meta.get("controls"), require_controls=True)
        return render_report("pdf", findings, RECON, gate, meta)

    def test_pdf_is_a_registered_format(self):
        self.assertIn("pdf", RENDERERS)
        self.assertNotIn("pdf", __import__("kavach.render", fromlist=["x"]).TEXT_FORMATS)

    def test_render_writes_the_file_and_returns_a_summary_line(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        summary = self._render(output=self.out, date="2026-08-21", commit="abc1234")
        self.assertIsInstance(summary, str)
        self.assertEqual(len(summary.splitlines()), 1)
        self.assertIn(self.out, summary)
        self.assertIn("page(s)", summary)
        self.assertTrue(os.path.exists(self.out))
        with open(self.out, "rb") as fh:
            self.assertTrue(fh.read(5).startswith(b"%PDF-"))

    def test_the_summary_page_count_matches_the_document(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        summary = self._render(output=self.out)
        claimed = int(re.search(r"\((\d+) page", summary).group(1))
        with open(self.out, "rb") as fh:
            raw = fh.read().decode("latin-1")
        self.assertEqual(len(re.findall(r"/Type\s*/Page[^s]", raw)), claimed)
        self.assertGreater(claimed, 5)

    def test_the_contents_page_carries_real_page_numbers(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        from reportlab import rl_config
        previous = rl_config.pageCompression
        rl_config.pageCompression = 0
        try:
            self._render(output=self.out, date="2026-08-21")
        finally:
            rl_config.pageCompression = previous
        with open(self.out, "rb") as fh:
            raw = fh.read().decode("latin-1")
        page = next(s for s in re.findall(r"stream\r?\n(.*?)\r?\nendstream", raw, re.S)
                    if "Contents" in s and "Executive summary" in s)
        drawn = re.findall(r"\((.*?)\) Tj", page)
        leaders = [t for t in drawn if t.strip().startswith(".")]
        self.assertTrue(leaders, "no dot-leader rows on the contents page")
        self.assertTrue(all(re.search(r"\d+$", t.strip()) for t in leaders),
                        "a contents row has no page number")
        self.assertIn("1. Executive summary", drawn)

    def test_output_is_required_because_a_pdf_is_a_file(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        with self.assertRaises(ValueError) as caught:
            self._render()
        self.assertIn("--output", str(caught.exception))

    def test_missing_reportlab_raises_the_install_command_not_a_traceback(self):
        with reportlab_absent():
            with self.assertRaises(charts.ReportlabMissing) as caught:
                self._render(output=self.out)
        message = str(caught.exception)
        self.assertIn("pip install 'kavach-audit[report]'", message)
        self.assertIn("Markdown, JSON, SARIF and HTML render without it", message)
        self.assertFalse(os.path.exists(self.out))

    def test_the_module_docstring_records_the_asymmetry(self):
        self.assertIn("asymmetry", pdf.__doc__)

    def test_a_finding_longer_than_a_page_does_not_abort_the_build(self):
        """A table cell cannot split across a page; an unbounded field would kill the build."""
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        prose = "This handler is exploitable because " * 400
        findings = [
            Finding(title="Oversized finding " * 40, severity=Severity.CRITICAL,
                    category="A01", source="kavach-api", finding_class="reasoned",
                    cvss_score=9.9, what_it_is=prose, how_exploited=prose,
                    business_impact=prose, remediation=prose, fix_impact=prose, effort="L",
                    references=[f"CWE-{i}" for i in range(200)],
                    locations=[Location(file="a/" * 80 + "x.js", line=1,
                                        snippet="\n".join("y" * 300 for _ in range(60)))]),
            Finding(title="B" * 4000, severity=Severity.MEDIUM, category="A05" * 200,
                    source="semgrep", finding_class="code", remediation=prose,
                    locations=[Location(file="b/" * 100 + "y.js", line=2)]),
        ]
        gate = run_gate(findings, None, require_controls=True)
        summary = render_report("pdf", findings, RECON, gate,
                               {"output": self.out, "narrative": {"exec-summary": prose}})
        self.assertIn("page(s)", summary)
        self.assertTrue(os.path.getsize(self.out) > 10_000)
        # The clip is visible and points at the artifact that still has the whole text.
        clipped = pdf._clip(prose)
        self.assertTrue(clipped.endswith("(truncated; full text in reports/report.json)"))
        self.assertLess(len(clipped), len(prose))
        self.assertEqual(pdf._clip("short"), "short")


class TestJsonAndSarif(unittest.TestCase):
    def _json(self):
        findings = fixture_findings()
        gate = run_gate(findings, None, require_controls=True)
        return json.loads(render_report("json", findings, RECON, gate, {}))

    def test_the_existing_contract_keys_survive(self):
        doc = self._json()
        self.assertEqual(doc["totals"], RECON["totals"])
        self.assertEqual(len(doc["findings"]), 6)
        self.assertIn("gate", doc)

    def test_annex_c_jq_paths_exist(self):
        doc = self._json()
        for key in ("class_counts", "scorecard", "limits", "figure_commands"):
            self.assertIn(key, doc)
        self.assertEqual(len(doc["scorecard"]["axes"]), 6)
        self.assertIn("critical", doc["gate"]["counts"])

    def test_sarif_carries_the_finding_class(self):
        findings = fixture_findings()
        gate = run_gate(findings, None, require_controls=True)
        doc = json.loads(render_report("sarif", findings, RECON, gate, {}))
        classes = {r["properties"]["findingClass"] for r in doc["runs"][0]["results"]}
        self.assertIn("secret", classes)

    def test_json_needs_no_reportlab(self):
        with reportlab_absent():
            self.assertEqual(len(self._json()["scorecard"]["axes"]), 6)


class TestNotAssessedRendering(unittest.TestCase):
    """A not-assessed axis must not reach the reader as a number, a "yes", or a full spoke.

    The fixture set maps to security, secrets & supply chain, architecture and reliability;
    nothing maps to data protection or maintainability, so every rendering has to carry two
    not-assessed axes without claiming either of them holds.
    """

    def setUp(self):
        self.report = build()
        self.blank = [a for a in self.report.axes if not a.assessed]
        self.assertEqual([a.key for a in self.blank],
                         ["data_protection", "maintainability"])

    def _text(self, fmt):
        findings = fixture_findings()
        gate = run_gate(findings, None, require_controls=True)
        return render_report(fmt, findings, RECON, gate, {})

    def test_the_cover_line_says_how_many_axes_the_figure_covers(self):
        line = self.report.scorecard.summary
        self.assertIn("across 4 assessed axes", line)
        self.assertIn("(2 not assessed)", line)
        for fmt in ("md", "html"):
            self.assertIn(line, self._text(fmt), fmt)

    def test_the_axis_table_shows_not_assessed_and_a_dash(self):
        for axis in self.blank:
            self.assertEqual(axis.score_text, "not assessed")
            self.assertEqual(axis.clears_text, "-")
        for fmt in ("md", "html"):
            body = self._text(fmt)
            self.assertIn("not assessed", body, fmt)
            self.assertNotIn("Maintainability | 10.0", body)

    def test_annex_a_prints_no_arithmetic_for_a_not_assessed_axis(self):
        for fmt in ("md", "html"):
            body = self._text(fmt)
            self.assertIn(model.NOT_ASSESSED_NOTE.split(" - ")[0], body, fmt)
        for axis in self.blank:
            self.assertEqual(self.report.scorecard.axis_rows(axis.key), [], axis.key)

    def test_every_rendering_states_the_fail_closed_rule(self):
        for fmt in ("md", "html"):
            self.assertIn("Absence of a finding is not evidence of a control",
                          self._text(fmt), fmt)

    def test_the_radar_table_flags_the_axes_it_does_not_plot(self):
        data = charts.data("axis_radar", self.report)
        rows = {r[0]: (r[1], r[2]) for r in data.rows}
        self.assertEqual(len(rows), len(self.report.axes))
        self.assertEqual(rows["Maintainability"], ("not assessed", "-"))
        self.assertEqual(rows["Data protection"], ("not assessed", "-"))
        self.assertIn("carry no spoke", data.caption)
        self.assertIn("Maintainability", data.caption)

    def test_the_sub_characteristic_table_separates_never_looked_at_from_clean(self):
        report = build(meta={"controls": {"ai_guardrails_present": True}})
        rows = {(r[0], r[1]): (r[2], r[3]) for r in charts.data("sub_bars", report).rows}
        # Assessed by a proven control: scored, and the cell names the control.
        score, why = rows[("Security", "AI / LLM safety")]
        self.assertEqual(score, "10.0")
        self.assertIn("ai_guardrails_present", why)
        # Never looked at: no number at all.
        for label in ("PII minimisation & exposure", "Consent, retention & erasure"):
            score, why = rows[("Data protection", label)]
            self.assertEqual(score, "not assessed", label)
            self.assertIn("no control credits it", why)

    def test_no_not_assessed_axis_gets_a_radar_spoke(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        from reportlab.graphics.shapes import Polygon, String
        drawing = charts.drawing("axis_radar", self.report)
        assessed = [a for a in self.report.axes if a.assessed]
        filled = [p for p in drawing.contents
                  if isinstance(p, Polygon) and p.fillColor is not None]
        self.assertEqual(len(filled), 1)
        # Two coordinates per plotted spoke, and only the assessed axes get one.
        self.assertEqual(len(filled[0].points), 2 * len(assessed))
        labels = [x.text for x in drawing.contents if isinstance(x, String)]
        # Every axis keeps its legend row; the unplotted ones read n/a, never a score.
        for axis in self.report.axes:
            self.assertIn(axis.label, labels, axis.label)
        self.assertEqual(labels.count("n/a"), len(self.blank))
        self.assertIn("n/a = not assessed, not plotted", labels)

    def test_no_not_assessed_sub_gets_a_bar(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        from reportlab.graphics.charts.barcharts import HorizontalBarChart
        drawing = charts.drawing("sub_bars", self.report)
        chart = next(c for c in drawing.contents if isinstance(c, HorizontalBarChart))
        plotted = [s for a in self.report.axes for s in a.subs if s.assessed]
        self.assertEqual(len(chart.data[0]), len(plotted))
        self.assertNotIn(None, chart.data[0])
        for name in chart.categoryAxis.categoryNames:
            self.assertNotIn("Consent, retention & erasure", name)

    def test_the_json_report_carries_the_state_a_consumer_needs(self):
        findings = fixture_findings()
        gate = run_gate(findings, None, require_controls=True)
        card = json.loads(render_report("json", findings, RECON, gate, {}))["scorecard"]
        self.assertEqual(card["not_assessed_axes"], ["data_protection", "maintainability"])
        self.assertEqual(len(card["assessed_axes"]), 4)
        by_key = {a["key"]: a for a in card["axes"]}
        self.assertIsNone(by_key["maintainability"]["score"])
        self.assertIsNone(by_key["maintainability"]["acceptable"])
        self.assertIs(by_key["maintainability"]["assessed"], False)

    def test_the_pdf_renders_with_two_axes_unassessed(self):
        if not charts.available():
            self.skipTest("reportlab not installed in this environment")
        tmp = tempfile.mkdtemp()
        try:
            out = os.path.join(tmp, "reports", "audit-report.pdf")
            findings = fixture_findings()
            gate = run_gate(findings, None, require_controls=True)
            render_report("pdf", findings, RECON, gate, {"output": out})
            self.assertGreater(os.path.getsize(out), 5000)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_a_run_with_nothing_assessed_still_renders_every_format(self):
        gate = run_gate([], None, require_controls=True)
        for fmt in ("md", "html", "json"):
            body = render_report(fmt, [], RECON, gate, {})
            self.assertIn("not assessed", body, fmt)
        if charts.available():
            charts.drawing("axis_radar", build(findings=[]))
            charts.drawing("sub_bars", build(findings=[]))


def untriaged_rows() -> list:
    """A legacy ``findings.json``: the ``finding_class`` key is absent from every row.

    Built as dicts and loaded through ``Finding.from_dict`` rather than constructed with
    ``finding_class=""``, because absent-key is the shape actually on disk and the one a
    renderer meets on an existing audit tree.
    """
    def row(**kw):
        d = dict(title="t", severity="high", source="", category="", rule_id="",
                 locations=[{"file": "a.py", "line": 1}])
        d.update(kw)
        assert "finding_class" not in d
        return d

    return (
        # Four trivy advisories: one class, one sub, one severity band - so this set proves
        # per-band rollup against per-row deduction on its own.
        [row(title=f"CVE-2019-1074{i}", source="trivy", rule_id=f"CVE-2019-1074{i}",
             category="A06:Vulnerable-Components",
             locations=[{"file": "package-lock.json"}]) for i in range(4)]
        + [row(title="Live key committed", source="gitleaks", category="A07:Secrets")]
        + [row(title="Container runs as root", source="hadolint", rule_id="DL3002",
               severity="low", category="A05:Misconfiguration",
               locations=[{"file": "Dockerfile", "line": 3}])]
        + [row(title="IDOR on orders", source="kavach-api", category="API1:BOLA")]
        + [row(title="Insecure cookie", source="semgrep", category="A05", severity="medium")]
        # rust-secret-apis files a secret that outlives its scope under A02:Crypto. Unclassified
        # this scores as an encryption failure on data protection; classified, `class:secret`
        # outranks the category and it scores as secret handling. The one row that proves the
        # `class:` keys in AXIS_MAP are live rather than inert.
        + [row(title="Secret outlives its scope", source="rust-secret-apis",
               category="A02:Crypto", severity="medium")]
    )


class TestRendererDoesNotAssumeTriageRan(unittest.TestCase):
    """The renderer is the second consumer of ``finding_class`` and must not be dependent.

    ``findings_tree.consolidate`` classifies in-line on load so a legacy ``findings.json``
    upgrades transparently. The report model did not, so ``kavach render --out .kavach`` on an
    existing tree - the command README documents for standalone core use, and the one an
    operator reaches for - read every row as ``unclassified``. Three things went wrong at once
    and all three were silent: Figure 3, the figure that exists to show how much of the set is
    raw tool output, showed a single 100% bar; the ``class:`` keys in ``AXIS_MAP`` were inert;
    and the aggregate rollup never fired, so scanner rows deducted one-by-one.
    """

    def setUp(self):
        self.raw = [Finding.from_dict(r) for r in untriaged_rows()]
        self.assertEqual({f.finding_class for f in self.raw}, {""})
        self.report = build(findings=self.raw)

    def test_figure_3_shows_the_real_class_distribution_not_one_unclassified_bar(self):
        rows = charts.data("class_bars", self.report).rows
        self.assertEqual({r[0]: int(r[1]) for r in rows},
                         {"dependency": 4, "secret": 2, "code": 1, "iac": 1, "reasoned": 1})
        self.assertNotIn("unclassified", [r[0] for r in rows])
        self.assertEqual(self.report.class_counts.get("unclassified"), None)

    def test_the_input_finding_list_is_left_untouched(self):
        """classify_all returns a new list; rendering is read-only and stays that way."""
        self.assertEqual({f.finding_class for f in self.raw}, {""})

    def test_an_aggregate_class_deducts_once_per_band_not_once_per_row(self):
        rows = self.report.scorecard.axis_rows("secrets_supply_chain")
        agg = [r for r in rows if r.item.startswith("Aggregate")]
        self.assertEqual(len(agg), 1)
        self.assertIn("dependency", agg[0].item)
        self.assertIn("4 row(s)", agg[0].item)          # member count named, nothing hidden
        self.assertEqual(agg[0].effect, -1.5)
        # Un-triaged the same four rows deducted 4 x -1.50 and took the axis to 2.5.
        self.assertEqual(self.report.scorecard.axis("secrets_supply_chain").score, 6.2)
        self.assertNotIn("CVE-2019-10740", " ".join(r.item for r in rows))

    def test_the_class_precedence_in_axis_map_is_live_not_inert(self):
        secrets = self.report.chapter("secrets_supply_chain").findings
        self.assertIn("Secret outlives its scope", [f.title for f in secrets])
        self.assertNotIn("Secret outlives its scope",
                         [f.title for f in self.report.chapter("data_protection").findings])

    def test_the_rolled_up_rows_reach_the_chapter_as_rolled_not_promoted(self):
        tiers = model.tier(self.report.chapter("secrets_supply_chain").findings)
        self.assertEqual(len(tiers["rolled"]), 4)
        self.assertNotIn("CVE-2019-10740", [f.title for f in tiers["full"]])

    def test_the_axis_reading_declares_the_rollup_on_an_untriaged_set(self):
        reading = self.report.scorecard.axis("secrets_supply_chain").reading
        self.assertIn("4 of them are rolled-up scanner rows", reading)
        self.assertIn("1 band(s)", reading)

    def test_every_rendering_carries_the_classes(self):
        gate = run_gate(self.raw, None, require_controls=True)
        for fmt in ("md", "html"):
            body = render_report(fmt, self.raw, RECON, gate, {})
            self.assertIn("dependency", body, fmt)
            self.assertNotIn("unclassified", body, fmt)

    def test_sarif_carries_the_class_though_it_never_builds_a_model(self):
        """sarif is the one renderer with no AuditReport, so model.build cannot reach it."""
        gate = run_gate(self.raw, None, require_controls=True)
        doc = json.loads(render_report("sarif", self.raw, RECON, gate, {}))
        classes = {r["properties"]["findingClass"] for r in doc["runs"][0]["results"]}
        self.assertEqual(classes, {"dependency", "secret", "code", "iac", "reasoned"})
        self.assertNotIn("", classes)

    def test_the_json_findings_array_agrees_with_its_own_class_counts(self):
        """A jq recompute off findings[] must match the printed class_counts."""
        gate = run_gate(self.raw, None, require_controls=True)
        doc = json.loads(render_report("json", self.raw, RECON, gate, {}))
        recomputed = {}
        for f in doc["findings"]:
            key = f["finding_class"] or "unclassified"
            recomputed[key] = recomputed.get(key, 0) + 1
        self.assertEqual(recomputed, doc["class_counts"])
        self.assertNotIn("unclassified", recomputed)


class TestEmptyFindingSet(unittest.TestCase):
    """A zero-finding run still has to produce every section - gates depend on it."""

    def test_every_format_renders(self):
        gate = run_gate([], {c: True for c in
                             __import__("kavach.score", fromlist=["x"]).GATE_CONTROLS})
        md = render_report("md", [], RECON, gate, {})
        self.assertIn("PRODUCTION-READY", md)
        self.assertEqual(len(re.findall(r"<!-- KAVACH:([a-z-]+) -->", md)),
                         len(model.ANCHORS))
        html = render_report("html", [], RECON, gate, {})
        self.assertIn("No findings", html)
        json.loads(render_report("json", [], RECON, gate, {}))

    def test_empty_recon_renders(self):
        gate = run_gate([], None, require_controls=True)
        md = render_report("md", [], {}, gate, {})
        self.assertIn("unspecified target", md)


if __name__ == "__main__":
    unittest.main()
