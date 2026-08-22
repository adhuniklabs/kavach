import json
import os
import unittest
from collections import Counter

from kavach import triage
from kavach.finding import Confidence, Finding, Location, Severity, load_findings
from kavach.scanners import ALL_SCANNERS

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures",
                       "tymewear-findings-reduced.json")


def _f(source, category="A01", rule_id="", title="Something"):
    return Finding(title=title, severity=Severity.HIGH, category=category, source=source,
                   rule_id=rule_id, locations=[Location(file="src/app.py", line=10)])


class TestClassify(unittest.TestCase):
    def test_reasoned_wins_over_every_other_rule(self):
        # a VAJRA finding about a CVE is judgement, not a scanner row - it stays promotable
        self.assertEqual(triage.classify(
            _f("kavach-supply", "A06:Vulnerable-Components", "CVE-2024-3651")), "reasoned")
        self.assertEqual(triage.classify(_f("reconciler")), "reasoned")
        self.assertEqual(triage.classify(_f("kavach-api", "API1:BOLA")), "reasoned")

    def test_secret_sources(self):
        for source in ("gitleaks", "trufflehog", "builtin-secrets", "rust-secret-apis",
                       "rust_secret_apis"):
            self.assertEqual(triage.classify(_f(source, "A02:Crypto")), "secret", source)

    def test_every_secret_emitter_in_the_tree_lands_in_secret(self):
        # the real (source, category) pair each scanner actually constructs, read off the
        # emitting line rather than off the spec table
        emitters = [
            ("builtin-secrets", "A07:Secrets"),    # builtin_secrets.py:94
            ("gitleaks", "A07:Secrets"),           # secrets.py:47
            ("trufflehog", "A07:Secrets"),         # secrets.py:105
            ("trivy", "A07:Secrets"),              # deps.py:60
            ("rust-secret-apis", "A02:Crypto"),    # rust_secret_apis.py:188
        ]
        for source, category in emitters:
            self.assertEqual(triage.classify(_f(source, category)), "secret",
                             f"{source} / {category}")

    def test_trivy_secret_is_not_dependency(self):
        """A committed secret that classifies as ``dependency`` is rolled into
        G1-vulnerable-dependencies instead of being promoted, and the issue exporter's
        redaction guard keys on ``finding_class == "secret"`` - so it would paste the
        credential into a public tracker unredacted. trivy is the only scanner that
        reports both dependencies and secrets under one source id, and it is also the
        only one whose secret finding carries the raw match (deps.py:63 sets
        ``snippet=s.get("Match")``, where gitleaks and trufflehog pass a redacted value),
        so this is the one path where the misclassification leaks a live value.
        """
        f = Finding(title="Secret in deploy/env.staging: AWS Access Key ID",
                    severity=Severity.CRITICAL, category="A07:Secrets", source="trivy",
                    rule_id="aws-access-key-id",
                    locations=[Location(file="deploy/env.staging", line=4,
                                        snippet="AKIAIOSFODNN7EXAMPLE")])
        self.assertEqual(triage.classify(f), "secret")
        self.assertIn("secret", triage.PROMOTABLE_CLASSES)
        self.assertNotIn("secret", triage.AGGREGATE_CLASSES)

    def test_non_secret_a07_category_is_not_a_secret(self):
        # A07 also spells the identification/authentication family. Matching on the A07
        # prefix would label those secrets and hand them to the redaction path, which
        # withholds a body that has nothing to withhold.
        for category in ("A07:Identification-Failures", "A07:Auth-Failures",
                         "A07:2021-Identification and Authentication Failures", "A07"):
            self.assertEqual(triage.classify(_f("sast", category)), "code", category)

    def test_source_sets_name_real_scanners(self):
        """The dead ``trivy-secret`` entry is what let a trivy secret classify as a
        dependency, so every source in the table has to trace to a scanner id."""
        real = {s.id for s in ALL_SCANNERS}
        # deliberate module-name aliases: nothing emits them, and if anything ever does,
        # it lands in the right class
        aliases = {"deps", "malware", "iac"}
        for name, sources in (("secret", triage._SECRET_SOURCES),
                              ("dependency", triage._DEPENDENCY_SOURCES),
                              ("iac", triage._IAC_SOURCES)):
            for source in sources:
                self.assertIn(source, real | aliases, f"{name}: {source!r} matches no scanner id")
        self.assertNotIn("trivy-secret", triage._SECRET_SOURCES)

    def test_secret_wins_over_the_dependency_source_set(self):
        # ordering is load-bearing, not incidental: trivy is in both branches' reach
        self.assertEqual(triage.classify(_f("trivy", "A07:Secrets")), "secret")
        self.assertEqual(triage.classify(_f("trivy", "A06:Vulnerable-Components")), "dependency")

    def test_reasoned_still_wins_over_secret(self):
        self.assertEqual(triage.classify(_f("kavach-harvester", "A07:Secrets")), "reasoned")

    def test_merge_alias_does_not_hide_a_reasoned_finding(self):
        # merge_findings.index_sources rewrites source to "<alias>:<source>", so an
        # unaliased startswith("kavach-") test drops every merged VAJRA finding to `code`
        # - and to `dependency` when the category is A06, which rolls a judgement call
        # into G1-vulnerable-dependencies instead of promoting it.
        self.assertEqual(triage.classify(_f("a:kavach-api", "API1:BOLA")), "reasoned")
        self.assertEqual(triage.classify(
            _f("a:kavach-supply", "A06:Vulnerable-Components", "CVE-2024-3651")), "reasoned")
        self.assertEqual(triage.classify(_f("b:reconciler", "A01:Broken-Access-Control")),
                         "reasoned")

    def test_merge_alias_does_not_hide_a_scanner_source_set(self):
        # the strip runs before every branch, not just the reasoned one
        self.assertEqual(triage.classify(_f("a:gitleaks", "A02:Crypto")), "secret")
        self.assertEqual(triage.classify(_f("b:npm-audit", "Dependency-Risk")), "dependency")
        self.assertEqual(triage.classify(_f("c:checkov", "A05:Misconfiguration")), "iac")
        self.assertEqual(triage.classify(_f("s26:hadolint", "A05:Misconfiguration")), "iac")

    def test_category_branch_still_survives_aliasing(self):
        self.assertEqual(triage.classify(_f("a:trivy", "A07:Secrets")), "secret")

    def test_nested_merge_alias_resolves(self):
        # merge-run over a previous merge's output dir aliases an already-aliased source
        self.assertEqual(triage.classify(_f("a:b:kavach-api", "API1:BOLA")), "reasoned")

    def test_alias_strip_stays_narrow(self):
        # merge_findings._alias only ever emits "a".."z" and "s<N>", so a longer prefix is
        # not an alias and must survive untouched - classifying `code` here proves the
        # pattern declined to strip it. No real scanner id contains a colon.
        self.assertEqual(triage.classify(_f("foo:kavach-api", "API1:BOLA")), "code")
        self.assertEqual(triage.classify(_f("ab:kavach-api", "API1:BOLA")), "code")
        self.assertEqual(triage.classify(_f("s26x:kavach-api", "API1:BOLA")), "code")

    def test_dedupe_corroboration_does_not_hide_a_source(self):
        # sweep.dedupe:56 rewrites source to "<keep>+<drop>" when two scanners agree on a
        # fingerprint, and picks `keep` by severity - so the kavach segment is not
        # reliably first. Any segment holding the class is enough.
        self.assertEqual(triage.classify(_f("semgrep+kavach-api", "API1:BOLA")), "reasoned")
        self.assertEqual(triage.classify(_f("kavach-api+semgrep", "API1:BOLA")), "reasoned")
        self.assertEqual(triage.classify(_f("builtin-secrets+trivy", "A02:Crypto")), "secret")
        self.assertEqual(triage.classify(_f("semgrep+checkov", "A05:Misconfiguration")), "iac")

    def test_merge_then_dedupe_form_resolves(self):
        # index_sources aliases every source and THEN calls sweep.dedupe, so this exact
        # shape is reachable in merge mode today
        self.assertEqual(triage.classify(_f("a:kavach-api+b:kavach-api", "API1:BOLA")),
                         "reasoned")
        self.assertEqual(triage.classify(_f("a:trivy+b:osv-scanner", "Dependency-Risk")),
                         "dependency")

    def test_dependency_by_source_category_or_advisory_id(self):
        for source in ("trivy", "pip-audit", "npm-audit", "osv-scanner", "guarddog", "deps",
                       "malware"):
            self.assertEqual(triage.classify(_f(source)), "dependency", source)
        self.assertEqual(triage.classify(_f("whatever", "A06:Vulnerable-Components")), "dependency")
        for rule in ("CVE-2024-3651", "GHSA-h4gh-qq45-vh27", "OSV-2023-1114"):
            self.assertEqual(triage.classify(_f("whatever", "A01", rule)), "dependency", rule)

    def test_iac_by_source_or_rule_prefix(self):
        for source in ("checkov", "kics", "hadolint", "iac"):
            self.assertEqual(triage.classify(_f(source, "A05:Misconfiguration")), "iac", source)
        for rule in ("CKV_AWS_18", "CKV2_AWS_6", "DL3008", "AVD-AWS-0088"):
            self.assertEqual(triage.classify(_f("whatever", "A05:Misconfiguration", rule)),
                             "iac", rule)

    def test_code_is_the_fallback(self):
        for source in ("semgrep", "bandit", "gosec", "sast", "fail_open_defaults", "who-knows"):
            self.assertEqual(triage.classify(_f(source)), "code", source)

    def test_classify_all_is_idempotent_over_an_aliased_set(self):
        findings = [_f("a:kavach-api", "API1:BOLA"), _f("b:trivy", "A07:Secrets"),
                    _f("a:trivy+b:osv-scanner", "A06:Vulnerable-Components"),
                    _f("c:checkov", "A05:Misconfiguration")]
        once = triage.classify_all(findings)
        twice = triage.classify_all(once)
        self.assertEqual([f.finding_class for f in once],
                         ["reasoned", "secret", "dependency", "iac"])
        self.assertEqual([f.finding_class for f in twice], [f.finding_class for f in once])
        self.assertEqual([f.source for f in twice], [f.source for f in findings])  # not rewritten

    def test_classify_all_is_idempotent_and_returns_a_new_list(self):
        findings = [_f("trivy"), _f("kavach-api"), _f("gitleaks")]
        once = triage.classify_all(findings)
        twice = triage.classify_all(once)
        self.assertEqual([f.finding_class for f in once], ["dependency", "reasoned", "secret"])
        self.assertEqual([f.finding_class for f in twice], [f.finding_class for f in once])
        self.assertEqual([f.finding_class for f in findings], ["", "", ""])   # inputs untouched

    def test_every_class_is_declared(self):
        self.assertEqual(set(triage.CLASSES),
                         set(triage.AGGREGATE_CLASSES) | set(triage.PROMOTABLE_CLASSES))


class TestPublicApi(unittest.TestCase):
    def test_sources_is_public_and_the_private_alias_still_points_at_it(self):
        # render/model.py keys Annex C's reproduction commands on the source, so this
        # helper has a second caller outside triage.py and must not be reached into by a
        # single-underscore name. The alias is asserted here so a later refactor cannot
        # drop it while the older tests keep passing through it.
        self.assertIs(triage.sources, triage._sources)
        self.assertEqual(triage.sources(_f("a:trivy+b:osv-scanner")),
                         ["trivy", "osv-scanner"])

    def test_all_lists_the_public_surface(self):
        self.assertEqual(set(triage.__all__),
                         {"sources", "classify", "classify_all", "CLASSES",
                          "AGGREGATE_CLASSES", "PROMOTABLE_CLASSES"})
        for name in triage.__all__:
            self.assertTrue(hasattr(triage, name), name)


class TestFingerprintIsUnchanged(unittest.TestCase):
    """finding_class is excluded from the fingerprint basis. These ids are the literal
    pre-upgrade values - if either changes, every stored kavach_id and every tracker
    issue keyed on one has silently been orphaned."""

    def test_pre_upgrade_reasoned_finding_keeps_its_exact_id(self):
        f = Finding(title="IDOR on /orders", severity=Severity.HIGH, category="API1:BOLA",
                    source="kavach-api", locations=[Location(file="src/orders.py", line=42)])
        self.assertEqual(f.id, "KAVACH-6c74638c84")
        self.assertEqual(triage.classify_all([f])[0].id, "KAVACH-6c74638c84")

    def test_pre_upgrade_scanner_finding_keeps_its_exact_id(self):
        f = Finding(title="requests 2.28.1: CVE-2024-35195", severity=Severity.HIGH,
                    category="A06:Vulnerable-Components", source="trivy",
                    rule_id="CVE-2024-35195",
                    locations=[Location(file="requirements.txt", line=3)])
        self.assertEqual(f.id, "KAVACH-1525fba58a")
        self.assertEqual(triage.classify_all([f])[0].id, "KAVACH-1525fba58a")

    def test_findings_json_without_finding_class_still_loads(self):
        row = {"title": "IDOR on /orders", "severity": "high", "category": "API1:BOLA",
               "source": "kavach-api", "locations": [{"file": "src/orders.py", "line": 42}],
               "confidence": "confirmed", "id": "KAVACH-6c74638c84"}
        self.assertNotIn("finding_class", row)
        f = Finding.from_dict(row)
        self.assertEqual(f.finding_class, "")
        self.assertEqual(f.id, "KAVACH-6c74638c84")

    def test_finding_class_round_trips_through_to_dict(self):
        f = triage.classify_all([_f("checkov", "A05:Misconfiguration")])[0]
        again = Finding.from_dict(f.to_dict())
        self.assertEqual(again.finding_class, "iac")
        self.assertEqual(again.id, f.id)

    def test_confidence_default_unaffected(self):
        self.assertEqual(_f("trivy").confidence, Confidence.SUSPECTED)


class TestReducedCorpus(unittest.TestCase):
    """Acceptance criterion 2, against a committed reduced stand-in for the real run -
    never the operator's private repo."""

    def test_class_mix_is_scanner_dominated(self):
        counts = Counter(f.finding_class for f in triage.classify_all(load_findings(FIXTURE)))
        self.assertEqual(counts["dependency"], 18)
        self.assertEqual(counts["iac"], 12)
        self.assertEqual(counts["code"], 8)
        self.assertEqual(counts["reasoned"], 6)
        self.assertEqual(counts["secret"], 5)
        aggregate = counts["dependency"] + counts["iac"]
        self.assertGreater(aggregate, sum(counts.values()) / 2)   # the noise really is the bulk

    def test_the_trivy_secret_row_is_exercised(self):
        rows = [f for f in triage.classify_all(load_findings(FIXTURE))
                if f.source == "trivy" and f.category == "A07:Secrets"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].finding_class, "secret")

    def test_no_finding_is_left_unclassified(self):
        for f in triage.classify_all(load_findings(FIXTURE)):
            self.assertIn(f.finding_class, triage.CLASSES, f.title)

    def test_fixture_is_not_pre_classified(self):
        # proves the counts above come from classify(), not from a baked-in field
        with open(FIXTURE, encoding="utf-8") as fh:
            rows = json.load(fh)["findings"]
        self.assertTrue(all(not r.get("finding_class") for r in rows))


if __name__ == "__main__":
    unittest.main()
