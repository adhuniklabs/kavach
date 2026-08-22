"""Scorecard arithmetic - deterministic, reproducible, no evaluator override."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kavach import scoring  # noqa: E402
from kavach.finding import Finding, Location, Severity  # noqa: E402


def mk(sev, *, cat="A01", cls="", chain=None, title="t", file="a.py", cvss=0.0):
    return Finding(title=title, severity=sev, category=cat, source="s", finding_class=cls,
                   kill_chain=chain, cvss_score=cvss, locations=[Location(file=file, line=1)])


class TestAxisMapping(unittest.TestCase):
    def test_category_outranks_class_and_kill_chain(self):
        f = mk(Severity.HIGH, cat="A01", cls="dependency", chain="read-others-data")
        self.assertEqual(scoring.axis_for(f), "security")

    def test_category_outranks_class(self):
        f = mk(Severity.HIGH, cat="A03", cls="iac")
        self.assertEqual(scoring.axis_for(f), "security")

    def test_class_decides_only_when_the_category_is_unmapped(self):
        self.assertEqual(scoring.axis_for(mk(Severity.HIGH, cat="", cls="iac")), "architecture")
        self.assertEqual(scoring.axis_for(mk(Severity.HIGH, cat="Something-New", cls="dependency")),
                         "secrets_supply_chain")

    def test_kill_chain_decides_only_when_category_and_class_are_unmapped(self):
        f = mk(Severity.HIGH, cat="Business-Logic-Abuse", cls="reasoned", chain="bypass-billing")
        self.assertEqual(scoring.axis_for(f), "reliability")

    def test_the_secret_class_outranks_the_category(self):
        # rust-secret-apis emits A02:Crypto for a secret that outlives its scope in memory.
        f = mk(Severity.MEDIUM, cat="A02:Crypto", cls="secret")
        self.assertEqual(scoring.axis_for(f), "secrets_supply_chain")
        self.assertEqual(scoring.sub_for(f, "secrets_supply_chain"), "secret_management")

    def test_an_idor_is_scored_as_access_control_not_data_protection(self):
        for cat in ("API1:BOLA", "API1:2023-Broken Object Level Authorization", "API5:BFLA",
                    "A01:Broken Access Control", "API3:Excessive-Data-Exposure"):
            f = mk(Severity.CRITICAL, cat=cat, cls="reasoned", chain="read-others-data")
            self.assertEqual(scoring.axis_for(f), "security", cat)
            self.assertEqual(scoring.sub_for(f, "security"), "access_control", cat)

    def test_a07_splits_between_kavach_secrets_and_owasp_auth_failures(self):
        secret = mk(Severity.CRITICAL, cat="A07:Secrets", cls="reasoned", chain="steal-keys")
        self.assertEqual(scoring.axis_for(secret), "secrets_supply_chain")
        self.assertEqual(scoring.sub_for(secret, "secrets_supply_chain"), "secret_management")
        for cat in ("A07:Auth-Failures", "A07:2021-Identification and Authentication Failures",
                    "A07:Identification-and-Authentication-Failures"):
            f = mk(Severity.HIGH, cat=cat, cls="reasoned", chain="read-others-data")
            self.assertEqual(scoring.axis_for(f), "security", cat)
            self.assertEqual(scoring.sub_for(f, "security"), "authentication", cat)

    def test_code_and_reasoned_classes_defer_to_category(self):
        for cls in ("code", "reasoned"):
            f = mk(Severity.HIGH, cat="A02", cls=cls)
            self.assertEqual(scoring.axis_for(f), "data_protection", cls)

    def test_category_matches_on_the_token_before_the_colon(self):
        self.assertEqual(scoring.axis_for(mk(Severity.LOW, cat="A06:Vulnerable-Components")),
                         "secrets_supply_chain")
        self.assertEqual(scoring.axis_for(mk(Severity.LOW, cat="api4:Resource-Consumption")),
                         "reliability")

    def test_unmapped_category_falls_back_to_the_default_axis(self):
        self.assertEqual(scoring.axis_for(mk(Severity.LOW, cat="Something-New")),
                         scoring.DEFAULT_AXIS)

    def test_the_class_picks_the_sub_within_the_axis_the_category_picked(self):
        # Both are A05 - only the class separates an IaC default from application config.
        iac = mk(Severity.HIGH, cat="A05:Misconfiguration", cls="iac")
        self.assertEqual(scoring.axis_for(iac), "architecture")
        self.assertEqual(scoring.sub_for(iac, "architecture"), "infrastructure_as_code")
        app = mk(Severity.HIGH, cat="A05:Misconfiguration", cls="reasoned")
        self.assertEqual(scoring.sub_for(app, "architecture"), "configuration")

    def test_a_sub_belonging_to_another_axis_is_skipped_not_taken(self):
        # trivy emits A05:Misconfiguration rows classified `dependency`: architecture axis,
        # but dependency_hygiene is a sub of secrets_supply_chain, so the category decides.
        f = mk(Severity.HIGH, cat="A05:Misconfiguration", cls="dependency")
        self.assertEqual(scoring.axis_for(f), "architecture")
        self.assertEqual(scoring.sub_for(f, "architecture"), "configuration")

    def test_sub_falls_back_to_the_axis_default_when_nothing_maps_inside_it(self):
        f = mk(Severity.HIGH, cat="A09", cls="", chain="steal-keys")
        axis = scoring.axis_for(f)
        self.assertEqual(axis, "reliability")
        self.assertEqual(scoring.sub_for(f, axis), "observability")
        bare = mk(Severity.HIGH, cat="Something-New", cls="")
        self.assertEqual(scoring.sub_for(bare, scoring.DEFAULT_AXIS),
                         scoring.SUBS[scoring.DEFAULT_AXIS][0][0])


class TestArithmetic(unittest.TestCase):
    def test_deduction_scale_is_exact(self):
        card = scoring.score([mk(Severity.HIGH, cat="A01")])
        self.assertEqual(card.axis("security").score, 8.5)
        card = scoring.score([mk(Severity.CRITICAL, cat="A01")])
        self.assertEqual(card.axis("security").score, 7.0)
        card = scoring.score([mk(Severity.MEDIUM, cat="A01")])
        self.assertEqual(card.axis("security").score, 9.2)   # 9.25 rounded to one decimal
        card = scoring.score([mk(Severity.LOW, cat="A01")])
        self.assertEqual(card.axis("security").score, 9.8)   # 9.75 rounded to one decimal

    def test_info_findings_deduct_nothing(self):
        card = scoring.score([mk(Severity.INFO, cat="A01") for _ in range(20)])
        self.assertEqual(card.axis("security").score, 10.0)

    def test_axis_floors_at_one(self):
        findings = [mk(Severity.CRITICAL, cat="A01", title=f"c{i}") for i in range(10)]
        self.assertEqual(scoring.score(findings).axis("security").score, scoring.FLOOR)

    def test_proven_control_adds_the_bonus_but_never_above_ten(self):
        controls = {"authz_on_every_object_and_function": True}
        self.assertEqual(scoring.score([], controls).axis("security").score, 10.0)
        card = scoring.score([mk(Severity.HIGH, cat="A01")], controls)
        self.assertEqual(card.axis("security").score, 9.0)

    def test_unproven_control_earns_nothing(self):
        for value in (False, None, "true"):
            card = scoring.score([], {"authz_on_every_object_and_function": value})
            rows = [r for r in card.axis_rows("security")
                    if r.item == "authz_on_every_object_and_function"]
            self.assertEqual(rows, [], repr(value))

    def test_rows_sum_to_the_axis_score(self):
        findings = [mk(Severity.CRITICAL, cat="A01"), mk(Severity.HIGH, cat="A03", title="x"),
                    mk(Severity.MEDIUM, cat="A02", title="y")]
        card = scoring.score(findings, {"encryption_tls_and_at_rest": True})
        for axis in card.assessed_axes:
            total = sum(r.effect for r in axis.rows)
            self.assertAlmostEqual(round(total, 1), axis.score, places=6, msg=axis.key)
        self.assertTrue(card.assessed_axes)

    def test_clamp_is_recorded_as_a_row(self):
        findings = [mk(Severity.CRITICAL, cat="A01", title=f"c{i}") for i in range(10)]
        rows = scoring.score(findings).axis_rows("security")
        self.assertTrue(any("Clamped" in r.item for r in rows))

    def test_deterministic_across_calls_and_input_order(self):
        findings = [mk(Severity.HIGH, cat="A01", title="a"), mk(Severity.MEDIUM, cat="A02", title="b"),
                    mk(Severity.LOW, cat="A05", title="c")]
        first = scoring.score(findings).to_dict()
        second = scoring.score(list(reversed(findings))).to_dict()
        self.assertEqual(first, second)

    def test_overall_is_the_mean_of_the_assessed_axes_only(self):
        # One critical on security, nothing anywhere else: the figure is that one axis, not
        # 7.0 diluted upward by five unmeasured tens.
        card = scoring.score([mk(Severity.CRITICAL, cat="A01")])
        self.assertEqual([a.key for a in card.assessed_axes], ["security"])
        self.assertEqual(card.overall, 7.0)
        self.assertEqual(card.overall,
                         round(sum(a.score for a in card.assessed_axes)
                               / len(card.assessed_axes), 1))

    def test_acceptable_needs_every_assessed_axis_to_clear_the_threshold(self):
        clean = scoring.score([mk(Severity.LOW, cat="A01")])
        self.assertTrue(clean.acceptable)
        sunk = scoring.score([mk(Severity.CRITICAL, cat="A01", title=f"c{i}")
                              for i in range(4)])
        self.assertFalse(sunk.acceptable)
        # An unmeasured axis is neither acceptable nor unacceptable, so it rescues nothing.
        self.assertIsNone(sunk.axis("maintainability").acceptable)

    def test_a_scorecard_with_nothing_assessed_is_not_acceptable(self):
        card = scoring.score([])
        self.assertFalse(card.acceptable)
        self.assertIsNone(card.overall)


class TestAxisRows(unittest.TestCase):
    def test_module_function_and_method_agree(self):
        findings = [mk(Severity.HIGH, cat="A01")]
        card = scoring.score(findings)
        self.assertEqual([r.to_dict() for r in scoring.axis_rows("security", findings)],
                         [r.to_dict() for r in card.axis_rows("security")])

    def test_first_row_is_the_baseline(self):
        rows = scoring.axis_rows("security", [mk(Severity.HIGH, cat="A01")])
        self.assertEqual(rows[0].item, "Baseline")
        self.assertEqual(rows[0].effect, scoring.BASE)

    def test_unknown_axis_raises(self):
        with self.assertRaises(KeyError):
            scoring.axis_rows("velocity", [])
        with self.assertRaises(KeyError):
            scoring.score([]).axis("velocity")

    def test_every_deduction_carries_a_justification(self):
        rows = scoring.axis_rows("security", [mk(Severity.HIGH, cat="A01")])
        for row in rows[1:]:
            self.assertTrue(row.justification.strip(), row.item)


class TestSubScores(unittest.TestCase):
    def test_sub_keys_are_unique_across_axes(self):
        keys = [k for axis in scoring.SUBS.values() for k, _ in axis]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_axis_has_a_sub_and_every_axis_is_labelled(self):
        for axis in scoring.AXES:
            self.assertTrue(scoring.SUBS[axis])
            self.assertIn(axis, scoring.AXIS_LABELS)

    def test_every_sub_map_target_is_a_real_sub_key(self):
        keys = {k for axis in scoring.SUBS.values() for k, _ in axis}
        for target in scoring.SUB_MAP.values():
            self.assertIn(target, keys, target)

    def test_every_axis_map_target_is_a_real_axis(self):
        for target in scoring.AXIS_MAP.values():
            self.assertIn(target, scoring.AXES, target)

    def test_control_map_covers_every_gate_control(self):
        from kavach.score import GATE_CONTROLS
        self.assertEqual(sorted(scoring.CONTROL_MAP), sorted(GATE_CONTROLS))
        keys = {k for axis in scoring.SUBS.values() for k, _ in axis}
        for axis, sub in scoring.CONTROL_MAP.values():
            self.assertIn(axis, scoring.AXES)
            self.assertIn(sub, keys)

    def test_determined_by_names_the_finding_that_moved_the_sub(self):
        f = mk(Severity.HIGH, cat="A01")
        card = scoring.score([f])
        sub = next(s for s in card.axis("security").subs if s.key == "access_control")
        self.assertTrue(any(f.id in entry for entry in sub.determined_by))


class TestAggregateWeighting(unittest.TestCase):
    """A rolled-up scanner class deducts once per severity band, not once per row."""

    def deps(self, n, sev=Severity.HIGH):
        return [mk(sev, cat="A06:Vulnerable-Components", cls="dependency", title=f"cve{i}")
                for i in range(n)]

    def test_one_row_and_one_deduction_per_band_however_many_members(self):
        for n in (1, 5, 136):
            card = scoring.score(self.deps(n))
            rows = [r for r in card.axis_rows("secrets_supply_chain")
                    if r.item.startswith("Aggregate")]
            self.assertEqual(len(rows), 1, n)
            self.assertEqual(card.axis("secrets_supply_chain").score, 8.5, n)

    def test_the_row_names_the_member_count_so_nothing_is_hidden(self):
        rows = scoring.axis_rows("secrets_supply_chain", self.deps(42))
        row = next(r for r in rows if r.item.startswith("Aggregate"))
        self.assertIn("42", row.item)
        self.assertIn("dependency", row.item)
        self.assertIn("high", row.justification)

    def test_each_severity_band_present_deducts_once(self):
        findings = (self.deps(20, Severity.CRITICAL) + self.deps(30, Severity.HIGH)
                    + self.deps(40, Severity.MEDIUM) + self.deps(50, Severity.LOW))
        card = scoring.score(findings)
        rows = [r for r in card.axis_rows("secrets_supply_chain")
                if r.item.startswith("Aggregate")]
        self.assertEqual([r.effect for r in rows], [-3.0, -1.5, -0.75, -0.25])
        self.assertEqual(card.axis("secrets_supply_chain").score, 4.5)

    def test_info_band_deducts_nothing_and_gets_no_row(self):
        rows = scoring.axis_rows("secrets_supply_chain", self.deps(9, Severity.INFO))
        self.assertEqual([r.item for r in rows], ["Baseline"])

    def test_promotable_classes_still_deduct_once_per_finding(self):
        findings = [mk(Severity.HIGH, cat="A01", cls="reasoned", title=f"r{i}") for i in range(4)]
        card = scoring.score(findings)
        rows = [r for r in card.axis_rows("security") if r.item != "Baseline"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(card.axis("security").score, 4.0)

    def test_bands_are_split_by_sub_so_the_sub_scores_still_reconcile(self):
        # Both classes land on architecture, on two different subs.
        findings = ([mk(Severity.HIGH, cat="A05:Misconfiguration", cls="iac", title=f"i{i}")
                     for i in range(7)]
                    + [mk(Severity.HIGH, cat="A05:Misconfiguration", cls="dependency",
                          title=f"d{i}") for i in range(4)])
        axis = scoring.score(findings).axis("architecture")
        rows = [r for r in axis.rows if r.item.startswith("Aggregate")]
        self.assertEqual(len(rows), 2)
        self.assertEqual(axis.score, 7.0)
        subs = {s.key: s for s in axis.subs}
        self.assertEqual(subs["infrastructure_as_code"].score, 8.5)
        self.assertEqual(subs["configuration"].score, 8.5)
        self.assertEqual(len(subs["infrastructure_as_code"].determined_by), 1)

    def test_a_rolled_up_class_can_no_longer_floor_an_axis_on_its_own(self):
        card = scoring.score(self.deps(500, Severity.CRITICAL))
        self.assertGreater(card.axis("secrets_supply_chain").score, scoring.FLOOR)

    def test_rows_still_sum_to_the_axis_score_with_aggregates_present(self):
        findings = (self.deps(30, Severity.CRITICAL)
                    + [mk(Severity.HIGH, cat="A07:Secrets", cls="reasoned", title="s")]
                    + [mk(Severity.MEDIUM, cat="A05", cls="iac", title=f"k{i}") for i in range(6)])
        card = scoring.score(findings, {"no_client_reachable_secret": True})
        for axis in card.assessed_axes:
            self.assertAlmostEqual(round(sum(r.effect for r in axis.rows), 1), axis.score,
                                   places=6, msg=axis.key)


class TestReading(unittest.TestCase):
    def test_every_axis_reading_states_what_the_axis_scores(self):
        card = scoring.score([])
        for axis in card.axes:
            self.assertIn(scoring.AXIS_SCOPE[axis.key], axis.reading, axis.key)

    def test_reading_names_the_subs_nothing_was_scored_against(self):
        card = scoring.score([mk(Severity.HIGH, cat="A01")])
        reading = card.axis("security").reading
        self.assertIn("Not assessed: ", reading)
        self.assertIn("AI / LLM safety", reading)
        self.assertNotIn("Access control", reading)

    def test_an_axis_with_nothing_scored_against_it_reads_not_assessed(self):
        axis = scoring.score([]).axis("maintainability")
        self.assertIsNone(axis.score)
        self.assertTrue(axis.reading.startswith("Not assessed."))
        self.assertIn("absence of a finding is not evidence of a control", axis.reading)

    def test_reading_declares_the_aggregate_weighting_when_it_applies(self):
        findings = [mk(Severity.HIGH, cat="A06", cls="dependency", title=f"c{i}")
                    for i in range(136)]
        reading = scoring.score(findings).axis("secrets_supply_chain").reading
        self.assertIn("136 finding(s) map here", reading)
        self.assertIn("136 of them are rolled-up scanner rows", reading)
        self.assertIn("1 band(s)", reading)

    def test_no_aggregate_sentence_when_no_rolled_up_row_is_present(self):
        reading = scoring.score([mk(Severity.HIGH, cat="A01")]).axis("security").reading
        self.assertNotIn("rolled-up", reading)


class TestNotAssessed(unittest.TestCase):
    """Absence of evidence reads as absence of assessment, not as success.

    The rest of the framework is fail-closed - controls.json defaults every control to false and
    the gate withholds certification on an unproven one - so an axis nobody measured cannot come
    out of the scorecard at 10.0/10 "clears 5.0".
    """

    def test_an_axis_with_no_finding_and_no_control_has_no_score(self):
        card = scoring.score([])
        for axis in card.axes:
            self.assertIsNone(axis.score, axis.key)
            self.assertFalse(axis.assessed, axis.key)
            self.assertIsNone(axis.acceptable, axis.key)

    def test_the_number_is_never_substituted_for_a_default(self):
        # Not 10.0, not 0.0, not the floor, not the threshold: a number of any kind is a claim.
        axis = scoring.score([]).axis("maintainability")
        self.assertNotIn(axis.score, (scoring.BASE, 0.0, scoring.FLOOR, scoring.ACCEPTABLE))
        self.assertEqual(axis.score_text, scoring.NOT_ASSESSED)
        self.assertEqual(axis.clears_text, scoring.NOT_APPLICABLE)

    def test_an_assessed_axis_still_reports_a_number_and_a_verdict(self):
        axis = scoring.score([mk(Severity.HIGH, cat="A01")]).axis("security")
        self.assertEqual(axis.score, 8.5)
        self.assertEqual(axis.score_text, "8.5")
        self.assertEqual(axis.clears_text, "yes")

    def test_a_not_assessed_axis_has_no_arithmetic_to_print(self):
        # Not even a Baseline row: "Baseline +10.00, total 10.0" is the claim, restated.
        self.assertEqual(scoring.axis_rows("maintainability", []), [])
        self.assertEqual(scoring.score([]).axis_rows("security"), [])

    def test_a_not_assessed_axis_cannot_move_the_overall_figure(self):
        one = scoring.score([mk(Severity.CRITICAL, cat="A01")])
        both = scoring.score([mk(Severity.CRITICAL, cat="A01"),
                             mk(Severity.CRITICAL, cat="A02", title="d")])
        self.assertEqual(one.overall, 7.0)
        self.assertEqual(both.overall, 7.0)      # two assessed axes, both at 7.0
        self.assertEqual(len(one.assessed_axes), 1)
        self.assertEqual(len(both.assessed_axes), 2)

    def test_the_summary_says_how_many_axes_the_figure_covers(self):
        card = scoring.score([mk(Severity.CRITICAL, cat="A01")])
        self.assertIn("7.0 / 10 across 1 assessed axis", card.summary)
        self.assertIn("5 not assessed", card.summary)

    def test_the_summary_names_a_lone_unassessed_axis(self):
        findings = [mk(Severity.HIGH, cat=c, title=c) for c in
                    ("A01", "A02", "A06", "A05", "A09")]
        card = scoring.score(findings)
        self.assertEqual([a.key for a in card.unassessed_axes], ["maintainability"])
        self.assertIn("(1 not assessed: Maintainability)", card.summary)

    def test_a_finding_mapping_here_is_enough_to_count_as_assessed(self):
        # Info deducts nothing, but something was looked at and reported: 10.0 is a result.
        card = scoring.score([mk(Severity.INFO, cat="A01")])
        axis = card.axis("security")
        self.assertTrue(axis.assessed)
        self.assertEqual(axis.score, 10.0)
        self.assertFalse(card.axis("maintainability").assessed)

    def test_a_proven_control_alone_makes_its_sub_assessed(self):
        """Assessed-and-passed is a different statement from never-looked-at."""
        card = scoring.score([], {"ai_guardrails_present": True})
        subs = {s.key: s for s in card.axis("security").subs}
        self.assertTrue(subs["ai_safety"].assessed)
        self.assertEqual(subs["ai_safety"].score, 10.0)
        self.assertEqual(subs["ai_safety"].determined_by, ["ai_guardrails_present (+0.5)"])
        # ... and the siblings it says nothing about stay unassessed.
        self.assertFalse(subs["access_control"].assessed)
        self.assertIsNone(subs["access_control"].score)
        self.assertEqual(subs["access_control"].score_text, scoring.NOT_ASSESSED)

    def test_the_control_bonus_is_a_printed_term_not_the_baseline_default(self):
        rows = scoring.axis_rows("security", [], {"ai_guardrails_present": True})
        self.assertIn("ai_guardrails_present", [r.item for r in rows])
        # The +0.5 is clamped off a 10.0 baseline, and the clamp is printed rather than hidden.
        self.assertTrue(any("Clamped" in r.item for r in rows))

    def test_an_unproven_control_does_not_make_its_sub_assessed(self):
        for value in (False, None, "true"):
            card = scoring.score([], {"ai_guardrails_present": value})
            sub = next(s for s in card.axis("security").subs if s.key == "ai_safety")
            self.assertFalse(sub.assessed, repr(value))

    def test_data_protection_subs_with_no_coverage_are_not_perfect(self):
        """The GDPR line the cover cites: consent and retention were never looked for."""
        card = scoring.score([mk(Severity.HIGH, cat="A02")])
        subs = {s.key: s for s in card.axis("data_protection").subs}
        self.assertEqual(subs["encryption"].score, 8.5)
        for key in ("pii_exposure", "privacy_and_retention"):
            self.assertIsNone(subs[key].score, key)
            self.assertFalse(subs[key].assessed, key)

    def test_the_method_states_the_rule_in_prose(self):
        self.assertIn("Absence of a finding is not evidence of a control", scoring.METHOD)
        self.assertIn(scoring.NOT_ASSESSED, scoring.METHOD)

    def test_the_not_assessed_reading_says_why_the_axis_is_empty(self):
        reading = scoring.score([]).axis("maintainability").reading
        self.assertIn("No gate control credits this axis", reading)
        self.assertIn("API9", reading)
        self.assertIn("LLM09", reading)
        self.assertIn("security auditor", reading)

    def test_an_axis_a_control_can_reach_says_so_instead(self):
        reading = scoring.score([]).axis("data_protection").reading
        self.assertIn("gate control(s) can credit it", reading)
        self.assertNotIn("No gate control credits this axis", reading)

    def test_the_coverage_caveat_only_labels_maintainability(self):
        self.assertEqual(list(scoring.AXIS_COVERAGE_CAVEAT), ["maintainability"])
        for axis in scoring.AXES:
            reading = scoring.score([]).axis(axis).reading
            self.assertEqual("security auditor" in reading, axis == "maintainability", axis)

    def test_serialised_form_carries_the_state_not_a_bare_null(self):
        card = scoring.score([mk(Severity.HIGH, cat="A01")]).to_dict()
        by_key = {a["key"]: a for a in card["axes"]}
        self.assertIs(by_key["maintainability"]["assessed"], False)
        self.assertIsNone(by_key["maintainability"]["score"])
        self.assertIs(by_key["security"]["assessed"], True)
        self.assertEqual(card["not_assessed_axes"],
                         [a for a in scoring.AXES if a != "security"])
        self.assertEqual(card["assessed_axes"], ["security"])
        self.assertEqual(card["summary"], scoring.score([mk(Severity.HIGH, cat="A01")]).summary)

    def test_deterministic_with_unassessed_axes_present(self):
        findings = [mk(Severity.HIGH, cat="A01", title="a"), mk(Severity.LOW, cat="A02", title="b")]
        self.assertEqual(scoring.score(findings).to_dict(),
                         scoring.score(list(reversed(findings))).to_dict())


class TestClassCounts(unittest.TestCase):
    def test_counts_and_labels_unclassified(self):
        findings = [mk(Severity.LOW, cls="dependency", title="a"),
                    mk(Severity.LOW, cls="dependency", title="b"),
                    mk(Severity.LOW, cls="", title="c")]
        self.assertEqual(scoring.class_counts(findings),
                         {"dependency": 2, "unclassified": 1})


if __name__ == "__main__":
    unittest.main()
