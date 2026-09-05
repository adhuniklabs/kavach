import posixpath
import unittest

from kavach import cleanup, modes


class TestModes(unittest.TestCase):
    def test_three_modes(self):
        self.assertEqual(set(modes.MODES), {"lite", "balanced", "deep"})

    def test_presets_nest(self):
        lite = set(modes.phases_for("lite"))
        balanced = set(modes.phases_for("balanced"))
        deep = set(modes.phases_for("deep"))
        self.assertLess(lite, balanced)
        self.assertLess(balanced, deep)

    def test_preset_sizes(self):
        self.assertEqual(len(modes.phases_for("lite")), 6)
        self.assertEqual(len(modes.phases_for("balanced")), 13)
        self.assertEqual(len(modes.phases_for("deep")), 20)

    def test_phases_come_back_in_pipeline_order(self):
        for mode in modes.MODES:
            got = modes.phases_for(mode)
            self.assertEqual(got, [p for p in modes.PIPELINE if p in got], mode)

    def test_lite_renders_a_report(self):
        self.assertIn("render", modes.phases_for("lite"))
        self.assertNotIn("report", modes.phases_for("lite"))

    def test_every_preset_schedules_recon_and_sweep_for_itself(self):
        """The invariant that retired missing_prerequisites(). `recon` writes recon.json and
        `sweep` is the only verb that writes findings.json; `scope` ranks the manifest and
        `slice`, `triage` and `render` all read findings.json. balanced scheduled neither,
        and driving it sent eight hunters empty slices and then died in the report tail."""
        for mode in modes.MODES:
            self.assertLessEqual({"recon", "sweep"}, set(modes.phases_for(mode)), mode)

    def test_induced_prereqs_stay_inside_the_preset(self):
        for mode in modes.MODES:
            members = set(modes.phases_for(mode))
            for phase in members:
                for prereq in modes.prereqs_for(mode, phase):
                    self.assertIn(prereq, members, f"{mode}/{phase} -> {prereq}")

    def test_dropped_phases_reroute_through_their_own_prereqs(self):
        # poc declares crosscheck, which lite drops; resolution walks crosscheck ->
        # variant -> verify -> chamber and keeps only what lite actually runs.
        self.assertEqual(set(modes.prereqs_for("lite", "poc")), {"recon", "hunt"})
        self.assertEqual(set(modes.prereqs_for("balanced", "crosscheck")),
                         {"intent", "chamber"})

    def test_deep_keeps_the_full_dag(self):
        self.assertEqual(modes.prereqs_for("deep", "verify"), ["chamber"])
        self.assertEqual(modes.prereqs_for("deep", "recon"), [])

    def test_hunt_roster_is_preset_dependent(self):
        self.assertEqual(modes.roster_for("hunt", "lite"), ["kavach-sast"])
        self.assertEqual(len(modes.roster_for("hunt", "deep")), 8)
        self.assertEqual(len(modes.roster_for("hunt", "balanced")), 8)

    def test_every_phase_has_label_and_agent(self):
        for phase in modes.PIPELINE:
            self.assertIn(phase, modes.PHASE_LABELS, f"{phase} missing label")
            self.assertIn(phase, modes.PHASE_AGENT, f"{phase} missing agent")

    def test_gate_globs_are_lists(self):
        self.assertIsInstance(modes.gate_for("render"), list)
        self.assertTrue(any("final-audit-report" in g for g in modes.gate_for("render")))

    def test_per_finding_phases_gate_on_coverage_not_on_the_directory(self):
        self.assertEqual(modes.gate_for("poc"), ["attack-surface/poc-coverage.json"])
        self.assertEqual(modes.gate_for("report"), ["attack-surface/report-coverage.json"])

    def test_gate_names_carry_no_mode_prefix(self):
        for phase in modes.PIPELINE:
            for pat in modes.gate_for(phase):
                for prefix in ("lite-", "balanced-", "deep-", "diff-", "confirm-",
                               "revisit-", "merge-", "longshot-"):
                    self.assertNotIn(prefix, pat, f"{phase} gates on {pat!r}")

    def test_every_phase_in_a_preset_has_a_distinct_gate(self):
        """The assertion MG3 and MG4 would have failed: they gated on the file MG1 wrote,
        so next_actionable skipped them and neither ever ran."""
        for mode in modes.MODES:
            seen = {}
            for phase in modes.phases_for(mode, True):
                for pat in modes.gate_for(phase):
                    self.assertNotIn(pat, seen,
                                     f"{mode}: {phase} gates on {pat}, already written "
                                     f"by {seen.get(pat)}")
                    seen[pat] = phase

    def test_no_gate_under_transient(self):
        """The invariant whose absence let chamber and verify gate on tmp/: a gate that
        cleanup deletes makes its phase eligible again on every resume, which is how a run
        pays for the same fan-out twice."""
        for phase in modes.PIPELINE:
            for pat in modes.gate_for(phase):
                root = posixpath.normpath(pat).split("/")[0]
                self.assertNotIn(root, cleanup.TRANSIENT,
                                 f"{phase} gates on transient {pat!r}")

    def test_unknown_mode_raises(self):
        with self.assertRaises(KeyError):
            modes.phases_for("nope")

    def test_an_unknown_phase_is_answered_not_raised(self):
        """An unknown *mode* is a caller error; an unknown *phase* is not. gate_for,
        roster_for and spec_for each answer with a safe default so a caller never has to
        branch on presence, and prereqs_for is the fourth of that family - a retired id
        still quoted in the docs has to yield a generic prompt, not a CLI traceback."""
        self.assertEqual(modes.prereqs_for("balanced", "BL3"), [])
        self.assertEqual(modes.gate_for("BL3"), [])
        self.assertEqual(modes.roster_for("BL3", "balanced"), [])
        self.assertTrue(modes.spec_for("BL3").task)

    def test_removed_modes_are_gone(self):
        for name in ("diff", "confirm", "revisit", "merge", "longshot"):
            with self.assertRaises(KeyError, msg=name):
                modes.phases_for(name)


if __name__ == "__main__":
    unittest.main()
