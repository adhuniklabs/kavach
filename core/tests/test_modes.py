import posixpath
import unittest

from kavach import cleanup, modes


class TestModes(unittest.TestCase):
    def test_three_modes(self):
        self.assertEqual(set(modes.MODES), {"lite", "balanced", "deep"})

    def test_removed_modes_are_gone(self):
        for name in ("diff", "confirm", "revisit", "merge", "longshot"):
            with self.assertRaises(KeyError, msg=name):
                modes.phases_for(name)

    def test_balanced_phase_order(self):
        self.assertEqual(
            modes.phases_for("balanced"),
            ["BL1", "BL2", "BL3", "BL4", "BL5", "BL6", "BL6b", "BL6c", "BL7"],
        )

    def test_deep_has_seventeen_phases(self):
        self.assertEqual(len(modes.phases_for("deep")), 17)
        self.assertEqual(modes.phases_for("deep")[0], "DP1")
        self.assertEqual(modes.phases_for("deep")[-1], "DP17")

    def test_deep_prereq_dag(self):
        self.assertEqual(modes.prereqs_for("deep", "DP4"), ["DP3"])
        self.assertEqual(set(modes.prereqs_for("deep", "DP10")),
                         {"DP5", "DP6", "DP7", "DP8", "DP9"})
        self.assertEqual(modes.prereqs_for("deep", "DP1"), [])

    def test_every_phase_has_label_and_agent(self):
        for mode in modes.MODES:
            for phase in modes.phases_for(mode):
                self.assertIn(phase, modes.PHASE_LABELS, f"{phase} missing label")
                self.assertIn(phase, modes.PHASE_AGENT, f"{phase} missing agent")

    def test_gate_globs_are_lists(self):
        self.assertIsInstance(modes.gate_for("BL6c"), list)
        self.assertTrue(any("final-audit-report" in g for g in modes.gate_for("BL6c")))

    def test_no_gate_under_transient(self):
        """The invariant whose absence let DP10/DP11 gate on tmp/: a gate that cleanup
        deletes makes its phase eligible again on every resume, so the run pays for the
        same fan-out twice."""
        for mode in modes.MODES:
            for phase in modes.phases_for(mode):
                for pat in modes.gate_for(phase):
                    root = posixpath.normpath(pat).split("/")[0]
                    self.assertNotIn(root, cleanup.TRANSIENT,
                                     f"{mode}/{phase} gates on transient {pat!r}")

    def test_per_finding_phases_gate_on_coverage_not_on_the_directory(self):
        for phase in ("LT3", "BL6", "DP13"):
            self.assertEqual(modes.gate_for(phase), ["attack-surface/poc-coverage.json"], phase)
        for phase in ("BL6b", "DP14"):
            self.assertEqual(modes.gate_for(phase), ["attack-surface/report-coverage.json"], phase)

    def test_unknown_mode_raises(self):
        with self.assertRaises(KeyError):
            modes.phases_for("nope")


if __name__ == "__main__":
    unittest.main()
