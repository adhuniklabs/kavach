import unittest


class TestEngineImports(unittest.TestCase):
    def test_deps_present(self):
        import yaml  # noqa: F401
        import filelock  # noqa: F401

    def test_modes_module_imports(self):
        from kavach import modes  # noqa: F401
        self.assertIn("balanced", modes.MODES)


class TestBalancedEngineDryRun(unittest.TestCase):
    def test_plan_then_gate_then_consolidate_then_cleanup(self):
        import os, tempfile
        from kavach import state, runner, kb, cleanup, findings_tree
        from kavach.finding import Finding, Location, Severity

        d = tempfile.mkdtemp()
        state.init_audit(d, "balanced", ["BL1", "BL2", "BL6c", "BL7"], repository="o/r")
        self.assertEqual(runner.next_actionable(d, "balanced")[0], "BL1")

        # simulate BL1..BL2 producing their gate artifacts
        kb.write_section(d, "advisory-summary.md", "Advisories", "none")
        kb.write_section(d, "knowledge-base-report.md", "Architecture Model", "single service")
        self.assertNotIn("BL1", runner.next_actionable(d, "balanced"))

        # consolidate a finding + write the final report gate artifact
        findings_tree.consolidate(d, [Finding(
            title="SQLi", severity=Severity.CRITICAL, category="A01", source="kavach-sast",
            locations=[Location(file="a.py", line=1)])])
        with open(os.path.join(d, "final-audit-report.md"), "w") as fh:
            fh.write("KAVACH final report\n" + "x" * 600)
        self.assertTrue(runner.gate_satisfied(d, "BL6c"))

        cleanup.cleanup(d, "balanced")
        self.assertTrue(os.path.isdir(os.path.join(d, "findings")))
        self.assertFalse(os.path.exists(os.path.join(d, "tmp")))


if __name__ == "__main__":
    unittest.main()
