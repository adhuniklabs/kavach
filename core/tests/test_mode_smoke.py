"""Per-mode smoke: drives the engine plan loop with stubbed sub-agent outputs (no live
model calls) and proves each mode plans -> ingests -> consolidates -> gates -> cleans.
"""

import json
import os
import posixpath
import tempfile
import unittest

from kavach import (cleanup, coverage, dispatch, findings_tree, kb, modes, report_finding,
                    runner, state)
from kavach.finding import Finding, Location, Severity, dump_findings
from kavach.recon import run_recon

FIXTURE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "corpus", "fixtures", "mode-smoke")


def _satisfy_per_finding_work(audit_dir, promoted):
    """Stand in for kavach-poc + kavach-reporter: every promoted dir gets a PoC and a
    contract-passing report, which is what the coverage gates now demand."""
    for fdir in promoted:
        with open(os.path.join(fdir, "poc.theoretical.md"), "w", encoding="utf-8") as fh:
            fh.write("# Theoretical PoC\n\nStubbed by the smoke test.\n")
        report_finding.write_report(fdir, _stub_finding())


def _stub_finding(title="SQLi in find_user"):
    return Finding(title=title, severity=Severity.CRITICAL, category="A03:Injection",
                   source="kavach-sast", locations=[Location(file="app.py", line=10)],
                   what_it_is="x" * 200, how_exploited="x" * 200,
                   business_impact="x" * 200, remediation="x" * 200)


class TestLiteModeSmoke(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_lite_mode_plan_ingest_consolidate_cleanup(self):
        state.init_audit(self.dir, "lite", modes.phases_for("lite"), repository="o/r")
        self.assertEqual(runner.next_actionable(self.dir, "lite")[0], "LT0")

        # LT0 core:recon - pure-Python, safe to run for real
        recon, files = run_recon(FIXTURE)
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            json.dump(recon, fh)
        with open(os.path.join(self.dir, "file-manifest.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(files))
        self.assertNotIn("LT0", runner.next_actionable(self.dir, "lite"))

        # LT1 core:sweep - stubbed summary, no docker/network dependency in a smoke test
        dump_findings([], os.path.join(self.dir, "findings.json"))
        with open(os.path.join(self.dir, "sweep-summary.json"), "w", encoding="utf-8") as fh:
            json.dump({"scanners_run": [], "unavailable": [], "total_findings": 0}, fh)
        self.assertNotIn("LT1", runner.next_actionable(self.dir, "lite"))

        # LT2 kavach-sast - stubbed subagent output, ingested through the real engine seam
        stub = _stub_finding()
        agent_json = os.path.join(self.dir, "agent-sast.json")
        dump_findings([stub], agent_json)
        dispatch.ingest(self.dir, "LT2", agent_json)
        kb.write_section(self.dir, "lite-q2-summary.md", "Lite Q2 Summary", "Stubbed SAST pass.")
        self.assertNotIn("LT2", runner.next_actionable(self.dir, "lite"))

        # LT3 kavach-poc + consolidate - promotes the stub finding, then the PoC coverage
        # artifact proves the per-finding work actually happened
        promoted = findings_tree.consolidate(self.dir, [stub])
        coverage.write_coverage(self.dir, "poc")
        self.assertIn("LT3", runner.next_actionable(self.dir, "lite"))   # promoted, no PoC yet
        _satisfy_per_finding_work(self.dir, promoted)
        coverage.write_coverage(self.dir, "poc")
        self.assertNotIn("LT3", runner.next_actionable(self.dir, "lite"))

        # LT4 core:cleanup
        cleanup.cleanup(self.dir, "lite")
        self.assertEqual(runner.next_actionable(self.dir, "lite"), [])
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "tmp")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "findings-draft")))


class TestBalancedModeSmoke(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_balanced_mode_plan_ingest_consolidate_cleanup(self):
        state.init_audit(self.dir, "balanced", modes.phases_for("balanced"), repository="o/r")
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "BL1")

        recon, _ = run_recon(FIXTURE)
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            json.dump(recon, fh)

        kb.write_section(self.dir, "advisory-summary.md", "Advisories", "stubbed - none found")
        self.assertNotIn("BL1", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "knowledge-base-report.md", "Architecture Model", "single service")
        self.assertNotIn("BL2", runner.next_actionable(self.dir, "balanced"))

        stub = _stub_finding()
        agent_json = os.path.join(self.dir, "agent-sast.json")
        dump_findings([stub], agent_json)
        dispatch.ingest(self.dir, "BL3", agent_json)
        kb.write_section(self.dir, "source-sink-flows-all-severities.md", "Source-Sink Flows", "Stubbed.")
        # BL3 fans out to eight hunters that share one gate artifact, so the artifact
        # alone no longer closes it — every hunter needs a result. See
        # runner.fanout_pending.
        self.assertIn("BL3", runner.next_actionable(self.dir, "balanced"))
        for i, name in enumerate(modes.roster_for("BL3"), start=1):
            dump_findings([stub], dispatch.result_path(self.dir, "BL3", name, index=i))
        self.assertNotIn("BL3", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "manual-attack-surface-inventory.md", "Manual Attack Surface",
                         "Stubbed.")
        self.assertNotIn("BL4", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "balanced-chamber-summary.md", "Chamber Summary",
                         "Stubbed - no false positives found.")
        self.assertNotIn("BL5", runner.next_actionable(self.dir, "balanced"))

        # BL6/BL6b (PoC + report drafting) each gate on their own coverage artifact, so
        # promotion alone no longer closes them
        promoted = findings_tree.consolidate(self.dir, [stub])
        _satisfy_per_finding_work(self.dir, promoted)
        coverage.write_coverage(self.dir, "poc")
        coverage.write_coverage(self.dir, "report")
        self.assertNotIn("BL6", runner.next_actionable(self.dir, "balanced"))
        self.assertNotIn("BL6b", runner.next_actionable(self.dir, "balanced"))

        with open(os.path.join(self.dir, "final-audit-report.md"), "w", encoding="utf-8") as fh:
            fh.write("# KAVACH Final Audit Report\n\n" + "x" * 600)
        self.assertNotIn("BL6c", runner.next_actionable(self.dir, "balanced"))

        cleanup.cleanup(self.dir, "balanced")
        self.assertEqual(runner.next_actionable(self.dir, "balanced"), [])
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "tmp")))


class TestOtherModesPlanAndGatesWire(unittest.TestCase):
    """Lighter smoke for the remaining modes - no stubbing, just proves the plan loop
    resolves a first phase and every phase in the mode has a wired gate. lite/balanced
    get the full stubbed walk above; deep is the only mode left without one."""

    def test_every_other_mode_plans_first_phase_and_has_gates(self):
        for mode in ("deep",):
            d = tempfile.mkdtemp()
            phases = modes.phases_for(mode)
            state.init_audit(d, mode, phases, repository="o/r")
            actionable = runner.next_actionable(d, mode)
            self.assertEqual(actionable[0], phases[0], mode)
            for phase in phases:
                self.assertTrue(modes.gate_for(phase), f"{mode}/{phase} missing gate")


class TestCF7GateSurvivesCleanup(unittest.TestCase):
    """CF7's gate used to be confirm-workspace/cleanup-summary.json - a file its own
    core:cleanup step deletes and never wrote in the first place, so confirm mode could
    not finish. The durable artifact cleanup() already writes is the honest gate.

    CF1-CF7 are orphaned since the mode collapse deleted `confirm` from MODE_PHASES (Task 3
    re-keys them into the --live tail), so this is asserted directly against the registry
    rather than by driving a mode through state/runner."""

    def test_cf7_gates_on_a_durable_artifact_cleanup_writes(self):
        root = posixpath.normpath(modes.gate_for("CF7")[0]).split("/")[0]
        self.assertNotIn(root, cleanup.TRANSIENT)


if __name__ == "__main__":
    unittest.main()
