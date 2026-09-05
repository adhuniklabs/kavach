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


def _json_artifact(audit_dir, name, payload):
    """The attack-surface/ half kb.write_section does not cover: a JSON gate artifact."""
    d = os.path.join(audit_dir, "attack-surface")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def _stub_finding(title="SQLi in find_user"):
    return Finding(title=title, severity=Severity.CRITICAL, category="A03:Injection",
                   source="kavach-sast", locations=[Location(file="app.py", line=10)],
                   what_it_is="x" * 200, how_exploited="x" * 200,
                   business_impact="x" * 200, remediation="x" * 200)


def _stub_sweep(audit_dir):
    dump_findings([], os.path.join(audit_dir, "findings.json"))
    with open(os.path.join(audit_dir, "sweep-summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"scanners_run": [], "unavailable": [], "total_findings": 0}, fh)


class TestLiteModeSmoke(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_lite_mode_plan_ingest_consolidate_cleanup(self):
        state.init_audit(self.dir, "lite", modes.phases_for("lite"), repository="o/r")
        self.assertEqual(runner.next_actionable(self.dir, "lite")[0], "recon")

        # recon core:recon - pure-Python, safe to run for real
        recon, files = run_recon(FIXTURE)
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            json.dump(recon, fh)
        with open(os.path.join(self.dir, "file-manifest.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(files))
        self.assertNotIn("recon", runner.next_actionable(self.dir, "lite"))

        # sweep core:sweep - stubbed summary, no docker/network dependency in a smoke test
        _stub_sweep(self.dir)
        self.assertNotIn("sweep", runner.next_actionable(self.dir, "lite"))

        # hunt kavach-sast - stubbed subagent output, ingested through the real engine seam.
        # lite's roster is the single agent that owns the gate, so the artifact closes it.
        stub = _stub_finding()
        agent_json = os.path.join(self.dir, "agent-sast.json")
        dump_findings([stub], agent_json)
        dispatch.ingest(self.dir, "hunt", agent_json)
        kb.write_section(self.dir, "source-sink-flows-all-severities.md", "Source-Sink Flows",
                         "Stubbed SAST pass.")
        self.assertNotIn("hunt", runner.next_actionable(self.dir, "lite"))

        # poc kavach-poc + consolidate - promotes the stub finding, then the PoC coverage
        # artifact proves the per-finding work actually happened
        promoted = findings_tree.consolidate(self.dir, [stub])
        coverage.write_coverage(self.dir, "poc")
        self.assertIn("poc", runner.next_actionable(self.dir, "lite"))   # promoted, no PoC yet
        _satisfy_per_finding_work(self.dir, promoted)
        coverage.write_coverage(self.dir, "poc")
        self.assertNotIn("poc", runner.next_actionable(self.dir, "lite"))

        # render core:render - the deterministic pass lite used to stop one step short of
        os.makedirs(os.path.join(self.dir, "reports"), exist_ok=True)
        with open(os.path.join(self.dir, "reports", "final-audit-report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("# KAVACH Final Audit Report\n\n" + "x" * 600)
        self.assertNotIn("render", runner.next_actionable(self.dir, "lite"))

        # cleanup core:cleanup
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
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "recon")

        recon, _ = run_recon(FIXTURE)
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            json.dump(recon, fh)
        self.assertNotIn("recon", runner.next_actionable(self.dir, "balanced"))

        _stub_sweep(self.dir)
        self.assertNotIn("sweep", runner.next_actionable(self.dir, "balanced"))

        _json_artifact(self.dir, "intent-corpus.json", {"behaviors": [], "risks": []})
        self.assertNotIn("intent", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "advisory-summary.md", "Advisories", "stubbed - none found")
        self.assertNotIn("intel", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "knowledge-base-report.md", "Architecture Model", "single service")
        self.assertNotIn("kb", runner.next_actionable(self.dir, "balanced"))

        stub = _stub_finding()
        agent_json = os.path.join(self.dir, "agent-sast.json")
        dump_findings([stub], agent_json)
        dispatch.ingest(self.dir, "hunt", agent_json)
        kb.write_section(self.dir, "source-sink-flows-all-severities.md", "Source-Sink Flows", "Stubbed.")
        # balanced fans hunt out to eight hunters that share one gate artifact, so the
        # artifact alone no longer closes it — every hunter needs a result. See
        # runner.fanout_pending.
        self.assertIn("hunt", runner.next_actionable(self.dir, "balanced"))
        for i, name in enumerate(modes.roster_for("hunt", "balanced"), start=1):
            dump_findings([stub], dispatch.result_path(self.dir, "hunt", name, index=i))
        self.assertNotIn("hunt", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "probe-summary.md", "Manual Attack Surface", "Stubbed.")
        self.assertNotIn("probe", runner.next_actionable(self.dir, "balanced"))

        kb.write_section(self.dir, "chamber-summary.md", "Chamber Summary",
                         "Stubbed - no false positives found.")
        self.assertNotIn("chamber", runner.next_actionable(self.dir, "balanced"))

        _json_artifact(self.dir, "intent-crosscheck.json", {"findings": []})
        self.assertNotIn("crosscheck", runner.next_actionable(self.dir, "balanced"))

        # poc/report (PoC + report drafting) each gate on their own coverage artifact, so
        # promotion alone no longer closes them
        promoted = findings_tree.consolidate(self.dir, [stub])
        _satisfy_per_finding_work(self.dir, promoted)
        coverage.write_coverage(self.dir, "poc")
        coverage.write_coverage(self.dir, "report")
        self.assertNotIn("poc", runner.next_actionable(self.dir, "balanced"))
        self.assertNotIn("report", runner.next_actionable(self.dir, "balanced"))

        with open(os.path.join(self.dir, "final-audit-report.md"), "w", encoding="utf-8") as fh:
            fh.write("# KAVACH Final Audit Report\n\n" + "x" * 600)
        self.assertNotIn("render", runner.next_actionable(self.dir, "balanced"))

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


class TestCleanupGateSurvivesCleanup(unittest.TestCase):
    """The cleanup gate used to be confirm-workspace/cleanup-summary.json - a file its own
    core:cleanup step deletes and never wrote in the first place, so confirm mode could not
    finish. The durable artifact cleanup() already writes is the honest gate, and the one
    `cleanup` phase the three presets share now carries it."""

    def test_cleanup_gates_on_a_durable_artifact_cleanup_writes(self):
        root = posixpath.normpath(modes.gate_for("cleanup")[0]).split("/")[0]
        self.assertNotIn(root, cleanup.TRANSIENT)
        d = tempfile.mkdtemp()
        cleanup.cleanup(d, "lite")
        self.assertTrue(runner.gate_satisfied(d, "cleanup"))


if __name__ == "__main__":
    unittest.main()
