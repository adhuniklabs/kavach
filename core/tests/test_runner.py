import json
import os
import tempfile
import threading
import unittest

from kavach import dispatch, modes, runner, state
from kavach.state import PhaseStatus


def _touch(audit_dir, rel, content="x" * 600):
    path = os.path.join(audit_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.run = state.init_audit(self.dir, "balanced", modes.phases_for("balanced"),
                                    repository="o/r")

    def test_next_actionable_is_first_when_nothing_done(self):
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "recon")

    def test_gate_satisfied_by_artifact(self):
        self.assertFalse(runner.gate_satisfied(self.dir, "intel"))
        _touch(self.dir, "attack-surface/advisory-summary.md")
        self.assertTrue(runner.gate_satisfied(self.dir, "intel"))

    def test_report_gate_needs_size(self):
        _touch(self.dir, "final-audit-report.md", content="tiny")
        self.assertFalse(runner.gate_satisfied(self.dir, "render"))
        _touch(self.dir, "final-audit-report.md", content="x" * 600)
        self.assertTrue(runner.gate_satisfied(self.dir, "render"))

    def test_coverage_gate_needs_complete_true(self):
        def _coverage(complete, missing=()):
            _touch(self.dir, "attack-surface/poc-coverage.json",
                   content=json.dumps({"kind": "poc", "complete": complete, "total": 1,
                                       "satisfied": int(complete), "aggregates_exempt": 0,
                                       "missing": list(missing)}))

        self.assertFalse(runner.gate_satisfied(self.dir, "poc"))
        _coverage(False, [{"display_id": "H1", "dir": "findings/H1-idor", "reason": "no poc.*"}])
        self.assertFalse(runner.gate_satisfied(self.dir, "poc"))   # the file alone is not enough
        _coverage(True)
        self.assertTrue(runner.gate_satisfied(self.dir, "poc"))

    def test_unparseable_coverage_artifact_does_not_gate(self):
        _touch(self.dir, "attack-surface/poc-coverage.json", content="{truncated")
        self.assertFalse(runner.gate_satisfied(self.dir, "poc"))

    def test_satisfied_phase_drops_out_of_actionable(self):
        _touch(self.dir, "recon.json")
        self.assertNotIn("recon", runner.next_actionable(self.dir, "balanced"))
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "sweep")

    def _reach_hunt(self):
        """sweep and kb closed, and hunt's shared gate written by whichever hunter got home."""
        _touch(self.dir, "recon.json")
        _touch(self.dir, "sweep-summary.json")
        _touch(self.dir, "attack-surface/knowledge-base-report.md")
        _touch(self.dir, "attack-surface/source-sink-flows-all-severities.md")

    def _bank(self, phase, *agents):
        roster = modes.roster_for(phase, "balanced")
        for name in agents:
            path = dispatch.result_path(self.dir, phase, name, index=roster.index(name) + 1)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"domain": name, "controls": {}, "findings": []}, fh)

    def test_fanout_stays_actionable_while_hunters_have_no_result(self):
        # Measured on a real resume: four of hunt's eight hunters failed upstream, one of
        # the four that succeeded wrote the shared gate artifact, and `plan` never
        # offered hunt again. The audit advanced to probe permanently missing half its
        # static analysis, including the 62-lead supply slice.
        self._reach_hunt()
        self._bank("hunt", "kavach-sast", "kavach-api", "kavach-llm", "kavach-billing")
        self.assertTrue(runner.gate_satisfied(self.dir, "hunt"))
        self.assertEqual(
            runner.fanout_pending(self.dir, "hunt", "balanced"),
            ["kavach-crypto", "kavach-supply", "kavach-config", "kavach-logic"],
        )
        self.assertIn("hunt", runner.next_actionable(self.dir, "balanced"))

    def test_fanout_drops_out_once_every_hunter_has_a_result(self):
        self._reach_hunt()
        self._bank("hunt", *modes.roster_for("hunt", "balanced"))
        self.assertEqual(runner.fanout_pending(self.dir, "hunt", "balanced"), [])
        self.assertNotIn("hunt", runner.next_actionable(self.dir, "balanced"))

    def test_incomplete_fanout_does_not_block_what_comes_after_it(self):
        # Reported, not blocked: a hunter that can never succeed would otherwise wedge
        # the audit, so hunt is re-planned but probe stays reachable.
        self._reach_hunt()
        self._bank("hunt", "kavach-sast")
        actionable = runner.next_actionable(self.dir, "balanced")
        self.assertIn("hunt", actionable)
        self.assertIn("probe", actionable)

    def test_single_agent_phase_is_never_treated_as_a_fanout(self):
        # intel dispatches one agent and its result carries no index, so asking for a
        # roster diff there would look for a file that is never written.
        self.assertEqual(runner.fanout_pending(self.dir, "intel", "balanced"), [])

    def test_planning_creates_no_run_directories(self):
        runner.next_actionable(self.dir, "balanced")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "runs", "hunt")))

    def test_ensure_prereqs_blocks_out_of_order(self):
        with self.assertRaises(runner.PrereqError):
            runner.ensure_prereqs(self.dir, "deep", "chamber")

    def test_record_attempt_persists_backoff(self):
        n = runner.record_attempt(self.dir, self.run.audit_id, "intel", "network flaked")
        self.assertEqual(n, 1)
        ph = state.load_state(self.dir).audits[0].phases["intel"]
        self.assertEqual(ph.last_error, "network flaked")
        self.assertEqual(ph.retry_backoff_ms, 5000)

    def test_record_attempt_no_lost_updates_under_concurrency(self):
        threads = [
            threading.Thread(target=runner.record_attempt,
                             args=(self.dir, self.run.audit_id, "intel", "network flaked"))
            for _ in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ph = state.load_state(self.dir).audits[0].phases["intel"]
        self.assertEqual(ph.attempt, 10)


if __name__ == "__main__":
    unittest.main()
