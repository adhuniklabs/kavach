import json
import os
import tempfile
import threading
import unittest

from kavach import runner, state
from kavach.state import PhaseStatus


def _touch(audit_dir, rel, content="x" * 600):
    path = os.path.join(audit_dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.run = state.init_audit(self.dir, "balanced",
                                    ["BL1", "BL2", "BL3", "BL4", "BL5", "BL6", "BL6b", "BL6c", "BL7"],
                                    repository="o/r")

    def test_next_actionable_is_first_when_nothing_done(self):
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "BL1")

    def test_gate_satisfied_by_artifact(self):
        self.assertFalse(runner.gate_satisfied(self.dir, "BL1"))
        _touch(self.dir, "attack-surface/advisory-summary.md")
        self.assertTrue(runner.gate_satisfied(self.dir, "BL1"))

    def test_report_gate_needs_size(self):
        _touch(self.dir, "final-audit-report.md", content="tiny")
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6c"))
        _touch(self.dir, "final-audit-report.md", content="x" * 600)
        self.assertTrue(runner.gate_satisfied(self.dir, "BL6c"))

    def test_coverage_gate_needs_complete_true(self):
        def _coverage(complete, missing=()):
            _touch(self.dir, "attack-surface/poc-coverage.json",
                   content=json.dumps({"kind": "poc", "complete": complete, "total": 1,
                                       "satisfied": int(complete), "aggregates_exempt": 0,
                                       "missing": list(missing)}))

        self.assertFalse(runner.gate_satisfied(self.dir, "BL6"))
        _coverage(False, [{"display_id": "H1", "dir": "findings/H1-idor", "reason": "no poc.*"}])
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6"))   # the file alone is not enough
        _coverage(True)
        self.assertTrue(runner.gate_satisfied(self.dir, "BL6"))

    def test_unparseable_coverage_artifact_does_not_gate(self):
        _touch(self.dir, "attack-surface/poc-coverage.json", content="{truncated")
        self.assertFalse(runner.gate_satisfied(self.dir, "BL6"))

    def test_satisfied_phase_drops_out_of_actionable(self):
        _touch(self.dir, "attack-surface/advisory-summary.md")
        self.assertNotIn("BL1", runner.next_actionable(self.dir, "balanced"))
        self.assertEqual(runner.next_actionable(self.dir, "balanced")[0], "BL2")

    def test_ensure_prereqs_blocks_out_of_order(self):
        with self.assertRaises(runner.PrereqError):
            runner.ensure_prereqs(self.dir, "deep", "DP10")

    def test_record_attempt_persists_backoff(self):
        n = runner.record_attempt(self.dir, self.run.audit_id, "BL1", "network flaked")
        self.assertEqual(n, 1)
        ph = state.load_state(self.dir).audits[0].phases["BL1"]
        self.assertEqual(ph.last_error, "network flaked")
        self.assertEqual(ph.retry_backoff_ms, 5000)

    def test_record_attempt_no_lost_updates_under_concurrency(self):
        threads = [
            threading.Thread(target=runner.record_attempt,
                             args=(self.dir, self.run.audit_id, "BL1", "network flaked"))
            for _ in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ph = state.load_state(self.dir).audits[0].phases["BL1"]
        self.assertEqual(ph.attempt, 10)


if __name__ == "__main__":
    unittest.main()
