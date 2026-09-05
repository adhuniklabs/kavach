import json
import os
import tempfile
import unittest

from filelock import FileLock

from kavach import cleanup

LOCK = "audit-state.json.lock"   # state._lock_path(audit_dir)


class TestCleanup(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "tmp", "runs", "x"))
        os.makedirs(os.path.join(self.dir, "findings-draft"))
        os.makedirs(os.path.join(self.dir, "live-workspace"))
        os.makedirs(os.path.join(self.dir, "attack-surface"))
        os.makedirs(os.path.join(self.dir, "findings", "C1-x"))
        os.makedirs(os.path.join(self.dir, "reports"))
        os.makedirs(os.path.join(self.dir, "runs", "hunt"))
        open(os.path.join(self.dir, "final-audit-report.md"), "w").write("x")

    def _write(self, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x")
        return path

    def test_cleanup_removes_transient_keeps_durable(self):
        summary = cleanup.cleanup(self.dir, "balanced")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "tmp")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "findings-draft")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "live-workspace")))
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings", "C1-x")))
        self.assertTrue(os.path.exists(os.path.join(self.dir, "final-audit-report.md")))
        self.assertIn("tmp", summary["removed"][0] if summary["removed"] else "")

    def test_summary_written(self):
        cleanup.cleanup(self.dir, "balanced")
        p = os.path.join(self.dir, "attack-surface", "cleanup-summary.json")
        self.assertTrue(os.path.exists(p))
        # The filename is mode-independent - one `cleanup` phase, one gate string across
        # three presets - so the mode it ran for is carried in the payload instead.
        self.assertEqual(json.load(open(p))["mode"], "balanced")

    def test_reports_and_runs_are_durable(self):
        summary = cleanup.cleanup(self.dir, "deep")
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "reports")))
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "runs", "hunt")))
        self.assertIn("reports", summary["retained"])
        self.assertIn("runs", summary["retained"])

    def test_final_audit_report_stays_at_the_root(self):
        # `render` gates on .kavach/final-audit-report.md; moving it is the integrator's
        # job, not cleanup's.
        cleanup.cleanup(self.dir, "balanced")
        self.assertTrue(os.path.exists(os.path.join(self.dir, "final-audit-report.md")))

    def test_stale_state_lock_removed(self):
        self._write(LOCK)
        summary = cleanup.cleanup(self.dir, "balanced")
        self.assertFalse(os.path.exists(os.path.join(self.dir, LOCK)))
        self.assertIn(LOCK, summary["removed"])

    def test_held_state_lock_survives(self):
        lock = FileLock(os.path.join(self.dir, LOCK))
        lock.acquire()
        try:
            summary = cleanup.cleanup(self.dir, "balanced")
        finally:
            lock.release()
        self.assertTrue(os.path.exists(os.path.join(self.dir, LOCK)))
        self.assertNotIn(LOCK, summary["removed"])
        self.assertNotIn(LOCK, summary["unexpected"])

    def test_unexpected_reports_invented_root_files(self):
        self._write("findings.raw-backup.json")
        self._write("agent-lead.json")
        self._write("findings-baseline-abc123.json")
        summary = cleanup.cleanup(self.dir, "deep")
        self.assertEqual(summary["unexpected"], ["findings.raw-backup.json"])

    def test_unexpected_files_are_never_deleted(self):
        path = self._write("findings.raw-backup.json")
        cleanup.cleanup(self.dir, "deep")
        self.assertTrue(os.path.exists(path))

    def test_unexpected_ignores_durable_transient_and_dirs(self):
        self._write("controls.json")
        os.makedirs(os.path.join(self.dir, "findings-deferred"))
        os.makedirs(os.path.join(self.dir, "some-invented-dir"))
        summary = cleanup.cleanup(self.dir, "deep")
        self.assertEqual(summary["unexpected"], [])


if __name__ == "__main__":
    unittest.main()
