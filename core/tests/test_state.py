import json
import os
import tempfile
import unittest

from kavach import state
from kavach.state import PhaseStatus, RunStatus


class TestState(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_init_seeds_pending_phases(self):
        run = state.init_audit(self.dir, "balanced", ["intel", "kb"], repository="o/r")
        self.assertEqual(run.mode, "balanced")
        self.assertEqual(run.status, RunStatus.IN_PROGRESS)
        self.assertEqual(set(run.phases), {"intel", "kb"})
        self.assertEqual(run.phases["intel"].status, PhaseStatus.PENDING)

    def test_state_persists_and_reloads(self):
        state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        reloaded = state.load_state(self.dir)
        self.assertEqual(len(reloaded.audits), 1)
        self.assertEqual(reloaded.audits[0].phases["intel"].status, PhaseStatus.PENDING)

    def test_set_phase_complete_stamps_and_clears_retry(self):
        run = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        state.set_phase_status(self.dir, run.audit_id, "intel", PhaseStatus.FAILED,
                               attempt=2, last_error="boom")
        state.set_phase_status(self.dir, run.audit_id, "intel", PhaseStatus.COMPLETE,
                               artifacts=["final-audit-report.md"])
        ph = state.load_state(self.dir).audits[0].phases["intel"]
        self.assertEqual(ph.status, PhaseStatus.COMPLETE)
        self.assertIsNotNone(ph.completed_at)
        self.assertIsNone(ph.last_error)          # transient wiped on complete
        self.assertEqual(ph.artifacts, ["final-audit-report.md"])

    def test_atomic_write_no_partial_file(self):
        run = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        with open(state.state_path(self.dir), encoding="utf-8") as fh:
            json.load(fh)  # must parse - proves no partial write

    def test_corrupt_state_moved_aside(self):
        with open(state.state_path(self.dir), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        loaded = state.load_state(self.dir)
        self.assertEqual(loaded.audits, [])
        aside = [f for f in os.listdir(self.dir) if ".corrupt-" in f]
        self.assertEqual(len(aside), 1)

    def test_init_audit_ids_are_unique_and_isolated(self):
        r1 = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        r2 = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        self.assertNotEqual(r1.audit_id, r2.audit_id)
        state.set_phase_status(self.dir, r1.audit_id, "intel", PhaseStatus.COMPLETE)
        audits = {a.audit_id: a for a in state.load_state(self.dir).audits}
        self.assertEqual(audits[r1.audit_id].phases["intel"].status, PhaseStatus.COMPLETE)
        self.assertEqual(audits[r2.audit_id].phases["intel"].status, PhaseStatus.PENDING)

    def test_complete_audit_marks_complete_and_records_commit(self):
        run = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        completed = state.complete_audit(self.dir, "abc123")
        self.assertEqual(completed.audit_id, run.audit_id)
        self.assertEqual(completed.status, RunStatus.COMPLETE)
        self.assertIsNotNone(completed.completed_at)
        self.assertEqual(completed.commit, "abc123")

    def test_complete_audit_no_in_progress_returns_none(self):
        self.assertIsNone(state.complete_audit(self.dir, "abc123"))

    def test_complete_audit_no_commit_leaves_null(self):
        state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        completed = state.complete_audit(self.dir, None)
        self.assertIsNone(completed.commit)

    def test_complete_audit_picks_the_newest_in_progress_run(self):
        old = state.init_audit(self.dir, "balanced", ["intel"], repository="o/r")
        new = state.init_audit(self.dir, "deep", ["intel"], repository="o/r")
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "started_at",
                                                       "2026-08-01T09:00:00Z"))
        state.mutate_state(self.dir, lambda f: setattr(f.audits[1], "started_at",
                                                       "2026-08-20T09:00:00Z"))
        completed = state.complete_audit(self.dir, "abc123")
        self.assertEqual(completed.audit_id, new.audit_id)
        audits = {a.audit_id: a for a in state.load_state(self.dir).audits}
        self.assertEqual(audits[old.audit_id].status, RunStatus.IN_PROGRESS)

    def test_audit_record_carries_a_budget_block(self):
        run = state.init_audit(self.dir, "deep", ["intel"], repository="o/r")
        self.assertEqual(run.budget, {})
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "budget",
                                                       {"max_dispatches": 120}))
        self.assertEqual(state.load_state(self.dir).audits[0].budget["max_dispatches"], 120)

    def test_state_file_written_before_v03_still_loads(self):
        legacy = {"audits": [{
            "audit_id": "2026-08-01T09:00:00Z-1-abcd1234", "mode": "balanced",
            "status": "in_progress", "commit": None, "branch": "nogit", "repository": "o/r",
            "history_available": False, "model": "", "started_at": "2026-08-01T09:00:00Z",
            "completed_at": None, "phases": {"BL1": {"status": "pending"}},
        }]}
        with open(state.state_path(self.dir), "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)
        loaded = state.load_state(self.dir)
        self.assertEqual(loaded.audits[0].budget, {})
        self.assertEqual(loaded.audits[0].phases["BL1"].status, PhaseStatus.PENDING)

    def test_latest_resumable_prefers_in_progress_never_complete(self):
        r1 = state.init_audit(self.dir, "deep", ["intel"], repository="o/r")
        state.set_phase_status(self.dir, r1.audit_id, "intel", PhaseStatus.COMPLETE)
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "status", RunStatus.COMPLETE))
        self.assertIsNone(state.latest_resumable_audit(self.dir))
        r2 = state.init_audit(self.dir, "deep", ["intel", "history"], repository="o/r")
        got = state.latest_resumable_audit(self.dir)
        self.assertEqual(got.audit_id, r2.audit_id)


class TestLatestResumableRecency(unittest.TestCase):
    """Acceptance criterion 5: the shape observed live on the tymewear tree - an
    abandoned balanced run followed by a finished deep run. Before the recency
    comparison, `kavach resume` reopened the balanced run's phases."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _audit(self, audit_id, mode, status, started_at):
        run = state.AuditRunState(audit_id=audit_id, mode=mode, status=status,
                                  started_at=started_at, phases={})
        state.mutate_state(self.dir, lambda f: f.audits.append(run))

    def test_newer_complete_run_beats_an_older_abandoned_one(self):
        self._audit("a", "balanced", RunStatus.IN_PROGRESS.value, "2026-08-19T11:20:00Z")
        self._audit("b", "deep", RunStatus.COMPLETE.value, "2026-08-21T08:05:00Z")
        self.assertIsNone(state.latest_resumable_audit(self.dir))

    def test_mode_scoped_lookup_still_finds_the_abandoned_run(self):
        self._audit("a", "balanced", RunStatus.IN_PROGRESS.value, "2026-08-19T11:20:00Z")
        self._audit("b", "deep", RunStatus.COMPLETE.value, "2026-08-21T08:05:00Z")
        got = state.latest_resumable_audit(self.dir, "balanced")
        self.assertEqual(got.audit_id, "a")

    def test_older_complete_run_does_not_block_a_newer_failure(self):
        self._audit("a", "deep", RunStatus.COMPLETE.value, "2026-08-19T08:00:00Z")
        self._audit("b", "deep", RunStatus.FAILED.value, "2026-08-21T08:00:00Z")
        self.assertEqual(state.latest_resumable_audit(self.dir).audit_id, "b")

    def test_newest_resumable_wins_across_in_progress_and_failed(self):
        self._audit("a", "deep", RunStatus.IN_PROGRESS.value, "2026-08-19T08:00:00Z")
        self._audit("b", "deep", RunStatus.FAILED.value, "2026-08-21T08:00:00Z")
        self.assertEqual(state.latest_resumable_audit(self.dir).audit_id, "b")

    def test_same_second_tie_resolves_to_list_order(self):
        self._audit("a", "deep", RunStatus.COMPLETE.value, "2026-08-21T08:00:00Z")
        self._audit("b", "deep", RunStatus.IN_PROGRESS.value, "2026-08-21T08:00:00Z")
        self.assertEqual(state.latest_resumable_audit(self.dir).audit_id, "b")

    def test_no_resumable_run_at_all(self):
        self._audit("a", "deep", RunStatus.COMPLETE.value, "2026-08-21T08:00:00Z")
        self.assertIsNone(state.latest_resumable_audit(self.dir))


if __name__ == "__main__":
    unittest.main()
