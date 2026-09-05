"""The .kavach layout contract: the filename the engine hands a sub-agent is the one the
engine later collects, and cleanup keeps it. Root cause 6 of the 2026-08-21 audit.
"""

import glob
import json
import os
import tempfile
import unittest

from kavach import cleanup, dispatch, modes
from kavach.finding import Finding, Location, Severity

SUBAGENT_PHASES = [(m, p) for m, phases in modes.MODE_PHASES.items() for p in phases
                   if not modes.PHASE_AGENT.get(p, "core:none").startswith("core:")]


class TestLayout(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _stub(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)

    def test_durable_and_transient_are_disjoint(self):
        self.assertEqual(set(cleanup.DURABLE) & set(cleanup.TRANSIENT), set())

    def test_runs_and_reports_are_durable(self):
        self.assertIn("runs", cleanup.DURABLE)
        self.assertIn("reports", cleanup.DURABLE)

    def test_every_subagent_phase_lands_two_levels_under_runs(self):
        for _, phase in SUBAGENT_PHASES:
            p = dispatch.result_path(self.dir, phase, modes.PHASE_AGENT[phase])
            self.assertEqual(os.path.dirname(os.path.dirname(p)),
                             os.path.join(self.dir, "runs"))

    def test_result_paths_are_unique_per_phase(self):
        paths = [dispatch.result_path(self.dir, p, modes.PHASE_AGENT[p])
                 for _, p in SUBAGENT_PHASES]
        self.assertEqual(len(set(paths)), len(paths))

    def test_engine_named_results_survive_cleanup_and_look_expected(self):
        for _, phase in SUBAGENT_PHASES:
            self._stub(dispatch.result_path(self.dir, phase, modes.PHASE_AGENT[phase]))
        summary = cleanup.cleanup(self.dir, "deep")
        self.assertEqual(summary["unexpected"], [])
        for _, phase in SUBAGENT_PHASES:
            self.assertTrue(os.path.exists(
                dispatch.result_path(self.dir, phase, modes.PHASE_AGENT[phase])))

    def test_header_names_the_path_result_glob_will_find(self):
        header = dispatch.build_runtime_header("deep", "DP4", self.dir, "/repo", [])
        named = header.split("audit root):\n")[1].splitlines()[0].strip()
        self._stub(named)
        self.assertEqual(glob.glob(dispatch.result_glob(self.dir, "DP4")), [named])

    def test_fanout_results_share_one_phase_dir(self):
        paths = [dispatch.result_path(self.dir, "BL3", "kavach-billing", index=i)
                 for i in range(1, 9)]
        for p in paths:
            self._stub(p)
        self.assertEqual(sorted(glob.glob(dispatch.result_glob(self.dir, "BL3"))),
                         sorted(paths))

    def test_result_glob_does_not_leak_across_phases(self):
        self._stub(dispatch.result_path(self.dir, "DP4", "kavach-sast"))
        self._stub(dispatch.result_path(self.dir, "DP5", "kavach-api"))
        self.assertEqual(len(glob.glob(dispatch.result_glob(self.dir, "DP4"))), 1)

    def test_ingest_reads_a_result_written_at_result_path(self):
        f = Finding(title="SQLi", severity=Severity.CRITICAL, category="A01",
                    source="kavach-sast", locations=[Location(file="a.py", line=1)])
        path = dispatch.result_path(self.dir, "BL3", "kavach-sast", index=1)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [f.to_dict()]}, fh)
        self.assertEqual(dispatch.ingest(self.dir, "BL3", path), (1, 0))

    def test_audited_root_sprawl_is_reported_not_deleted(self):
        # The four files the 2026-08-21 deep run invented at the audit root. agent-*.json
        # is the one legacy name the engine still recognises; the backup is not.
        sprawl = ("findings.raw-backup.json", "agent-lead.json", "agent-lead2.json",
                  "agent-verify-dp4-009.json")
        for name in sprawl:
            self._stub(os.path.join(self.dir, name))
        summary = cleanup.cleanup(self.dir, "deep")
        self.assertEqual(summary["unexpected"], ["findings.raw-backup.json"])
        for name in sprawl:
            self.assertTrue(os.path.exists(os.path.join(self.dir, name)))


if __name__ == "__main__":
    unittest.main()
