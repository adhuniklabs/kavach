import glob
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from kavach import dispatch
from kavach.finding import Finding, Location, Severity


class TestDispatch(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_run_id_shape(self):
        rid = dispatch.run_id("DP5", "2026-01-01T00:00:00Z-42", 1)
        self.assertTrue(rid.startswith("DP5-2026-01-01T000000Z-42-a1-"))

    def test_make_run_dir(self):
        d = dispatch.make_run_dir(self.dir, "BL3", "2026x", 1)
        self.assertTrue(os.path.isdir(d))
        self.assertIn(os.path.join("tmp", "runs"), d)

    def test_runtime_header_names_phase_and_paths(self):
        h = dispatch.build_runtime_header("balanced", "BL2", self.dir, "/repo",
                                          ["attack-surface/knowledge-base-report.md"])
        self.assertIn("BL2", h)
        self.assertIn("Architecture & Threat Model", h)
        self.assertIn("knowledge-base-report.md", h)

    def test_result_path_lands_under_runs_and_creates_parent(self):
        p = dispatch.result_path(self.dir, "DP4", "kavach-sast")
        self.assertTrue(os.path.isabs(p))
        self.assertEqual(p, os.path.join(self.dir, "runs", "dp4", "kavach-sast.json"))
        self.assertTrue(os.path.isdir(os.path.dirname(p)))

    def test_result_path_index_distinguishes_fanout_dispatches(self):
        a = dispatch.result_path(self.dir, "DP4", "kavach-sast", index=1)
        b = dispatch.result_path(self.dir, "DP4", "kavach-sast", index=2)
        self.assertNotEqual(a, b)
        self.assertTrue(a.endswith(os.path.join("dp4", "kavach-sast-1.json")))

    def test_result_path_slugs_agent_and_phase(self):
        p = dispatch.result_path(self.dir, "RV10k", "core:render")
        self.assertEqual(p, os.path.join(self.dir, "runs", "rv10k", "core-render.json"))

    def test_result_path_cannot_escape_the_runs_dir(self):
        p = dispatch.result_path(self.dir, "../..", "../../../etc/passwd")
        self.assertTrue(p.startswith(os.path.join(self.dir, "runs") + os.sep))

    def test_result_glob_matches_written_results(self):
        for agent in ("kavach-api", "kavach-state"):
            with open(dispatch.result_path(self.dir, "DP5", agent), "w") as fh:
                fh.write("{}")
        self.assertEqual(len(glob.glob(dispatch.result_glob(self.dir, "DP5"))), 2)

    def test_result_glob_agrees_with_result_path(self):
        self.assertEqual(os.path.dirname(dispatch.result_glob(self.dir, "BL3")),
                         os.path.dirname(dispatch.result_path(self.dir, "BL3", "kavach-sast")))

    def test_runtime_header_names_the_exact_result_path(self):
        h = dispatch.build_runtime_header("deep", "DP4", self.dir, "/repo", [])
        expected = dispatch.result_path(self.dir, "DP4", "kavach-sast")
        self.assertIn("- Write your machine result to exactly this path (create no other "
                      "file at the audit root):", h)
        self.assertIn(f"\n  {expected}\n", h)

    def test_runtime_header_honours_explicit_agent_and_index(self):
        h = dispatch.build_runtime_header("longshot", "LS2", self.dir, "/repo", [],
                                          agent="kavach-longshot-hunter", index=7)
        self.assertIn(os.path.join("runs", "ls2", "kavach-longshot-hunter-7.json"), h)

    def test_runtime_header_omits_result_line_for_core_phases(self):
        h = dispatch.build_runtime_header("deep", "DP17", self.dir, "/repo", [])
        self.assertNotIn("Write your machine result", h)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "runs", "dp17")))

    def test_compose_prompt_forwards_agent_and_index(self):
        p = dispatch.compose_prompt("deep", "DP4", "body", self.dir, "/repo", [],
                                    agent="kavach-sast", index=3)
        self.assertIn(os.path.join("runs", "dp4", "kavach-sast-3.json"), p)
        self.assertIn("body", p)

    def test_ingest_folds_agent_json_to_drafts(self):
        f = Finding(title="SQLi", severity=Severity.CRITICAL, category="A01", source="kavach-sast",
                    locations=[Location(file="a.py", line=1)])
        agent_json = os.path.join(self.dir, "agent-sast.json")
        json.dump({"findings": [f.to_dict()]}, open(agent_json, "w"))
        n = dispatch.ingest(self.dir, "BL3", agent_json)
        self.assertEqual(n, 1)
        drafts = os.listdir(os.path.join(self.dir, "findings-draft"))
        self.assertTrue(any(d.startswith("bl3-001-") for d in drafts))

    def test_ingest_twice_appends_without_overwrite(self):
        f = Finding(title="SQLi", severity=Severity.CRITICAL, category="A01", source="kavach-sast",
                    locations=[Location(file="a.py", line=1)])
        agent_json = os.path.join(self.dir, "agent-sast.json")
        json.dump({"findings": [f.to_dict()]}, open(agent_json, "w"))

        dispatch.ingest(self.dir, "BL3", agent_json)
        dispatch.ingest(self.dir, "BL3", agent_json)

        drafts = os.listdir(os.path.join(self.dir, "findings-draft"))
        self.assertEqual(len(drafts), 2)
        self.assertTrue(any(d.startswith("bl3-001-") for d in drafts))
        self.assertTrue(any(d.startswith("bl3-002-") for d in drafts))

    def test_concurrent_ingest_same_phase_does_not_collide_draft_numbers(self):
        # Widen the race window inside the locked section: without the lock in ingest(),
        # two threads both read the same next-draft-number before either writes, and the
        # second write's draft(s) overwrite the first's.
        real_next = dispatch._next_draft_number

        def _slow_next(audit_dir, prefix):
            n = real_next(audit_dir, prefix)
            threading.Event().wait(0.02)
            return n

        results: dict[int, int] = {}

        def _run(i: int) -> None:
            f = Finding(title=f"F{i}", severity=Severity.CRITICAL, category="A01",
                       source="s", locations=[Location(file=f"{i}.py", line=1)])
            agent_json = os.path.join(self.dir, f"agent-{i}.json")
            with open(agent_json, "w", encoding="utf-8") as fh:
                json.dump({"findings": [f.to_dict()]}, fh)
            results[i] = dispatch.ingest(self.dir, "BL3", agent_json)

        with patch.object(dispatch, "_next_draft_number", side_effect=_slow_next):
            threads = [threading.Thread(target=_run, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        self.assertTrue(all(n == 1 for n in results.values()))
        drafts = os.listdir(os.path.join(self.dir, "findings-draft"))
        self.assertEqual(len(drafts), 5)  # every thread's draft survived, none overwritten


if __name__ == "__main__":
    unittest.main()
