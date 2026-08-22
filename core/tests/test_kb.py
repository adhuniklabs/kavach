import json
import os
import tempfile
import threading
import unittest

from kavach import kb


class TestKB(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_write_section_creates_under_attack_surface(self):
        p = kb.write_section(self.dir, "knowledge-base-report.md", "Architecture Model", "single service")
        self.assertTrue(p.endswith(os.path.join("attack-surface", "knowledge-base-report.md")))
        with open(p, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("## Architecture Model", body)
        self.assertIn("single service", body)

    def test_kill_chains_render_leaf_verdicts(self):
        p = kb.write_kill_chains(self.dir, [{
            "letter": "c", "goal": "Bypass the billing wall", "verdict": "EXPLOITABLE",
            "leaves": [{"technique": "client-trusted price", "status": "EXPLOITABLE", "ref": "C1"}],
        }])
        with open(p, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("Bypass the billing wall", body)
        self.assertIn("EXPLOITABLE", body)

    def test_update_target_status_atomic(self):
        sidecar = os.path.join(self.dir, "attack-surface", "longshot-targets.json")
        os.makedirs(os.path.dirname(sidecar), exist_ok=True)
        targets = [{"id": f"t{i}", "status": "pending"} for i in range(10)]
        json.dump({"targets": targets}, open(sidecar, "w"))

        threads = [
            threading.Thread(target=kb.update_target_status, args=(self.dir, f"t{i}", "complete"))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        got = json.load(open(sidecar))
        statuses = {t["id"]: t["status"] for t in got["targets"]}
        self.assertEqual(len(statuses), 10)
        self.assertTrue(all(s == "complete" for s in statuses.values()))


if __name__ == "__main__":
    unittest.main()
