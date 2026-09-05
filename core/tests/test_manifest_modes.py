import json
import os
import unittest

from kavach import modes

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestManifestModes(unittest.TestCase):
    def test_manifest_advertises_exactly_the_engine_modes(self):
        """The manifest advertised six modes against an engine that had eight, so two were
        reachable and undocumented. Keep the two in step."""
        with open(os.path.join(ROOT, "karya-module.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual([m["id"] for m in manifest["modes"]], list(modes.MODES))

    def test_exactly_one_default_mode(self):
        with open(os.path.join(ROOT, "karya-module.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        defaults = [m["id"] for m in manifest["modes"] if m.get("default")]
        self.assertEqual(defaults, ["balanced"])


if __name__ == "__main__":
    unittest.main()
