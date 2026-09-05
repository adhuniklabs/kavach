import glob, os, re, unittest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PHASE_DECL = re.compile(r"\b[PLQVRMX]\d{1,2}\b")  # piolium-style ids must not appear


class TestAgentsLoad(unittest.TestCase):
    def _frontmatter(self, path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(text.startswith("---\n"), f"{path}: no frontmatter")
        _, fm, body = text.split("---\n", 2)
        return yaml.safe_load(fm), body

    def test_agents_parse_and_declare_name(self):
        for path in glob.glob(os.path.join(ROOT, "agents", "kavach-*.md")):
            fm, _ = self._frontmatter(path)
            self.assertIn("name", fm, path)
            self.assertIn("description", fm, path)

    def test_skills_parse(self):
        for path in glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md")):
            fm, _ = self._frontmatter(path)
            self.assertIn("name", fm, path)

    def test_model_tiering_is_applied_and_not_all_inherit(self):
        """§2 A6: all 40 agents were `model: inherit`, so on an Opus session every one of
        ~800 deep-mode dispatches was Opus. sonnet = mechanical, bounded, single-artifact;
        haiku = one label on one summary; inherit = judgement."""
        SONNET = {"kavach-reporter", "kavach-poc", "kavach-intel", "kavach-supply",
                  "kavach-confirm-reporter", "kavach-test-mapper", "kavach-env-detective",
                  "kavach-kb-loader"}
        HAIKU = {"kavach-triager"}
        tiers = {}
        for path in glob.glob(os.path.join(ROOT, "agents", "kavach-*.md")):
            fm, _ = self._frontmatter(path)
            self.assertIn(fm.get("model"), ("inherit", "sonnet", "haiku"), path)
            tiers[fm["name"]] = fm["model"]

        self.assertEqual(len(tiers), 37)
        self.assertEqual({n for n, m in tiers.items() if m == "sonnet"}, SONNET)
        self.assertEqual({n for n, m in tiers.items() if m == "haiku"}, HAIKU)
        # runs live exploits under the confirm charter - the last place to economise
        self.assertEqual(tiers["kavach-poc-executor"], "inherit")

    def test_tier_mirrors_model_so_the_two_cannot_drift(self):
        """`model:` is what Claude Code reads; `tier:` is the same decision spelled so a
        harness on any provider can act on it. Two spellings of one fact drift unless
        something checks - and a drifted tier silently runs a judgement agent on the cheap
        model."""
        from kavach.agentdefs import MODEL_TIER
        for path in glob.glob(os.path.join(ROOT, "agents", "kavach-*.md")):
            fm, _ = self._frontmatter(path)
            self.assertIn("tier", fm, f"{path}: no tier")
            self.assertEqual(fm["tier"], MODEL_TIER[fm["model"]], path)

    def test_no_piolium_phase_ids_in_agents(self):
        for path in glob.glob(os.path.join(ROOT, "agents", "kavach-*.md")):
            _, body = self._frontmatter(path)
            hits = [h for h in PHASE_DECL.findall(body)]
            self.assertEqual(hits, [], f"{path}: piolium phase ids leaked: {hits}")


if __name__ == "__main__":
    unittest.main()
