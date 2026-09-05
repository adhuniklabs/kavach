"""What decides which files an audit spends its budget on."""

import json
import os
import tempfile
import unittest

from kavach import dispatch, modes, scoping


class TestScoring(unittest.TestCase):
    def test_an_auth_route_outranks_a_plain_helper(self):
        auth, _ = scoping.score("src/api/auth/session.ts")
        helper, _ = scoping.score("src/utils/strings.ts")
        self.assertGreater(auth, helper)

    def test_tests_and_fixtures_rank_below_the_code_they_cover(self):
        real, _ = scoping.score("src/billing/webhook.ts")
        spec, _ = scoping.score("src/billing/__tests__/webhook.test.ts")
        self.assertGreater(real, spec)

    def test_a_dampened_file_is_deprioritised_not_dropped(self):
        """A test file can hold the credential; it just should not be where a hunter starts."""
        ranked = scoping.rank(["src/a.ts", "test/fixtures/keys.ts"])
        self.assertEqual(len(ranked), 2)
        self.assertEqual(ranked[-1]["path"], "test/fixtures/keys.ts")

    def test_domain_signal_reorders_the_same_tree_per_hunter(self):
        files = ["src/billing/checkout.ts", "src/llm/prompt.ts", "src/api/routes.ts"]
        top = lambda a: scoping.rank(files, a)[0]["path"]  # noqa: E731
        self.assertEqual(top("kavach-billing"), "src/billing/checkout.ts")
        self.assertEqual(top("kavach-llm"), "src/llm/prompt.ts")
        self.assertEqual(top("kavach-api"), "src/api/routes.ts")

    def test_an_agent_with_no_domain_map_still_gets_the_generic_ranking(self):
        ranked = scoping.rank(["src/auth/login.ts", "README.md"], "kavach-chamber")
        self.assertEqual(ranked[0]["path"], "src/auth/login.ts")

    def test_signals_are_reported_so_the_ranking_can_be_audited(self):
        _, why = scoping.score("src/api/billing/webhook.ts", "kavach-billing")
        self.assertIn("webhook", why)
        self.assertIn("billing:billing", why)

    def test_non_source_non_config_files_sink(self):
        code, _ = scoping.score("src/app.ts")
        asset, _ = scoping.score("src/app.png")
        self.assertGreater(code, asset)

    def test_config_files_are_ranked_even_though_they_are_not_source(self):
        """Skipping them misses whole finding classes - CORS, debug flags, container root."""
        ranked = scoping.rank(["docker-compose.yml", "src/utils/noop.ts"], "kavach-config")
        self.assertEqual(ranked[0]["path"], "docker-compose.yml")


class TestWriteScope(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, "file-manifest.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join([
                "src/api/auth/session.ts", "src/billing/webhook.ts", "src/utils/strings.ts",
                "test/fixtures/keys.ts", "README.md", "docker-compose.yml",
            ]))

    def test_scope_is_written_ranked_and_capped(self):
        result = scoping.write_scope(self.dir, limit=3)
        self.assertEqual((result["total_files"], result["ranked"]), (6, 3))
        with open(result["path"], encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(len(payload["files"]), 3)
        scores = [f["score"] for f in payload["files"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_the_scope_says_it_is_a_starting_point_not_a_boundary(self):
        result = scoping.write_scope(self.dir)
        with open(result["path"], encoding="utf-8") as fh:
            self.assertIn("not a boundary", json.load(fh)["note"])

    def test_limit_zero_ranks_everything(self):
        self.assertEqual(scoping.write_scope(self.dir, limit=0)["ranked"], 6)

    def test_per_agent_scope_lands_in_its_own_artifact(self):
        result = scoping.write_scope(self.dir, agent="kavach-billing")
        self.assertTrue(result["path"].endswith("scope-kavach-billing.json"))

    def test_missing_manifest_raises_for_the_caller_to_report(self):
        with self.assertRaises(FileNotFoundError):
            scoping.write_scope(tempfile.mkdtemp())

    def test_the_agents_own_scope_wins_over_the_repo_wide_one(self):
        scoping.write_scope(self.dir)
        scoping.write_scope(self.dir, agent="kavach-billing")
        p = dispatch.phase_prompt("balanced", "BL3", self.dir, "/repo", agent="kavach-billing")
        inputs = p.split("Audit inputs:")[1].split("---")[0]
        self.assertIn("scope-kavach-billing.json", inputs)
        self.assertNotIn("scope.json\n", inputs)

    def test_a_hunter_with_no_scope_of_its_own_gets_the_repo_wide_one(self):
        scoping.write_scope(self.dir)
        p = dispatch.phase_prompt("balanced", "BL3", self.dir, "/repo", agent="kavach-llm")
        self.assertIn("scope.json", p.split("Audit inputs:")[1].split("---")[0])


class TestSignalMatching(unittest.TestCase):
    """Both of these were live defects found by running `scope` on a real 25k-file tree."""

    def test_a_short_signal_does_not_match_inside_a_word(self):
        """`ci` inside "dependen*ci*es" put auth/dependencies.py at the top of the config
        hunter's list. A two-letter accident is worse than no ranking at all."""
        self.assertEqual(scoping.domain_hits("app/auth/dependencies.py", "kavach-config"), [])
        self.assertEqual(scoping.domain_hits("src/monkey/keyboard.ts", "kavach-sast"), [])
        self.assertEqual(scoping.domain_hits("src/blocklist.ts", "kavach-logic"), [])
        self.assertEqual(scoping.domain_hits("src/rapid.ts", "kavach-api"), [])

    def test_a_short_signal_still_matches_its_own_token(self):
        self.assertIn("api", scoping.domain_hits("src/api/routes.ts", "kavach-api"))
        self.assertIn("env", scoping.domain_hits("app/env/loader.py", "kavach-config"))

    def test_a_longer_signal_may_prefix_a_token(self):
        self.assertIn("authoriz", scoping.domain_hits("src/authorization/policy.ts", "kavach-api"))
        self.assertIn("deserial", scoping.domain_hits("src/deserializer.py", "kavach-sast"))

    def test_prefix_matching_does_not_dampen_an_innocent_word(self):
        """`test` must not reach "latest" - prefix, not substring."""
        _, why = scoping.score("src/latest.json")
        self.assertNotIn("-test", why)

    def test_punctuated_signals_stay_substring_matches(self):
        self.assertTrue(scoping.matches("a/go.mod", scoping._tokens("a/go.mod"), "go.mod"))
        _, why = scoping.score("app/dist/bundle.min.js")
        self.assertIn("-min", why)

    def test_vendored_scaffolding_ranks_below_the_code_that_runs(self):
        """A tree the target ships *to* its users reads as application code to every path
        signal: `_bmad_template/.../review-prompts/*.md` outranked the real prompt module."""
        ranked = scoping.rank([
            "data/_bmad_template/skills/review-prompts/edge-case-hunter.md",
            "app/agents/_shared/prompts.py",
        ], "kavach-llm")
        self.assertEqual(ranked[0]["path"], "app/agents/_shared/prompts.py")


class TestModePrerequisites(unittest.TestCase):
    """`balanced` was never runnable from a fresh audit dir, and nothing said so.

    `recon` writes recon.json and file-manifest.txt; `sweep` is the only verb that writes
    findings.json. `scope` ranks the manifest and `slice`, `triage` and `render` all read
    findings.json - so a mode whose phase list schedules neither needs both run up front.
    `lite` opens with core:recon and core:sweep. balanced and deep do not, and driving
    balanced without them sent eight hunters empty slices and then died in the report
    tail.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_lite_schedules_its_own_and_needs_nothing_up_front(self):
        self.assertEqual(modes.missing_prerequisites(self.dir, "lite"), [])

    def test_balanced_needs_both_on_a_fresh_audit_dir(self):
        self.assertEqual(
            [p["verb"] for p in modes.missing_prerequisites(self.dir, "balanced")],
            ["recon", "sweep"],
        )

    def test_deep_needs_them_too(self):
        self.assertTrue(modes.missing_prerequisites(self.dir, "deep"))

    def test_an_artifact_already_on_disk_is_not_asked_for_again(self):
        """Idempotent, so a resume does not re-walk the tree or re-run the scanners."""
        with open(os.path.join(self.dir, "recon.json"), "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.assertEqual(
            [p["verb"] for p in modes.missing_prerequisites(self.dir, "balanced")], ["sweep"]
        )

    def test_every_mode_either_schedules_them_or_declares_them(self):
        """The invariant a harness can rely on: no mode silently needs an artifact."""
        for mode in modes.MODE_PHASES:
            scheduled = {modes.PHASE_AGENT.get(p, "") for p in modes.phases_for(mode)}
            declared = {p["verb"] for p in modes.missing_prerequisites(self.dir, mode)}
            for verb, _artifact, executor in modes.PREREQ_ARTIFACTS:
                self.assertTrue(
                    executor in scheduled or verb in declared,
                    f"{mode} neither schedules nor declares {verb}",
                )

    def test_the_plan_carries_them_so_a_harness_need_not_hardcode_the_list(self):
        plan = dispatch.dispatch_plan("balanced", "BL1", self.dir, "/repo")
        self.assertEqual(plan["phase"], "BL1")           # unchanged shape
        self.assertEqual(modes.missing_prerequisites(self.dir, "balanced")[0]["verb"], "recon")


if __name__ == "__main__":
    unittest.main()
