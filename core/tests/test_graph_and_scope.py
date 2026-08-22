"""The two things that decide what an audit costs on a large repo.

The graph adapter is exercised against a stub binary, not the real one: `codegraph` is
optional by design, so the behaviour that matters most here is what happens when it is
absent, broken, or slow - and a test that needs the real tool installed would never run
those paths.
"""

import json
import os
import stat
import tempfile
import unittest

from kavach import dispatch, graphindex, scoping

STUB_OK = """#!/bin/sh
case "$1" in
  version) echo "codegraph 9.9.9" ;;
  index)   echo "indexed" ;;
  status)  echo '{"symbols": 1234, "files": 56}' ;;
  *)       exit 1 ;;
esac
"""

STUB_INDEX_FAILS = """#!/bin/sh
case "$1" in
  version) echo "codegraph 9.9.9" ;;
  index)   echo "cannot read target" >&2; exit 3 ;;
  *)       exit 1 ;;
esac
"""

STUB_NO_JSON_STATUS = """#!/bin/sh
case "$1" in
  version) echo "codegraph 9.9.9" ;;
  index)   echo "indexed" ;;
  status)  echo "Symbols: 1234 (not json)" ;;
  *)       exit 1 ;;
esac
"""


def _stub(directory: str, script: str, name: str = "codegraph") -> str:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TestGraphIndex(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.bin_dir = tempfile.mkdtemp()
        self.target = tempfile.mkdtemp()
        self._path = os.environ["PATH"]
        os.environ["PATH"] = self.bin_dir + os.pathsep + self._path

    def tearDown(self):
        os.environ["PATH"] = self._path

    def test_a_missing_binary_is_recorded_not_raised(self):
        """The graph is a scanner, not a prerequisite: no binary must not block a phase."""
        status = graphindex.index(self.target, self.dir, binary="definitely-not-installed")
        self.assertFalse(status["available"])
        self.assertIn("not installed", status["reason"])
        self.assertTrue(os.path.exists(graphindex.status_path(self.dir)))

    def test_successful_index_records_root_version_and_statistics(self):
        _stub(self.bin_dir, STUB_OK)
        status = graphindex.index(self.target, self.dir)
        self.assertTrue(status["available"])
        self.assertEqual(status["root"], os.path.abspath(self.target))
        self.assertEqual(status["version"], "codegraph 9.9.9")
        self.assertEqual(status["statistics"]["symbols"], 1234)
        self.assertTrue(graphindex.available(self.dir))

    def test_a_failed_index_is_unavailable_with_the_tools_own_reason(self):
        _stub(self.bin_dir, STUB_INDEX_FAILS)
        status = graphindex.index(self.target, self.dir)
        self.assertFalse(status["available"])
        self.assertIn("exited 3", status["reason"])
        self.assertIn("cannot read target", status["detail"])

    def test_non_json_status_still_leaves_the_graph_usable(self):
        """`codegraph status` is documented without --json, so a non-JSON answer is the
        expected case. Losing the counts must not lose the graph."""
        _stub(self.bin_dir, STUB_NO_JSON_STATUS)
        status = graphindex.index(self.target, self.dir)
        self.assertTrue(status["available"])
        self.assertNotIn("statistics", status)

    def test_a_timeout_is_unavailable_rather_than_a_hang(self):
        _stub(self.bin_dir, "#!/bin/sh\ncase \"$1\" in index) sleep 5 ;; *) exit 1 ;; esac\n")
        status = graphindex.index(self.target, self.dir, timeout=1)
        self.assertFalse(status["available"])
        self.assertIn("124", status["reason"])

    def test_status_of_an_untouched_audit_dir_is_not_available(self):
        self.assertFalse(graphindex.available(self.dir))
        self.assertEqual(graphindex.read_status(self.dir)["reason"], "not established")

    def test_a_corrupt_status_file_reads_as_unavailable(self):
        graphindex.write_status(self.dir, {"available": True})
        with open(graphindex.status_path(self.dir), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertFalse(graphindex.available(self.dir))


class TestGraphPrompt(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_an_agent_is_told_plainly_when_there_is_no_graph(self):
        """An agent that assumes a tool it does not have burns a turn discovering that."""
        section = graphindex.prompt_section(self.dir)
        self.assertIn("No pre-built code graph", section)
        self.assertNotIn("callers", section)

    def test_an_indexed_repo_gets_graph_first_instructions(self):
        graphindex.write_status(self.dir, {"available": True, "tool": "codegraph",
                                           "cli": "/usr/bin/codegraph"})
        section = graphindex.prompt_section(self.dir)
        self.assertIn("before you grep", section)
        self.assertIn("/usr/bin/codegraph callers", section)
        self.assertIn("impact", section)

    def test_the_dispatch_prompt_carries_whichever_applies(self):
        p = dispatch.phase_prompt("balanced", "BL3", self.dir, "/repo", agent="kavach-sast")
        self.assertIn("## Code graph", p)
        self.assertIn("No pre-built code graph", p)
        graphindex.write_status(self.dir, {"available": True, "cli": "codegraph"})
        p = dispatch.phase_prompt("balanced", "BL3", self.dir, "/repo", agent="kavach-sast")
        self.assertIn("before you grep", p)

    def test_the_dispatch_plan_reports_graph_status(self):
        plan = dispatch.dispatch_plan("balanced", "BL3", self.dir, "/repo")
        self.assertFalse(plan["graph"]["available"])


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


if __name__ == "__main__":
    unittest.main()


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
