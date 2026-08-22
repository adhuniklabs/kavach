"""Version, audit identity, and the tree an audit was pointed at.

Every check here exists because the value it guards is written in one place and read in another,
which is where versions and commits go wrong.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest

from kavach import __version__, gitinfo, state

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CORE = os.path.join(ROOT, "core")


class TestVersionSingleSource(unittest.TestCase):
    def test_version_is_semver(self):
        self.assertRegex(__version__, r"^\d+\.\d+\.\d+$")

    def test_pyproject_does_not_carry_a_second_copy(self):
        """A hardcoded `version =` here drifts from kavach.__version__ the first time either is
        bumped alone, and the packaged metadata is what a resume check reads."""
        text = open(os.path.join(CORE, "pyproject.toml"), encoding="utf-8").read()
        # A quoted literal is the drift; `version = { attr = ... }` under
        # [tool.setuptools.dynamic] is the mechanism that prevents it.
        self.assertNotRegex(text, r'(?m)^version\s*=\s*"')
        self.assertIn('dynamic = ["version"]', text)
        self.assertIn('version = { attr = "kavach.__version__" }', text)

    def test_the_changelog_has_an_entry_for_this_version(self):
        """Bumping the code and forgetting the changelog ships a release nobody can read."""
        text = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
        self.assertRegex(text, rf"(?m)^## \[{re.escape(__version__)}\]")


class TestAuditIdentity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_handle_is_the_trailing_hex(self):
        self.assertEqual(state.handle("2026-08-23T09:14:27Z-11497-9dfadd32"), "9dfadd32")

    def test_an_audit_records_the_engine_that_made_it(self):
        run = state.init_audit(self.dir, "balanced", ["BL1"])
        self.assertEqual(run.engine_version, __version__)
        self.assertEqual(state.load_state(self.dir).audits[0].engine_version, __version__)

    def test_find_audit_resolves_a_full_id_or_a_handle(self):
        run = state.init_audit(self.dir, "balanced", ["BL1"])
        self.assertEqual(state.find_audit(self.dir, run.audit_id).audit_id, run.audit_id)
        self.assertEqual(state.find_audit(self.dir, state.handle(run.audit_id)).audit_id,
                         run.audit_id)
        self.assertIsNone(state.find_audit(self.dir, "deadbeef"))

    def test_an_ambiguous_handle_resolves_to_nothing_rather_than_a_guess(self):
        a = state.init_audit(self.dir, "balanced", ["BL1"])
        clash = state.handle(a.audit_id)

        def _dup(f):
            second = state.AuditRunState(audit_id=f"2020-01-01T00:00:00Z-1-{clash}",
                                         mode="lite")
            f.audits.append(second)

        state.mutate_state(self.dir, _dup)
        self.assertIsNone(state.find_audit(self.dir, clash))


class TestVersionCompatibility(unittest.TestCase):
    def test_same_minor_resumes(self):
        self.assertTrue(state.version_compatible("0.2.0", "0.2.7"))

    def test_a_different_minor_does_not(self):
        """On 0.x the minor is the breaking axis, and what breaks across one is exactly what
        resume depends on: the phase list, the prereq graph, and which artifact closes a gate."""
        self.assertFalse(state.version_compatible("0.1.0", "0.2.0"))
        self.assertFalse(state.version_compatible("0.2.0", "0.3.0"))

    def test_an_audit_written_before_the_field_existed_is_allowed(self):
        """Refusing every pre-existing audit is a worse failure than the one this prevents."""
        self.assertTrue(state.version_compatible("", "9.9.9"))


class TestGitContext(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()

    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def _commit(self, name="a.py", body="x"):
        with open(os.path.join(self.repo, name), "w", encoding="utf-8") as fh:
            fh.write(body)
        self._git("add", "-A")
        self._git("-c", "user.email=t@t.t", "-c", "user.name=t", "commit", "-m", name)

    def test_a_target_with_no_git_is_not_an_error(self):
        ctx = gitinfo.context(self.repo)
        self.assertFalse(ctx.available)
        self.assertEqual(ctx.branch, "nogit")
        self.assertEqual(gitinfo.short(None), "no-git")

    def test_commit_branch_and_dirty_are_captured(self):
        self._git("init", "-q")
        self._commit()
        ctx = gitinfo.context(self.repo)
        self.assertTrue(ctx.available)
        self.assertFalse(ctx.dirty)
        with open(os.path.join(self.repo, "a.py"), "a", encoding="utf-8") as fh:
            fh.write("more")
        self.assertTrue(gitinfo.context(self.repo).dirty)

    def test_init_records_the_tree_the_audit_is_pointed_at(self):
        """complete_audit records the commit at the end, which is enough to key a baseline and
        not enough to notice a resume against a different tree."""
        self._git("init", "-q")
        self._commit()
        ctx = gitinfo.context(self.repo)
        out = tempfile.mkdtemp()
        run = state.init_audit(out, "balanced", ["BL1"], commit=ctx.commit,
                               branch=ctx.branch, dirty=ctx.dirty)
        self.assertEqual(run.commit, ctx.commit)
        self.assertFalse(run.dirty)


if __name__ == "__main__":
    unittest.main()
