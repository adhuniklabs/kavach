import os
import subprocess
import tempfile
import unittest

from kavach import diffing, state
from kavach.finding import Finding, Location, Severity
from kavach.state import RunStatus


def _f(title):
    return Finding(title=title, severity=Severity.HIGH, category="A01", source="s",
                   locations=[Location(file="a.py", line=1)])


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(repo):
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")


class TestDiffing(unittest.TestCase):
    def test_diff_new_fixed_unchanged(self):
        base = [_f("SQLi"), _f("XSS")]
        cur = [_f("SQLi"), _f("SSRF")]
        new, fixed, unchanged = diffing.diff_findings(base, cur)
        self.assertEqual([f.title for f in new], ["SSRF"])
        self.assertEqual([f.title for f in fixed], ["XSS"])
        self.assertEqual([f.title for f in unchanged], ["SQLi"])

    def test_scope_guard(self):
        self.assertTrue(diffing.scope_guard(["a.py"], max_changed=200))
        self.assertFalse(diffing.scope_guard([], max_changed=200))
        self.assertFalse(diffing.scope_guard(["f"] * 201, max_changed=200))


class TestResolvePriorCommit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_since_wins_over_state(self):
        self.assertEqual(diffing.resolve_prior_commit(self.dir, since="deadbeef"), "deadbeef")

    def test_no_audits_returns_none(self):
        self.assertIsNone(diffing.resolve_prior_commit(self.dir))

    def test_in_progress_audit_not_used(self):
        state.init_audit(self.dir, "balanced", ["intel"], commit="abc123", repository="o/r")
        self.assertIsNone(diffing.resolve_prior_commit(self.dir))

    def test_latest_complete_audit_commit(self):
        run = state.init_audit(self.dir, "balanced", ["intel"], commit="abc123", repository="o/r")
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "status", RunStatus.COMPLETE))
        self.assertEqual(diffing.resolve_prior_commit(self.dir), "abc123")

    def test_walks_backward_past_in_progress_to_last_complete(self):
        state.init_audit(self.dir, "balanced", ["intel"], commit="c1", repository="o/r")
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "status", RunStatus.COMPLETE))
        state.init_audit(self.dir, "balanced", ["intel"], commit="c2", repository="o/r")  # in_progress
        self.assertEqual(diffing.resolve_prior_commit(self.dir), "c1")

    def test_walks_backward_past_no_git_complete_run_to_older_complete_with_commit(self):
        # the newest COMPLETE run has commit=None (target had no git history at the time);
        # that's not a usable diff baseline, so keep walking back for an older COMPLETE
        # run that does have a commit, instead of stopping on the newest regardless.
        state.init_audit(self.dir, "balanced", ["intel"], commit="c1", repository="o/r")
        state.mutate_state(self.dir, lambda f: setattr(f.audits[0], "status", RunStatus.COMPLETE))
        state.init_audit(self.dir, "balanced", ["intel"], commit=None, repository="o/r")
        state.mutate_state(self.dir, lambda f: setattr(f.audits[1], "status", RunStatus.COMPLETE))
        self.assertEqual(diffing.resolve_prior_commit(self.dir), "c1")


class TestChangedFiles(unittest.TestCase):
    def test_changed_files_between_commits(self):
        repo = tempfile.mkdtemp()
        _init_repo(repo)
        with open(os.path.join(repo, "a.py"), "w") as fh:
            fh.write("print(1)\n")
        _git(repo, "add", "a.py")
        _git(repo, "commit", "-q", "-m", "first")
        first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                               text=True, check=True).stdout.strip()

        with open(os.path.join(repo, "b.py"), "w") as fh:
            fh.write("print(2)\n")
        _git(repo, "add", "b.py")
        _git(repo, "commit", "-q", "-m", "second")

        files = diffing.changed_files(repo, first)
        self.assertEqual(files, ["b.py"])

    def test_changed_files_bad_ref_returns_empty(self):
        repo = tempfile.mkdtemp()
        _init_repo(repo)
        with open(os.path.join(repo, "a.py"), "w") as fh:
            fh.write("print(1)\n")
        _git(repo, "add", "a.py")
        _git(repo, "commit", "-q", "-m", "first")
        self.assertEqual(diffing.changed_files(repo, "not-a-real-ref"), [])


if __name__ == "__main__":
    unittest.main()
