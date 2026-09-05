"""Coverage is scoped to the directories that belong to this audit.

`consolidate` never deletes, so a tree upgraded from a legacy `severity >= medium` policy -
or re-audited after the finding mix changed - carries directories that will never receive a
PoC. Unscoped, they made the gate permanently unsatisfiable: 291 directories, 2 satisfiable,
289 demanded forever on the audited tree. These tests pin the scoping, the four stale
reasons, and that pruning MOVES rather than deletes.
"""

import json
import os
import shutil
import tempfile
import unittest

from kavach import cleanup, coverage, findings_tree, runner
from kavach.finding import (Confidence, Finding, Location, Severity, dump_findings,
                            load_findings)


def _reasoned(title="IDOR on /orders", severity=Severity.HIGH, cvss=8.1):
    return Finding(
        title=title, severity=severity, category="API1:BOLA", source="kavach-api",
        locations=[Location(file=f"api/{title.split()[0].lower()}.py", line=42)],
        what_it_is="x" * 200, how_exploited="y" * 200, business_impact="z" * 200,
        remediation="w" * 200, confidence=Confidence.CONFIRMED, cvss_score=cvss,
    )


def _iac_row(title="Container runs as root"):
    return Finding(title=title, severity=Severity.HIGH, category="A05:Misconfiguration",
                   source="checkov", rule_id="CKV_DOCKER_3",
                   locations=[Location(file="Dockerfile", line=1)],
                   remediation="Declare a non-root USER.", confidence=Confidence.CONFIRMED)


def _scanner_row(title="requests 2.28.1: CVE-2024-35195"):
    return Finding(title=title, severity=Severity.HIGH, category="A06:Vulnerable-Components",
                   source="trivy", rule_id="CVE-2024-35195",
                   locations=[Location(file="requirements.txt", line=3)],
                   remediation="Upgrade requests to 2.31.0.", confidence=Confidence.CONFIRMED)


class TestPromotedIndex(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _index(self):
        with open(findings_tree.promoted_index_path(self.dir), encoding="utf-8") as fh:
            return json.load(fh)

    def test_consolidate_records_every_dir_it_wrote(self):
        created = findings_tree.consolidate(self.dir, [_reasoned(), _scanner_row()])
        index = self._index()
        self.assertEqual(index["count"], len(created))
        self.assertEqual({e["dir"] for e in index["entries"]},
                         {os.path.relpath(d, self.dir) for d in created})
        self.assertTrue(any(e["is_aggregate"] for e in index["entries"]))

    def test_the_manifest_is_a_snapshot_not_an_append(self):
        findings_tree.consolidate(self.dir, [_reasoned("First one")])
        findings_tree.consolidate(self.dir, [_reasoned("Second one")])
        # the first pass's dir is still on disk, but the manifest describes only this pass
        self.assertEqual(self._index()["count"], 1)
        self.assertEqual(len(findings_tree.promoted_dirs(self.dir)), 2)

    def test_absent_manifest_reads_as_none(self):
        self.assertIsNone(findings_tree.read_promoted_index(self.dir))

    def test_unreadable_manifest_reads_as_none(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        with open(findings_tree.promoted_index_path(self.dir), "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        self.assertIsNone(findings_tree.read_promoted_index(self.dir))


class TestScopePromoted(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _reasons(self, stale):
        return {s["dir"]: s["reason"] for s in stale}

    def test_the_manifest_is_the_authority_over_the_id_checks(self):
        """A dir consolidate just wrote is live even if findings.json disagrees - the
        manifest records what this pass actually promoted."""
        created = findings_tree.consolidate(self.dir, [_reasoned()])
        dump_findings([], os.path.join(self.dir, "findings.json"))
        live, stale, scoped_by = findings_tree.scope_promoted(self.dir)
        self.assertEqual(scoped_by, "promoted-index")
        self.assertEqual(live, created)
        self.assertEqual(stale, [])

    def test_renumbered_duplicate_from_an_earlier_run_is_stale(self):
        """The case an id-keyed predicate cannot see: display ids renumber, so the legacy dir
        and the fresh dir carry the SAME fingerprint under different names."""
        finding = _reasoned()
        dump_findings([finding], os.path.join(self.dir, "findings.json"))
        created = findings_tree.consolidate(self.dir, [finding])
        legacy = os.path.join(self.dir, "findings", "H7-idor-on-orders")
        shutil.copytree(created[0], legacy)

        live, stale, _ = findings_tree.scope_promoted(self.dir)
        self.assertEqual(live, created)
        self.assertEqual(self._reasons(stale),
                         {"findings/H7-idor-on-orders": "not_in_manifest_legacy_run"})

    def test_de_promoted_finding_is_stale_with_that_reason(self):
        """Medium is table-only under the current policy, so its old dir stops gating."""
        finding = _reasoned("Verbose stack trace", severity=Severity.HIGH)
        findings_tree.consolidate(self.dir, [finding])
        downgraded = _reasoned("Verbose stack trace", severity=Severity.MEDIUM)
        dump_findings([downgraded], os.path.join(self.dir, "findings.json"))
        findings_tree.consolidate(self.dir, [downgraded])

        live, stale, _ = findings_tree.scope_promoted(self.dir)
        self.assertEqual(live, [])
        self.assertEqual([s["reason"] for s in stale], ["de_promoted"])

    def test_finding_no_longer_in_findings_json_is_gone(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        dump_findings([_reasoned("Something else entirely")],
                      os.path.join(self.dir, "findings.json"))
        findings_tree.consolidate(self.dir, [_reasoned("Something else entirely")])
        stale = findings_tree.scope_promoted(self.dir)[1]
        self.assertEqual([s["reason"] for s in stale], ["gone"])

    def test_dir_without_metadata_is_stale_not_missing(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        os.makedirs(os.path.join(self.dir, "findings", "H9-hand-made"))
        stale = findings_tree.scope_promoted(self.dir)[1]
        self.assertEqual(self._reasons(stale), {"findings/H9-hand-made": "no_metadata"})
        self.assertNotIn("H9", [m["display_id"] for m in coverage.poc_coverage(self.dir)["missing"]])

    def test_aggregates_are_never_checked_against_findings_json(self):
        findings_tree.consolidate(self.dir, [_scanner_row()])
        dump_findings([], os.path.join(self.dir, "findings.json"))
        live, stale, _ = findings_tree.scope_promoted(self.dir)
        self.assertEqual(len(live), 1)
        self.assertEqual(stale, [])

    def test_fallback_to_the_promotion_policy_when_there_is_no_manifest(self):
        finding = _reasoned()
        dump_findings([finding], os.path.join(self.dir, "findings.json"))
        findings_tree.consolidate(self.dir, [finding])
        os.remove(findings_tree.promoted_index_path(self.dir))
        legacy = os.path.join(self.dir, "findings", "M3-medium-thing")
        os.makedirs(legacy)
        with open(os.path.join(legacy, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": "M3", "kavach_id": "KAVACH-notinthisrun",
                       "is_aggregate": False}, fh)

        live, stale, scoped_by = findings_tree.scope_promoted(self.dir)
        self.assertEqual(scoped_by, "promotion-policy")
        self.assertEqual(len(live), 1)
        self.assertEqual([s["reason"] for s in stale], ["gone"])

    def test_unscoped_when_neither_manifest_nor_findings_json_exists(self):
        findings_tree.consolidate(self.dir, [_reasoned()])
        os.remove(findings_tree.promoted_index_path(self.dir))
        live, stale, scoped_by = findings_tree.scope_promoted(self.dir)
        self.assertEqual(scoped_by, "unscoped")
        self.assertEqual(len(live), 1)
        self.assertEqual(stale, [])

    def test_fp_renames_are_neither_live_nor_stale(self):
        created = findings_tree.consolidate(self.dir, [_reasoned()])
        findings_tree.mark_false_positive(self.dir, created[0])
        live, stale, _ = findings_tree.scope_promoted(self.dir)
        self.assertEqual((live, stale), ([], []))


class TestCoverageIsScoped(unittest.TestCase):
    """The deadlock, reproduced in miniature: legacy dirs must not gate the audit."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.finding = _reasoned()
        dump_findings([self.finding], os.path.join(self.dir, "findings.json"))
        self.created = findings_tree.consolidate(self.dir, [self.finding])
        for i in range(1, 6):
            legacy = os.path.join(self.dir, "findings", f"M{i}-legacy-medium-{i}")
            os.makedirs(legacy)
            with open(os.path.join(legacy, "metadata.json"), "w", encoding="utf-8") as fh:
                json.dump({"display_id": f"M{i}", "kavach_id": f"KAVACH-legacy{i}",
                           "is_aggregate": False}, fh)

    def test_stale_dirs_are_counted_separately_and_do_not_block_the_gate(self):
        report = coverage.poc_coverage(self.dir)
        self.assertEqual(report["total"], 1)          # not 6
        self.assertEqual(report["stale"], 5)
        self.assertEqual(report["scoped_by"], "promoted-index")
        self.assertEqual({s["reason"] for s in report["stale_dirs"]}, {"gone"})
        self.assertEqual([m["display_id"] for m in report["missing"]], ["H1"])

    def test_the_gate_can_close_once_the_live_finding_has_its_poc(self):
        coverage.write_coverage(self.dir, "poc")
        self.assertFalse(runner.gate_satisfied(self.dir, "poc"))
        with open(os.path.join(self.created[0], "poc.theoretical.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("# Theoretical\n\nNo safe live repro.\n")
        coverage.write_coverage(self.dir, "poc")
        self.assertTrue(runner.gate_satisfied(self.dir, "poc"))

    def test_the_written_artifact_carries_the_new_keys(self):
        path = coverage.write_coverage(self.dir, "report")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["stale"], 5)
        self.assertEqual(doc["scoped_by"], "promoted-index")
        self.assertEqual(len(doc["stale_dirs"]), 5)
        for entry in doc["stale_dirs"]:
            self.assertEqual(set(entry),
                             {"display_id", "dir", "kavach_id", "reason", "detail"})
            self.assertIn(entry["reason"], findings_tree.STALE_REASONS)


class TestStableDisplayIds(unittest.TestCase):
    """Numbering from scratch grew the tree on its own.

    A second pass over a larger finding set slid every id down a place and wrote a fresh
    directory beside each old one - measured at 35 directories for 24 promoted findings, with
    the report rendered over the duplicates. These pin that a live finding keeps the id, and
    the directory, the first pass gave it.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _consolidate(self, findings):
        dump_findings(findings, os.path.join(self.dir, "findings.json"))
        return findings_tree.consolidate(self.dir, findings)

    def _ids(self):
        """kavach_id -> display id, over every directory on disk."""
        out = {}
        for fdir in findings_tree.promoted_dirs(self.dir):
            meta = findings_tree.read_metadata(fdir)
            out[meta["kavach_id"]] = meta["display_id"]
        return out

    def test_a_later_pass_does_not_renumber_what_the_first_one_promoted(self):
        first, second = _reasoned("IDOR on orders"), _reasoned("Mass assignment on users")
        self._consolidate([first, second])
        outranks = _reasoned("Auth bypass on admin", cvss=9.6)
        self._consolidate([outranks, first, second])

        self.assertEqual(len(findings_tree.promoted_dirs(self.dir)), 3)
        ids = self._ids()
        self.assertEqual(ids[first.fingerprint()], "H1")
        self.assertEqual(ids[second.fingerprint()], "H2")
        self.assertEqual(ids[outranks.fingerprint()], "H3")
        self.assertEqual(findings_tree.scope_promoted(self.dir)[1], [])

    def test_evidence_written_between_two_passes_stays_with_its_finding(self):
        """Why --prune-stale was held back: a renumber between a PoC landing and the next
        promote left that PoC in the directory the prune would carry away."""
        finding = _reasoned("IDOR on orders")
        [fdir] = self._consolidate([finding])
        with open(os.path.join(fdir, "poc.md"), "w", encoding="utf-8") as fh:
            fh.write("# Repro\n\ncurl -s http://localhost/orders/2\n")
        self._consolidate([_reasoned("Auth bypass on admin", cvss=9.6), finding])

        self.assertEqual(findings_tree.prune_stale(self.dir), [])
        self.assertTrue(os.path.exists(os.path.join(fdir, "poc.md")))

    def test_a_number_a_dropped_finding_left_is_not_handed_to_a_new_one(self):
        """A recycled number puts two directories on the same display id, and the report has
        no way to tell them apart. New ids are issued above every id on disk instead."""
        kept = _reasoned("Mass assignment on users")
        self._consolidate([_reasoned("IDOR on orders"), kept])
        self._consolidate([kept, _reasoned("SSRF on webhooks")])

        display_ids = [findings_tree.read_metadata(d)["display_id"]
                       for d in findings_tree.promoted_dirs(self.dir)]
        self.assertEqual(sorted(display_ids), ["H1", "H2", "H3"])

    def test_a_severity_that_crosses_bands_takes_its_directory_with_it(self):
        """dedupe raises severity when a second scanner corroborates a finding, and the
        fingerprint does not move with it. The evidence belongs to the finding, not the id."""
        [fdir] = self._consolidate([_reasoned("IDOR on orders")])
        with open(os.path.join(fdir, "poc.md"), "w", encoding="utf-8") as fh:
            fh.write("# Repro\n")
        [promoted] = self._consolidate([_reasoned("IDOR on orders",
                                                  severity=Severity.CRITICAL)])

        self.assertEqual(os.path.basename(promoted), "C1-idor-on-orders")
        self.assertTrue(os.path.exists(os.path.join(promoted, "poc.md")))
        self.assertEqual(findings_tree.promoted_dirs(self.dir), [promoted])

    def test_a_tree_an_older_engine_doubled_is_adopted_by_its_evidence(self):
        """0.2.4 and earlier left two directories for one fingerprint. Re-consolidating such
        a tree has to keep the one that was paid for, not the one that sorts first."""
        finding = _reasoned("IDOR on orders")
        [empty] = self._consolidate([finding])
        doubled = os.path.join(self.dir, "findings", "H2-idor-on-orders")
        shutil.copytree(empty, doubled)
        meta = findings_tree.read_metadata(doubled)
        meta["display_id"] = "H2"
        with open(os.path.join(doubled, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh)
        with open(os.path.join(doubled, "poc.md"), "w", encoding="utf-8") as fh:
            fh.write("# Repro\n")

        self.assertEqual(self._consolidate([finding]), [doubled])
        self.assertEqual(findings_tree.prune_stale(self.dir),
                         [os.path.join(self.dir, "findings-stale", "H1-idor-on-orders")])
        self.assertTrue(os.path.exists(os.path.join(doubled, "poc.md")))

    def test_an_aggregate_keeps_the_band_letter_it_was_promoted_under(self):
        iac = _iac_row()
        self._consolidate([iac])
        self._consolidate([_scanner_row(), iac])

        self.assertEqual(len(findings_tree.promoted_dirs(self.dir)), 2)
        ids = self._ids()
        self.assertEqual(ids["KAVACH-AGG-iac"], "G1")
        self.assertEqual(ids["KAVACH-AGG-dependency"], "G2")


class TestPruneStale(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        finding = _reasoned()
        dump_findings([finding], os.path.join(self.dir, "findings.json"))
        self.created = findings_tree.consolidate(self.dir, [finding])
        self.legacy = os.path.join(self.dir, "findings", "M1-legacy-medium")
        os.makedirs(self.legacy)
        with open(os.path.join(self.legacy, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": "M1", "kavach_id": "KAVACH-legacy1",
                       "is_aggregate": False}, fh)
        with open(os.path.join(self.legacy, "report.md"), "w", encoding="utf-8") as fh:
            fh.write("# evidence that must survive\n")

    def test_prune_moves_and_never_deletes(self):
        moved = findings_tree.prune_stale(self.dir)
        self.assertEqual(len(moved), 1)
        self.assertFalse(os.path.exists(self.legacy))
        dest = os.path.join(self.dir, "findings-stale", "M1-legacy-medium")
        self.assertTrue(os.path.isdir(dest))
        with open(os.path.join(dest, "report.md"), encoding="utf-8") as fh:
            self.assertIn("evidence that must survive", fh.read())

    def test_prune_leaves_the_live_tree_alone(self):
        findings_tree.prune_stale(self.dir)
        self.assertEqual(findings_tree.promoted_dirs(self.dir), self.created)
        self.assertEqual(coverage.poc_coverage(self.dir)["stale"], 0)

    def test_pruning_is_idempotent(self):
        findings_tree.prune_stale(self.dir)
        self.assertEqual(findings_tree.prune_stale(self.dir), [])

    def test_a_name_collision_in_findings_stale_does_not_overwrite(self):
        findings_tree.prune_stale(self.dir)
        os.makedirs(self.legacy)
        with open(os.path.join(self.legacy, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": "M1", "kavach_id": "KAVACH-legacy1"}, fh)
        second = findings_tree.prune_stale(self.dir)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(os.path.basename(second[0]), "M1-legacy-medium")
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings-stale",
                                                   "M1-legacy-medium")))

    def test_findings_stale_survives_cleanup(self):
        findings_tree.prune_stale(self.dir)
        summary = cleanup.cleanup(self.dir, "balanced")
        self.assertIn("findings-stale", cleanup.DURABLE)
        self.assertIn("findings-stale", summary["retained"])
        self.assertTrue(os.path.isdir(os.path.join(self.dir, "findings-stale",
                                                   "M1-legacy-medium")))


class TestStaleReachesTheReport(unittest.TestCase):
    def test_the_limits_section_names_the_stale_directories(self):
        d = tempfile.mkdtemp()
        finding = _reasoned()
        dump_findings([finding], os.path.join(d, "findings.json"))
        findings_tree.consolidate(d, [finding])
        legacy = os.path.join(d, "findings", "M1-legacy")
        os.makedirs(legacy)
        with open(os.path.join(legacy, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": "M1", "kavach_id": "KAVACH-legacy1"}, fh)
        coverage.write_coverage(d, "poc")

        from kavach.render import model
        report = model.build(load_findings(os.path.join(d, "findings.json")), {},
                             _gate(), {"audit_dir": d})
        stale_lines = [x for x in report.limits if "no longer part of" in x]
        self.assertEqual(len(stale_lines), 1)
        self.assertIn("1 promoted directory(ies)", stale_lines[0])


def _gate():
    from kavach.score import gate
    return gate([], {}, require_controls=False)


if __name__ == "__main__":
    unittest.main()
