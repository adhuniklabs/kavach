import json
import os
import tempfile
import unittest

from kavach import merge_findings
from kavach.finding import Finding, Location, Severity, dump_findings


def _f(title, severity, file="a.py", line=1, category="A01"):
    return Finding(title=title, severity=severity, category=category, source="s",
                   locations=[Location(file=file, line=line)])


class TestSeverityRenumber(unittest.TestCase):
    def test_stable_severity_order(self):
        findings = [
            _f("Low1", Severity.LOW), _f("Crit1", Severity.CRITICAL),
            _f("High1", Severity.HIGH), _f("Crit2", Severity.CRITICAL),
        ]
        ordered = merge_findings.severity_renumber(findings)
        self.assertEqual([f.title for f in ordered], ["Crit1", "Crit2", "High1", "Low1"])

    def test_cvss_breaks_ties_within_same_severity(self):
        low_cvss = _f("HighA", Severity.HIGH); low_cvss.cvss_score = 7.1
        high_cvss = _f("HighB", Severity.HIGH); high_cvss.cvss_score = 8.9
        ordered = merge_findings.severity_renumber([low_cvss, high_cvss])
        self.assertEqual([f.title for f in ordered], ["HighB", "HighA"])


class TestIndexSources(unittest.TestCase):
    def setUp(self):
        self.audit_dir = tempfile.mkdtemp()
        self.src_a = tempfile.mkdtemp()
        self.src_b = tempfile.mkdtemp()

    def test_indexes_sources_with_letter_aliases(self):
        dump_findings([_f("SQLi", Severity.HIGH, file="x.py")],
                      os.path.join(self.src_a, "findings.json"))
        dump_findings([_f("XSS", Severity.MEDIUM, file="y.py")],
                      os.path.join(self.src_b, "findings.json"))

        index = merge_findings.index_sources(self.audit_dir, [self.src_a, self.src_b])

        aliases = {s["alias"]: s for s in index["sources"]}
        self.assertEqual(set(aliases), {"a", "b"})
        self.assertEqual(aliases["a"]["count"], 1)
        self.assertEqual(aliases["b"]["count"], 1)

        index_path = os.path.join(self.audit_dir, "attack-surface", "merge-index.json")
        self.assertTrue(os.path.exists(index_path))

    def test_exact_duplicate_across_sources_is_deduped(self):
        same = _f("SQLi", Severity.HIGH, file="x.py")
        dump_findings([same], os.path.join(self.src_a, "findings.json"))
        dump_findings([same], os.path.join(self.src_b, "findings.json"))

        index = merge_findings.index_sources(self.audit_dir, [self.src_a, self.src_b])
        self.assertEqual(index["merged_count"], 1)

        merged_path = os.path.join(self.audit_dir, "tmp", "merge-workspace", "findings-merged.json")
        self.assertTrue(os.path.exists(merged_path))


class TestApplyDedupDecisions(unittest.TestCase):
    def setUp(self):
        self.audit_dir = tempfile.mkdtemp()

    def test_no_decisions_file_passes_findings_through(self):
        findings = [_f("SQLi", Severity.HIGH)]
        kept, notes = merge_findings.apply_dedup_decisions(self.audit_dir, findings)
        self.assertEqual(kept, findings)
        self.assertEqual(notes, [])

    def test_dropped_finding_is_folded_out(self):
        keep = _f("SQLi", Severity.HIGH, file="x.py")
        drop = _f("SQLi variant", Severity.MEDIUM, file="y.py")
        gate_dir = os.path.join(self.audit_dir, "attack-surface")
        os.makedirs(gate_dir, exist_ok=True)
        with open(os.path.join(gate_dir, "merge-dedup-decisions.json"), "w", encoding="utf-8") as fh:
            json.dump([{"drop": drop.fingerprint(), "keep": keep.fingerprint(),
                       "reason": "same root cause"}], fh)

        kept, notes = merge_findings.apply_dedup_decisions(self.audit_dir, [keep, drop])
        self.assertEqual([f.title for f in kept], ["SQLi"])
        self.assertIn("same root cause", notes[0])

    def test_decision_missing_keep_id_is_ignored(self):
        drop = _f("Orphan", Severity.MEDIUM, file="z.py")
        gate_dir = os.path.join(self.audit_dir, "attack-surface")
        os.makedirs(gate_dir, exist_ok=True)
        with open(os.path.join(gate_dir, "merge-dedup-decisions.json"), "w", encoding="utf-8") as fh:
            json.dump([{"drop": drop.fingerprint()}], fh)

        kept, notes = merge_findings.apply_dedup_decisions(self.audit_dir, [drop])
        self.assertEqual(kept, [drop])
        self.assertEqual(notes, [])


class TestMergeSummary(unittest.TestCase):
    def test_writes_markdown_summary(self):
        d = tempfile.mkdtemp()
        decisions = {
            "sources": [{"alias": "a", "path": "/x", "count": 3}],
            "renames": {"H2": "H1"},
        }
        path = merge_findings.merge_summary(d, decisions)
        self.assertTrue(os.path.exists(path))
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        self.assertIn("Merge Summary", body)
        self.assertIn("H2", body)
        self.assertIn("H1", body)


class TestRenameMap(unittest.TestCase):
    def setUp(self):
        self.src_a = tempfile.mkdtemp()
        self.src_b = tempfile.mkdtemp()

    def _promote(self, src, display_id, finding):
        fdir = os.path.join(src, "findings", f"{display_id}-x")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": display_id, "kavach_id": finding.fingerprint()}, fh)

    def test_maps_surviving_finding_to_its_new_id(self):
        f = _f("SQLi", Severity.HIGH, file="x.py")
        self._promote(self.src_a, "H2", f)

        promoted_dir = tempfile.mkdtemp()
        with open(os.path.join(promoted_dir, "metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"display_id": "H1", "kavach_id": f.fingerprint()}, fh)

        renames = merge_findings.rename_map([self.src_a, self.src_b], [promoted_dir])
        self.assertEqual(renames, {"a:H2": "H1"})

    def test_finding_dropped_by_merge_has_no_rename_entry(self):
        f = _f("Dropped", Severity.LOW, file="y.py")
        self._promote(self.src_a, "M3", f)

        renames = merge_findings.rename_map([self.src_a, self.src_b], [])
        self.assertEqual(renames, {})

    def test_source_with_no_findings_dir_is_skipped(self):
        renames = merge_findings.rename_map([self.src_a, self.src_b], [])
        self.assertEqual(renames, {})


if __name__ == "__main__":
    unittest.main()
