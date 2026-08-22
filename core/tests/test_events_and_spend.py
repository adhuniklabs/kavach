"""The two things a live run could not report: what it is doing, and what it has cost."""

import json
import os
import tempfile
import threading
import unittest

from kavach import budget, cleanup, events, state


class TestEvents(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_emit_then_read_round_trips(self):
        events.emit(self.dir, "audit_start", mode="balanced")
        events.emit(self.dir, "budget_check", phase="BL3", allowed=6)
        got = events.read(self.dir)
        self.assertEqual([e["kind"] for e in got], ["audit_start", "budget_check"])
        self.assertEqual(got[1]["allowed"], 6)
        self.assertTrue(all(e["at"].endswith("Z") for e in got))

    def test_since_skips_what_a_reader_already_has(self):
        for i in range(5):
            events.emit(self.dir, "tick", i=i)
        self.assertEqual([e["i"] for e in events.read(self.dir, since=3)], [3, 4])

    def test_missing_log_reads_empty_rather_than_raising(self):
        self.assertEqual(events.read(os.path.join(self.dir, "nope")), [])

    def test_a_torn_line_does_not_break_the_reader(self):
        """The log is tailed while it is being written, so a half-line is normal, not a bug."""
        events.emit(self.dir, "ok")
        with open(events.path(self.dir), "a", encoding="utf-8") as fh:
            fh.write('{"kind": "tor')
        self.assertEqual([e["kind"] for e in events.read(self.dir)], ["ok"])

    def test_an_oversized_record_is_truncated_not_dropped(self):
        """Lines stay under PIPE_BUF so concurrent phases interleave whole lines. A record
        that would break that is recorded as truncated - losing the line loses the event."""
        events.emit(self.dir, "big", blob="x" * (events.MAX_LINE * 2))
        got = events.read(self.dir)
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0]["truncated"])

    def test_concurrent_emits_keep_whole_lines(self):
        def spam(tag):
            for i in range(40):
                events.emit(self.dir, "tick", tag=tag, i=i)

        threads = [threading.Thread(target=spam, args=(t,)) for t in "abcdef"]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        with open(events.path(self.dir), encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln]
        self.assertEqual(len(lines), 240)
        for line in lines:
            json.loads(line)

    def test_the_log_survives_cleanup(self):
        """A gate under a transient path re-opens its phase on every resume; the same is
        true of a run log a reader is following."""
        self.assertIn("events.jsonl", cleanup.DURABLE)
        events.emit(self.dir, "audit_start")
        cleanup.cleanup(self.dir, "balanced")
        self.assertTrue(os.path.exists(events.path(self.dir)))

    def test_the_log_is_not_reported_as_an_unexpected_root_file(self):
        events.emit(self.dir, "audit_start")
        self.assertNotIn("events.jsonl", cleanup.cleanup(self.dir, "balanced")["unexpected"])


class TestSpendLedger(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        run = state.init_audit(self.dir, "balanced", ["BL1", "BL3"])
        self.audit_id = run.audit_id

    def test_charge_accumulates_tokens_and_dollars_per_phase(self):
        budget.init_budget(self.dir, self.audit_id, "balanced")
        budget.charge(self.dir, self.audit_id, "BL3", 6, tokens_in=1000, tokens_out=200,
                      cost_usd=0.5)
        ledger = budget.charge(self.dir, self.audit_id, "BL3", 2, tokens_in=500,
                               tokens_out=100, cost_usd=0.25)
        self.assertEqual(ledger["dispatches"], 8)
        self.assertEqual(ledger["tokens_in"], 1500)
        self.assertEqual(ledger["cost_usd"], 0.75)
        self.assertEqual(ledger["spend_by_phase"]["BL3"]["tokens_out"], 300)

    def test_charging_nothing_leaves_the_spend_columns_alone(self):
        """The engine cannot measure tokens; a harness that does not report them must still
        be able to charge dispatches without writing zeros over a real figure."""
        budget.init_budget(self.dir, self.audit_id, "balanced")
        budget.charge(self.dir, self.audit_id, "BL1", 1, cost_usd=0.4)
        ledger = budget.charge(self.dir, self.audit_id, "BL3", 1)
        self.assertEqual(ledger["cost_usd"], 0.4)

    def test_cost_ceiling_sheds_and_says_why(self):
        budget.init_budget(self.dir, self.audit_id, "balanced", max_cost_usd=1.0)
        budget.charge(self.dir, self.audit_id, "BL1", 1, cost_usd=1.25)
        decision = budget.check(self.dir, self.audit_id, "BL3", 8)
        self.assertEqual((decision.allowed, decision.dropped), (0, 8))
        self.assertEqual(decision.reason, budget.COST_CEILING)

    def test_the_shed_is_recorded_for_the_reports_limits_section(self):
        budget.init_budget(self.dir, self.audit_id, "balanced", max_cost_usd=1.0)
        budget.charge(self.dir, self.audit_id, "BL1", 1, cost_usd=2.0)
        budget.check(self.dir, self.audit_id, "BL3", 8)
        shed = budget.shed_records(self.dir, self.audit_id)
        self.assertEqual(shed[-1]["reason"], budget.COST_CEILING)
        self.assertEqual(shed[-1]["dropped"], 8)

    def test_zero_ceiling_is_unlimited_not_exhausted(self):
        budget.init_budget(self.dir, self.audit_id, "balanced", max_cost_usd=0.0)
        budget.charge(self.dir, self.audit_id, "BL1", 1, cost_usd=999.0)
        self.assertEqual(budget.check(self.dir, self.audit_id, "BL3", 8).allowed, 8)

    def test_show_reports_remaining_spend(self):
        budget.init_budget(self.dir, self.audit_id, "balanced", max_cost_usd=2.0)
        budget.charge(self.dir, self.audit_id, "BL1", 1, cost_usd=0.5)
        shown = budget.show(self.dir, self.audit_id)
        self.assertEqual(shown["cost_usd"], 0.5)
        self.assertEqual(shown["cost_remaining"], 1.5)

    def test_a_pre_spend_ledger_backfills_instead_of_crashing(self):
        """An audit started before the spend columns existed is resumable, so `charge` has
        to cope with a ledger that has no `cost_usd` key at all."""
        budget.init_budget(self.dir, self.audit_id, "balanced")

        def _strip(f):
            for a in f.audits:
                for key in ("cost_usd", "tokens_in", "tokens_out", "max_cost_usd",
                            "spend_by_phase"):
                    a.budget.pop(key, None)

        state.mutate_state(self.dir, _strip)
        ledger = budget.charge(self.dir, self.audit_id, "BL3", 1, cost_usd=0.25)
        self.assertEqual(ledger["cost_usd"], 0.25)


if __name__ == "__main__":
    unittest.main()
