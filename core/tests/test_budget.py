import os
import tempfile
import threading
import unittest

from kavach import budget, flags, state


class TestInitBudget(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.run = state.init_audit(self.dir, "deep", ["DP1", "DP13"], repository="o/r")

    def test_mode_default_ceiling(self):
        ledger = budget.init_budget(self.dir, self.run.audit_id, "deep")
        self.assertEqual(ledger["max_dispatches"], budget.DEFAULT_MAX_DISPATCHES["deep"])
        self.assertEqual(ledger["max_wall_seconds"], budget.DEFAULT_MAX_WALL_SECONDS)
        self.assertEqual(ledger["dispatches"], 0)
        self.assertEqual(ledger["by_phase"], {})
        self.assertEqual(ledger["shed"], [])

    def test_ledger_lives_in_the_audit_record_and_survives_reload(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=9)
        reloaded = state.load_state(self.dir).audits[0]
        self.assertEqual(reloaded.budget["max_dispatches"], 9)

    def test_env_override(self):
        os.environ["KAVACH_MAX_DISPATCHES"] = "7"
        os.environ["KAVACH_MAX_WALL_SECONDS"] = "60"
        try:
            ledger = budget.init_budget(self.dir, self.run.audit_id, "deep")
        finally:
            del os.environ["KAVACH_MAX_DISPATCHES"]
            del os.environ["KAVACH_MAX_WALL_SECONDS"]
        self.assertEqual(ledger["max_dispatches"], 7)
        self.assertEqual(ledger["max_wall_seconds"], 60)

    def test_explicit_argument_beats_env(self):
        os.environ["KAVACH_MAX_DISPATCHES"] = "7"
        try:
            ledger = budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=3)
        finally:
            del os.environ["KAVACH_MAX_DISPATCHES"]
        self.assertEqual(ledger["max_dispatches"], 3)

    def test_zero_is_a_legal_env_value_meaning_unlimited(self):
        os.environ["KAVACH_MAX_DISPATCHES"] = "0"
        try:
            self.assertEqual(flags.max_dispatches(120), 0)
        finally:
            del os.environ["KAVACH_MAX_DISPATCHES"]

    def test_negative_env_value_falls_back_to_the_default(self):
        os.environ["KAVACH_MAX_DISPATCHES"] = "-4"
        try:
            self.assertEqual(flags.max_dispatches(120), 120)
        finally:
            del os.environ["KAVACH_MAX_DISPATCHES"]


class TestCheckAndCharge(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.run = state.init_audit(self.dir, "deep", ["DP4", "DP13"], repository="o/r")

    def _ledger(self):
        return state.load_state(self.dir).audits[0].budget

    def test_within_budget_allows_everything_and_records_no_shed(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=50)
        decision = budget.check(self.dir, self.run.audit_id, "DP4", 8)
        self.assertEqual((decision.allowed, decision.dropped), (8, 0))
        self.assertEqual(decision.reason, budget.WITHIN_BUDGET)
        self.assertEqual(self._ledger()["shed"], [])

    def test_check_never_charges(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=50)
        budget.check(self.dir, self.run.audit_id, "DP4", 8)
        self.assertEqual(self._ledger()["dispatches"], 0)

    def test_charge_accumulates_per_phase(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=50)
        budget.charge(self.dir, self.run.audit_id, "DP4", 8)
        ledger = budget.charge(self.dir, self.run.audit_id, "DP13", 22)
        self.assertEqual(ledger["dispatches"], 30)
        self.assertEqual(ledger["by_phase"], {"DP4": 8, "DP13": 22})

    def test_sheds_and_records_when_planned_exceeds_the_ceiling(self):
        """Acceptance criterion 6."""
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=30)
        budget.charge(self.dir, self.run.audit_id, "DP4", 8)
        decision = budget.check(self.dir, self.run.audit_id, "DP13", 40)
        self.assertEqual((decision.allowed, decision.dropped), (22, 18))
        self.assertEqual(decision.reason, budget.DISPATCH_CEILING)

        shed = self._ledger()["shed"]
        self.assertEqual(len(shed), 1)
        self.assertEqual(shed[0]["phase"], "DP13")
        self.assertEqual(shed[0]["planned"], 40)
        self.assertEqual(shed[0]["allowed"], 22)
        self.assertEqual(shed[0]["dropped"], 18)
        self.assertEqual(shed[0]["reason"], budget.DISPATCH_CEILING)
        self.assertTrue(shed[0]["at"].endswith("Z"))

    def test_shed_is_recorded_even_if_the_coordinator_never_charges(self):
        # a crash between shedding and charging still owes the reader the note
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=5)
        budget.check(self.dir, self.run.audit_id, "DP13", 40)
        self.assertEqual(budget.shed_records(self.dir)[0]["dropped"], 35)
        self.assertEqual(self._ledger()["dispatches"], 0)

    def test_exhausted_budget_allows_nothing(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=8)
        budget.charge(self.dir, self.run.audit_id, "DP4", 8)
        decision = budget.check(self.dir, self.run.audit_id, "DP13", 4)
        self.assertEqual((decision.allowed, decision.dropped), (0, 4))
        self.assertEqual(decision.reason, budget.DISPATCH_CEILING)

    def test_zero_ceiling_is_unlimited_not_exhausted(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=0)
        budget.charge(self.dir, self.run.audit_id, "DP4", 500)
        decision = budget.check(self.dir, self.run.audit_id, "DP13", 40)
        self.assertEqual((decision.allowed, decision.dropped), (40, 0))
        self.assertEqual(decision.reason, budget.UNLIMITED)
        self.assertEqual(self._ledger()["shed"], [])

    def test_wall_clock_stops_the_fan_out_regardless_of_dispatch_headroom(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=0,
                           max_wall_seconds=1)
        state.mutate_state(self.dir, lambda f: f.audits[0].budget.update(
            {"started_at": "2020-01-01T00:00:00Z"}))
        decision = budget.check(self.dir, self.run.audit_id, "DP13", 40)
        self.assertEqual((decision.allowed, decision.dropped), (0, 40))
        self.assertEqual(decision.reason, budget.WALL_CLOCK)
        self.assertEqual(self._ledger()["shed"][0]["reason"], budget.WALL_CLOCK)

    def test_zero_wall_seconds_is_unlimited(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=50,
                           max_wall_seconds=0)
        state.mutate_state(self.dir, lambda f: f.audits[0].budget.update(
            {"started_at": "2020-01-01T00:00:00Z"}))
        self.assertEqual(budget.check(self.dir, self.run.audit_id, "DP13", 4).allowed, 4)

    def test_pre_v03_state_file_gains_a_ledger_on_first_use(self):
        self.assertEqual(state.load_state(self.dir).audits[0].budget, {})
        decision = budget.check(self.dir, self.run.audit_id, "DP4", 4)
        self.assertEqual(decision.allowed, 4)
        self.assertEqual(self._ledger()["max_dispatches"],
                         budget.DEFAULT_MAX_DISPATCHES["deep"])

    def test_charge_has_no_lost_updates_under_concurrency(self):
        budget.init_budget(self.dir, self.run.audit_id, "deep", max_dispatches=0)
        threads = [threading.Thread(target=budget.charge,
                                    args=(self.dir, self.run.audit_id, "DP13", 1))
                   for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self._ledger()["dispatches"], 10)
        self.assertEqual(self._ledger()["by_phase"]["DP13"], 10)

    def test_unknown_audit_id_raises(self):
        with self.assertRaises(KeyError):
            budget.check(self.dir, "no-such-audit", "DP4", 1)


class TestShow(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_empty_audit_dir(self):
        self.assertEqual(budget.show(self.dir), {})

    def test_derived_numbers(self):
        run = state.init_audit(self.dir, "lite", ["LT1"], repository="o/r")
        budget.init_budget(self.dir, run.audit_id, "lite", max_dispatches=15)
        budget.charge(self.dir, run.audit_id, "LT1", 4)
        shown = budget.show(self.dir)
        self.assertEqual(shown["audit_id"], run.audit_id)
        self.assertEqual(shown["mode"], "lite")
        self.assertEqual(shown["dispatches"], 4)
        self.assertEqual(shown["remaining"], 11)
        self.assertFalse(shown["exhausted"])
        self.assertGreaterEqual(shown["elapsed_seconds"], 0)

    def test_unlimited_reports_no_remaining(self):
        run = state.init_audit(self.dir, "lite", ["LT1"], repository="o/r")
        budget.init_budget(self.dir, run.audit_id, "lite", max_dispatches=0)
        self.assertIsNone(budget.show(self.dir)["remaining"])
        self.assertFalse(budget.show(self.dir)["exhausted"])

    def test_audit_without_a_ledger_reports_its_identity_only(self):
        run = state.init_audit(self.dir, "lite", ["LT1"], repository="o/r")
        self.assertEqual(budget.show(self.dir), {"audit_id": run.audit_id, "mode": "lite"})


if __name__ == "__main__":
    unittest.main()
