import os
import unittest

from kavach import flags, scheduler


class TestFlagsScheduler(unittest.TestCase):
    def test_max_agents_default_and_env(self):
        os.environ.pop("KAVACH_MAX_AGENTS", None)
        self.assertEqual(flags.max_agents(), 6)
        os.environ["KAVACH_MAX_AGENTS"] = "8"
        self.assertEqual(flags.max_agents(), 8)
        del os.environ["KAVACH_MAX_AGENTS"]

    def test_plan_batches_chunks_in_order(self):
        self.assertEqual(scheduler.plan_batches([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]])

    def test_run_batch_preserves_order_and_captures_errors(self):
        def ok(x): return lambda: x * 10
        def boom(): raise ValueError("nope")
        results = scheduler.run_batch([ok(1), boom, ok(3)], cap=2)
        self.assertEqual(results[0], 10)
        self.assertIsInstance(results[1], ValueError)
        self.assertEqual(results[2], 30)


if __name__ == "__main__":
    unittest.main()
