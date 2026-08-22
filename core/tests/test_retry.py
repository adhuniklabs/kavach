import os
import unittest
from kavach import retry


class TestRetry(unittest.TestCase):
    def test_backoff_doubles_and_caps(self):
        self.assertEqual(retry.backoff_ms(1, base_ms=5000, cap_ms=120000), 5000)
        self.assertEqual(retry.backoff_ms(2, base_ms=5000, cap_ms=120000), 10000)
        self.assertEqual(retry.backoff_ms(6, base_ms=5000, cap_ms=120000), 120000)

    def test_env_reader(self):
        os.environ["KAVACH_TEST_N"] = "7"
        self.assertEqual(retry.read_positive_int_env("KAVACH_TEST_N", 3), 7)
        os.environ["KAVACH_TEST_N"] = "-1"
        self.assertEqual(retry.read_positive_int_env("KAVACH_TEST_N", 3), 3)
        del os.environ["KAVACH_TEST_N"]
        self.assertEqual(retry.read_positive_int_env("KAVACH_TEST_N", 3), 3)


if __name__ == "__main__":
    unittest.main()
