import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.mutator import PayloadMutator


class TestPayloadMutator(unittest.TestCase):
    def setUp(self):
        self.mutator = PayloadMutator(aggressiveness=2)

    def test_query_params_mutation(self):
        url = "https://example.com/api?id=10&category=news"
        mutated = self.mutator.mutate_query_params(url)
        self.assertGreater(len(mutated), 0)
        # Check for HPP (duplicate params) or array notation
        has_hpp_or_array = any("mutated_hpp" in m or "id[]=" in m for m in mutated)
        self.assertTrue(has_hpp_or_array)

    def test_json_mutation(self):
        json_data = {"user": "admin", "role_id": 1}
        mutated = self.mutator.mutate_json(json_data)
        self.assertGreater(len(mutated), 0)
        # Check for prototype pollution key injection
        has_proto = any("__proto__" in m for m in mutated if isinstance(m, dict))
        self.assertTrue(has_proto)

    def test_path_mutation(self):
        path = "etc/passwd"
        mutated = self.mutator.mutate_path(path)
        self.assertGreater(len(mutated), 0)
        has_traversal = any("../" in m or "%c0%af" in m for m in mutated)
        self.assertTrue(has_traversal)

    def test_anomaly_detection(self):
        baseline = {"status": 200, "body": "OK", "time": 0.1}
        
        # Test 500 error anomaly
        res_500 = {"status": 500, "body": "Internal Error", "time": 0.1}
        anomaly = PayloadMutator.detect_anomaly(baseline, res_500)
        self.assertIsNotNone(anomaly)
        self.assertIn("500", anomaly)

        # Test timing anomaly
        res_slow = {"status": 200, "body": "OK", "time": 3.5}
        anomaly_time = PayloadMutator.detect_anomaly(baseline, res_slow)
        self.assertIsNotNone(anomaly_time)
        self.assertIn("Timing anomaly", anomaly_time)

        # Test error leak
        res_leak = {"status": 200, "body": "Traceback (most recent call last):", "time": 0.1}
        anomaly_leak = PayloadMutator.detect_anomaly(baseline, res_leak)
        self.assertIsNotNone(anomaly_leak)
        self.assertIn("Error leak", anomaly_leak)


if __name__ == "__main__":
    unittest.main()
