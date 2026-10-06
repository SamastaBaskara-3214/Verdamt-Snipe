import json
import os
import tempfile
import unittest
from core.audit import AuditLogger
from core.policy import ScanPolicy
from core.client import http_send, AsyncNetworkEngine


class TestAuditAndDryRun(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.audit_path = os.path.join(self.tmp_dir.name, "audit_test.jsonl")
        AuditLogger.configure(self.audit_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_audit_logger_records_requests(self):
        logger = AuditLogger.get_instance()
        logger.log_request("https://target.com/api", "POST", status_code=200, elapsed=0.12, allowed=True)
        logger.log_finding("XSS", "High", "https://target.com/api", "Reflected XSS")

        self.assertTrue(os.path.exists(self.audit_path))
        with open(self.audit_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["type"], "request")
        self.assertEqual(lines[0]["url"], "https://target.com/api")
        self.assertEqual(lines[0]["method"], "POST")

        self.assertEqual(lines[1]["type"], "finding")
        self.assertEqual(lines[1]["title"], "XSS")
        self.assertEqual(lines[1]["severity"], "High")

    def test_dry_run_mode_policy(self):
        policy = ScanPolicy("target.com", dry_run=True)
        self.assertTrue(policy.dry_run)

        # Test sync http_send short-circuit under dry_run
        res = http_send("https://target.com/test", policy=policy)
        self.assertEqual(res["status"], 200)
        self.assertIn("DRY RUN", res["body"])
        self.assertEqual(res["headers"].get("x-verdamt-dry-run"), "1")


if __name__ == "__main__":
    unittest.main()
