"""Refund audit: charged-but-never-dispatched must be visible in jsonl."""
import json
import os
import tempfile
import unittest

from core.audit import AuditLogger
from core.policy import ScanPolicy


class TestRefundAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        AuditLogger.configure(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def _entries(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def test_refund_writes_entry_and_returns_budget(self):
        policy = ScanPolicy("target.com", max_requests=5)
        policy.authorize_request("https://target.com/a", "GET",
                                 trace_id="traceREFUND")
        self.assertEqual(policy.requests_sent, 1)

        policy.refund_request(reason="rate_limited:host target.com",
                              url="https://target.com/a",
                              trace_id="traceREFUND")
        self.assertEqual(policy.requests_sent, 0)

        entries = self._entries()
        self.assertEqual([e["type"] for e in entries], ["request", "refund"])
        refund = entries[1]
        self.assertEqual(refund["reason"],
                         "rate_limited:host target.com")
        self.assertEqual(refund["url"], "https://target.com/a")
        self.assertEqual(refund["trace_id"], "traceREFUND")

    def test_refund_at_zero_budget_writes_nothing(self):
        policy = ScanPolicy("target.com", max_requests=5)
        policy.refund_request(reason="ghost")  # nothing charged
        self.assertFalse(os.path.exists(self.path))

    def test_refund_without_args_still_audits(self):
        policy = ScanPolicy("target.com", max_requests=5)
        policy.authorize_request("https://target.com/b", "GET")
        policy.refund_request()
        entries = self._entries()
        self.assertEqual(entries[-1]["type"], "refund")
        self.assertEqual(entries[-1]["reason"], "unspecified")


if __name__ == "__main__":
    unittest.main()
