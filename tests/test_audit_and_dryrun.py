import json
import os
import shlex
import tempfile
import unittest
from core.audit import AuditLogger, BODY_CAP, entry_to_curl
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

    def test_replay_fields_from_http_send(self):
        """authorize audit entry carries headers+body -> entry_to_curl replays."""
        policy = ScanPolicy("target.com", dry_run=True)
        http_send("https://target.com/login", method="POST",
                  headers={"X-Probe": "1", "Cookie": "sid=abc"},
                  data={"user": "a", "pass": "b c"}, policy=policy)

        with open(self.audit_path, "r", encoding="utf-8") as f:
            req = next(json.loads(l) for l in f
                       if l.strip() and json.loads(l)["type"] == "request")

        self.assertEqual(req["headers"]["X-Probe"], "1")
        self.assertEqual(req["body"], "user=a&pass=b+c")

        cmd = entry_to_curl(req)
        argv = shlex.split(cmd)  # must be shell-paste-safe
        self.assertIn("-X", argv)
        self.assertEqual(argv[argv.index("-X") + 1], "POST")
        self.assertIn("X-Probe: 1", argv)
        self.assertIn("user=a&pass=b+c", argv)
        self.assertEqual(argv[-1], "https://target.com/login")

    def test_body_cap_truncation(self):
        logger = AuditLogger.get_instance()
        logger.log_request("https://t/x", "POST", allowed=True, body="A" * (BODY_CAP + 500))
        with open(self.audit_path, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(len(entry["body"]), BODY_CAP)
        self.assertTrue(entry.get("body_truncated"))

    def test_entry_to_curl_skips_non_replayable(self):
        self.assertEqual(entry_to_curl(
            {"type": "request", "url": "bulk://ffuf", "method": "BULK", "allowed": True}), "")
        self.assertEqual(entry_to_curl(
            {"type": "request", "url": "https://t/", "method": "GET", "allowed": False}), "")
        self.assertEqual(entry_to_curl({"type": "response", "url": "https://t/"}), "")
        self.assertEqual(entry_to_curl({"type": "finding"}), "")
        # plain GET still replays, just no -X flag
        self.assertEqual(entry_to_curl(
            {"type": "request", "url": "https://t/a", "method": "GET", "allowed": True}),
            "curl -sk https://t/a")

    def test_log_response_entry(self):
        AuditLogger.get_instance().log_response(
            "https://t/api", "GET", status_code=403, elapsed=0.25, error=None)
        with open(self.audit_path, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["type"], "response")
        self.assertEqual(entry["status_code"], 403)
        self.assertEqual(entry["elapsed_ms"], 250.0)

    def test_trace_id_joins_request_and_response(self):
        """request + response entries from one dispatch share a trace_id."""
        policy = ScanPolicy("target.com", dry_run=False)
        policy.authorize_request("https://target.com/a", "GET", trace_id="abc123def456")
        AuditLogger.get_instance().log_response(
            "https://target.com/a", "GET", status_code=200, elapsed=0.1,
            trace_id="abc123def456")
        with open(self.audit_path, "r", encoding="utf-8") as f:
            entries = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(entries[0]["trace_id"], "abc123def456")
        self.assertEqual(entries[1]["trace_id"], "abc123def456")

    def test_log_finding_evidence_capped(self):
        AuditLogger.get_instance().log_finding(
            "LFI", "High", "https://t/x", "test", evidence="E" * 10000)
        with open(self.audit_path, "r", encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(entry["type"], "finding")
        self.assertEqual(len(entry["evidence"]), 4096)

    def test_inject_replay_curls_and_poc_override(self):
        """audit jsonl -> finding['audit_curl'] -> report PoC uses the real request."""
        AuditLogger.get_instance().log_request(
            "https://t/sqli?id=1", "GET", allowed=True,
            headers={"Cookie": "sid=xyz"}, body=None)
        findings = [
            {"url": "https://t/sqli?id=1", "type": "sqli_error", "title": "SQLi"},
            {"url": "https://t/tidak-ada", "type": "lfi", "title": "LFI"},
        ]
        from core.audit import inject_replay_curls
        matched = inject_replay_curls(findings, self.audit_path)
        self.assertEqual(matched, 1)
        self.assertIn("audit_curl", findings[0])
        self.assertNotIn("audit_curl", findings[1])

        from reports.engine import PoCGenerator
        poc = PoCGenerator.generate_poc(findings[0])
        self.assertEqual(poc["code"], findings[0]["audit_curl"])
        self.assertIn("audit trail", poc["instructions"])
        # finding tanpa audit_curl tetap pakai template generik
        poc2 = PoCGenerator.generate_poc(findings[1])
        self.assertNotIn("audit_curl", poc2["code"])

    def test_probe_ok_stashes_evidence(self):
        from modules.scanners.scanner import VulnVerifier
        finding = {}
        probe = {"status": 200, "body": "root:x:0:0:root:/root:/bin/bash", "url": "https://t/x?probe=1"}
        self.assertTrue(VulnVerifier._probe_ok(True, probe, finding))
        self.assertEqual(finding["evidence"], "root:x:0:0:root:/root:/bin/bash")
        self.assertEqual(finding["verified_url"], "https://t/x?probe=1")
        # evidence gak boleh di-overwrite oleh probe kedua
        finding2 = {"evidence": "sudah-ada"}
        VulnVerifier._probe_ok(True, {"body": "lain"}, finding2)
        self.assertEqual(finding2["evidence"], "sudah-ada")
        # kondisi gagal -> gak ada evidence, return False apa adanya
        failed = {}
        self.assertFalse(VulnVerifier._probe_ok(False, probe, failed))
        self.assertNotIn("evidence", failed)


if __name__ == "__main__":
    unittest.main()
