"""Characterization tests for the CLI parser (Tahap 2 refactor safety net).

These pin the CURRENT behavior of verd.py's flag grammar BEFORE the parsing
block moves to core/cli_parser.py. verd.py re-exports every name after the
move, so this file must pass unchanged on both sides of the refactor.
"""
import os
import tempfile
import unittest

from verd import (
    parse_target,
    parse_scan_args,
    parse_mode,
    parse_cli_headers,
    parse_scan_policy_options,
    _flag_value,
    _VALUE_FLAGS,
    _SHORT_ALIASES,
)


class TestParseScanArgs(unittest.TestCase):
    def test_no_args(self):
        self.assertEqual(parse_scan_args(["verd.py"]), (None, [], None))

    def test_target_only(self):
        self.assertEqual(parse_scan_args(["verd.py", "target.com"]),
                         ("target.com", [], None))

    def test_target_before_and_after_flag(self):
        a = parse_scan_args(["verd.py", "target.com", "--recon"])
        b = parse_scan_args(["verd.py", "--recon", "target.com"])
        self.assertEqual(a, b)
        self.assertEqual(a, ("target.com", ["--recon"], None))

    def test_short_proxy_alias_normalized(self):
        target, flags, _ = parse_scan_args(
            ["verd.py", "-p", "socks5://127.0.0.1:9050", "target.com"])
        self.assertEqual(target, "target.com")
        self.assertEqual(flags, ["--proxy", "socks5://127.0.0.1:9050"])

    def test_value_flag_swallows_next_token(self):
        # target must NOT be eaten as the value of --allowed-hosts
        target, flags, _ = parse_scan_args(
            ["verd.py", "--allowed-hosts", "a.com,b.com", "target.com"])
        self.assertEqual(target, "target.com")
        self.assertIn("--allowed-hosts", flags)

    def test_resume_bare_first_arg(self):
        self.assertEqual(parse_scan_args(["verd.py", "--resume"]),
                         (None, ["--resume"], None))

    def test_resume_with_path_first_arg(self):
        self.assertEqual(
            parse_scan_args(["verd.py", "--resume", "outputs/x.state"]),
            (None, ["--resume", "outputs/x.state"], "outputs/x.state"))

    def test_resume_mid_flags_with_target(self):
        target, flags, resume = parse_scan_args(
            ["verd.py", "target.com", "--resume", "out.state"])
        self.assertEqual(target, "target.com")
        self.assertEqual(resume, "out.state")

    def test_numeric_launcher_forms_are_snipe_side(self):
        # snipe maps `5 target` to `target --full`; verd never sees the digit
        target, flags, _ = parse_scan_args(["verd.py", "target.com", "--full"])
        self.assertEqual((target, flags), ("target.com", ["--full"]))


class TestParseMode(unittest.TestCase):
    def test_mode_flags(self):
        for flag, mode in [("--recon", "recon"), ("--recon-light", "recon_light"),
                           ("--app", "app"), ("--assault", "assault"),
                           ("--poisoning", "poisoning"), ("--full", "full"),
                           ("--nuclei", "nuclei")]:
            self.assertEqual(parse_mode([flag]), mode)

    def test_last_mode_wins(self):
        self.assertEqual(parse_mode(["--recon", "--full"]), "full")

    def test_no_mode_returns_none(self):
        self.assertIsNone(parse_mode(["--stealth"]))


class TestParseCliHeaders(unittest.TestCase):
    def test_bearer_and_cookie(self):
        h1, h2 = parse_cli_headers(["--bearer", "tok123", "--cookie", "a=b"])
        self.assertEqual(h1["Authorization"], "Bearer tok123")
        self.assertEqual(h1["Cookie"], "a=b")
        self.assertEqual(h2, {})

    def test_header_pairs_and_second_header_set(self):
        h1, h2 = parse_cli_headers(
            ["-H", "X-Api: v1", "-H2", "X-Api: v2", "--bearer2", "t2"])
        self.assertEqual(h1["X-Api"], "v1")
        self.assertEqual(h2["X-Api"], "v2")
        self.assertEqual(h2["Authorization"], "Bearer t2")

    def test_bearer_from_env(self):
        os.environ["VERDAMT_TEST_TOK"] = "env-secret-42"
        try:
            h1, _ = parse_cli_headers(["--bearer", "env:VERDAMT_TEST_TOK"])
            self.assertEqual(h1["Authorization"], "Bearer env-secret-42")
        finally:
            del os.environ["VERDAMT_TEST_TOK"]

    def test_bearer_missing_env_exits(self):
        with self.assertRaises(SystemExit):
            parse_cli_headers(["--bearer", "env:VERDAMT_TIDAK_ADA"])

    def test_bearer_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tok",
                                         delete=False) as fh:
            fh.write("file-secret-99\nline2-ignored\n")
            path = fh.name
        try:
            h1, _ = parse_cli_headers(["--bearer-file", path])
            self.assertEqual(h1["Authorization"], "Bearer file-secret-99")
        finally:
            os.unlink(path)


class TestParsePolicyOptions(unittest.TestCase):
    def test_defaults(self):
        opts = parse_scan_policy_options([])
        self.assertEqual(opts["mode"], "active")
        self.assertEqual(opts["max_requests"], 10_000)
        self.assertEqual(opts["allowed_ports"], (80, 443))
        self.assertFalse(opts["dry_run"])

    def test_numeric_and_scope_flags(self):
        opts = parse_scan_policy_options(
            ["--max-requests", "500", "--allowed-ports", "8443,8080",
             "--allowed-hosts", "a.com, b.com", "--dry-run", "--passive"])
        self.assertEqual(opts["max_requests"], 500)
        self.assertEqual(opts["allowed_ports"], (8080, 8443))
        self.assertEqual(opts["allowed_hosts"], ("a.com", "b.com"))
        self.assertTrue(opts["dry_run"])
        self.assertEqual(opts["mode"], "passive")

    def test_invalid_numbers_raise(self):
        with self.assertRaises(ValueError):
            parse_scan_policy_options(["--max-requests", "abc"])
        with self.assertRaises(ValueError):
            parse_scan_policy_options(["--allowed-ports", "99999"])

    def test_audit_log_passthrough(self):
        opts = parse_scan_policy_options(["--audit-log", "outputs/a.jsonl"])
        self.assertEqual(opts["audit_log"], "outputs/a.jsonl")


class TestHelpers(unittest.TestCase):
    def test_flag_value_equals_and_space_forms(self):
        self.assertEqual(_flag_value(["--max-time", "9"], "--max-time"), "9")
        self.assertEqual(_flag_value(["--max-time=9"], "--max-time"), "9")
        self.assertIsNone(_flag_value(["--other"], "--max-time"))

    def test_value_flag_and_alias_tables(self):
        self.assertIn("-p", _VALUE_FLAGS)
        self.assertIn("--allowed-hosts", _VALUE_FLAGS)
        self.assertEqual(_SHORT_ALIASES["-p"], "--proxy")
        self.assertEqual(_SHORT_ALIASES["-r"], "--resume")

    def test_parse_target(self):
        self.assertEqual(parse_target("a.com"), ("a.com", "https://a.com"))
        self.assertEqual(parse_target("https://a.com/p?q=1"),
                         ("a.com", "https://a.com/p?q=1"))


if __name__ == "__main__":
    unittest.main()
