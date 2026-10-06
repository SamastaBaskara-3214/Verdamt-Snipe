import unittest

from runners.shared import PARAM_TARGET_CAP, build_param_scan_targets


class TestParamTargetCap(unittest.TestCase):
    def test_query_param_prioritas_saat_dipotong(self):
        urls = [f"https://ex.com/p{i}?q=1" for i in range(300)]
        params = {f"/p{i}": ["guess"] for i in range(300)}
        out = build_param_scan_targets(urls, params, max_targets=10)

        self.assertEqual(len(out), 10)
        # observed query param menang atas path guess
        self.assertTrue(all(param == "q" for _, param in out))

    def test_dibawah_cap_tidak_dipotong(self):
        urls = ["https://ex.com/a?x=1", "https://ex.com/b"]
        params = {"/b": ["y"]}
        out = build_param_scan_targets(urls, params, max_targets=400)
        self.assertEqual(sorted(out), sorted([
            ("https://ex.com/a?x=1", "x"),
            ("https://ex.com/b", "y"),
        ]))

    def test_max_targets_none_artinya_unbounded(self):
        urls = [f"https://ex.com/p{i}?q=1" for i in range(500)]
        out = build_param_scan_targets(urls, {}, max_targets=None)
        self.assertEqual(len(out), 500)

    def test_cap_default_bukan_none(self):
        self.assertIsInstance(PARAM_TARGET_CAP, int)
        self.assertGreater(PARAM_TARGET_CAP, 0)

    def test_dedup_tetap_jalan(self):
        urls = ["https://ex.com/a?x=1", "https://ex.com/a?x=1"]
        out = build_param_scan_targets(urls, {}, max_targets=400)
        self.assertEqual(out, [("https://ex.com/a?x=1", "x")])


if __name__ == "__main__":
    unittest.main()
