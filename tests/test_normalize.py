import unittest

from urlthreat.normalize import normalize_rule_url, normalize_url


class NormalizeTest(unittest.TestCase):
    def test_scheme_host_case_and_trailing_dot(self):
        u = normalize_url("HTTPS://X.EXAMPLE.TEST.:443/a")
        self.assertEqual(u.scheme, "https")
        self.assertEqual(u.host, "x.example.test")
        self.assertEqual(u.port, 443)

    def test_default_ports(self):
        self.assertEqual(normalize_url("http://h/").port, 80)
        self.assertEqual(normalize_url("https://h/").port, 443)
        self.assertEqual(normalize_url("http://h:8080/").port, 8080)

    def test_empty_path_is_root(self):
        self.assertEqual(normalize_url("http://h").path, "/")
        self.assertEqual(normalize_url("http://h?x=1").path, "/")

    def test_query_fragment_userinfo_ignored(self):
        u = normalize_url("http://user:pw@h/a?b=/c#d")
        self.assertEqual((u.host, u.path), ("h", "/a"))

    def test_pct_decode_unreserved_only(self):
        self.assertEqual(normalize_url("http://h/%62").path, "/b")
        self.assertEqual(normalize_url("http://h/%2f").path, "/%2F")
        self.assertEqual(normalize_url("http://h/%7e").path, "/~")
        # 不重复解码：%25 不是 unreserved，原样保留，不会再被解码成 %
        self.assertEqual(normalize_url("http://h/%2562").path, "/%2562")

    def test_dot_segments(self):
        self.assertEqual(normalize_url("http://h/a/./b").path, "/a/b")
        self.assertEqual(normalize_url("http://h/a/../b").path, "/b")
        self.assertEqual(normalize_url("http://h/../../a").path, "/a")
        self.assertEqual(normalize_url("http://h/a/.").path, "/a/")
        self.assertEqual(normalize_url("http://h/a/..").path, "/")

    def test_consecutive_slashes_preserved(self):
        self.assertEqual(normalize_url("http://h/a//b").path, "/a//b")

    def test_wildcard_rule_host(self):
        r = normalize_rule_url("https://*.Example.TEST./a")
        self.assertTrue(r.host_pattern)
        self.assertEqual(r.host, "example.test")
        self.assertFalse(normalize_rule_url("https://example.test/a").host_pattern)

    def test_bad_scheme_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://h/")


if __name__ == "__main__":
    unittest.main()
