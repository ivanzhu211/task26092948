import os
import tempfile
import unittest

from urlthreat import ThreatDB

TARGET = "HTTPS://X.EXAMPLE.TEST.:443/a/%62/../b/c?q=/ab#f"
RULE_A = {"id": "A", "url": "https://*.example.test/a", "risk": 40, "categories": {"跟踪"}}
RULE_B = {"id": "B", "url": "https://x.example.test/a/b", "risk": 85, "categories": {"钓鱼"}}


class AcceptanceTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        self.db = ThreatDB(self.path)
        self.db.import_rules([RULE_A, RULE_B])

    def tearDown(self):
        self.db.close()
        os.remove(self.path)

    def test_hit_both_rules(self):
        v = self.db.judge(TARGET)
        self.assertEqual(v.matched_ids, ("A", "B"))
        self.assertEqual(v.max_risk, 85)
        self.assertEqual(v.categories, frozenset({"跟踪", "钓鱼"}))

    def test_no_hit_cases(self):
        for url in (
            "https://example.test/a",       # 通配不匹配域名自身
            "https://x.example.test/ab",    # /a 不匹配 /ab
            "https://x.example.test/a%2Fb", # 编码斜杠不是分隔符
        ):
            v = self.db.judge(url)
            self.assertEqual(v.matched_ids, (), url)
            self.assertEqual(v.max_risk, 0, url)
            self.assertEqual(v.categories, frozenset(), url)

    def test_replace_and_reopen(self):
        self.db.import_rules([
            {"id": "B", "url": "https://other.test/a/b", "risk": 85, "categories": {"钓鱼"}}
        ])
        v = self.db.judge(TARGET)
        self.assertEqual(v.matched_ids, ("A",))
        self.assertEqual(v.max_risk, 40)
        self.assertEqual(v.categories, frozenset({"跟踪"}))
        self.db.close()
        self.db = ThreatDB(self.path)  # 重新打开结果不变
        v = self.db.judge(TARGET)
        self.assertEqual(v.matched_ids, ("A",))
        self.assertEqual(v.max_risk, 40)
        self.assertEqual(v.categories, frozenset({"跟踪"}))


class MatchingSemanticsTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        self.db = ThreatDB(self.path)

    def tearDown(self):
        self.db.close()
        os.remove(self.path)

    def judge_ids(self, url):
        return self.db.judge(url).matched_ids

    def test_root_matches_all_paths_on_host(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test/", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://h.test/any/thing"), ("R",))
        self.assertEqual(self.judge_ids("http://h.test"), ("R",))

    def test_prefix_requires_boundary(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test/a", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://h.test/a/b"), ("R",))
        self.assertEqual(self.judge_ids("http://h.test/ab"), ())
        self.assertEqual(self.judge_ids("http://h.test/a"), ("R",))

    def test_trailing_slash_rule_prefix(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test/a/", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://h.test/a/b"), ("R",))
        self.assertEqual(self.judge_ids("http://h.test/a"), ())

    def test_path_case_sensitive(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test/Ab", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://h.test/ab"), ())
        self.assertEqual(self.judge_ids("http://h.test/Ab"), ("R",))

    def test_scheme_and_port_must_match(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test:8080/a", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://h.test:8080/a"), ("R",))
        self.assertEqual(self.judge_ids("http://h.test/a"), ())
        self.assertEqual(self.judge_ids("https://h.test:8080/a"), ())

    def test_default_port_equivalence(self):
        self.db.import_rules([{"id": "R", "url": "https://h.test:443/a", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("https://h.test/a"), ("R",))

    def test_wildcard_depth(self):
        self.db.import_rules([{"id": "R", "url": "http://*.h.test/a", "risk": 1, "categories": set()}])
        self.assertEqual(self.judge_ids("http://x.h.test/a"), ("R",))
        self.assertEqual(self.judge_ids("http://x.y.h.test/a"), ("R",))
        self.assertEqual(self.judge_ids("http://h.test/a"), ())
        self.assertEqual(self.judge_ids("http://noth.test/a"), ())

    def test_full_replace_on_reimport(self):
        self.db.import_rules([{"id": "R", "url": "http://h.test/a", "risk": 10, "categories": {"跟踪"}}])
        self.db.import_rules([{"id": "R", "url": "http://other.test/b", "risk": 20, "categories": {"采集"}}])
        self.assertEqual(self.judge_ids("http://h.test/a"), ())
        v = self.db.judge("http://other.test/b")
        self.assertEqual(v.matched_ids, ("R",))
        self.assertEqual(v.max_risk, 20)
        self.assertEqual(v.categories, frozenset({"采集"}))

    def test_all_hits_returned_not_overridden(self):
        self.db.import_rules([
            {"id": "P1", "url": "http://h.test/", "risk": 10, "categories": {"跟踪"}},
            {"id": "P2", "url": "http://h.test/a", "risk": 30, "categories": {"采集"}},
            {"id": "P3", "url": "http://h.test/a/b", "risk": 20, "categories": {"钓鱼"}},
        ])
        v = self.db.judge("http://h.test/a/b")
        self.assertEqual(v.matched_ids, ("P1", "P2", "P3"))
        self.assertEqual(v.max_risk, 30)
        self.assertEqual(v.categories, frozenset({"跟踪", "采集", "钓鱼"}))

    def test_invalid_rule_rejected(self):
        with self.assertRaises(ValueError):
            self.db.import_rules([{"id": "X", "url": "http://h/", "risk": 101, "categories": set()}])
        with self.assertRaises(ValueError):
            self.db.import_rules([{"id": "X", "url": "http://h/", "risk": 1, "categories": {"未知"}}])


if __name__ == "__main__":
    unittest.main()
