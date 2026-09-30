"""规模测试：50 万条规则（其中 25 万条共享同一主机），
加载后连续 1 万次判定总耗时 <=10 秒，进程峰值内存 <=512 MiB。"""
import os
import resource
import tempfile
import time
import unittest

from urlthreat import ThreatDB

SHARED_RULES = 250_000
SPREAD_RULES = 250_000
JUDGE_ROUNDS = 10_000
TIME_BUDGET_S = 10.0
MEMORY_BUDGET_BYTES = 512 * 1024 * 1024
_CATS = (frozenset({"跟踪"}), frozenset({"钓鱼"}), frozenset({"采集"}))


def _rule_stream():
    for i in range(SHARED_RULES):
        yield {
            "id": f"shared-{i}",
            "url": f"http://shared.test/p/{i}",
            "risk": i % 101,
            "categories": _CATS[i % 3],
        }
    for i in range(SPREAD_RULES):
        yield {
            "id": f"spread-{i}",
            "url": f"http://h{i}.test/x",
            "risk": i % 101,
            "categories": _CATS[i % 3],
        }


class ScaleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(cls.path)
        cls.db = ThreatDB(cls.path)
        cls.db.import_rules(_rule_stream())

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        os.remove(cls.path)

    def test_spot_check_correctness(self):
        v = self.db.judge("http://shared.test/p/42")
        self.assertEqual(v.matched_ids, ("shared-42",))
        self.assertEqual(v.max_risk, 42)
        v = self.db.judge("http://shared.test/p/42/child")
        self.assertEqual(v.matched_ids, ("shared-42",))
        v = self.db.judge("http://h777.test/x")
        self.assertEqual(v.matched_ids, ("spread-777",))
        v = self.db.judge("http://absent.test/x")
        self.assertEqual(v.matched_ids, ())
        self.assertEqual(v.max_risk, 0)

    def test_judge_performance_and_memory(self):
        urls = []
        for i in range(JUDGE_ROUNDS):
            k = i % 4
            if k == 0:
                urls.append(f"http://shared.test/p/{i % SHARED_RULES}")
            elif k == 1:
                urls.append(f"http://shared.test/p/{i % SHARED_RULES}/child")
            elif k == 2:
                urls.append(f"http://h{i % SPREAD_RULES}.test/x")
            else:
                urls.append(f"http://absent-{i}.test/x")
        start = time.perf_counter()
        hits = 0
        for u in urls:
            if self.db.judge(u).matched_ids:
                hits += 1
        elapsed = time.perf_counter() - start
        self.assertGreater(hits, 0)
        print(f"\n[scale] {JUDGE_ROUNDS} judgments in {elapsed:.2f}s "
              f"({JUDGE_ROUNDS / elapsed:.0f}/s), hits={hits}")
        self.assertLess(elapsed, TIME_BUDGET_S)
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        print(f"[scale] peak RSS: {peak / 1024 / 1024:.0f} MiB")
        self.assertLess(peak, MEMORY_BUDGET_BYTES)

    def test_replace_at_scale_then_judge(self):
        # 规则替换后性能与正确性同样适用
        self.db.import_rules([
            {"id": "shared-0", "url": "http://moved.test/y", "risk": 99, "categories": {"钓鱼"}}
        ])
        v = self.db.judge("http://shared.test/p/0")
        self.assertEqual(v.matched_ids, ())
        v = self.db.judge("http://moved.test/y")
        self.assertEqual(v.matched_ids, ("shared-0",))
        self.assertEqual(v.max_risk, 99)
        start = time.perf_counter()
        for i in range(JUDGE_ROUNDS):
            self.db.judge(f"http://shared.test/p/{i % SHARED_RULES}")
        elapsed = time.perf_counter() - start
        print(f"[scale] post-replace {JUDGE_ROUNDS} judgments in {elapsed:.2f}s")
        self.assertLess(elapsed, TIME_BUDGET_S)


if __name__ == "__main__":
    unittest.main()
