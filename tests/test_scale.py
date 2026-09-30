import resource
import time

import pytest

from urlthreat import Rule, ThreatDB

TOTAL = 500_000
SHARED_HOST = 250_000
JUDGE_ROUNDS = 10_000
MAX_JUDGE_SECONDS = 10.0
MAX_RSS_BYTES = 512 * 1024 * 1024


def _make_rules():
    for i in range(SHARED_HOST):
        yield Rule(f"shared-{i}", f"https://bulk.test/p{i}/x", i % 101,
                   frozenset({"跟踪"}))
    for i in range(TOTAL - SHARED_HOST):
        yield Rule(f"host-{i}", f"https://h{i}.test/a/b", i % 101,
                   frozenset({"钓鱼"}))


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("scale") / "rules.sqlite")
    db = ThreatDB(path)
    db.import_rules(_make_rules())
    yield db
    db.close()


def _judge_rounds(db):
    start = time.perf_counter()
    hits = 0
    for i in range(JUDGE_ROUNDS):
        r = db.judge(f"https://bulk.test/p{i % SHARED_HOST}/x")
        hits += len(r.ids)
        r = db.judge(f"https://h{i}.test/a/b/c")
        hits += len(r.ids)
        db.judge(f"https://miss{i}.test/none")
    elapsed = time.perf_counter() - start
    assert hits > 0
    return elapsed


def test_judge_performance(db):
    elapsed = _judge_rounds(db)
    assert elapsed < MAX_JUDGE_SECONDS, f"{JUDGE_ROUNDS} judgments took {elapsed:.2f}s"


def test_memory_limit(db):
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert rss < MAX_RSS_BYTES, f"peak RSS {rss / 1024 / 1024:.0f} MiB"


def test_performance_after_replace(db):
    db.import_rules(
        [Rule(f"shared-{i}", f"https://bulk.test/q{i}/y", 1,
              frozenset({"采集"})) for i in range(1000)]
    )
    elapsed = _judge_rounds(db)
    assert elapsed < MAX_JUDGE_SECONDS, (
        f"after replace, {JUDGE_ROUNDS} judgments took {elapsed:.2f}s"
    )
