from urlthreat import Rule, ThreatDB

TARGET = "HTTPS://X.EXAMPLE.TEST.:443/a/%62/../b/c?q=/ab#f"


def test_replace_same_id_removes_old_rule(tmp_path):
    path = str(tmp_path / "rules.sqlite")
    with ThreatDB(path) as db:
        db.import_rules(
            [
                Rule("A", "https://*.example.test/a", 40, frozenset({"跟踪"})),
                Rule("B", "https://x.example.test/a/b", 85, frozenset({"钓鱼"})),
            ]
        )
        db.import_rules(
            [Rule("B", "https://other.test/a/b", 85, frozenset({"钓鱼"}))]
        )
        r = db.judge(TARGET)
        assert set(r.ids) == {"A"}
        assert r.risk == 40
        assert r.categories == {"跟踪"}
        assert db.judge("https://other.test/a/b").ids == ("B",)

    with ThreatDB(path) as db:
        r = db.judge(TARGET)
        assert set(r.ids) == {"A"}
        assert r.risk == 40
        assert r.categories == {"跟踪"}


def test_reopen_preserves_results(tmp_path):
    path = str(tmp_path / "rules.sqlite")
    with ThreatDB(path) as db:
        db.import_rules(
            [Rule("A", "https://a.test/x", 60, frozenset({"采集"}))]
        )
        before = db.judge("https://a.test/x/1")
    with ThreatDB(path) as db:
        after = db.judge("https://a.test/x/1")
    assert before == after
    assert after.ids == ("A",)
