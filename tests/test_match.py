import pytest

from urlthreat import Rule, ThreatDB

TARGET = "HTTPS://X.EXAMPLE.TEST.:443/a/%62/../b/c?q=/ab#f"


@pytest.fixture()
def db(tmp_path):
    with ThreatDB(str(tmp_path / "rules.sqlite")) as db:
        db.import_rules(
            [
                Rule("A", "https://*.example.test/a", 40, frozenset({"跟踪"})),
                Rule("B", "https://x.example.test/a/b", 85, frozenset({"钓鱼"})),
            ]
        )
        yield db


def test_acceptance_hit(db):
    r = db.judge(TARGET)
    assert set(r.ids) == {"A", "B"}
    assert r.risk == 85
    assert r.categories == {"跟踪", "钓鱼"}


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/a",
        "https://x.example.test/ab",
        "https://x.example.test/a%2Fb",
    ],
)
def test_acceptance_miss(db, url):
    r = db.judge(url)
    assert r.ids == ()
    assert r.risk == 0
    assert r.categories == frozenset()


def test_wildcard_matches_any_depth(db):
    assert "A" in db.judge("https://y.x.example.test/a").ids
    assert "A" not in db.judge("https://example.test/a").ids


def test_scheme_and_port_must_match(db):
    assert db.judge("http://x.example.test/a/b").ids == ()
    assert db.judge("https://x.example.test:8443/a/b").ids == ()


def test_path_case_sensitive(db):
    assert db.judge("https://x.example.test/A/b").ids == ()


def test_root_rule_matches_all_paths(tmp_path):
    with ThreatDB(str(tmp_path / "r.sqlite")) as db:
        db.import_rules([Rule("R", "https://h.test", 5, frozenset({"采集"}))])
        assert db.judge("https://h.test/any/thing").ids == ("R",)
        assert db.judge("https://h.test").ids == ("R",)


def test_trailing_slash_rule(tmp_path):
    with ThreatDB(str(tmp_path / "r.sqlite")) as db:
        db.import_rules([Rule("R", "https://h.test/a/", 5, frozenset({"采集"}))])
        assert db.judge("https://h.test/a").ids == ()
        assert db.judge("https://h.test/a/").ids == ("R",)
        assert db.judge("https://h.test/a/b").ids == ("R",)


def test_multiple_hits_union_categories(tmp_path):
    with ThreatDB(str(tmp_path / "r.sqlite")) as db:
        db.import_rules(
            [
                Rule("R1", "https://h.test/a", 30, frozenset({"跟踪"})),
                Rule("R2", "https://h.test/a/b", 70, frozenset({"采集"})),
                Rule("R3", "https://h.test/a/b/c", 50, frozenset({"钓鱼"})),
            ]
        )
        r = db.judge("https://h.test/a/b/c/d")
        assert set(r.ids) == {"R1", "R2", "R3"}
        assert r.risk == 70
        assert r.categories == {"跟踪", "采集", "钓鱼"}
