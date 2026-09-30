from __future__ import annotations

from typing import Iterable, Iterator

from .index import RuleIndex
from .models import MatchResult, Rule
from .normalize import normalize_url
from .store import RuleStore


def _validated(rules: Iterable[Rule]) -> Iterator[Rule]:
    for rule in rules:
        normalize_url(rule.url)
        yield rule


class ThreatDB:
    def __init__(self, path: str) -> None:
        self._store = RuleStore(path)
        self._index = RuleIndex()
        self._reload()

    def _reload(self) -> None:
        self._index.rebuild(
            (rule, normalize_url(rule.url)) for rule in self._store.iter_all()
        )

    def import_rules(self, rules: Iterable[Rule]) -> None:
        self._store.replace_rules(_validated(rules))
        self._reload()

    def judge(self, url: str) -> MatchResult:
        return self._index.match(normalize_url(url))

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "ThreatDB":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
