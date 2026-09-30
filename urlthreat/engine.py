"""上层调用入口：ThreatDB 直接由上层代码调用，无接口层。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .matcher import RuleIndex
from .normalize import normalize_url
from .store import Rule, RuleStore

_IMPORT_CHUNK = 20000


@dataclass(frozen=True)
class Verdict:
    """判定结果：全部命中 ID、命中规则中的最高风险分、类别并集。"""

    matched_ids: tuple[str, ...]
    max_risk: int
    categories: frozenset[str]


class ThreatDB:
    """本地 URL 威胁判定库。规则持久化到 SQLite，判定走内存索引。"""

    def __init__(self, path: str) -> None:
        self._store = RuleStore(path)
        self._index = RuleIndex()
        self._index.build(self._store.iter_rules())

    def import_rules(self, rules: Iterable[Mapping[str, object]]) -> None:
        """批量导入规则：{id, url, risk, categories}。同 ID 完整替换。"""
        chunk: list[Rule] = []
        for r in rules:
            chunk.append(
                Rule(
                    rule_id=str(r["id"]),
                    url=str(r["url"]),
                    risk=int(r["risk"]),
                    categories=frozenset(str(c) for c in r["categories"]),  # type: ignore[union-attr]
                )
            )
            if len(chunk) >= _IMPORT_CHUNK:
                self._store.replace_all(chunk)
                chunk.clear()
        if chunk:
            self._store.replace_all(chunk)
        self._index.build(self._store.iter_rules())

    def judge(self, url: str) -> Verdict:
        entries = self._index.match(normalize_url(url))
        if not entries:
            return Verdict(matched_ids=(), max_risk=0, categories=frozenset())
        ids = sorted(e[0] for e in entries)
        max_risk = max(e[1] for e in entries)
        categories = frozenset().union(*(e[2] for e in entries))
        return Verdict(matched_ids=tuple(ids), max_risk=max_risk, categories=categories)

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "ThreatDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
