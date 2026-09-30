"""SQLite 规则持久化。"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Iterator, Sequence

VALID_CATEGORIES = frozenset({"跟踪", "钓鱼", "采集"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    rule_id   TEXT PRIMARY KEY,
    url       TEXT NOT NULL,
    risk      INTEGER NOT NULL CHECK (risk BETWEEN 0 AND 100),
    categories TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Rule:
    """一条威胁规则。"""

    rule_id: str
    url: str
    risk: int
    categories: frozenset[str]

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id must be non-empty")
        if not 0 <= self.risk <= 100:
            raise ValueError(f"risk out of range: {self.risk}")
        unknown = set(self.categories) - VALID_CATEGORIES
        if unknown:
            raise ValueError(f"unknown categories: {unknown}")


class RuleStore:
    """基于 SQLite 的规则存储。同 ID 重导即完整替换。"""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def replace_all(self, rules: Sequence[Rule]) -> None:
        """批量导入：同 ID 完整替换，其余旧规则保留。"""
        with self._conn:
            self._conn.executemany(
                "INSERT OR REPLACE INTO rules (rule_id, url, risk, categories)"
                " VALUES (?, ?, ?, ?)",
                [
                    (r.rule_id, r.url, r.risk, json.dumps(sorted(r.categories), ensure_ascii=False))
                    for r in rules
                ],
            )

    def iter_rules(self) -> Iterator[Rule]:
        cur = self._conn.execute("SELECT rule_id, url, risk, categories FROM rules")
        for rule_id, url, risk, categories in cur:
            yield Rule(
                rule_id=rule_id,
                url=url,
                risk=risk,
                categories=frozenset(json.loads(categories)),
            )

    def close(self) -> None:
        self._conn.close()
