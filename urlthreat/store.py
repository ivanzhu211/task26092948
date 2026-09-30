from __future__ import annotations

import json
import sqlite3
from typing import Iterable, Iterator

from .models import Rule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    risk INTEGER NOT NULL,
    categories TEXT NOT NULL
)
"""

_BATCH = 10000


class RuleStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def replace_rules(self, rules: Iterable[Rule]) -> None:
        batch: list[tuple] = []
        with self._conn:
            for rule in rules:
                batch.append(
                    (rule.id, rule.url, rule.risk,
                     json.dumps(sorted(rule.categories)))
                )
                if len(batch) >= _BATCH:
                    self._conn.executemany(
                        "INSERT OR REPLACE INTO rules"
                        " (id, url, risk, categories) VALUES (?, ?, ?, ?)",
                        batch,
                    )
                    batch.clear()
            if batch:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO rules"
                    " (id, url, risk, categories) VALUES (?, ?, ?, ?)",
                    batch,
                )

    def iter_all(self) -> Iterator[Rule]:
        cursor = self._conn.execute(
            "SELECT id, url, risk, categories FROM rules"
        )
        for row in cursor:
            yield Rule(
                id=row[0],
                url=row[1],
                risk=row[2],
                categories=frozenset(json.loads(row[3])),
            )

    def close(self) -> None:
        self._conn.close()
