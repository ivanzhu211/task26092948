from __future__ import annotations

from dataclasses import dataclass, field

CATEGORIES = frozenset({"跟踪", "钓鱼", "采集"})


@dataclass(frozen=True)
class Rule:
    id: str
    url: str
    risk: int
    categories: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("rule id must be non-empty")
        if not 0 <= self.risk <= 100:
            raise ValueError(f"risk out of range [0, 100]: {self.risk}")
        cats = frozenset(self.categories)
        unknown = cats - CATEGORIES
        if unknown:
            raise ValueError(f"unknown categories: {sorted(unknown)}")
        object.__setattr__(self, "categories", cats)


@dataclass(frozen=True)
class MatchResult:
    ids: tuple[str, ...]
    risk: int
    categories: frozenset[str]
