from __future__ import annotations

from typing import Iterable, Tuple

from .models import MatchResult, Rule
from .normalize import NormalizedURL

_Entry = Tuple[str, int, frozenset, bool]
_Bucket = dict[tuple[str, ...], list[_Entry]]


def _host_keys(host: str) -> list[str]:
    keys = [host]
    labels = host.split(".")
    for i in range(1, len(labels)):
        keys.append("*." + ".".join(labels[i:]))
    return keys


class RuleIndex:
    def __init__(self) -> None:
        self._buckets: dict[tuple[str, str, int], _Bucket] = {}

    def rebuild(self, rules: Iterable[Tuple[Rule, NormalizedURL]]) -> None:
        self._buckets = {}
        buckets = self._buckets
        for rule, norm in rules:
            key = (norm.scheme, norm.host, norm.port)
            bucket = buckets.get(key)
            if bucket is None:
                bucket = {}
                buckets[key] = bucket
            segments = norm.segments
            needs_extra = segments[-1] == ""
            if needs_extra:
                segments = segments[:-1]
            entry = (rule.id, rule.risk, rule.categories, needs_extra)
            existing = bucket.get(segments)
            if existing is None:
                bucket[segments] = [entry]
            else:
                existing.append(entry)

    def match(self, target: NormalizedURL) -> MatchResult:
        ids: list[str] = []
        max_risk = 0
        categories: set[str] = set()
        target_segments = target.segments
        target_len = len(target_segments)
        for host_key in _host_keys(target.host):
            bucket = self._buckets.get((target.scheme, host_key, target.port))
            if bucket is None:
                continue
            for depth in range(1, target_len + 1):
                entries = bucket.get(target_segments[:depth])
                if entries is None:
                    continue
                for rule_id, risk, cats, needs_extra in entries:
                    if needs_extra and target_len <= depth:
                        continue
                    ids.append(rule_id)
                    if risk > max_risk:
                        max_risk = risk
                    categories.update(cats)
        return MatchResult(tuple(ids), max_risk, frozenset(categories))
