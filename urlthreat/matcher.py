"""内存索引与匹配。

索引结构：(scheme, port) -> host -> path -> 规则条目列表。
精确主机与 "*." 通配主机分表；目标主机按各级后缀探测通配表。
路径匹配通过枚举目标路径的全部合法规则前缀候选完成，
候选数量为路径斜杠数级别（性能包线内 <=16 段），查找为 O(1) 字典命中。
"""
from __future__ import annotations

from typing import Iterable

from .normalize import NormalizedURL, normalize_rule_url
from .store import Rule

# 条目：(rule_id, risk, categories)
Entry = tuple[str, int, frozenset[str]]
_PathMap = dict[str, list[Entry]]
_HostMap = dict[str, _PathMap]


class RuleIndex:
    """规则内存索引，支持主机/路径前缀快速匹配。"""

    def __init__(self) -> None:
        self._exact: dict[tuple[str, int], _HostMap] = {}
        self._wild: dict[tuple[str, int], _HostMap] = {}
        self._interned_categories: dict[frozenset[str], frozenset[str]] = {}

    def _intern(self, categories: frozenset[str]) -> frozenset[str]:
        cached = self._interned_categories.get(categories)
        if cached is None:
            self._interned_categories[categories] = categories
            return categories
        return cached

    def build(self, rules: Iterable[Rule]) -> None:
        self._exact.clear()
        self._wild.clear()
        for rule in rules:
            norm = normalize_rule_url(rule.url)
            table = self._wild if norm.host_pattern else self._exact
            host_map = table.setdefault((norm.scheme, norm.port), {})
            path_map = host_map.setdefault(norm.host, {})
            bucket = path_map.setdefault(norm.path, [])
            bucket.append((rule.rule_id, rule.risk, self._intern(rule.categories)))

    @staticmethod
    def _collect(path_map: _PathMap, target_path: str, out: list[Entry]) -> None:
        seen: set[int] = set()

        def add(bucket: list[Entry] | None) -> None:
            if bucket is not None and id(bucket) not in seen:
                seen.add(id(bucket))
                out.extend(bucket)

        add(path_map.get(target_path))
        for i, ch in enumerate(target_path):
            if ch == "/":
                add(path_map.get(target_path[: i + 1]))  # 规则路径以斜杠结尾（含根路径）
                if i > 0:
                    add(path_map.get(target_path[:i]))  # 目标紧接其后的字符为斜杠

    def match(self, target: NormalizedURL) -> list[Entry]:
        """返回全部命中条目 (rule_id, risk, categories)。"""
        key = (target.scheme, target.port)
        out: list[Entry] = []
        exact = self._exact.get(key)
        if exact is not None:
            path_map = exact.get(target.host)
            if path_map is not None:
                self._collect(path_map, target.path, out)
        wild = self._wild.get(key)
        if wild is not None:
            host = target.host
            idx = host.find(".")
            while idx != -1:
                path_map = wild.get(host[idx + 1 :])
                if path_map is not None:
                    self._collect(path_map, target.path, out)
                idx = host.find(".", idx + 1)
        return out
