"""URL 解析与规范化。

规则与目标共用同一套规范化语义：
- 协议、主机忽略大小写；主机去掉末尾的一个点。
- 省略端口等价于 HTTP 80 / HTTPS 443。
- 空路径视为根路径；查询、片段、用户信息不参与匹配。
- 百分号编码仅解码 ASCII 字母数字及 "-._~"，其余保留并将十六进制字母转为大写，不重复解码。
- 消除单点/双点路径段，双点回退一段且不越过根；连续斜杠保留；末尾点段处理后保留目录斜杠。
"""
from __future__ import annotations

import string
from dataclasses import dataclass
from urllib.parse import urlsplit

_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_HEX = frozenset(string.hexdigits)
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class NormalizedURL:
    """规范化后的 URL 结构。host_pattern 为 True 表示 "*.domain" 形式的规则主机。"""

    scheme: str
    host: str
    host_pattern: bool
    port: int
    path: str


def _decode_pct(path: str) -> str:
    """单趟百分号解码：仅解码 unreserved 字符，其余保留并大写十六进制。"""
    out: list[str] = []
    i = 0
    n = len(path)
    while i < n:
        ch = path[i]
        if ch == "%" and i + 2 < n + 1 and i + 2 <= n - 1:
            hi, lo = path[i + 1], path[i + 2]
            if hi in _HEX and lo in _HEX:
                val = int(hi + lo, 16)
                c = chr(val)
                if c in _UNRESERVED:
                    out.append(c)
                else:
                    out.append("%" + hi.upper() + lo.upper())
                i += 3
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    """消除 . 与 .. 段；保留连续斜杠；末尾点段处理后保留目录斜杠。"""
    segments = path.split("/")
    out: list[str] = []
    trailing_slash = False
    last_index = len(segments) - 1
    for idx, seg in enumerate(segments):
        if idx == 0:
            continue  # 根前的空前缀
        is_last = idx == last_index
        if seg == ".":
            if is_last:
                trailing_slash = True
            continue
        if seg == "..":
            if out:
                out.pop()
            if is_last:
                trailing_slash = True
            continue
        out.append(seg)
        trailing_slash = False
    result = "/" + "/".join(out)
    if trailing_slash and not result.endswith("/"):
        result += "/"
    return result


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    return _remove_dot_segments(_decode_pct(path))


def _split(url: str, allow_pattern: bool) -> NormalizedURL:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme: {parts.scheme!r}")
    host = parts.hostname
    if host is None:
        raise ValueError(f"missing host: {url!r}")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    host_pattern = False
    if allow_pattern and host.startswith("*."):
        host_pattern = True
        host = host[2:]
        if not host:
            raise ValueError(f"empty pattern host: {url!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {url!r}") from exc
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return NormalizedURL(
        scheme=scheme,
        host=host,
        host_pattern=host_pattern,
        port=port,
        path=_normalize_path(parts.path),
    )


def normalize_url(url: str) -> NormalizedURL:
    """将目标 URL 规范化为 NormalizedURL。"""
    return _split(url, allow_pattern=False)


def normalize_rule_url(url: str) -> NormalizedURL:
    """将规则 URL 规范化为 NormalizedURL（允许 "*." 主机前缀）。"""
    return _split(url, allow_pattern=True)
