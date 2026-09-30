from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_HEX = "0123456789abcdefABCDEF"


@dataclass(frozen=True)
class NormalizedURL:
    scheme: str
    host: str
    port: int
    segments: tuple[str, ...]


def _normalize_percent(path: str) -> str:
    out: list[str] = []
    i = 0
    n = len(path)
    while i < n:
        ch = path[i]
        if (
            ch == "%"
            and i + 2 < n
            and path[i + 1] in _HEX
            and path[i + 2] in _HEX
        ):
            decoded = chr(int(path[i + 1 : i + 3], 16))
            if decoded in _UNRESERVED:
                out.append(decoded)
            else:
                out.append("%" + path[i + 1 : i + 3].upper())
            i += 3
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    segs = path.split("/")
    out: list[str] = []
    last = len(segs) - 1
    for i, seg in enumerate(segs):
        if seg == ".":
            if i == last:
                out.append("")
        elif seg == "..":
            if len(out) > 1:
                out.pop()
            if i == last:
                out.append("")
        else:
            out.append(seg)
    return "/".join(out)


def normalize_path(path: str) -> tuple[str, ...]:
    if not path:
        path = "/"
    path = _remove_dot_segments(_normalize_percent(path))
    if not path.startswith("/"):
        path = "/" + path
    return tuple(path.split("/"))


def normalize_url(url: str) -> NormalizedURL:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"missing host: {url!r}")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid port: {url!r}") from exc
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    return NormalizedURL(
        scheme=scheme,
        host=host,
        port=port,
        segments=normalize_path(parts.path),
    )
