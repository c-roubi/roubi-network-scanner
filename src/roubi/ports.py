"""Port-specification parsing.

Turns strings such as ``22,80,443`` or ``1-1024`` or ``80,8000-8100`` into a
sorted list of unique port numbers, rejecting anything outside 1-65535.
"""

from __future__ import annotations

_MIN_PORT = 1
_MAX_PORT = 65535


def parse(spec: str) -> list[int]:
    """Parse a port specification into a sorted, de-duplicated list.

    Raises:
        ValueError: if a token is not a valid port or range.
    """
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            ports.update(_parse_range(token))
        else:
            ports.add(_parse_single(token))
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)


def _parse_single(token: str) -> int:
    try:
        port = int(token)
    except ValueError as exc:
        raise ValueError(f"invalid port: {token!r}") from exc
    if not _MIN_PORT <= port <= _MAX_PORT:
        raise ValueError(f"port out of range (1-65535): {token!r}")
    return port


def _parse_range(token: str) -> range:
    low_str, high_str = token.split("-", 1)
    low = _parse_single(low_str)
    high = _parse_single(high_str)
    if low > high:
        raise ValueError(f"reversed port range: {token!r}")
    return range(low, high + 1)
