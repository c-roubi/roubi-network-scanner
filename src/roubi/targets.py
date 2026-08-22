"""Target specification parsing.

Accepts the forms a scanner operator expects and expands them into a flat,
de-duplicated list of hosts:

    single host / IP     example.com, 192.0.2.10
    comma-separated      10.0.0.1,10.0.0.2,example.com
    CIDR network         192.0.2.0/24
    a file of the above  one entry per line, '#' comments allowed

Malformed entries are collected rather than raised. A single typo in a large
target list should never abort a scan.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

_HOSTNAME_MAX_LEN = 253
_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
)


@dataclass(slots=True)
class TargetSet:
    """Expanded hosts and the entries that failed to parse."""

    hosts: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)


def _is_hostname(value: str) -> bool:
    if not value or len(value) > _HOSTNAME_MAX_LEN:
        return False
    labels = value.rstrip(".").split(".")
    return all(label and set(label) <= _LABEL_CHARS for label in labels)


def _expand_entry(entry: str, hosts: list[str], invalid: list[str]) -> None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return

    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            invalid.append(entry)
            return
        # A /31 or /32 has no usable-host distinction worth skipping.
        members = network if network.num_addresses <= 2 else network.hosts()
        hosts.extend(str(address) for address in members)
        return

    try:
        ipaddress.ip_address(entry)
    except ValueError:
        if _is_hostname(entry):
            hosts.append(entry)
        else:
            invalid.append(entry)
    else:
        hosts.append(entry)


def _read_file(path: str, hosts: list[str], invalid: list[str]) -> None:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for entry in line.split(","):
                _expand_entry(entry, hosts, invalid)


def expand(spec: str | None = None, file_path: str | None = None) -> TargetSet:
    """Build a :class:`TargetSet` from an inline spec and/or a file.

    Duplicates are removed while preserving first-seen order so scan output is
    deterministic regardless of how targets were supplied.
    """
    hosts: list[str] = []
    invalid: list[str] = []

    if spec:
        for entry in spec.split(","):
            _expand_entry(entry, hosts, invalid)
    if file_path:
        _read_file(file_path, hosts, invalid)

    seen: set[str] = set()
    unique: list[str] = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique.append(host)
    return TargetSet(hosts=unique, invalid=invalid)
