"""Roubi: a dependency-free TCP network scanner with structured reporting.

The public API exposes the scanning engine and its result types so the tool can
be embedded in other Python code, not only driven from the command line.
"""

from __future__ import annotations

from roubi._version import __version__
from roubi.engine import HostResult, PortResult, ScanConfig, Scanner, ScanResult

__all__ = [
    "HostResult",
    "PortResult",
    "ScanConfig",
    "ScanResult",
    "Scanner",
    "__version__",
]
