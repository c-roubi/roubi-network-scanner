"""Machine-readable exporters (JSON, CSV) for integration with other tooling."""

from __future__ import annotations

import csv
import json

from roubi.engine import ScanResult

_CSV_HEADER = (
    "host", "resolved_ip", "status", "port", "protocol",
    "service", "banner", "advisory",
)


def write_json(result: ScanResult, path: str) -> None:
    """Write *result* as indented JSON to *path*."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2)
        handle.write("\n")


def write_csv(result: ScanResult, path: str) -> None:
    """Write *result* as one row per open port (or one row per host with none)."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(_CSV_HEADER)
        for host in result.hosts:
            if not host.open_ports:
                writer.writerow(
                    [host.target, host.resolved_ip, host.status, "", "", "", "", ""]
                )
                continue
            for port in host.open_ports:
                writer.writerow([
                    host.target, host.resolved_ip, host.status, port.port,
                    port.protocol, port.service, port.banner, port.advisory or "",
                ])
