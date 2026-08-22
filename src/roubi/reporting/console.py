"""Human-readable console rendering.

Colour is applied only when writing to a terminal, and can be disabled
explicitly so piped or redirected output stays clean.
"""

from __future__ import annotations

import sys

from roubi.engine import HostResult, ScanResult

_RESET = "\033[0m"
_CODES = {
    "green": "32", "yellow": "33", "red": "31",
    "cyan": "36", "grey": "90", "bold": "1",
}


class _Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, colour: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{_CODES[colour]}m{text}{_RESET}"


def _render_host(host: HostResult, palette: _Palette, lines: list[str]) -> None:
    label = host.target
    if host.resolved_ip and host.resolved_ip != host.target:
        label += palette.paint(f" ({host.resolved_ip})", "grey")

    if host.status != "up":
        marker = palette.paint("down", "red")
        detail = palette.paint(f"- {host.error or host.status}", "grey")
        lines.append(f"{palette.paint('x', 'red')} {label}  {marker} {detail}")
        return

    if not host.open_ports:
        lines.append(f"{palette.paint('-', 'yellow')} {label}  "
                     f"{palette.paint('no open ports', 'grey')}")
        return

    count = palette.paint(f"{len(host.open_ports)} open", "green")
    lines.append(f"{palette.paint('+', 'green')} "
                 f"{palette.paint(label, 'bold')}  {count}")
    for port in host.open_ports:
        banner = port.banner if len(port.banner) <= 60 else port.banner[:59] + "..."
        port_col = palette.paint(f"{port.port:>5}", "green")
        lines.append(f"    {port_col}/{port.protocol}  "
                     f"{port.service:<16}{palette.paint(banner, 'cyan')}")
        if port.advisory:
            lines.append(f"           {palette.paint('! ' + port.advisory, 'red')}")


def render_console(
    result: ScanResult,
    *,
    color: bool | None = None,
) -> str:
    """Return a console-ready string for *result*.

    ``color`` forces colour on or off; when ``None`` it is auto-detected from
    whether stdout is a terminal.
    """
    enabled = sys.stdout.isatty() if color is None else color
    palette = _Palette(enabled)
    lines: list[str] = []

    if result.invalid_targets:
        shown = ", ".join(result.invalid_targets[:5])
        if len(result.invalid_targets) > 5:
            shown += ", ..."
        lines.append(palette.paint(
            f"skipped {len(result.invalid_targets)} invalid target(s): {shown}",
            "yellow",
        ))
        lines.append("")

    for host in result.hosts:
        _render_host(host, palette, lines)

    lines.append("-" * 60)
    summary = (f"{len(result.hosts)} host(s) scanned  |  "
               f"{result.hosts_up} up  |  "
               f"{result.total_open_ports} open port(s)")
    lines.append(palette.paint(summary, "bold"))
    return "\n".join(lines)
