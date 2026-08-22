"""Self-contained HTML report.

The output embeds its own styles and has no external dependencies, so a single
file can be archived with an engagement or shared with a stakeholder.
"""

from __future__ import annotations

import html
from datetime import datetime

from roubi.engine import HostResult, ScanResult

_STYLE = """
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--fg:#e6edf3;
--muted:#8b949e;--open:#3fb950;--warn:#d29922;--down:#f85149;--mono:ui-monospace,
SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);padding:2.5rem 1.5rem;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,sans-serif;
line-height:1.55}
.wrap{max-width:940px;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 .2rem;font-weight:600}
.meta{color:var(--muted);font-size:.85rem;margin-bottom:1.75rem}
.cards{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1.75rem}
.cell{background:var(--card);border:1px solid var(--border);border-radius:6px;
padding:.7rem 1rem;min-width:110px}
.cell .v{font-size:1.35rem;font-weight:600}
.cell .k{color:var(--muted);font-size:.72rem;text-transform:uppercase;
letter-spacing:.06em}
.host{background:var(--card);border:1px solid var(--border);border-radius:6px;
margin-bottom:.9rem;overflow:hidden}
.host>.head{display:flex;justify-content:space-between;align-items:center;
padding:.65rem 1rem;border-bottom:1px solid var(--border);font-weight:600}
.host>.head .ip{color:var(--muted);font-family:var(--mono);font-weight:400;
font-size:.82rem}
.tag{font-size:.68rem;font-weight:600;padding:.12rem .5rem;border-radius:999px;
text-transform:uppercase;letter-spacing:.04em}
.tag.up{background:rgba(63,185,80,.14);color:var(--open)}
.tag.down{background:rgba(248,81,73,.14);color:var(--down)}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.45rem 1rem;border-bottom:1px solid var(--border);
font-size:.88rem;vertical-align:top}
tr:last-child td{border-bottom:none}
th{color:var(--muted);font-size:.68rem;text-transform:uppercase;
letter-spacing:.06em;font-weight:600}
td.port{color:var(--open);font-weight:600;font-family:var(--mono);white-space:nowrap}
.advisory{color:var(--warn);font-size:.8rem;margin-top:.15rem}
.banner{color:var(--muted);font-family:var(--mono);font-size:.78rem;
word-break:break-all}
.note{padding:.7rem 1rem;color:var(--muted);font-size:.85rem}
footer{margin-top:2rem;color:var(--muted);font-size:.78rem;text-align:center}
"""


def _esc(value: object) -> str:
    return html.escape(str(value)) if value is not None else ""


def _host_section(host: HostResult) -> str:
    if host.status == "up":
        tag = '<span class="tag up">up</span>'
    else:
        tag = f'<span class="tag down">{_esc(host.status)}</span>'

    head = (
        f'<div class="head"><span>{_esc(host.target)} '
        f'<span class="ip">{_esc(host.resolved_ip)}</span></span>{tag}</div>'
    )

    if host.status != "up":
        return (
            f'<div class="host">{head}'
            f'<div class="note">{_esc(host.error)}</div></div>'
        )
    if not host.open_ports:
        return f'<div class="host">{head}<div class="note">No open ports.</div></div>'

    rows = []
    for port in host.open_ports:
        advisory = (
            f'<div class="advisory">{_esc(port.advisory)}</div>'
            if port.advisory else ""
        )
        rows.append(
            f"<tr><td class='port'>{port.port}/{_esc(port.protocol)}</td>"
            f"<td>{_esc(port.state)}</td>"
            f"<td>{_esc(port.service)}{advisory}</td>"
            f"<td class='banner'>{_esc(port.banner)}</td></tr>"
        )
    table = (
        "<table><thead><tr><th>Port</th><th>State</th><th>Service</th>"
        f"<th>Banner</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )
    return f'<div class="host">{head}{table}</div>'


def render_html(result: ScanResult, title: str = "Roubi Scan Report") -> str:
    """Return a complete, self-contained HTML document for *result*."""
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cells = (
        ("Hosts", len(result.hosts)),
        ("Hosts up", result.hosts_up),
        ("Open ports", result.total_open_ports),
        ("Ports/host", result.ports_per_host),
    )
    cards = "".join(
        f'<div class="cell"><div class="v">{value}</div>'
        f'<div class="k">{label}</div></div>'
        for label, value in cells
    )
    sections = "".join(_host_section(host) for host in result.hosts)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{_STYLE}</style></head><body>"
        f'<div class="wrap"><h1>{_esc(title)}</h1>'
        f'<div class="meta">Generated {generated} &middot; '
        f'scan started {_esc(result.started_at)}</div>'
        f'<div class="cards">{cards}</div>{sections}'
        "<footer>Roubi Scanner &middot; authorised security testing only</footer>"
        "</div></body></html>"
    )


def write_html(result: ScanResult, path: str, title: str = "Roubi Scan Report") -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(result, title))
