# Roubi Network Scanner

A dependency-free TCP network scanner with structured reporting, written in
Python. Roubi scans single hosts, comma-separated lists, CIDR networks, or a
file of targets, identifies services on open ports, and produces console,
JSON, CSV, or self-contained HTML output.

The core library has no third-party dependencies; the standard library is
sufficient for scanning and every report format.

> **Authorised use only.** Roubi is intended for auditing assets you own or are
> explicitly authorised to test. Port scanning without permission may be
> unlawful in your jurisdiction. Responsibility for lawful use rests with the
> operator.

## Scope

Roubi implements a TCP connect scan with service identification and reporting.
It is deliberately focused: it is not a replacement for mature tooling such as
Nmap, and does not attempt raw-socket scan modes, OS fingerprinting, or a
scripting engine. What it aims to be is a small, correct, well-tested codebase
that is easy to read, embed, and extend.

## Installation

```bash
git clone https://github.com/c-roubi/roubi-network-scanner.git
cd roubi-network-scanner
python -m pip install .
```

This installs a `roubi` console command. For development, install the optional
tooling as well:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
# Single host, default 1-1024 port range
roubi 192.0.2.10

# A CIDR network, curated common ports, HTML report
roubi 192.0.2.0/24 --top-ports --html report.html

# Targets from a file, specific ports, JSON output
roubi -iL targets.txt -p 22,80,443,8080 --json results.json

# Mixed inline targets, rate-limited to be gentle on the network
roubi "example.com,192.0.2.0/28" -p 1-1000 --rate 500

roubi --help
```

### Example output

```
+ 192.0.2.10  3 open
       22/tcp  ssh             SSH-2.0-OpenSSH_9.6
       80/tcp  http            HTTP/1.1 200 OK
     3306/tcp  mysql
             ! Database service; verify it is not externally reachable.

x old.example.com  down - name resolution failed
------------------------------------------------------------
2 host(s) scanned  |  1 up  |  3 open port(s)
```

## Options

| Option                     | Description                                        |
|----------------------------|----------------------------------------------------|
| `targets`                  | Host, IP, CIDR, or comma-separated list            |
| `-iL, --input-list FILE`   | Read targets from a file, one entry per line       |
| `-p, --ports SPEC`         | Ports to scan, e.g. `1-1024` or `22,80,443`        |
| `--top-ports`              | Scan a curated set of common service ports         |
| `-t, --timeout SECONDS`    | Per-port connection timeout (default `1.0`)        |
| `-w, --workers N`          | Concurrent connections per host (default `200`)    |
| `-r, --retries N`          | Retries per port on transient errors (default `1`) |
| `--rate N`                 | Cap connection attempts per second                 |
| `--no-banner-grab`         | Do not read service banners                        |
| `--json / --csv / --html`  | Write a report in the given format                 |
| `--no-color`               | Disable coloured console output                    |
| `-q, --quiet`              | Suppress banner and progress bar                   |

## Design

**Scan method.** Roubi performs a TCP connect scan, completing the three-way
handshake through the operating-system socket layer. This needs no elevated
privileges and behaves consistently across platforms. Connections are
short-lived and closed immediately after a banner read.

**Concurrency.** Port scanning is I/O-bound, so a thread pool provides a large
speed-up while the GIL is released during blocking socket calls. Concurrency is
bounded per host by `--workers`.

**Resilience.** Failures are contained in the result model rather than raised.
A name-resolution failure marks a host `unresolved`; any other host-level error
is recorded as `error`; transient socket errors trigger a configurable number
of retries. One bad target never aborts a multi-host run. Malformed entries in
a target list are collected and reported, not treated as fatal.

**Separation of concerns.** The engine returns typed result objects
(`ScanResult`, `HostResult`, `PortResult`) that know nothing about presentation.
Rendering lives entirely in `roubi.reporting`, so new output formats can be
added without touching the scanning logic.

## Library use

```python
from roubi import Scanner, ScanConfig
from roubi.reporting import write_html

scanner = Scanner(ScanConfig(timeout=0.5, workers=100))
result = scanner.scan(["192.0.2.10"], ports=[22, 80, 443])

for host in result.hosts:
    for port in host.open_ports:
        print(host.target, port.port, port.service)

write_html(result, "report.html")
```

## Project layout

```
roubi-network-scanner/
├── src/roubi/
│   ├── engine.py          scanning engine and result model
│   ├── targets.py         target specification parsing
│   ├── ports.py           port specification parsing
│   ├── services.py        service map, fingerprints, advisories
│   ├── banner.py          startup banner
│   ├── cli.py             command-line interface
│   └── reporting/
│       ├── console.py     terminal rendering
│       ├── structured.py  JSON and CSV
│       └── html.py        self-contained HTML report
├── tests/                 unit and integration tests
├── examples/targets.txt
├── .github/workflows/ci.yml
├── pyproject.toml
├── CHANGELOG.md
└── LICENSE
```

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .      # lint
mypy              # static type checking (strict)
pytest            # tests
```

Continuous integration runs all three across Python 3.10, 3.11, and 3.12.

## License

MIT. See [LICENSE](LICENSE). Provided for authorised security testing and
education only.
