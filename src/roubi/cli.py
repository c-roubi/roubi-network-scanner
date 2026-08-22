"""Command-line interface for Roubi.

Exit codes:
    0  scan completed
    1  runtime error during scanning
    2  invalid arguments or no valid targets
    130 interrupted by the user
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

from roubi import banner, ports, targets
from roubi._version import __version__
from roubi.engine import ProgressCallback, ScanConfig, Scanner
from roubi.reporting import render_console, write_csv, write_html, write_json
from roubi.services import TOP_PORTS

_DEFAULT_PORTS = "1-1024"
_PROGRESS_WIDTH = 25


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roubi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Roubi - a dependency-free TCP network scanner.\n"
            "Scan only assets you own or are explicitly authorised to test."
        ),
    )
    parser.add_argument(
        "targets", nargs="?",
        help="host, IP, CIDR, or comma-separated list (e.g. 10.0.0.0/24,host)",
    )
    parser.add_argument(
        "-iL", "--input-list", metavar="FILE",
        help="read targets from a file, one entry per line",
    )
    parser.add_argument(
        "-p", "--ports", default=_DEFAULT_PORTS,
        help=f"ports to scan (default: {_DEFAULT_PORTS})",
    )
    parser.add_argument(
        "--top-ports", action="store_true",
        help="scan a curated set of common service ports",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="per-port timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=200,
        help="concurrent connections per host (default: 200)",
    )
    parser.add_argument(
        "-r", "--retries", type=int, default=1,
        help="retries per port on transient errors (default: 1)",
    )
    parser.add_argument(
        "--rate", type=float, default=None,
        help="cap connection attempts per second (default: unlimited)",
    )
    parser.add_argument(
        "--no-banner-grab", action="store_true",
        help="do not read service banners",
    )
    parser.add_argument("--json", metavar="FILE", help="write a JSON report")
    parser.add_argument("--csv", metavar="FILE", help="write a CSV report")
    parser.add_argument("--html", metavar="FILE", help="write an HTML report")
    parser.add_argument(
        "--no-color", action="store_true", help="disable coloured output",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="suppress the banner and progress bar",
    )
    parser.add_argument(
        "--version", action="version", version=f"roubi {__version__}",
    )
    return parser


def _make_progress(enabled: bool) -> ProgressCallback | None:
    if not enabled:
        return None

    def progress(done: int, total: int) -> None:
        if total == 0:
            return
        fraction = done / total
        filled = int(fraction * _PROGRESS_WIDTH)
        bar = "#" * filled + "." * (_PROGRESS_WIDTH - filled)
        sys.stderr.write(f"\r  [{bar}] {int(fraction * 100):3d}%  ({done}/{total})")
        sys.stderr.flush()
        if done >= total:
            sys.stderr.write("\r" + " " * 48 + "\r")
            sys.stderr.flush()

    return progress


def _resolve_ports(args: argparse.Namespace) -> list[int]:
    if args.top_ports:
        return list(TOP_PORTS)
    return ports.parse(args.ports)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty()

    if not args.quiet:
        sys.stderr.write(banner.render(use_color))

    if not args.targets and not args.input_list:
        sys.stderr.write("error: provide a target or use -iL <file>\n")
        return 2

    try:
        target_set = targets.expand(args.targets, args.input_list)
    except FileNotFoundError:
        sys.stderr.write(f"error: target file not found: {args.input_list}\n")
        return 2

    if not target_set.hosts:
        sys.stderr.write("error: no valid targets to scan\n")
        return 2

    try:
        port_list = _resolve_ports(args)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    try:
        config = ScanConfig(
            timeout=args.timeout,
            workers=args.workers,
            retries=args.retries,
            grab_banners=not args.no_banner_grab,
            rate=args.rate,
        )
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    scanner = Scanner(config)

    if not args.quiet:
        sys.stderr.write(
            f"targets: {len(target_set.hosts)}   ports/host: {len(port_list)}   "
            f"probes: {len(target_set.hosts) * len(port_list)}\n\n"
        )

    started = time.perf_counter()
    try:
        result = scanner.scan(
            target_set.hosts,
            port_list,
            invalid_targets=target_set.invalid,
            progress=_make_progress(not args.quiet),
        )
    except KeyboardInterrupt:
        sys.stderr.write("\naborted by user\n")
        return 130

    elapsed = time.perf_counter() - started
    print(render_console(result, color=use_color))
    print(f"completed in {elapsed:.2f}s")

    if args.json:
        write_json(result, args.json)
        print(f"json -> {args.json}")
    if args.csv:
        write_csv(result, args.csv)
        print(f"csv  -> {args.csv}")
    if args.html:
        write_html(result, args.html)
        print(f"html -> {args.html}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
