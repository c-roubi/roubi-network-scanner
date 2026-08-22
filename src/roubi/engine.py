"""The scanning engine.

A TCP connect scan is used deliberately. It completes the three-way handshake
through the operating system socket layer, which means it needs no elevated
privileges and behaves identically across platforms. The trade-off, relative to
a raw-socket SYN scan, is that connections are fully established; the engine
keeps them short-lived and closes them immediately.

Concurrency is provided by a thread pool. Port scanning is I/O-bound, so the
GIL is released during the blocking socket calls and threads give a large
speed-up without the overhead of processes.

Resilience is a first-class concern. Name-resolution failures and unexpected
per-host errors are captured in the result model rather than propagated, so a
single bad target never aborts a multi-host run.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from roubi.services import advisory_for_port, name_for_port, refine_from_banner

ProgressCallback = Callable[[int, int], None]

_HTTP_PROBE_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8888, 9000})
_BANNER_BYTES = 256
_RETRY_BACKOFF_SECONDS = 0.05


@dataclass(slots=True)
class ScanConfig:
    """Tunable parameters for a scan run.

    Attributes:
        timeout: Per-port connection timeout, in seconds.
        workers: Maximum concurrent connections per host.
        retries: Additional attempts for a port after a transient error.
        grab_banners: Whether to read a service banner from open ports.
        rate: Maximum connection attempts per second, or ``None`` for no limit.
    """

    timeout: float = 1.0
    workers: int = 200
    retries: int = 1
    grab_banners: bool = True
    rate: float | None = None

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.workers < 1:
            raise ValueError("workers must be at least 1")
        if self.retries < 0:
            raise ValueError("retries cannot be negative")
        if self.rate is not None and self.rate <= 0:
            raise ValueError("rate must be positive when set")


@dataclass(slots=True)
class PortResult:
    """A single open port and what could be learned about it."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    advisory: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HostResult:
    """The outcome of scanning one host.

    ``status`` is ``"up"`` when the host was scanned, ``"unresolved"`` when name
    resolution failed, or ``"error"`` for any other host-level failure.
    """

    target: str
    resolved_ip: str = ""
    status: str = "up"
    error: str | None = None
    open_ports: list[PortResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["open_ports"] = [port.to_dict() for port in self.open_ports]
        return data


@dataclass(slots=True)
class ScanResult:
    """The full result of a scan across one or more hosts."""

    started_at: str
    finished_at: str = ""
    ports_per_host: int = 0
    hosts: list[HostResult] = field(default_factory=list)
    invalid_targets: list[str] = field(default_factory=list)

    @property
    def hosts_up(self) -> int:
        return sum(1 for host in self.hosts if host.status == "up")

    @property
    def total_open_ports(self) -> int:
        return sum(len(host.open_ports) for host in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "ports_per_host": self.ports_per_host,
            "invalid_targets": list(self.invalid_targets),
            "summary": {
                "hosts": len(self.hosts),
                "hosts_up": self.hosts_up,
                "open_ports": self.total_open_ports,
            },
            "hosts": [host.to_dict() for host in self.hosts],
        }


class _RateLimiter:
    """Spaces out connection starts to at most *rate* per second."""

    def __init__(self, rate: float | None) -> None:
        self._interval = (1.0 / rate) if rate else 0.0
        self._lock = threading.Lock()
        self._next_time = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.perf_counter()
            wait = self._next_time - now
            if wait > 0:
                time.sleep(wait)
                now = time.perf_counter()
            self._next_time = now + self._interval


class Scanner:
    """A resilient multi-target TCP connect scanner."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._limiter = _RateLimiter(self.config.rate)

    @staticmethod
    def _resolve(target: str) -> str:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return socket.gethostbyname(target)
        return target

    def _read_banner(self, sock: socket.socket, port: int) -> bytes:
        try:
            sock.settimeout(self.config.timeout)
            if port in _HTTP_PROBE_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return sock.recv(_BANNER_BYTES).strip()
        except OSError:
            return b""

    def _probe(self, ip: str, port: int) -> PortResult | None:
        self._limiter.acquire()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.config.timeout)
            if sock.connect_ex((ip, port)) != 0:
                return None
            banner = (
                self._read_banner(sock, port)
                if self.config.grab_banners
                else b""
            )
        service = refine_from_banner(banner, name_for_port(port))
        text = banner.decode("utf-8", errors="replace") if banner else ""
        return PortResult(
            port=port,
            service=service,
            banner=text,
            advisory=advisory_for_port(port),
        )

    def _scan_port(self, ip: str, port: int) -> PortResult | None:
        attempts = self.config.retries + 1
        for attempt in range(attempts):
            try:
                return self._probe(ip, port)
            except OSError:
                if attempt + 1 < attempts:
                    time.sleep(_RETRY_BACKOFF_SECONDS)
        return None

    def _scan_host(
        self,
        target: str,
        ports: Sequence[int],
        on_port_done: Callable[[], None] | None,
    ) -> HostResult:
        result = HostResult(target=target)
        try:
            result.resolved_ip = self._resolve(target)
        except OSError as exc:
            result.status = "unresolved"
            result.error = f"name resolution failed: {exc}"
            return result

        try:
            with ThreadPoolExecutor(max_workers=self.config.workers) as pool:
                futures = {
                    pool.submit(self._scan_port, result.resolved_ip, port): port
                    for port in ports
                }
                for future in as_completed(futures):
                    if on_port_done is not None:
                        on_port_done()
                    port_result = future.result()
                    if port_result is not None:
                        result.open_ports.append(port_result)
        except Exception as exc:  # noqa: BLE001 - deliberate host-level isolation
            # Any failure scanning one host is recorded on that host's result
            # so it cannot abort the scan of the remaining targets.
            result.status = "error"
            result.error = str(exc)
            return result

        result.open_ports.sort(key=lambda item: item.port)
        return result

    def scan(
        self,
        targets: Iterable[str],
        ports: Sequence[int],
        invalid_targets: Sequence[str] | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Scan every target over *ports* and return a :class:`ScanResult`.

        Hosts are scanned sequentially; ports within a host run concurrently.
        *progress*, if given, is called with ``(completed, total)`` port probes.
        """
        targets = list(targets)
        ports = list(ports)
        result = ScanResult(
            started_at=datetime.now(timezone.utc).isoformat(),
            ports_per_host=len(ports),
            invalid_targets=list(invalid_targets or []),
        )

        total = len(targets) * len(ports)
        completed = 0

        def on_port_done() -> None:
            nonlocal completed
            completed += 1
            if progress is not None:
                progress(completed, total)

        for target in targets:
            result.hosts.append(
                self._scan_host(target, ports, on_port_done if progress else None)
            )

        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result
