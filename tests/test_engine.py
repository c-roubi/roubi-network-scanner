from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from roubi.engine import ScanConfig, Scanner

_UNRESOLVABLE = "host.invalid.tld.doesnotexist.zzz"


def test_config_rejects_bad_values() -> None:
    with pytest.raises(ValueError):
        ScanConfig(timeout=0)
    with pytest.raises(ValueError):
        ScanConfig(workers=0)
    with pytest.raises(ValueError):
        ScanConfig(retries=-1)
    with pytest.raises(ValueError):
        ScanConfig(rate=0)


def test_unresolved_host_isolated() -> None:
    scanner = Scanner(ScanConfig(timeout=0.3, workers=4))
    result = scanner.scan([_UNRESOLVABLE], [80])
    assert len(result.hosts) == 1
    assert result.hosts[0].status == "unresolved"
    assert result.total_open_ports == 0


@contextmanager
def _echo_server(banner: bytes = b"") -> Iterator[int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = int(server.getsockname()[1])
    stop = threading.Event()

    def serve() -> None:
        server.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if banner:
                conn.sendall(banner)
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        server.close()


def test_detects_open_port_with_banner() -> None:
    with _echo_server(b"SSH-2.0-RoubiTest\r\n") as port:
        scanner = Scanner(ScanConfig(timeout=0.5, workers=8))
        result = scanner.scan(["127.0.0.1"], [port])
    host = result.hosts[0]
    assert host.status == "up"
    assert len(host.open_ports) == 1
    assert host.open_ports[0].port == port
    assert host.open_ports[0].service == "ssh"


def test_mixed_targets_report_independently() -> None:
    with _echo_server() as port:
        scanner = Scanner(ScanConfig(timeout=0.4, workers=8))
        result = scanner.scan(["127.0.0.1", _UNRESOLVABLE], [port])
    statuses = {host.target: host.status for host in result.hosts}
    assert statuses["127.0.0.1"] == "up"
    assert statuses[_UNRESOLVABLE] == "unresolved"


def test_progress_callback_reaches_total() -> None:
    seen: list[tuple[int, int]] = []
    with _echo_server() as port:
        scanner = Scanner(ScanConfig(timeout=0.4, workers=8))
        scanner.scan(["127.0.0.1"], [port, port + 1, port + 2],
                     progress=lambda done, total: seen.append((done, total)))
    assert seen[-1] == (3, 3)


def test_result_serialization_shape() -> None:
    with _echo_server() as port:
        scanner = Scanner(ScanConfig(timeout=0.4, workers=8))
        result = scanner.scan(["127.0.0.1"], [port])
    data = result.to_dict()
    assert set(data) >= {"started_at", "finished_at", "summary", "hosts"}
    assert data["summary"]["hosts"] == 1
