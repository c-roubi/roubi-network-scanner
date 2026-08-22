from __future__ import annotations

from roubi import services


def test_known_ports() -> None:
    assert services.name_for_port(22) == "ssh"
    assert services.name_for_port(443) == "https"
    assert services.name_for_port(3306) == "mysql"


def test_unknown_port() -> None:
    assert services.name_for_port(65001) == services.UNKNOWN


def test_advisory_present_for_risky_port() -> None:
    assert services.advisory_for_port(23) is not None
    assert services.advisory_for_port(80) is None


def test_banner_refines_service() -> None:
    assert services.refine_from_banner(b"SSH-2.0-OpenSSH_9.6", "unknown") == "ssh"
    assert services.refine_from_banner(b"HTTP/1.1 200 OK", "unknown") == "http"


def test_banner_falls_back_when_no_match() -> None:
    assert services.refine_from_banner(b"", "https") == "https"
    assert services.refine_from_banner(b"random noise", "mysql") == "mysql"
