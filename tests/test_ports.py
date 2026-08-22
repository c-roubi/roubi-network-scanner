from __future__ import annotations

import pytest

from roubi import ports


def test_single_ports() -> None:
    assert ports.parse("22,80,443") == [22, 80, 443]


def test_range() -> None:
    assert ports.parse("20-23") == [20, 21, 22, 23]


def test_mixed_and_deduplicated() -> None:
    assert ports.parse("80,80,20-22") == [20, 21, 22, 80]


def test_whitespace_tolerated() -> None:
    assert ports.parse(" 80 , 443 ") == [80, 443]


def test_reversed_range_rejected() -> None:
    with pytest.raises(ValueError, match="reversed"):
        ports.parse("100-50")


def test_out_of_range_rejected() -> None:
    with pytest.raises(ValueError, match="out of range"):
        ports.parse("70000")


def test_zero_rejected() -> None:
    with pytest.raises(ValueError):
        ports.parse("0")


def test_empty_rejected() -> None:
    with pytest.raises(ValueError, match="no ports"):
        ports.parse(",")
