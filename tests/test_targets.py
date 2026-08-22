from __future__ import annotations

from pathlib import Path

from roubi import targets


def test_single_and_list() -> None:
    result = targets.expand("127.0.0.1,example.com")
    assert result.hosts == ["127.0.0.1", "example.com"]
    assert result.invalid == []


def test_cidr_expansion_skips_network_and_broadcast() -> None:
    result = targets.expand("192.0.2.0/30")
    assert result.hosts == ["192.0.2.1", "192.0.2.2"]


def test_slash_32_includes_host() -> None:
    result = targets.expand("10.0.0.5/32")
    assert result.hosts == ["10.0.0.5"]


def test_invalid_entry_collected_not_raised() -> None:
    result = targets.expand("bad host!!,10.0.0.1")
    assert "10.0.0.1" in result.hosts
    assert "bad host!!" in result.invalid


def test_deduplication_preserves_order() -> None:
    result = targets.expand("10.0.0.2,10.0.0.1,10.0.0.2")
    assert result.hosts == ["10.0.0.2", "10.0.0.1"]


def test_file_with_comments_and_commas(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "# a comment, with a comma\n"
        "\n"
        "127.0.0.1\n"
        "10.0.0.1,10.0.0.2\n",
        encoding="utf-8",
    )
    result = targets.expand(file_path=str(target_file))
    assert result.hosts == ["127.0.0.1", "10.0.0.1", "10.0.0.2"]
    assert result.invalid == []
