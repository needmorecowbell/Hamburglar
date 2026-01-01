"""Tests for the hexdump utility module."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from hamburglar.utils.hexdump import (
    hexdump,
    hexdump_file,
    hexdump_iter,
    hexdump_rich,
)


class TestHexdump:
    """Tests for the hexdump function."""

    def test_hexdump_empty_file(self, tmp_path: Path) -> None:
        """Test hexdump of an empty file."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        result = hexdump(empty_file)
        assert result == ""

    def test_hexdump_single_byte(self, tmp_path: Path) -> None:
        """Test hexdump of a single byte file."""
        single_byte = tmp_path / "single.bin"
        single_byte.write_bytes(b"\x41")

        result = hexdump(single_byte)
        # Format: offset(8) + 2 spaces + hex(48, padded) + 1 space + |ascii|
        assert result.startswith("00000000  41")
        assert result.endswith("|A|")
        # Verify correct structure
        assert "41" in result

    def test_hexdump_16_bytes(self, tmp_path: Path) -> None:
        """Test hexdump of exactly 16 bytes (one full line)."""
        test_file = tmp_path / "16bytes.bin"
        test_file.write_bytes(b"0123456789ABCDEF")

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 1
        assert lines[0].startswith("00000000  ")
        assert "|0123456789ABCDEF|" in lines[0]

    def test_hexdump_multiple_lines(self, tmp_path: Path) -> None:
        """Test hexdump with multiple lines."""
        test_file = tmp_path / "multi.bin"
        # 32 bytes = 2 lines
        test_file.write_bytes(b"A" * 32)

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("00000000  ")
        assert lines[1].startswith("00000010  ")

    def test_hexdump_non_printable_chars(self, tmp_path: Path) -> None:
        """Test hexdump replaces non-printable characters with dots."""
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03\x7f\x80\xff")

        result = hexdump(test_file)
        # All non-printable should be dots in ASCII column
        assert "|.......|" in result

    def test_hexdump_printable_chars(self, tmp_path: Path) -> None:
        """Test hexdump preserves printable characters."""
        test_file = tmp_path / "text.bin"
        test_file.write_bytes(b"Hello World!")

        result = hexdump(test_file)
        assert "|Hello World!|" in result

    def test_hexdump_hex_format(self, tmp_path: Path) -> None:
        """Test hexdump produces correct hex values."""
        test_file = tmp_path / "hex.bin"
        test_file.write_bytes(b"\x00\x0a\x0f\xff")

        result = hexdump(test_file)
        # Check hex values are present
        assert "00 0a 0f ff" in result.lower()

    def test_hexdump_elf_magic(self, tmp_path: Path) -> None:
        """Test hexdump with ELF magic bytes."""
        test_file = tmp_path / "elf.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 12)

        result = hexdump(test_file)
        assert "7f 45 4c 46" in result
        assert "|.ELF" in result

    def test_hexdump_partial_last_line(self, tmp_path: Path) -> None:
        """Test hexdump with a partial last line."""
        test_file = tmp_path / "partial.bin"
        # 20 bytes = 1 full line + 4 bytes
        test_file.write_bytes(b"X" * 20)

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 2
        # Second line should have only 4 bytes
        assert lines[1].count("58") == 4  # "X" = 0x58

    def test_hexdump_offset_increment(self, tmp_path: Path) -> None:
        """Test hexdump offset increments correctly."""
        test_file = tmp_path / "offset.bin"
        test_file.write_bytes(b"A" * 64)

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 4
        assert lines[0].startswith("00000000  ")
        assert lines[1].startswith("00000010  ")
        assert lines[2].startswith("00000020  ")
        assert lines[3].startswith("00000030  ")

    def test_hexdump_path_string(self, tmp_path: Path) -> None:
        """Test hexdump accepts string path."""
        test_file = tmp_path / "string_path.bin"
        test_file.write_bytes(b"test")

        result = hexdump(str(test_file))
        assert "test" in result

    def test_hexdump_file_not_found(self) -> None:
        """Test hexdump raises error for non-existent file."""
        with pytest.raises(FileNotFoundError):
            hexdump("/nonexistent/file.bin")

    def test_hexdump_permission_error(self, tmp_path: Path) -> None:
        """Test hexdump raises error for unreadable file."""
        test_file = tmp_path / "unreadable.bin"
        test_file.write_bytes(b"test")
        test_file.chmod(0o000)

        try:
            with pytest.raises(PermissionError):
                hexdump(test_file)
        finally:
            test_file.chmod(0o644)

    def test_hexdump_is_directory(self, tmp_path: Path) -> None:
        """Test hexdump raises error for directory."""
        with pytest.raises(IsADirectoryError):
            hexdump(tmp_path)


class TestHexdumpIter:
    """Tests for the hexdump_iter generator function."""

    def test_hexdump_iter_empty(self, tmp_path: Path) -> None:
        """Test iterator on empty file."""
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        lines = list(hexdump_iter(empty_file))
        assert lines == []

    def test_hexdump_iter_yields_lines(self, tmp_path: Path) -> None:
        """Test iterator yields individual lines."""
        test_file = tmp_path / "multi.bin"
        test_file.write_bytes(b"A" * 32)

        lines = list(hexdump_iter(test_file))
        assert len(lines) == 2

    def test_hexdump_iter_matches_hexdump(self, tmp_path: Path) -> None:
        """Test iterator output matches hexdump function."""
        test_file = tmp_path / "compare.bin"
        test_file.write_bytes(b"Hello World! This is a test file." * 3)

        iter_result = "\n".join(hexdump_iter(test_file))
        direct_result = hexdump(test_file)
        assert iter_result == direct_result


class TestHexdumpFile:
    """Tests for the hexdump_file function."""

    def test_hexdump_file_to_path(self, tmp_path: Path) -> None:
        """Test writing hexdump to file path."""
        input_file = tmp_path / "input.bin"
        input_file.write_bytes(b"Test data")

        output_file = tmp_path / "output.hexdump"
        hexdump_file(input_file, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "Test data" in content

    def test_hexdump_file_to_string_io(self, tmp_path: Path) -> None:
        """Test writing hexdump to StringIO."""
        input_file = tmp_path / "input.bin"
        input_file.write_bytes(b"Test data")

        output = io.StringIO()
        hexdump_file(input_file, output)

        content = output.getvalue()
        assert "Test data" in content

    def test_hexdump_file_to_file_object(self, tmp_path: Path) -> None:
        """Test writing hexdump to file object."""
        input_file = tmp_path / "input.bin"
        input_file.write_bytes(b"Test data")

        output_file = tmp_path / "output.hexdump"
        with open(output_file, "w") as f:
            hexdump_file(input_file, f)

        content = output_file.read_text()
        assert "Test data" in content


class TestHexdumpRich:
    """Tests for the hexdump_rich colorized output function."""

    def test_hexdump_rich_basic(self, tmp_path: Path) -> None:
        """Test basic colorized hexdump."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        # Just verify it doesn't raise
        from rich.console import Console

        console = Console(file=io.StringIO(), force_terminal=True)
        hexdump_rich(test_file, console=console)

    def test_hexdump_rich_with_patterns(self, tmp_path: Path) -> None:
        """Test colorized hexdump with highlight patterns."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 12)

        from rich.console import Console

        console = Console(file=io.StringIO(), force_terminal=True)
        hexdump_rich(
            test_file,
            console=console,
            highlight_patterns={b"\x7fELF": "red"},
        )

    def test_hexdump_rich_empty_file(self, tmp_path: Path) -> None:
        """Test colorized hexdump of empty file."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        from rich.console import Console

        console = Console(file=io.StringIO(), force_terminal=True)
        hexdump_rich(test_file, console=console)

    def test_hexdump_rich_default_console(self, tmp_path: Path, capsys) -> None:
        """Test colorized hexdump with default console."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test")

        # This should not raise even without explicit console
        # (will create default console)
        hexdump_rich(test_file)


class TestHexdumpCompatibility:
    """Tests for compatibility with original hamburglar.py hexdump format."""

    def test_format_matches_original(self, tmp_path: Path) -> None:
        """Test output format matches original hamburglar.py format.

        Original format:
        {offset:08x}  {hex_left}  {hex_right}  |{ascii}|
        """
        test_file = tmp_path / "compat.bin"
        test_file.write_bytes(b"0123456789ABCDEF")

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 1

        line = lines[0]
        # Should have 8-char offset, double space, hex values, double space separator, more hex, space, ASCII
        assert line.startswith("00000000  ")
        assert "  " in line[10:]  # Double space separator between hex halves
        assert line.endswith("|0123456789ABCDEF|")

    def test_hex_spacing(self, tmp_path: Path) -> None:
        """Test hex bytes are space-separated with extra space at midpoint."""
        test_file = tmp_path / "spacing.bin"
        test_file.write_bytes(bytes(range(16)))

        result = hexdump(test_file)

        # Check that there's an extra space between byte 7 and 8
        # (between the two halves of 16 bytes)
        hex_part = result[10:58]  # Skip offset, get hex section
        # Should have format: "xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx"
        assert "  " in hex_part  # Double space in middle

    def test_ascii_column_format(self, tmp_path: Path) -> None:
        """Test ASCII column uses pipe delimiters."""
        test_file = tmp_path / "ascii.bin"
        test_file.write_bytes(b"ABCD")

        result = hexdump(test_file)

        # ASCII column should be pipe-delimited
        assert "|ABCD|" in result

    def test_offset_is_hex(self, tmp_path: Path) -> None:
        """Test offset is in hexadecimal format."""
        test_file = tmp_path / "offset.bin"
        test_file.write_bytes(b"A" * 256)

        result = hexdump(test_file)
        lines = result.split("\n")

        # Check various offsets are in hex
        assert lines[0].startswith("00000000  ")
        assert lines[1].startswith("00000010  ")  # 16 in hex
        assert lines[15].startswith("000000f0  ")  # 240 in hex
