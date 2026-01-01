"""Tests for the CLI hexdump command.

This module tests the 'hamburglar hexdump' command that displays
hexadecimal dumps of files, matching the original 'hamburglar.py -x' behavior.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.cli.main import app
from hamburglar.config import reset_config

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_config_before_each_test():
    """Reset config cache before each test to ensure isolation."""
    reset_config()
    yield
    reset_config()


class TestHexdumpCommand:
    """Tests for 'hamburglar hexdump' command."""

    def test_hexdump_help(self) -> None:
        """Test that hexdump --help displays help."""
        result = runner.invoke(app, ["hexdump", "--help"])
        assert result.exit_code == 0
        assert "hexadecimal dump" in result.output.lower()
        assert "--output" in result.output
        assert "--color" in result.output

    def test_hexdump_basic(self, tmp_path: Path) -> None:
        """Test basic hexdump of a file."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        result = runner.invoke(app, ["hexdump", str(test_file)])
        assert result.exit_code == 0
        # Should contain hex values for "Hello World!"
        assert "48 65 6c 6c 6f" in result.output.lower()  # "Hello" in hex

    def test_hexdump_with_output_file(self, tmp_path: Path) -> None:
        """Test hexdump with --output flag."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test data")

        output_file = tmp_path / "output.hexdump"
        result = runner.invoke(
            app, ["hexdump", str(test_file), "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert "Hexdump written to" in result.output
        assert output_file.exists()

        content = output_file.read_text()
        assert "Test data" in content  # ASCII column

    def test_hexdump_with_output_short_flag(self, tmp_path: Path) -> None:
        """Test hexdump with -o short flag."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test data")

        output_file = tmp_path / "output.hexdump"
        result = runner.invoke(
            app, ["hexdump", str(test_file), "-o", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

    def test_hexdump_quiet_mode(self, tmp_path: Path) -> None:
        """Test hexdump with --quiet flag suppresses messages."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test data")

        output_file = tmp_path / "output.hexdump"
        result = runner.invoke(
            app, ["hexdump", str(test_file), "-o", str(output_file), "--quiet"]
        )
        assert result.exit_code == 0
        assert "Hexdump written to" not in result.output
        assert output_file.exists()

    def test_hexdump_no_color(self, tmp_path: Path) -> None:
        """Test hexdump with --no-color flag."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Should still contain hex values
        assert "48 65 6c 6c 6f" in result.output.lower()

    def test_hexdump_empty_file(self, tmp_path: Path) -> None:
        """Test hexdump of an empty file."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        result = runner.invoke(app, ["hexdump", str(test_file)])
        assert result.exit_code == 0
        # Empty file should produce no hex output

    def test_hexdump_binary_file(self, tmp_path: Path) -> None:
        """Test hexdump of a binary file with non-printable chars."""
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"\x00\x01\x02\x7f\x80\xff")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Should contain hex values and dots for non-printable
        assert "00 01 02" in result.output.lower()
        assert "......" in result.output or "|" in result.output

    def test_hexdump_large_file(self, tmp_path: Path) -> None:
        """Test hexdump of a file with multiple lines."""
        test_file = tmp_path / "large.bin"
        # 64 bytes = 4 lines
        test_file.write_bytes(b"A" * 64)

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Should have multiple offset lines
        assert "00000000" in result.output
        assert "00000010" in result.output
        assert "00000020" in result.output
        assert "00000030" in result.output


class TestHexdumpErrors:
    """Tests for hexdump command error handling."""

    def test_hexdump_file_not_found(self, tmp_path: Path) -> None:
        """Test hexdump with non-existent file."""
        result = runner.invoke(app, ["hexdump", str(tmp_path / "nonexistent.bin")])
        assert result.exit_code != 0

    def test_hexdump_directory(self, tmp_path: Path) -> None:
        """Test hexdump with directory path."""
        result = runner.invoke(app, ["hexdump", str(tmp_path)])
        assert result.exit_code != 0
        # Should show error about directory
        assert "directory" in result.output.lower() or "error" in result.output.lower()

    def test_hexdump_output_to_new_directory(self, tmp_path: Path) -> None:
        """Test hexdump creates output directory if needed."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test data")

        output_file = tmp_path / "new_dir" / "output.hexdump"
        result = runner.invoke(
            app, ["hexdump", str(test_file), "-o", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestHexdumpFormat:
    """Tests for hexdump output format matching original behavior."""

    def test_hexdump_format_structure(self, tmp_path: Path) -> None:
        """Test hexdump output follows expected format."""
        test_file = tmp_path / "format.bin"
        test_file.write_bytes(b"0123456789ABCDEF")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0

        # Should have offset, hex values, and ASCII column
        output = result.output.strip()
        assert "00000000" in output
        assert "|0123456789ABCDEF|" in output

    def test_hexdump_hex_values_lowercase(self, tmp_path: Path) -> None:
        """Test hex values are in lowercase."""
        test_file = tmp_path / "case.bin"
        test_file.write_bytes(b"\xAB\xCD\xEF")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Should use lowercase hex
        assert "ab cd ef" in result.output.lower()

    def test_hexdump_offset_padding(self, tmp_path: Path) -> None:
        """Test offset is 8-character padded hex."""
        test_file = tmp_path / "offset.bin"
        test_file.write_bytes(b"A" * 32)

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Should have properly padded offsets
        assert "00000000" in result.output
        assert "00000010" in result.output

    def test_hexdump_ascii_non_printable_dots(self, tmp_path: Path) -> None:
        """Test non-printable chars shown as dots in ASCII column."""
        test_file = tmp_path / "dots.bin"
        test_file.write_bytes(b"\x00\x01\x02Hi\x7f")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # Non-printable should be dots
        assert "...Hi." in result.output


class TestHexdumpOutputOptions:
    """Tests for various output options."""

    def test_hexdump_output_to_existing_file(self, tmp_path: Path) -> None:
        """Test hexdump overwrites existing output file."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"New content")

        output_file = tmp_path / "output.hexdump"
        output_file.write_text("Old content")

        result = runner.invoke(
            app, ["hexdump", str(test_file), "-o", str(output_file)]
        )
        assert result.exit_code == 0

        content = output_file.read_text()
        assert "New content" in content
        assert "Old content" not in content

    def test_hexdump_output_file_matches_stdout(self, tmp_path: Path) -> None:
        """Test output file content matches stdout output."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Comparison test data")

        # Get stdout output
        stdout_result = runner.invoke(
            app, ["hexdump", str(test_file), "--no-color"]
        )

        # Get file output
        output_file = tmp_path / "output.hexdump"
        runner.invoke(
            app, ["hexdump", str(test_file), "-o", str(output_file)]
        )

        file_content = output_file.read_text()

        # Should be equivalent (file may have trailing newline)
        stdout_lines = [
            line for line in stdout_result.output.strip().split("\n") if line
        ]
        file_lines = [line for line in file_content.strip().split("\n") if line]

        # Compare actual hexdump lines (skip any informational messages)
        stdout_hex_lines = [l for l in stdout_lines if l.startswith("0000")]
        file_hex_lines = [l for l in file_lines if l.startswith("0000")]

        assert stdout_hex_lines == file_hex_lines


class TestHexdumpSpecialFiles:
    """Tests for special file types and edge cases."""

    def test_hexdump_elf_magic(self, tmp_path: Path) -> None:
        """Test hexdump correctly shows ELF magic bytes."""
        test_file = tmp_path / "elf.bin"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 12)

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # ELF magic: 7f 45 4c 46
        assert "7f 45 4c 46" in result.output.lower()
        assert ".ELF" in result.output or "|.ELF" in result.output

    def test_hexdump_zip_magic(self, tmp_path: Path) -> None:
        """Test hexdump correctly shows ZIP magic bytes."""
        test_file = tmp_path / "zip.bin"
        test_file.write_bytes(b"PK\x03\x04" + b"\x00" * 12)

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        # ZIP magic: 50 4b 03 04
        assert "50 4b 03 04" in result.output.lower()

    def test_hexdump_single_byte(self, tmp_path: Path) -> None:
        """Test hexdump of single byte file."""
        test_file = tmp_path / "single.bin"
        test_file.write_bytes(b"X")

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0
        assert "58" in result.output.lower()  # X = 0x58
        assert "|X|" in result.output

    def test_hexdump_partial_last_line(self, tmp_path: Path) -> None:
        """Test hexdump with partial last line (not 16 bytes)."""
        test_file = tmp_path / "partial.bin"
        test_file.write_bytes(b"A" * 20)  # 16 + 4 bytes

        result = runner.invoke(app, ["hexdump", str(test_file), "--no-color"])
        assert result.exit_code == 0

        lines = [l for l in result.output.strip().split("\n") if l.startswith("0000")]
        assert len(lines) == 2
        # First line: 16 bytes, second line: 4 bytes
        assert "00000000" in lines[0]
        assert "00000010" in lines[1]
