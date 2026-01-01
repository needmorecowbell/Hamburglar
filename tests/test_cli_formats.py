"""Tests for the Hamburglar CLI output format options.

This module tests all supported output formats (json, table, sarif, csv, html, markdown)
across the scan, scan-git, and scan-web commands.
"""

from __future__ import annotations

import json
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

from hamburglar.cli.main import FORMAT_FORMATTERS, VALID_FORMATS, app, get_formatter
from hamburglar.core.models import OutputFormat

runner = CliRunner()


class TestValidFormats:
    """Test that all expected formats are in VALID_FORMATS."""

    def test_all_formats_in_valid_formats(self) -> None:
        """Test that all expected format names are in VALID_FORMATS."""
        expected_formats = {"json", "table", "sarif", "csv", "html", "markdown"}
        assert set(VALID_FORMATS.keys()) == expected_formats

    def test_valid_formats_maps_to_output_format(self) -> None:
        """Test that VALID_FORMATS maps to OutputFormat enum values."""
        for name, fmt in VALID_FORMATS.items():
            assert isinstance(fmt, OutputFormat)
            assert fmt.value == name

    def test_format_formatters_has_all_formats(self) -> None:
        """Test that FORMAT_FORMATTERS has entries for all OutputFormat values."""
        for fmt in OutputFormat:
            assert fmt in FORMAT_FORMATTERS, f"Missing formatter for {fmt}"


class TestGetFormatter:
    """Test the get_formatter helper function."""

    def test_get_formatter_returns_correct_types(self) -> None:
        """Test that get_formatter returns correct formatter instances."""
        # Check by class name to avoid module identity issues
        assert get_formatter(OutputFormat.JSON).__class__.__name__ == "JsonOutput"
        assert get_formatter(OutputFormat.TABLE).__class__.__name__ == "TableOutput"
        assert get_formatter(OutputFormat.SARIF).__class__.__name__ == "SarifOutput"
        assert get_formatter(OutputFormat.CSV).__class__.__name__ == "CsvOutput"
        assert get_formatter(OutputFormat.HTML).__class__.__name__ == "HtmlOutput"
        assert get_formatter(OutputFormat.MARKDOWN).__class__.__name__ == "MarkdownOutput"

    def test_get_formatter_all_formats_return_formatter(self) -> None:
        """Test that all OutputFormat values return a valid formatter."""
        for fmt in OutputFormat:
            formatter = get_formatter(fmt)
            assert hasattr(formatter, "format"), f"Formatter for {fmt} missing format method"
            assert hasattr(formatter, "name"), f"Formatter for {fmt} missing name property"


class TestSarifFormat:
    """Test --format sarif output."""

    def test_sarif_format_produces_valid_json(self, temp_directory: Path) -> None:
        """Test that --format sarif produces valid JSON output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "sarif"])
        assert result.exit_code == 0

        # Should be valid JSON
        try:
            data = json.loads(result.output)
        except json.JSONDecodeError:
            pytest.fail("SARIF output is not valid JSON")

    def test_sarif_output_has_required_structure(self, temp_directory: Path) -> None:
        """Test that SARIF output has required SARIF 2.1.0 structure."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "sarif"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "$schema" in data
        assert "version" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) > 0

        # Check run structure
        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "results" in run

    def test_sarif_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f sarif works."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "sarif"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_sarif_format_case_insensitive(self, temp_directory: Path) -> None:
        """Test that format option is case-insensitive for sarif."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "SARIF"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_sarif_output_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that SARIF output can be written to file."""
        output_file = tmp_path / "output.sarif"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "sarif", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"


class TestCsvFormat:
    """Test --format csv output."""

    def test_csv_format_produces_output(self, temp_directory: Path) -> None:
        """Test that --format csv produces CSV output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "csv"])
        assert result.exit_code == 0
        # CSV should have content
        assert len(result.output) > 0

    def test_csv_output_has_headers(self, temp_directory: Path) -> None:
        """Test that CSV output includes headers."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "csv"])
        assert result.exit_code == 0

        lines = result.output.strip().split("\r\n")  # RFC 4180 uses CRLF
        if not lines:
            lines = result.output.strip().split("\n")  # Fallback
        assert len(lines) > 0
        # Check for expected header fields
        header = lines[0].lower()
        assert "file" in header or "path" in header

    def test_csv_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f csv works."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "csv"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_csv_format_case_insensitive(self, temp_directory: Path) -> None:
        """Test that format option is case-insensitive for csv."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "CSV"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_csv_output_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that CSV output can be written to file."""
        output_file = tmp_path / "output.csv"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "csv", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        assert len(content) > 0


class TestHtmlFormat:
    """Test --format html output."""

    def test_html_format_produces_valid_html(self, temp_directory: Path) -> None:
        """Test that --format html produces HTML output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "html"])
        assert result.exit_code == 0

        # Should contain HTML structure
        assert "<!DOCTYPE html>" in result.output or "<html" in result.output
        assert "</html>" in result.output

    def test_html_output_has_required_elements(self, temp_directory: Path) -> None:
        """Test that HTML output has required elements."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "html"])
        assert result.exit_code == 0

        # Check for key HTML elements
        assert "<head>" in result.output
        assert "<body>" in result.output
        assert "<style>" in result.output  # Inline styles

    def test_html_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f html works."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "html"])
        assert result.exit_code == 0
        assert "<html" in result.output

    def test_html_format_case_insensitive(self, temp_directory: Path) -> None:
        """Test that format option is case-insensitive for html."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "HTML"])
        assert result.exit_code == 0
        assert "<html" in result.output

    def test_html_output_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that HTML output can be written to file."""
        output_file = tmp_path / "output.html"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "html", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        assert "<html" in content


class TestMarkdownFormat:
    """Test --format markdown output."""

    def test_markdown_format_produces_output(self, temp_directory: Path) -> None:
        """Test that --format markdown produces Markdown output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "markdown"])
        assert result.exit_code == 0
        # Markdown should contain headers or tables
        assert "#" in result.output or "|" in result.output

    def test_markdown_output_has_structure(self, temp_directory: Path) -> None:
        """Test that Markdown output has expected structure."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "markdown"])
        assert result.exit_code == 0

        # Should have a title header
        assert "# " in result.output or "## " in result.output

    def test_markdown_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f markdown works."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "markdown"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_markdown_format_case_insensitive(self, temp_directory: Path) -> None:
        """Test that format option is case-insensitive for markdown."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "MARKDOWN"])
        assert result.exit_code == 0
        assert len(result.output) > 0

    def test_markdown_output_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that Markdown output can be written to file."""
        output_file = tmp_path / "output.md"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "markdown", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        assert len(content) > 0


class TestInvalidFormat:
    """Test handling of invalid format options."""

    def test_invalid_format_fails_with_error(self, temp_directory: Path) -> None:
        """Test that an invalid format option produces an error."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code == 1
        assert "Invalid format" in result.output

    def test_invalid_format_shows_valid_options(self, temp_directory: Path) -> None:
        """Test that invalid format error shows valid format options."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "invalid"])
        assert result.exit_code == 1
        # Should mention valid formats
        assert "csv" in result.output.lower() or "Valid formats" in result.output


class TestFormatHelpText:
    """Test that help text includes all format options."""

    def test_scan_help_shows_format_options(self) -> None:
        """Test that scan --help shows format options."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        # Check that help text mentions available formats
        help_text = result.output.lower()
        assert "json" in help_text
        assert "table" in help_text
        assert "sarif" in help_text
        assert "csv" in help_text
        assert "html" in help_text
        assert "markdown" in help_text


class TestFormatWithQuiet:
    """Test format options with --quiet flag."""

    def test_sarif_quiet_with_output_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --quiet --format sarif still writes to file."""
        output_file = tmp_path / "output.sarif"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--quiet",
                "--format",
                "sarif",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert result.output == ""
        assert output_file.exists()

        content = output_file.read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"

    def test_csv_quiet_with_output_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --quiet --format csv still writes to file."""
        output_file = tmp_path / "output.csv"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--quiet",
                "--format",
                "csv",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert result.output == ""
        assert output_file.exists()


class TestEmptyDirectoryFormats:
    """Test format options with empty directory (no findings)."""

    def test_sarif_empty_directory(self, tmp_path: Path) -> None:
        """Test SARIF format with empty directory produces valid output."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 2  # No findings

        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"] == []

    def test_csv_empty_directory(self, tmp_path: Path) -> None:
        """Test CSV format with empty directory."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "csv"])
        assert result.exit_code == 2  # No findings
        # Should still have header row
        assert len(result.output) > 0

    def test_html_empty_directory(self, tmp_path: Path) -> None:
        """Test HTML format with empty directory."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "html"])
        assert result.exit_code == 2  # No findings
        assert "<html" in result.output

    def test_markdown_empty_directory(self, tmp_path: Path) -> None:
        """Test Markdown format with empty directory."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "markdown"])
        assert result.exit_code == 2  # No findings
        assert len(result.output) > 0


class TestVerboseWithFormats:
    """Test format options with --verbose flag."""

    def test_sarif_verbose_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test SARIF format with verbose mode writes valid SARIF to file."""
        # Verbose mode outputs debug info to console, but file should be clean SARIF
        output_file = tmp_path / "output.sarif"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--format",
                "sarif",
                "--verbose",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()

        content = output_file.read_text()
        data = json.loads(content)
        assert data["version"] == "2.1.0"

    def test_html_verbose(self, temp_directory: Path) -> None:
        """Test HTML format with verbose mode."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "html", "--verbose"])
        assert result.exit_code == 0
        assert "<html" in result.output
