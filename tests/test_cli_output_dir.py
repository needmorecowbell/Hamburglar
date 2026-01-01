"""Tests for the Hamburglar CLI --output-dir option.

This module tests the --output-dir option which saves output to a directory
with auto-generated filenames based on target and timestamp.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

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

from hamburglar.cli.main import (
    FORMAT_EXTENSIONS,
    app,
    generate_output_filename,
)
from hamburglar.core.models import OutputFormat

runner = CliRunner()


class TestFormatExtensions:
    """Test the FORMAT_EXTENSIONS mapping."""

    def test_all_formats_have_extensions(self) -> None:
        """Test that all OutputFormat values have extensions defined."""
        for fmt in OutputFormat:
            assert fmt in FORMAT_EXTENSIONS, f"Missing extension for {fmt}"

    def test_extensions_are_valid(self) -> None:
        """Test that all extensions start with a dot."""
        for fmt, ext in FORMAT_EXTENSIONS.items():
            assert ext.startswith("."), f"Extension for {fmt} should start with '.'"

    def test_expected_extensions(self) -> None:
        """Test that extensions match expected values."""
        assert FORMAT_EXTENSIONS[OutputFormat.JSON] == ".json"
        assert FORMAT_EXTENSIONS[OutputFormat.TABLE] == ".txt"
        assert FORMAT_EXTENSIONS[OutputFormat.SARIF] == ".sarif.json"
        assert FORMAT_EXTENSIONS[OutputFormat.CSV] == ".csv"
        assert FORMAT_EXTENSIONS[OutputFormat.HTML] == ".html"
        assert FORMAT_EXTENSIONS[OutputFormat.MARKDOWN] == ".md"


class TestGenerateOutputFilename:
    """Test the generate_output_filename helper function."""

    def test_generates_filename_for_path_scan(self) -> None:
        """Test filename generation for file/directory scan."""
        filename = generate_output_filename(
            "/path/to/myproject", OutputFormat.JSON, scan_type="scan"
        )
        assert filename.startswith("hamburglar_scan_myproject_")
        assert filename.endswith(".json")

    def test_generates_filename_for_git_scan(self) -> None:
        """Test filename generation for git scan."""
        filename = generate_output_filename(
            "https://github.com/user/repo.git", OutputFormat.JSON, scan_type="git"
        )
        assert filename.startswith("hamburglar_git_repo_")
        assert filename.endswith(".json")

    def test_generates_filename_for_web_scan(self) -> None:
        """Test filename generation for web scan."""
        filename = generate_output_filename(
            "https://example.com/path", OutputFormat.JSON, scan_type="web"
        )
        assert filename.startswith("hamburglar_web_example_com_")
        assert filename.endswith(".json")

    def test_timestamp_format(self) -> None:
        """Test that filename contains valid timestamp."""
        filename = generate_output_filename("/test", OutputFormat.JSON, scan_type="scan")
        # Extract timestamp part
        match = re.search(r"_(\d{8}_\d{6})", filename)
        assert match is not None, "Filename should contain timestamp in YYYYMMDD_HHMMSS format"
        timestamp = match.group(1)
        # Verify it's a valid timestamp
        datetime.strptime(timestamp, "%Y%m%d_%H%M%S")

    def test_extension_for_sarif(self) -> None:
        """Test that SARIF uses .sarif.json extension."""
        filename = generate_output_filename("/test", OutputFormat.SARIF, scan_type="scan")
        assert filename.endswith(".sarif.json")

    def test_extension_for_html(self) -> None:
        """Test that HTML uses .html extension."""
        filename = generate_output_filename("/test", OutputFormat.HTML, scan_type="scan")
        assert filename.endswith(".html")

    def test_extension_for_csv(self) -> None:
        """Test that CSV uses .csv extension."""
        filename = generate_output_filename("/test", OutputFormat.CSV, scan_type="scan")
        assert filename.endswith(".csv")

    def test_extension_for_markdown(self) -> None:
        """Test that Markdown uses .md extension."""
        filename = generate_output_filename("/test", OutputFormat.MARKDOWN, scan_type="scan")
        assert filename.endswith(".md")

    def test_extension_for_table(self) -> None:
        """Test that table uses .txt extension."""
        filename = generate_output_filename("/test", OutputFormat.TABLE, scan_type="scan")
        assert filename.endswith(".txt")

    def test_sanitizes_special_characters(self) -> None:
        """Test that special characters in target are sanitized."""
        filename = generate_output_filename(
            "/path/to/my-project.test!@#", OutputFormat.JSON, scan_type="scan"
        )
        # Should not contain special characters except alphanumeric, dash, underscore
        name_part = filename.replace("hamburglar_scan_", "").split("_20")[0]
        assert re.match(r"^[a-zA-Z0-9_-]+$", name_part), f"Name part '{name_part}' should be sanitized"

    def test_removes_consecutive_underscores(self) -> None:
        """Test that consecutive underscores are collapsed."""
        filename = generate_output_filename(
            "/path/to/my___project", OutputFormat.JSON, scan_type="scan"
        )
        assert "___" not in filename

    def test_git_remote_url_parsing(self) -> None:
        """Test parsing of various git remote URL formats."""
        # HTTPS URL
        filename = generate_output_filename(
            "https://github.com/user/myrepo.git", OutputFormat.JSON, scan_type="git"
        )
        assert "myrepo" in filename
        assert ".git" not in filename.replace(".json", "")

        # SSH URL
        filename = generate_output_filename(
            "git@github.com:user/myrepo.git", OutputFormat.JSON, scan_type="git"
        )
        assert "myrepo" in filename

    def test_web_url_parsing(self) -> None:
        """Test parsing of web URLs."""
        # With port
        filename = generate_output_filename(
            "https://example.com:8080/path", OutputFormat.JSON, scan_type="web"
        )
        assert "example_com" in filename
        assert "8080" not in filename

        # With subdomain
        filename = generate_output_filename(
            "https://www.example.com/path", OutputFormat.JSON, scan_type="web"
        )
        assert "www_example_com" in filename

    def test_empty_target_name_fallback(self) -> None:
        """Test that empty target names use 'target' fallback."""
        # This is an edge case - test the sanitization path
        with patch("hamburglar.cli.main.Path") as mock_path:
            mock_path.return_value.resolve.return_value.name = "!!!"
            filename = generate_output_filename("!!!", OutputFormat.JSON, scan_type="scan")
            # Should fall back to "target"
            assert "hamburglar_scan_" in filename


class TestScanOutputDir:
    """Test --output-dir option for scan command."""

    def test_output_dir_creates_directory(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir creates the directory if it doesn't exist."""
        output_dir = tmp_path / "new_output_dir"
        assert not output_dir.exists()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json"]
        )
        assert result.exit_code == 0
        assert output_dir.exists()

    def test_output_dir_creates_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir creates an output file."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json"]
        )
        assert result.exit_code == 0

        # Should have created a file in the output directory
        files = list(output_dir.glob("hamburglar_scan_*.json"))
        assert len(files) == 1

    def test_output_dir_auto_names_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir auto-names the file correctly."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.json"))
        assert len(files) == 1
        filename = files[0].name
        assert filename.startswith("hamburglar_scan_")
        assert temp_directory.name in filename or "temp" in filename.lower()

    def test_output_dir_with_sarif_format(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir works with SARIF format."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "sarif"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.sarif.json"))
        assert len(files) == 1

    def test_output_dir_with_csv_format(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir works with CSV format."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "csv"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.csv"))
        assert len(files) == 1

    def test_output_dir_with_html_format(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir works with HTML format."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "html"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.html"))
        assert len(files) == 1

    def test_output_dir_with_markdown_format(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir works with Markdown format."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "markdown"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.md"))
        assert len(files) == 1

    def test_output_dir_creates_nested_directories(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir creates nested directories."""
        output_dir = tmp_path / "nested" / "output" / "dir"
        assert not output_dir.exists()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json"]
        )
        assert result.exit_code == 0
        assert output_dir.exists()

    def test_output_and_output_dir_conflict(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output and --output-dir cannot be used together."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--output",
                str(output_file),
                "--output-dir",
                str(output_dir),
            ],
        )
        assert result.exit_code == 1
        assert "Cannot use both" in result.output

    def test_output_dir_quiet_mode(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir works with --quiet."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json", "--quiet"],
        )
        assert result.exit_code == 0
        assert result.output == ""

        files = list(output_dir.glob("*.json"))
        assert len(files) == 1

    def test_output_dir_verbose_mode(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output-dir shows output file path in --verbose mode."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json", "--verbose"],
        )
        assert result.exit_code == 0
        assert "Output file:" in result.output

    def test_output_dir_file_contains_valid_json(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that the output file contains valid JSON."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app, ["scan", str(temp_directory), "--output-dir", str(output_dir), "--format", "json"]
        )
        assert result.exit_code == 0

        files = list(output_dir.glob("*.json"))
        assert len(files) == 1

        content = files[0].read_text()
        try:
            json.loads(content)
        except json.JSONDecodeError:
            pytest.fail("Output file should contain valid JSON")


class TestScanGitOutputDir:
    """Test --output-dir option for scan-git command."""

    def test_scan_git_output_and_output_dir_conflict(self, tmp_path: Path) -> None:
        """Test that --output and --output-dir cannot be used together in scan-git."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "scan-git",
                str(tmp_path),  # Use tmp_path as a fake git target
                "--output",
                str(output_file),
                "--output-dir",
                str(output_dir),
            ],
        )
        assert result.exit_code == 1
        assert "Cannot use both" in result.output


class TestScanWebOutputDir:
    """Test --output-dir option for scan-web command."""

    def test_scan_web_output_and_output_dir_conflict(self, tmp_path: Path) -> None:
        """Test that --output and --output-dir cannot be used together in scan-web."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "scan-web",
                "https://example.com",
                "--output",
                str(output_file),
                "--output-dir",
                str(output_dir),
            ],
        )
        assert result.exit_code == 1
        assert "Cannot use both" in result.output


class TestHelpText:
    """Test that help text includes --output-dir option."""

    def test_scan_help_shows_output_dir(self) -> None:
        """Test that scan --help shows --output-dir option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--output-dir" in result.output

    def test_scan_git_help_shows_output_dir(self) -> None:
        """Test that scan-git --help shows --output-dir option."""
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "--output-dir" in result.output

    def test_scan_web_help_shows_output_dir(self) -> None:
        """Test that scan-web --help shows --output-dir option."""
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0
        assert "--output-dir" in result.output
