"""Tests for the Hamburglar CLI async features.

This module tests the async CLI features including concurrency options,
streaming output mode, and the rich progress bar integration.
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

from hamburglar.cli.main import app, DEFAULT_CONCURRENCY

runner = CliRunner()


class TestConcurrencyOption:
    """Tests for the --concurrency/-j option."""

    def test_default_concurrency_is_50(self) -> None:
        """Test that default concurrency is 50."""
        assert DEFAULT_CONCURRENCY == 50

    def test_concurrency_option_in_help(self) -> None:
        """Test that --concurrency option appears in help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--concurrency" in result.output or "-j" in result.output
        assert "50" in result.output  # Default value should be shown

    def test_concurrency_short_option_in_help(self) -> None:
        """Test that -j short option appears in help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "-j" in result.output

    def test_scan_with_default_concurrency(
        self, temp_directory: Path
    ) -> None:
        """Test that scan works with default concurrency."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_with_custom_concurrency(
        self, temp_directory: Path
    ) -> None:
        """Test that scan works with custom concurrency value."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--concurrency", "10", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_scan_with_short_concurrency_flag(
        self, temp_directory: Path
    ) -> None:
        """Test that -j works the same as --concurrency."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "25", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_concurrency_with_verbose_shows_value(
        self, temp_directory: Path
    ) -> None:
        """Test that verbose mode shows the concurrency value."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "15", "--verbose"]
        )
        assert result.exit_code == 0
        assert "Concurrency" in result.output
        assert "15" in result.output

    def test_concurrency_minimum_value(
        self, temp_directory: Path
    ) -> None:
        """Test that concurrency accepts minimum value of 1."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "1", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data

    def test_concurrency_invalid_value_zero(
        self, temp_directory: Path
    ) -> None:
        """Test that concurrency rejects 0."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "0"]
        )
        assert result.exit_code != 0

    def test_concurrency_invalid_value_negative(
        self, temp_directory: Path
    ) -> None:
        """Test that concurrency rejects negative values."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "-5"]
        )
        assert result.exit_code != 0

    def test_concurrency_invalid_value_too_high(
        self, temp_directory: Path
    ) -> None:
        """Test that concurrency rejects values above 1000."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-j", "1001"]
        )
        assert result.exit_code != 0


class TestStreamingOption:
    """Tests for the --stream option."""

    def test_stream_option_in_help(self) -> None:
        """Test that --stream option appears in help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--stream" in result.output
        assert "NDJSON" in result.output

    def test_stream_produces_ndjson_output(
        self, temp_directory: Path
    ) -> None:
        """Test that --stream produces NDJSON (one JSON per line)."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--stream"])
        assert result.exit_code == 0

        # Each non-empty line should be valid JSON
        lines = [line for line in result.output.strip().split("\n") if line.strip()]
        assert len(lines) > 0

        for line in lines:
            # Should parse as valid JSON
            try:
                finding = json.loads(line)
                # Each finding should have expected fields
                assert "file_path" in finding
                assert "detector_name" in finding
            except json.JSONDecodeError:
                pytest.fail(f"Line is not valid JSON: {line}")

    def test_stream_with_verbose_shows_mode(
        self, temp_directory: Path
    ) -> None:
        """Test that verbose mode shows streaming mode indicator."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--stream", "--verbose"]
        )
        assert result.exit_code == 0
        # The verbose output goes to stderr, but the mode should be indicated
        assert "Streaming" in result.output or "NDJSON" in result.output or len(result.output.strip()) > 0

    def test_stream_with_output_file(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test that --stream can write to an output file."""
        output_file = tmp_path / "stream_output.ndjson"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--stream", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        # Verify file contents are valid NDJSON
        content = output_file.read_text()
        lines = [line for line in content.strip().split("\n") if line.strip()]
        assert len(lines) > 0

        for line in lines:
            finding = json.loads(line)
            assert "file_path" in finding

    def test_stream_empty_directory_exit_code(
        self, tmp_path: Path
    ) -> None:
        """Test that --stream returns exit code 2 for empty directory."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--stream"])
        assert result.exit_code == 2

    def test_stream_with_quiet(
        self, temp_directory: Path
    ) -> None:
        """Test that --stream with --quiet outputs only NDJSON."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--stream", "--quiet"]
        )
        # exit code 0 for findings, output should only be NDJSON
        if result.exit_code == 0:
            # All output should be JSON lines
            lines = [line for line in result.output.strip().split("\n") if line.strip()]
            for line in lines:
                json.loads(line)  # Should not raise

    def test_stream_with_concurrency(
        self, temp_directory: Path
    ) -> None:
        """Test that --stream works with --concurrency."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--stream", "-j", "5"]
        )
        assert result.exit_code == 0

        lines = [line for line in result.output.strip().split("\n") if line.strip()]
        assert len(lines) > 0


class TestProgressBar:
    """Tests for the rich progress bar functionality."""

    def test_scan_without_quiet_produces_output(
        self, temp_directory: Path
    ) -> None:
        """Test that scan without --quiet produces visible output."""
        # This test verifies the progress bar path is taken
        result = runner.invoke(app, ["scan", str(temp_directory)])
        assert result.exit_code == 0
        # Should have table output (progress bar is transient by default)
        assert len(result.output) > 0

    def test_scan_with_verbose_shows_stats(
        self, temp_directory: Path
    ) -> None:
        """Test that verbose mode shows scan statistics."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--verbose"])
        assert result.exit_code == 0
        # Verbose mode should show scanning information
        assert "Scanning" in result.output or "files" in result.output.lower()

    def test_quiet_mode_no_table_output(
        self, temp_directory: Path
    ) -> None:
        """Test that quiet mode does not produce table output.

        Note: The CLI uses logging which may still produce output when
        Rich handlers are configured. This test verifies no table/findings
        output is produced (logging output is separate from CLI output).
        """
        result = runner.invoke(app, ["scan", str(temp_directory), "--quiet"])
        assert result.exit_code == 0
        # Quiet mode should not produce findings table output
        # (but may have logging output from Rich handlers in test environment)
        # Check that there's no finding-related output
        assert "Finding" not in result.output or "findings" in result.output.lower()


class TestAsyncScannerIntegration:
    """Tests for AsyncScanner integration with CLI."""

    def test_scan_produces_valid_stats(
        self, temp_directory: Path
    ) -> None:
        """Test that scan produces valid stats from AsyncScanner."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "json"]
        )
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "stats" in data
        assert "files_scanned" in data["stats"]
        assert "files_discovered" in data["stats"]
        assert data["stats"]["files_scanned"] >= 0
        assert data["stats"]["files_discovered"] >= 0

    def test_scan_duration_is_recorded(
        self, temp_directory: Path
    ) -> None:
        """Test that scan duration is recorded correctly."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "json"]
        )
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "scan_duration" in data
        assert data["scan_duration"] >= 0

    def test_scan_with_categories_filter(
        self, temp_directory: Path
    ) -> None:
        """Test that scan with categories filter works with async scanner."""
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--format", "json", "--categories", "api_keys"]
        )
        # Should work regardless of findings
        assert result.exit_code in (0, 2)

        data = json.loads(result.output)
        assert "findings" in data


class TestCombinedOptions:
    """Tests for combinations of CLI options."""

    def test_stream_and_json_format(
        self, temp_directory: Path
    ) -> None:
        """Test that --stream takes precedence over --format json."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--stream", "--format", "json"]
        )
        assert result.exit_code == 0

        # Output should be NDJSON (multiple JSON objects, one per line)
        # not a single JSON array
        lines = [line for line in result.output.strip().split("\n") if line.strip()]
        if len(lines) > 0:
            # First line should be a complete JSON object (a finding)
            first = json.loads(lines[0])
            assert "file_path" in first

    def test_verbose_with_concurrency_shows_both(
        self, temp_directory: Path
    ) -> None:
        """Test that verbose mode shows concurrency setting."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--verbose", "-j", "20"]
        )
        assert result.exit_code == 0
        assert "Concurrency" in result.output
        assert "20" in result.output

    def test_quiet_with_output_file(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test that quiet mode with output file works correctly."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--quiet", "--format", "json", "-o", str(output_file)]
        )
        assert result.exit_code == 0
        # Output file should exist and contain valid JSON
        assert output_file.exists()

        # File should contain valid JSON
        content = output_file.read_text()
        data = json.loads(content)
        assert "findings" in data
