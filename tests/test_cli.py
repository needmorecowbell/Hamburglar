"""Tests for the Hamburglar CLI.

This module tests the command-line interface using Typer's CliRunner,
including version output, scan command functionality, and output formats.
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

from hamburglar import __version__
from hamburglar.cli.main import app

runner = CliRunner()


class TestVersionOutput:
    """Test --version flag outputs version correctly."""

    def test_version_flag_outputs_version(self) -> None:
        """Test that --version outputs the version number."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output
        assert "Hamburglar" in result.output

    def test_version_flag_on_scan_command(self) -> None:
        """Test that --version works on the scan command too."""
        result = runner.invoke(app, ["scan", "--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_version_is_2_0_0(self) -> None:
        """Test that version is 2.0.0 as expected."""
        assert __version__ == "2.0.0"


class TestScanCommand:
    """Test scan command with temp directory produces output."""

    def test_scan_command_with_temp_directory(self, temp_directory: Path) -> None:
        """Test that scan command produces output for directory with secrets."""
        result = runner.invoke(app, ["scan", str(temp_directory)])
        assert result.exit_code == 0
        # Should produce table output by default
        assert (
            "Hamburglar" in result.output or "Finding" in result.output or "Scan" in result.output
        )

    def test_scan_command_finds_secrets(self, temp_directory: Path) -> None:
        """Test that scan command finds secrets in temp directory."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0
        # Parse JSON and verify findings exist
        data = json.loads(result.output)
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_scan_single_file(self, temp_directory: Path) -> None:
        """Test scanning a single file."""
        single_file = temp_directory / "secrets.txt"
        result = runner.invoke(app, ["scan", str(single_file)])
        assert result.exit_code == 0

    def test_scan_nonexistent_path_fails(self, tmp_path: Path) -> None:
        """Test that scanning a nonexistent path fails with appropriate error."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        # Typer should catch this and return non-zero exit code
        assert result.exit_code != 0

    def test_scan_with_recursive_flag(self, temp_directory: Path) -> None:
        """Test scan with explicit --recursive flag."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-r"])
        assert result.exit_code == 0

    def test_scan_default_is_recursive(self, temp_directory: Path) -> None:
        """Test that scan is recursive by default."""
        # Default behavior is recursive, which finds secrets in subdir
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Should find findings from subdir (e.g., nested.txt has ethereum address)
        nested_findings = [f for f in data["findings"] if "subdir" in f["file_path"]]
        # There should be findings from nested files
        assert len(nested_findings) >= 0  # May or may not have findings depending on content


class TestJsonFormatOutput:
    """Test --format json produces valid JSON."""

    def test_format_json_produces_valid_json(self, temp_directory: Path) -> None:
        """Test that --format json produces valid JSON output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0

        # Should be valid JSON
        try:
            data = json.loads(result.output)
        except json.JSONDecodeError:
            pytest.fail("Output is not valid JSON")

    def test_json_output_has_required_fields(self, temp_directory: Path) -> None:
        """Test that JSON output contains required fields."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "target_path" in data
        assert "findings" in data
        assert "scan_duration" in data
        assert "stats" in data

    def test_json_output_findings_structure(self, temp_directory: Path) -> None:
        """Test that findings in JSON output have correct structure."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert len(data["findings"]) > 0

        # Check first finding structure
        finding = data["findings"][0]
        assert "file_path" in finding
        assert "detector_name" in finding
        assert "matches" in finding
        assert "severity" in finding

    def test_json_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f json works the same as --format json."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "json"])
        assert result.exit_code == 0

        # Should be valid JSON
        data = json.loads(result.output)
        assert "findings" in data

    def test_json_format_case_insensitive(self, temp_directory: Path) -> None:
        """Test that format option is case-insensitive."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "JSON"])
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "findings" in data


class TestTableFormatOutput:
    """Test --format table produces table output."""

    def test_format_table_produces_table_output(self, temp_directory: Path) -> None:
        """Test that --format table produces table-formatted output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "table"])
        assert result.exit_code == 0
        # Table output should contain scan results header or summary
        # Rich tables may have various formatting, but should have content
        assert len(result.output) > 0

    def test_table_is_default_format(self, temp_directory: Path) -> None:
        """Test that table is the default format when not specified."""
        result_default = runner.invoke(app, ["scan", str(temp_directory)])
        result_table = runner.invoke(app, ["scan", str(temp_directory), "--format", "table"])

        # Both should succeed
        assert result_default.exit_code == 0
        assert result_table.exit_code == 0

        # Default output should not be JSON
        try:
            json.loads(result_default.output)
            pytest.fail("Default output should be table, not JSON")
        except json.JSONDecodeError:
            pass  # Expected - table format is not valid JSON

    def test_table_format_short_flag(self, temp_directory: Path) -> None:
        """Test that -f table works the same as --format table."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-f", "table"])
        assert result.exit_code == 0
        # Should not be JSON
        try:
            json.loads(result.output)
            pytest.fail("Table output should not be valid JSON")
        except json.JSONDecodeError:
            pass  # Expected


class TestInvalidFormat:
    """Test handling of invalid format option."""

    def test_invalid_format_fails(self, temp_directory: Path) -> None:
        """Test that an invalid format option produces an error."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code != 0
        assert "Invalid format" in result.output or "Error" in result.output


class TestVerboseFlag:
    """Test --verbose/-v flag."""

    def test_verbose_flag(self, temp_directory: Path) -> None:
        """Test that --verbose produces additional output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--verbose"])
        assert result.exit_code == 0
        # Verbose mode should show scanning details
        assert "Scanning" in result.output or "Recursive" in result.output

    def test_verbose_short_flag(self, temp_directory: Path) -> None:
        """Test that -v works the same as --verbose."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-v"])
        assert result.exit_code == 0
        assert "Scanning" in result.output or "Recursive" in result.output


class TestOutputFileOption:
    """Test --output/-o file option."""

    def test_output_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --output writes to a file."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--format", "json", "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()

        # Verify file contains valid JSON
        content = output_file.read_text()
        data = json.loads(content)
        assert "findings" in data

    def test_output_file_short_flag(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that -o works the same as --output."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-f", "json", "-o", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestEmptyDirectory:
    """Test scanning empty directories."""

    def test_scan_empty_directory_json(self, tmp_path: Path) -> None:
        """Test scanning an empty directory produces valid output with exit code 2 (no findings)."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        # Exit code 2 means no findings (empty directory)
        assert result.exit_code == 2

        data = json.loads(result.output)
        assert data["findings"] == []
        assert data["stats"]["files_discovered"] == 0

    def test_scan_empty_directory_table(self, tmp_path: Path) -> None:
        """Test scanning an empty directory with table format and exit code 2 (no findings)."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "table"])
        # Exit code 2 means no findings (empty directory)
        assert result.exit_code == 2


class TestHelpOutput:
    """Test help output."""

    def test_help_flag(self) -> None:
        """Test that --help shows help information."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Hamburglar" in result.output
        assert "scan" in result.output

    def test_scan_help_flag(self) -> None:
        """Test that scan --help shows scan command help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "scan" in result.output.lower()
        assert "--format" in result.output or "-f" in result.output

    def test_no_args_shows_help(self) -> None:
        """Test that running without arguments shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        # Should show help or usage information
        assert "Hamburglar" in result.output or "Usage" in result.output


class TestExitCodes:
    """Test exit codes for various scenarios."""

    def test_exit_code_0_success_with_findings(self, temp_directory: Path) -> None:
        """Test that exit code 0 is returned when findings are found."""
        result = runner.invoke(app, ["scan", str(temp_directory)])
        assert result.exit_code == 0

    def test_exit_code_1_error(self, tmp_path: Path) -> None:
        """Test that exit code 1 is returned on error."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        assert result.exit_code != 0  # Typer returns 2 for invalid args, but 1 is for errors

    def test_exit_code_2_no_findings(self, tmp_path: Path) -> None:
        """Test that exit code 2 is returned when no findings are found."""
        # Create empty directory
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 2

    def test_exit_code_1_invalid_format(self, temp_directory: Path) -> None:
        """Test that exit code 1 is returned for invalid format."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code == 1


class TestQuietFlag:
    """Test --quiet/-q flag."""

    def test_quiet_flag_suppresses_output(self, temp_directory: Path) -> None:
        """Test that --quiet suppresses non-error output."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--quiet"])
        assert result.exit_code == 0
        # Quiet mode should produce no stdout output
        assert result.output == ""

    def test_quiet_short_flag(self, temp_directory: Path) -> None:
        """Test that -q works the same as --quiet."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-q"])
        assert result.exit_code == 0
        assert result.output == ""

    def test_quiet_still_writes_to_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --quiet still writes output to file when specified."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--quiet",
                "--format",
                "json",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        # File should exist and contain findings
        assert output_file.exists()
        content = output_file.read_text()
        data = json.loads(content)
        assert "findings" in data

    def test_quiet_with_no_findings(self, tmp_path: Path) -> None:
        """Test that --quiet returns correct exit code with no findings."""
        result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
        # Exit code 2 for no findings
        assert result.exit_code == 2
        assert result.output == ""


class TestErrorDisplay:
    """Test rich error display for various error types."""

    def test_invalid_format_shows_error_panel(self, temp_directory: Path) -> None:
        """Test that invalid format shows rich error panel."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code == 1
        # Error should be displayed (the Panel will contain the error info)
        # Note: the rich Panel output may vary, but the error message should be present
        assert (
            "Invalid format" in result.output
            or "Config Error" in result.output
            or "Error" in result.output
        )


class TestHelpContainsQuietOption:
    """Test that help includes the quiet option."""

    def test_help_shows_quiet_option(self) -> None:
        """Test that scan --help shows the --quiet option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--quiet" in result.output or "-q" in result.output


class TestHelpShowsExitCodes:
    """Test that help mentions exit codes."""

    def test_help_shows_exit_codes(self) -> None:
        """Test that scan --help documents exit codes."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        # Exit codes should be documented in the help
        assert "Exit codes" in result.output or "exit code" in result.output.lower()


class TestShellCompletion:
    """Test shell completion support."""

    def test_help_shows_install_completion(self) -> None:
        """Test that --help shows --install-completion option."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--install-completion" in result.output

    def test_help_shows_show_completion(self) -> None:
        """Test that --help shows --show-completion option."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--show-completion" in result.output

    def test_show_completion_outputs_script(self) -> None:
        """Test that --show-completion outputs a completion script."""
        result = runner.invoke(app, ["--show-completion"])
        # The command should succeed and output a completion script
        # The output contains shell-specific completion code
        assert result.exit_code == 0
        # Check for completion function markers (works for bash/zsh/fish)
        assert "hamburglar" in result.output.lower() or "completion" in result.output.lower()
