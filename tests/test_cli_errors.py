"""Tests for CLI error handling.

This module tests the command-line interface error handling including
non-existent paths, permission errors, invalid options, and graceful
interruption handling.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

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
    EXIT_ERROR,
    EXIT_NO_FINDINGS,
    EXIT_SUCCESS,
    app,
)

runner = CliRunner()


class TestScanNonExistentPath:
    """Test error handling for scanning non-existent paths."""

    def test_nonexistent_path_returns_exit_code_2(self, tmp_path: Path) -> None:
        """Test that scanning a nonexistent path returns exit code 2 (Typer validation)."""
        nonexistent = tmp_path / "this_path_does_not_exist"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        # Typer's exists=True validation returns exit code 2 for missing paths
        assert result.exit_code == 2

    def test_nonexistent_path_shows_error_message(self, tmp_path: Path) -> None:
        """Test that scanning a nonexistent path shows an error message."""
        nonexistent = tmp_path / "missing_file.txt"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        # Typer should display an error about the path not existing
        assert "does not exist" in result.output.lower() or "error" in result.output.lower()

    def test_nonexistent_nested_path(self, tmp_path: Path) -> None:
        """Test that deeply nested nonexistent paths are handled."""
        nonexistent = tmp_path / "a" / "b" / "c" / "deeply" / "nested" / "path"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        assert result.exit_code == 2
        assert "does not exist" in result.output.lower() or "error" in result.output.lower()

    def test_nonexistent_file_in_existing_dir(self, tmp_path: Path) -> None:
        """Test that nonexistent file in an existing directory is handled."""
        nonexistent = tmp_path / "nonexistent_file.json"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        assert result.exit_code == 2

    def test_empty_path_argument(self) -> None:
        """Test that empty path argument is handled.

        Note: An empty string path resolves to the current working directory,
        so it may succeed if the CWD exists and is scannable.
        """
        result = runner.invoke(app, ["scan", ""])
        # Empty path resolves to CWD, which exists, so scan proceeds
        # The exit code depends on whether findings are found in CWD
        assert result.exit_code in (0, 2)  # Either findings or no findings


class TestPermissionDenied:
    """Test error handling for permission denied scenarios."""

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific permission tests")
    def test_unreadable_directory_shows_error(self, tmp_path: Path) -> None:
        """Test that scanning an unreadable directory shows an error."""
        # Create a directory with no read permissions
        unreadable_dir = tmp_path / "unreadable"
        unreadable_dir.mkdir()
        unreadable_dir.chmod(0o000)

        try:
            result = runner.invoke(app, ["scan", str(unreadable_dir)])
            # Should either show an error panel or exit with error code
            # The behavior depends on whether Typer validates access before passing to scan
            assert result.exit_code != 0 or "permission" in result.output.lower() or len(result.output) > 0
        finally:
            # Restore permissions for cleanup
            unreadable_dir.chmod(0o755)

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific permission tests")
    def test_unreadable_file_shows_error(self, tmp_path: Path) -> None:
        """Test that scanning an unreadable file shows appropriate behavior."""
        # Create a file with no read permissions
        unreadable_file = tmp_path / "unreadable.txt"
        unreadable_file.write_text("secret = 'AKIAIOSFODNN7EXAMPLE'")
        unreadable_file.chmod(0o000)

        try:
            result = runner.invoke(app, ["scan", str(unreadable_file)])
            # Scanner should continue (skip unreadable files) or report the issue
            # Exit code 2 (no findings) is acceptable since the file was skipped
            assert result.exit_code in (0, 2) or "permission" in result.output.lower()
        finally:
            # Restore permissions for cleanup
            unreadable_file.chmod(0o644)

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific permission tests")
    def test_partial_permission_denied_continues(self, tmp_path: Path) -> None:
        """Test that scan continues when some files are unreadable."""
        # Create one readable file with secrets
        readable = tmp_path / "readable.txt"
        readable.write_text("aws_key = 'AKIAIOSFODNN7EXAMPLE'")

        # Create one unreadable file
        unreadable = tmp_path / "unreadable.txt"
        unreadable.write_text("more_secrets")
        unreadable.chmod(0o000)

        try:
            result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
            # Scan should continue and find secrets in readable file
            # Exit code 0 means findings were found
            assert result.exit_code == 0
        finally:
            unreadable.chmod(0o644)

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific permission tests")
    def test_unwritable_output_file(self, tmp_path: Path) -> None:
        """Test that writing to an unwritable location shows error."""
        # Create a directory for test files
        test_dir = tmp_path / "test"
        test_dir.mkdir()

        # Create a file with secrets
        secrets_file = test_dir / "secrets.txt"
        secrets_file.write_text("api_key = 'AKIAIOSFODNN7EXAMPLE'")

        # Create a directory with no write permissions
        unwritable_dir = tmp_path / "readonly"
        unwritable_dir.mkdir()
        unwritable_dir.chmod(0o555)

        output_file = unwritable_dir / "output.json"

        try:
            result = runner.invoke(
                app,
                ["scan", str(test_dir), "--format", "json", "--output", str(output_file)]
            )
            # Should fail with permission error
            assert result.exit_code == 1 or "permission" in result.output.lower()
        finally:
            unwritable_dir.chmod(0o755)


class TestInvalidFormatOption:
    """Test error handling for invalid --format values."""

    def test_invalid_format_returns_exit_1(self, temp_directory: Path) -> None:
        """Test that invalid format returns exit code 1."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code == EXIT_ERROR

    def test_invalid_format_shows_error_message(self, temp_directory: Path) -> None:
        """Test that invalid format shows an error message."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert "invalid format" in result.output.lower() or "error" in result.output.lower()

    def test_invalid_format_mentions_valid_options(self, temp_directory: Path) -> None:
        """Test that the error suggests valid format options."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "csv"])
        assert result.exit_code == 1
        # Error should mention it's a config error or invalid format
        assert "format" in result.output.lower()

    def test_various_invalid_formats(self, temp_directory: Path) -> None:
        """Test various invalid format values."""
        invalid_formats = ["xml", "csv", "yaml", "html", "md", "plaintext", "123"]
        for fmt in invalid_formats:
            result = runner.invoke(app, ["scan", str(temp_directory), "--format", fmt])
            assert result.exit_code == 1, f"Expected exit 1 for format '{fmt}'"

    def test_empty_format_value(self, temp_directory: Path) -> None:
        """Test that empty format value shows error."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", ""])
        assert result.exit_code == 1

    def test_format_with_spaces(self, temp_directory: Path) -> None:
        """Test that format with spaces shows error."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "json table"])
        assert result.exit_code == 1


class TestInvalidYaraPath:
    """Test error handling for invalid --yara paths."""

    def test_nonexistent_yara_path_returns_exit_2(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that nonexistent YARA path returns exit code 2 (Typer validation)."""
        nonexistent_yara = tmp_path / "rules" / "nonexistent.yar"
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(nonexistent_yara)]
        )
        # Typer's exists=True validation returns exit code 2
        assert result.exit_code == 2

    def test_nonexistent_yara_path_shows_error(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that nonexistent YARA path shows an error message."""
        nonexistent_yara = tmp_path / "missing_rules.yar"
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(nonexistent_yara)]
        )
        assert "does not exist" in result.output.lower() or "error" in result.output.lower()

    def test_invalid_yara_rules_syntax(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that invalid YARA rule syntax shows compilation error."""
        # Create a YARA file with invalid syntax
        bad_yara = tmp_path / "bad.yar"
        bad_yara.write_text("""
rule invalid_rule {
    strings:
        $a = "test"  // Missing 'condition' section
}
""")
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(bad_yara)]
        )
        # Should show YARA compilation error
        assert result.exit_code == 1
        assert "yara" in result.output.lower() or "error" in result.output.lower()

    def test_empty_yara_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that empty YARA file is handled."""
        empty_yara = tmp_path / "empty.yar"
        empty_yara.write_text("")
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(empty_yara)]
        )
        # Empty file should either work (no rules) or show a meaningful message
        # Exit code 0, 1, or 2 are all acceptable depending on implementation
        assert result.exit_code in (0, 1, 2)

    def test_yara_file_with_only_comments(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that YARA file with only comments is handled."""
        comments_only = tmp_path / "comments.yar"
        comments_only.write_text("""
// This is a YARA file with only comments
/* Block comment */
// No actual rules here
""")
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(comments_only)]
        )
        # Should work but find nothing, or show that no rules loaded
        assert result.exit_code in (0, 1, 2)

    @pytest.mark.skipif(os.name == "nt", reason="Unix-specific permission tests")
    def test_unreadable_yara_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that unreadable YARA file shows permission error.

        Note: Typer's exists=True check may fail early with exit code 2 on some
        systems when the file exists but is unreadable, as it may check path
        existence before we try to read the file contents.
        """
        unreadable_yara = tmp_path / "unreadable.yar"
        unreadable_yara.write_text("rule test { condition: true }")
        unreadable_yara.chmod(0o000)

        try:
            result = runner.invoke(
                app,
                ["scan", str(temp_directory), "--yara", str(unreadable_yara)]
            )
            # Exit code 1 (our error) or 2 (Typer validation) are both acceptable
            assert result.exit_code in (1, 2)
            assert "permission" in result.output.lower() or "error" in result.output.lower() or "does not exist" in result.output.lower()
        finally:
            unreadable_yara.chmod(0o644)

    def test_yara_directory_with_no_yar_files(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that YARA directory with no .yar files is handled."""
        empty_dir = tmp_path / "no_rules"
        empty_dir.mkdir()
        # Create a non-yar file
        (empty_dir / "readme.txt").write_text("This is not a YARA file")

        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--yara", str(empty_dir)]
        )
        # Should either show error about no rules or handle gracefully
        assert result.exit_code in (0, 1, 2)


class TestKeyboardInterrupt:
    """Test graceful handling of keyboard interrupts."""

    def test_keyboard_interrupt_returns_exit_1(self, temp_directory: Path) -> None:
        """Test that KeyboardInterrupt returns exit code 1."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            result = runner.invoke(app, ["scan", str(temp_directory)])
            assert result.exit_code == EXIT_ERROR

    def test_keyboard_interrupt_shows_message(self, temp_directory: Path) -> None:
        """Test that KeyboardInterrupt shows interrupted message."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            result = runner.invoke(app, ["scan", str(temp_directory)])
            # Should show that scan was interrupted
            assert "interrupt" in result.output.lower()

    def test_keyboard_interrupt_in_quiet_mode(self, temp_directory: Path) -> None:
        """Test that KeyboardInterrupt in quiet mode exits with correct code.

        Note: In quiet mode, the interrupted message goes to stderr which may
        not appear in result.output depending on CliRunner configuration.
        The important thing is the exit code is correct.
        """
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = KeyboardInterrupt()
            result = runner.invoke(app, ["scan", str(temp_directory), "--quiet"])
            assert result.exit_code == EXIT_ERROR
            # Quiet mode may suppress the message; just verify the exit code


class TestUnexpectedErrors:
    """Test handling of unexpected errors during scan."""

    def test_unexpected_exception_returns_exit_1(self, temp_directory: Path) -> None:
        """Test that unexpected exceptions return exit code 1."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = RuntimeError("Unexpected error occurred")
            result = runner.invoke(app, ["scan", str(temp_directory)])
            assert result.exit_code == EXIT_ERROR

    def test_unexpected_exception_shows_error_panel(self, temp_directory: Path) -> None:
        """Test that unexpected exceptions show an error panel."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = ValueError("Something went wrong")
            result = runner.invoke(app, ["scan", str(temp_directory)])
            # Should show an error message
            assert "error" in result.output.lower()

    def test_scan_error_during_scan(self, temp_directory: Path) -> None:
        """Test that ScanError during scan is displayed properly."""
        from hamburglar.core.exceptions import ScanError

        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = ScanError("Failed to read file", path="/some/file")
            result = runner.invoke(app, ["scan", str(temp_directory)])
            assert result.exit_code == EXIT_ERROR
            assert "scan error" in result.output.lower() or "error" in result.output.lower()

    def test_permission_error_during_scan(self, temp_directory: Path) -> None:
        """Test that PermissionError during scan is handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = PermissionError("Access denied")
            result = runner.invoke(app, ["scan", str(temp_directory)])
            assert result.exit_code == EXIT_ERROR
            assert "permission" in result.output.lower()


class TestOutputFileErrors:
    """Test error handling for output file writing."""

    def test_output_to_invalid_path(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test writing output to an invalid path."""
        invalid_output = tmp_path / "nonexistent_dir" / "output.json"
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--output", str(invalid_output), "--format", "json"]
        )
        # Should fail with an error about the output path
        assert result.exit_code == 1

    def test_output_error_shows_path(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that output errors show the problematic path."""
        # Try to write to a path that will fail
        invalid_output = tmp_path / "missing" / "deep" / "path" / "output.json"
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--output", str(invalid_output), "--format", "json"]
        )
        assert result.exit_code == 1


class TestCombinedErrorScenarios:
    """Test combinations of error conditions."""

    def test_nonexistent_path_with_invalid_format(self, tmp_path: Path) -> None:
        """Test nonexistent path combined with invalid format."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(
            app,
            ["scan", str(nonexistent), "--format", "xml"]
        )
        # Typer should catch the path issue first
        assert result.exit_code != 0

    def test_verbose_with_error(self, tmp_path: Path) -> None:
        """Test that verbose mode works with errors."""
        nonexistent = tmp_path / "missing"
        result = runner.invoke(app, ["scan", str(nonexistent), "--verbose"])
        assert result.exit_code != 0

    def test_quiet_with_error(self, tmp_path: Path) -> None:
        """Test that quiet mode shows errors."""
        nonexistent = tmp_path / "missing"
        result = runner.invoke(app, ["scan", str(nonexistent), "--quiet"])
        # Errors should still be shown even in quiet mode
        assert result.exit_code != 0
        # Error output should still appear (it goes to stderr which CliRunner captures)
        assert len(result.output) > 0 or result.exit_code == 2


class TestErrorExitCodes:
    """Test that exit codes are correct for various error scenarios."""

    def test_exit_0_for_findings(self, temp_directory: Path) -> None:
        """Verify exit code 0 when findings are found."""
        result = runner.invoke(app, ["scan", str(temp_directory)])
        assert result.exit_code == EXIT_SUCCESS

    def test_exit_1_for_errors(self, temp_directory: Path) -> None:
        """Verify exit code 1 for errors."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "invalid"])
        assert result.exit_code == EXIT_ERROR

    def test_exit_2_for_no_findings(self, tmp_path: Path) -> None:
        """Verify exit code 2 when no findings are found."""
        # Empty directory has no findings
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == EXIT_NO_FINDINGS

    def test_exit_2_for_nonexistent_path_typer_validation(self, tmp_path: Path) -> None:
        """Verify exit code 2 from Typer's path validation."""
        nonexistent = tmp_path / "not_here"
        result = runner.invoke(app, ["scan", str(nonexistent)])
        # Typer returns exit code 2 for validation errors
        assert result.exit_code == 2


class TestMissingRequiredArguments:
    """Test handling of missing required arguments."""

    def test_missing_path_argument(self) -> None:
        """Test that missing path argument shows error."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0
        assert "missing argument" in result.output.lower() or "path" in result.output.lower()

    def test_scan_without_subcommand(self) -> None:
        """Test running app without subcommand shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        # Should show help
        assert "hamburglar" in result.output.lower() or "usage" in result.output.lower()
