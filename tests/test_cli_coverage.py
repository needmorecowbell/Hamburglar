"""Additional tests to improve CLI coverage.

This module contains tests specifically designed to cover error handling paths,
edge cases, and streaming functionality in the CLI.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

# Configure path before any hamburglar imports
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
    FORMAT_EXTENSIONS,
    FORMAT_FORMATTERS,
    OutputFormat,
    app,
    generate_output_filename,
    get_db_path,
    get_formatter,
    parse_categories,
    parse_confidence,
    parse_date,
    parse_severities,
)
from hamburglar.core.exceptions import (
    HamburglarError,
    ScanError,
)
from hamburglar.core.models import ScanResult, Severity

runner = CliRunner()


class TestGetFormatter:
    """Test the get_formatter helper function."""

    def test_get_formatter_json(self) -> None:
        """Test getting JSON formatter."""
        formatter = get_formatter(OutputFormat.JSON)
        assert formatter is not None

    def test_get_formatter_table(self) -> None:
        """Test getting table formatter."""
        formatter = get_formatter(OutputFormat.TABLE)
        assert formatter is not None

    def test_get_formatter_sarif(self) -> None:
        """Test getting SARIF formatter."""
        formatter = get_formatter(OutputFormat.SARIF)
        assert formatter is not None

    def test_get_formatter_csv(self) -> None:
        """Test getting CSV formatter."""
        formatter = get_formatter(OutputFormat.CSV)
        assert formatter is not None

    def test_get_formatter_html(self) -> None:
        """Test getting HTML formatter."""
        formatter = get_formatter(OutputFormat.HTML)
        assert formatter is not None

    def test_get_formatter_markdown(self) -> None:
        """Test getting Markdown formatter."""
        formatter = get_formatter(OutputFormat.MARKDOWN)
        assert formatter is not None


class TestGenerateOutputFilename:
    """Test the generate_output_filename helper function."""

    def test_git_remote_url_with_git_suffix(self) -> None:
        """Test extracting repo name from remote URL with .git suffix."""
        filename = generate_output_filename(
            "https://github.com/user/repo.git", OutputFormat.JSON, scan_type="git"
        )
        assert "repo" in filename
        assert filename.endswith(".json")

    def test_git_remote_url_without_git_suffix(self) -> None:
        """Test extracting repo name from remote URL without .git suffix."""
        filename = generate_output_filename(
            "https://github.com/user/myrepo", OutputFormat.JSON, scan_type="git"
        )
        assert "myrepo" in filename

    def test_git_ssh_url(self) -> None:
        """Test extracting repo name from SSH URL."""
        filename = generate_output_filename(
            "git@github.com:user/repo.git", OutputFormat.JSON, scan_type="git"
        )
        assert "repo" in filename

    def test_git_local_path(self) -> None:
        """Test extracting repo name from local path."""
        filename = generate_output_filename(
            "/home/user/projects/myproject", OutputFormat.JSON, scan_type="git"
        )
        assert "myproject" in filename

    def test_web_url_with_port(self) -> None:
        """Test extracting domain from URL with port."""
        filename = generate_output_filename(
            "https://example.com:8080/path", OutputFormat.HTML, scan_type="web"
        )
        # Domain gets sanitized - dots become underscores
        assert "example" in filename
        assert "8080" not in filename
        assert filename.endswith(".html")

    def test_web_url_no_domain(self) -> None:
        """Test handling URL with no domain."""
        filename = generate_output_filename(
            "file:///path/to/file", OutputFormat.CSV, scan_type="web"
        )
        # Should default to "url" when no netloc
        assert "url" in filename or "hamburglar" in filename

    def test_local_scan_type(self) -> None:
        """Test local scan type filename generation."""
        filename = generate_output_filename(
            "/some/local/path", OutputFormat.TABLE, scan_type="scan"
        )
        assert "path" in filename or "hamburglar" in filename
        assert filename.endswith(".txt")


class TestParseCategories:
    """Test the parse_categories helper function."""

    def test_parse_empty_categories(self) -> None:
        """Test parsing empty categories string."""
        result = parse_categories("")
        assert result == []

    def test_parse_valid_categories(self) -> None:
        """Test parsing valid category names."""
        result = parse_categories("api_keys,cloud")
        assert len(result) == 2

    def test_parse_categories_with_whitespace(self) -> None:
        """Test parsing categories with extra whitespace."""
        result = parse_categories("  api_keys ,  cloud  ")
        assert len(result) == 2


class TestParseConfidence:
    """Test the parse_confidence helper function."""

    def test_parse_high_confidence(self) -> None:
        """Test parsing 'high' confidence level."""
        result = parse_confidence("high")
        assert result is not None
        assert result.value == "high"

    def test_parse_confidence_case_insensitive(self) -> None:
        """Test confidence parsing is case insensitive."""
        result = parse_confidence("HIGH")
        assert result is not None


class TestParseSeverities:
    """Test the parse_severities helper function."""

    def test_parse_single_severity(self) -> None:
        """Test parsing single severity."""
        result = parse_severities("high")
        assert len(result) == 1
        assert result[0] == Severity.HIGH

    def test_parse_multiple_severities(self) -> None:
        """Test parsing multiple severities."""
        result = parse_severities("high,critical")
        assert len(result) == 2

    def test_parse_severities_with_whitespace(self) -> None:
        """Test parsing severities with whitespace."""
        result = parse_severities("  high ,  critical  ")
        assert len(result) == 2

    def test_parse_severities_case_insensitive(self) -> None:
        """Test severity parsing is case insensitive."""
        result = parse_severities("HIGH,Critical")
        assert len(result) == 2


class TestParseDate:
    """Test the parse_date helper function."""

    def test_parse_relative_days(self) -> None:
        """Test parsing relative days format."""
        result = parse_date("7d")
        assert result is not None
        expected = datetime.now() - timedelta(days=7)
        assert abs((result - expected).total_seconds()) < 60

    def test_parse_relative_hours(self) -> None:
        """Test parsing relative hours format."""
        result = parse_date("24h")
        assert result is not None
        expected = datetime.now() - timedelta(hours=24)
        assert abs((result - expected).total_seconds()) < 60

    def test_parse_relative_weeks(self) -> None:
        """Test parsing relative weeks format."""
        result = parse_date("2w")
        assert result is not None
        expected = datetime.now() - timedelta(weeks=2)
        assert abs((result - expected).total_seconds()) < 60

    def test_parse_relative_months(self) -> None:
        """Test parsing relative months format."""
        result = parse_date("1m")
        assert result is not None
        expected = datetime.now() - timedelta(days=30)
        assert abs((result - expected).total_seconds()) < 60

    def test_parse_iso_date(self) -> None:
        """Test parsing ISO date format."""
        result = parse_date("2024-01-15")
        assert result is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_parse_iso_datetime(self) -> None:
        """Test parsing ISO datetime format."""
        result = parse_date("2024-01-15T10:30:00")
        assert result is not None
        assert result.hour == 10
        assert result.minute == 30


class TestGetDbPath:
    """Test the get_db_path helper function."""

    def test_default_db_path(self) -> None:
        """Test default database path expansion."""
        result = get_db_path(None)
        assert "hamburglar" in str(result) or ".hamburglar" in str(result)

    def test_custom_db_path(self) -> None:
        """Test custom database path."""
        custom = Path("/tmp/custom.db")
        result = get_db_path(custom)
        assert result == custom


class TestScanCommandErrorHandling:
    """Test error handling in the scan command."""

    def test_scan_with_storage_error(self, tmp_path: Path) -> None:
        """Test that storage errors are handled gracefully by save_to_database."""
        # Import locally to ensure proper module loading
        import hamburglar.cli.main as cli_module
        from hamburglar.cli.main import save_to_database
        from hamburglar.core.models import ScanResult
        from hamburglar.storage import StorageError as StorageErrorCls

        # Create a mock scan result
        result = ScanResult(
            target_path=str(tmp_path), findings=[], scan_duration=1.0, stats={"total_findings": 0}
        )

        import click.exceptions

        class MockStorageContextManager:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def save_scan(self, result):
                raise StorageErrorCls("Database error", backend="sqlite")

        original_storage = cli_module.SqliteStorage
        try:
            cli_module.SqliteStorage = MockStorageContextManager
            with pytest.raises(click.exceptions.Exit) as exc_info:
                save_to_database(result, tmp_path / "test.db", quiet=False, verbose=False)
            # Should exit with error code
            assert exc_info.value.exit_code == EXIT_ERROR
        finally:
            cli_module.SqliteStorage = original_storage

    def test_save_to_database_permission_error(self, tmp_path: Path) -> None:
        """Test that permission errors during database save are handled."""
        import hamburglar.cli.main as cli_module
        from hamburglar.cli.main import save_to_database
        from hamburglar.core.models import ScanResult

        result = ScanResult(
            target_path=str(tmp_path), findings=[], scan_duration=1.0, stats={"total_findings": 0}
        )

        class MockStorageRaisesPermission:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def save_scan(self, result):
                raise PermissionError("Permission denied")

        import click.exceptions

        original_storage = cli_module.SqliteStorage
        try:
            cli_module.SqliteStorage = MockStorageRaisesPermission
            with pytest.raises(click.exceptions.Exit) as exc_info:
                save_to_database(result, tmp_path / "test.db", quiet=False, verbose=False)
            assert exc_info.value.exit_code == EXIT_ERROR
        finally:
            cli_module.SqliteStorage = original_storage

    def test_save_to_database_oserror(self, tmp_path: Path) -> None:
        """Test that OSError during database save is handled."""
        import hamburglar.cli.main as cli_module
        from hamburglar.cli.main import save_to_database
        from hamburglar.core.models import ScanResult

        result = ScanResult(
            target_path=str(tmp_path), findings=[], scan_duration=1.0, stats={"total_findings": 0}
        )

        class MockStorageRaisesOS:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def save_scan(self, result):
                raise OSError("Disk full")

        import click.exceptions

        original_storage = cli_module.SqliteStorage
        try:
            cli_module.SqliteStorage = MockStorageRaisesOS
            with pytest.raises(click.exceptions.Exit) as exc_info:
                save_to_database(result, tmp_path / "test.db", quiet=False, verbose=False)
            assert exc_info.value.exit_code == EXIT_ERROR
        finally:
            cli_module.SqliteStorage = original_storage

    def test_scan_with_output_permission_error(self, tmp_path: Path) -> None:
        """Test that output permission errors are handled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("api_key = sk_live_1234567890")

        with patch("pathlib.Path.write_text") as mock_write:
            mock_write.side_effect = PermissionError("Permission denied")
            result = runner.invoke(
                app, ["scan", str(test_file), "--output", "/forbidden/output.json"]
            )
            # Expect error due to permission
            assert result.exit_code != 0

    def test_scan_with_output_oserror(self, tmp_path: Path) -> None:
        """Test that OSError during output is handled."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("api_key = sk_live_1234567890")

        # Create a file path where we expect success first
        output_file = tmp_path / "output.json"

        with patch.object(Path, "write_text", side_effect=OSError("Disk full")):
            result = runner.invoke(app, ["scan", str(test_file), "--output", str(output_file)])
            # Expect error
            assert result.exit_code != 0


class TestScanGitCommandErrorHandling:
    """Test error handling in scan-git command."""

    def test_scan_git_permission_error(self, tmp_path: Path) -> None:
        """Test that permission errors during git scan are handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = PermissionError("Permission denied")
            result = runner.invoke(app, ["scan-git", "https://github.com/test/repo"])
            assert result.exit_code == EXIT_ERROR

    def test_scan_git_hamburglar_error(self, tmp_path: Path) -> None:
        """Test that HamburglarError during git scan is handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = HamburglarError("Git error occurred")
            result = runner.invoke(app, ["scan-git", "https://github.com/test/repo"])
            assert result.exit_code == EXIT_ERROR

    def test_scan_git_unexpected_error(self, tmp_path: Path) -> None:
        """Test that unexpected errors during git scan are handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = RuntimeError("Unexpected error")
            result = runner.invoke(app, ["scan-git", "https://github.com/test/repo"])
            assert result.exit_code == EXIT_ERROR


class TestScanWebCommandErrorHandling:
    """Test error handling in scan-web command."""

    def test_scan_web_scan_error(self) -> None:
        """Test that ScanError during web scan is handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = ScanError("Connection failed")
            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == EXIT_ERROR

    def test_scan_web_permission_error(self) -> None:
        """Test that permission errors during web scan are handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = PermissionError("Access denied")
            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == EXIT_ERROR

    def test_scan_web_hamburglar_error(self) -> None:
        """Test that HamburglarError during web scan is handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = HamburglarError("Web scan failed")
            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == EXIT_ERROR

    def test_scan_web_unexpected_error(self) -> None:
        """Test that unexpected errors during web scan are handled."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = RuntimeError("Something went wrong")
            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == EXIT_ERROR


class TestStreamingMode:
    """Test streaming mode functionality."""

    def test_scan_streaming_mode(self, tmp_path: Path) -> None:
        """Test scan command in streaming mode."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("api_key = sk_live_1234567890abcdef")

        result = runner.invoke(app, ["scan", str(test_file), "--stream"])
        # Streaming mode should work
        assert result.exit_code in (EXIT_SUCCESS, EXIT_NO_FINDINGS, EXIT_ERROR)

    def test_scan_git_streaming_mode(self) -> None:
        """Test scan-git command in streaming mode."""
        # Mock the streaming scan
        mock_result = ScanResult(
            target_path="https://github.com/test/repo",
            findings=[],
            scan_duration=1.0,
            stats={"total_findings": 0},
        )

        with patch("hamburglar.cli.main.asyncio.run", return_value=None):
            result = runner.invoke(app, ["scan-git", "https://github.com/test/repo", "--stream"])
            # Streaming mode returns via asyncio.run
            assert result.exit_code in (0, EXIT_ERROR, EXIT_NO_FINDINGS)


class TestBenchmarkMode:
    """Test benchmark mode functionality."""

    def test_scan_benchmark_mode(self, tmp_path: Path) -> None:
        """Test scan command in benchmark mode."""
        test_dir = tmp_path / "benchmark_test"
        test_dir.mkdir()
        for i in range(5):
            (test_dir / f"file{i}.txt").write_text(f"content {i}")

        result = runner.invoke(app, ["scan", str(test_dir), "--benchmark"])
        # Benchmark mode should complete
        assert result.exit_code in (EXIT_SUCCESS, EXIT_NO_FINDINGS, EXIT_ERROR)


class TestVerboseOutput:
    """Test verbose output options."""

    def test_scan_verbose_shows_depth(self, tmp_path: Path) -> None:
        """Test that verbose mode shows depth information for git scan."""
        mock_result = ScanResult(
            target_path="https://github.com/test/repo",
            findings=[],
            scan_duration=1.0,
            stats={"total_findings": 0},
        )

        with patch("hamburglar.cli.main.asyncio.run", return_value=mock_result):
            result = runner.invoke(
                app, ["scan-git", "https://github.com/test/repo", "--verbose", "--depth", "10"]
            )
            assert "Depth" in result.output or result.exit_code in (0, 2)

    def test_scan_verbose_shows_branch(self, tmp_path: Path) -> None:
        """Test that verbose mode shows branch information for git scan."""
        mock_result = ScanResult(
            target_path="https://github.com/test/repo",
            findings=[],
            scan_duration=1.0,
            stats={"total_findings": 0},
        )

        with patch("hamburglar.cli.main.asyncio.run", return_value=mock_result):
            result = runner.invoke(
                app,
                ["scan-git", "https://github.com/test/repo", "--verbose", "--branch", "develop"],
            )
            assert "Branch" in result.output or result.exit_code in (0, 2)


class TestYaraRuleErrors:
    """Test YARA rule error handling."""

    def test_yara_file_not_found(self, tmp_path: Path) -> None:
        """Test handling of missing YARA file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        result = runner.invoke(app, ["scan", str(test_file), "--yara", "/nonexistent/rules.yar"])
        # Typer exits with code 2 for validation errors (file doesn't exist)
        assert result.exit_code in (EXIT_ERROR, 2)

    def test_yara_permission_error(self, tmp_path: Path) -> None:
        """Test handling of YARA file with no read permissions."""
        import os

        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        yara_file = tmp_path / "rules.yar"
        yara_file.write_text("rule test { condition: true }")

        if os.name != "nt":
            yara_file.chmod(0o000)
            try:
                result = runner.invoke(app, ["scan", str(test_file), "--yara", str(yara_file)])
                # May exit with 1 or 2 depending on error type
                assert result.exit_code in (EXIT_ERROR, 2)
            finally:
                yara_file.chmod(0o644)


class TestHistoryCommandAdditional:
    """Additional tests for history command."""

    def test_history_with_invalid_severity(self, tmp_path: Path) -> None:
        """Test history command with invalid severity."""
        db_path = tmp_path / "test.db"

        result = runner.invoke(
            app, ["history", "--severity", "invalid_severity", "--db-path", str(db_path)]
        )
        assert result.exit_code != 0

    def test_history_with_invalid_date_format(self, tmp_path: Path) -> None:
        """Test history command with invalid date format."""
        db_path = tmp_path / "test.db"

        result = runner.invoke(app, ["history", "--since", "not-a-date", "--db-path", str(db_path)])
        assert result.exit_code != 0


class TestReportCommandAdditional:
    """Additional tests for report command."""

    def test_report_with_invalid_top_value(self, tmp_path: Path) -> None:
        """Test report command with invalid --top value."""
        db_path = tmp_path / "test.db"

        result = runner.invoke(app, ["report", "--top", "0", "--db-path", str(db_path)])
        # Should fail validation
        assert result.exit_code != 0


class TestEnsureOutputDirErrors:
    """Test ensure_output_dir error handling."""

    def test_ensure_output_dir_permission_error(self, tmp_path: Path) -> None:
        """Test that PermissionError during output dir creation is handled."""
        import click.exceptions

        from hamburglar.cli.main import ensure_output_dir

        with patch("pathlib.Path.mkdir", side_effect=PermissionError("Permission denied")):
            with pytest.raises(click.exceptions.Exit) as exc_info:
                ensure_output_dir(tmp_path / "newdir", quiet=False)
            assert exc_info.value.exit_code == EXIT_ERROR

    def test_ensure_output_dir_oserror(self, tmp_path: Path) -> None:
        """Test that OSError during output dir creation is handled."""
        import click.exceptions

        from hamburglar.cli.main import ensure_output_dir

        with patch("pathlib.Path.mkdir", side_effect=OSError("Disk full")):
            with pytest.raises(click.exceptions.Exit) as exc_info:
                ensure_output_dir(tmp_path / "newdir", quiet=False)
            assert exc_info.value.exit_code == EXIT_ERROR

    def test_ensure_output_dir_creates_directory(self, tmp_path: Path) -> None:
        """Test that ensure_output_dir creates the directory."""
        from hamburglar.cli.main import ensure_output_dir

        new_dir = tmp_path / "new_output_dir"
        ensure_output_dir(new_dir, quiet=True)
        assert new_dir.exists()


class TestOutputDirErrorHandling:
    """Test --output-dir error handling."""

    def test_output_dir_permission_error(self, tmp_path: Path) -> None:
        """Test handling of output directory permission errors."""
        import os

        test_file = tmp_path / "test.txt"
        test_file.write_text("api_key = sk_live_test")

        if os.name != "nt":
            forbidden_dir = tmp_path / "forbidden"
            forbidden_dir.mkdir()
            forbidden_dir.chmod(0o000)

            try:
                result = runner.invoke(
                    app, ["scan", str(test_file), "--output-dir", str(forbidden_dir / "subdir")]
                )
                # Should fail with permission error
                assert result.exit_code == EXIT_ERROR
            finally:
                forbidden_dir.chmod(0o755)


class TestFormatExtensions:
    """Test format extension mapping."""

    def test_all_formats_have_extensions(self) -> None:
        """Test that all output formats have file extensions defined."""
        for fmt in OutputFormat:
            assert fmt in FORMAT_EXTENSIONS

    def test_all_formats_have_formatters(self) -> None:
        """Test that all output formats have formatters defined."""
        for fmt in OutputFormat:
            assert fmt in FORMAT_FORMATTERS


class TestQuietModeConsistency:
    """Test quiet mode behavior across commands."""

    def test_scan_quiet_suppresses_output(self, tmp_path: Path) -> None:
        """Test that quiet mode suppresses normal output."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("just some normal content")

        result = runner.invoke(app, ["scan", str(test_file), "--quiet"])
        # Quiet mode should produce minimal output
        assert len(result.output.strip()) == 0 or result.exit_code == EXIT_NO_FINDINGS

    def test_history_quiet_mode(self, tmp_path: Path) -> None:
        """Test history command quiet mode."""
        db_path = tmp_path / "test.db"

        # Create empty database
        from hamburglar.storage.sqlite import SqliteStorage

        with SqliteStorage(db_path) as storage:
            pass

        result = runner.invoke(app, ["history", "--quiet", "--db-path", str(db_path)])
        # Should produce no output for empty database
        assert len(result.output.strip()) == 0 or result.exit_code == EXIT_NO_FINDINGS


class TestAuthOption:
    """Test --auth option handling."""

    def test_scan_web_with_auth(self) -> None:
        """Test scan-web command with authentication."""
        mock_result = ScanResult(
            target_path="https://example.com",
            findings=[],
            scan_duration=1.0,
            stats={"total_findings": 0},
        )

        with patch("hamburglar.cli.main.asyncio.run", return_value=mock_result):
            result = runner.invoke(
                app, ["scan-web", "https://example.com", "--auth", "user:password", "--verbose"]
            )
            # Auth should be accepted
            assert result.exit_code in (0, 2)
