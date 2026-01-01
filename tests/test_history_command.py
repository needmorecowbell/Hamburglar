"""Tests for the Hamburglar CLI history command.

This module tests the `history` command which queries stored findings
from the database with various filters and output format support.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Note: sys.path configuration is handled by conftest.py which runs first
from hamburglar.cli.main import (
    app,
    parse_date,
    parse_severities,
)
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage.sqlite import SqliteStorage

runner = CliRunner()


@pytest.fixture
def populated_db(tmp_path: Path) -> Path:
    """Create a database with sample scan data.

    Args:
        tmp_path: pytest's tmp_path fixture.

    Returns:
        Path to the populated database file.
    """
    db_path = tmp_path / "test_findings.db"

    # Create sample scan results
    result1 = ScanResult(
        target_path="/test/path1",
        findings=[
            Finding(
                file_path="/test/path1/secrets.py",
                detector_name="aws_access_key",
                severity=Severity.CRITICAL,
                matches=["AKIAIOSFODNN7EXAMPLE"],
                metadata={"line": 10},
            ),
            Finding(
                file_path="/test/path1/config.json",
                detector_name="private_key",
                severity=Severity.HIGH,
                matches=["-----BEGIN RSA PRIVATE KEY-----"],
                metadata={"line": 5},
            ),
        ],
        scan_duration=1.5,
        stats={"files_scanned": 100},
    )

    result2 = ScanResult(
        target_path="/test/path2",
        findings=[
            Finding(
                file_path="/test/path2/app.py",
                detector_name="api_key",
                severity=Severity.MEDIUM,
                matches=["api_key_1234567890"],
                metadata={"line": 20},
            ),
            Finding(
                file_path="/test/path2/settings.py",
                detector_name="email_address",
                severity=Severity.LOW,
                matches=["admin@example.com"],
                metadata={"line": 15},
            ),
        ],
        scan_duration=0.8,
        stats={"files_scanned": 50},
    )

    # Save to database
    with SqliteStorage(db_path) as storage:
        storage.save_scan(result1)
        storage.save_scan(result2)

    return db_path


class TestParseSeverities:
    """Test the parse_severities helper function."""

    def test_parses_single_severity(self) -> None:
        """Test parsing a single severity level."""
        result = parse_severities("high")
        assert result == [Severity.HIGH]

    def test_parses_multiple_severities(self) -> None:
        """Test parsing multiple comma-separated severities."""
        result = parse_severities("high,critical,low")
        assert Severity.HIGH in result
        assert Severity.CRITICAL in result
        assert Severity.LOW in result
        assert len(result) == 3

    def test_handles_whitespace(self) -> None:
        """Test that whitespace is handled correctly."""
        result = parse_severities("high , critical , medium")
        assert Severity.HIGH in result
        assert Severity.CRITICAL in result
        assert Severity.MEDIUM in result

    def test_handles_empty_string(self) -> None:
        """Test that empty string returns empty list."""
        result = parse_severities("")
        assert result == []

    def test_raises_on_invalid_severity(self) -> None:
        """Test that invalid severity raises BadParameter."""
        import typer
        with pytest.raises(typer.BadParameter) as excinfo:
            parse_severities("invalid")
        assert "Invalid severity" in str(excinfo.value)

    def test_case_insensitive(self) -> None:
        """Test that severity parsing is case insensitive."""
        result = parse_severities("HIGH,Critical,MEDIUM")
        assert Severity.HIGH in result
        assert Severity.CRITICAL in result
        assert Severity.MEDIUM in result


class TestParseDate:
    """Test the parse_date helper function."""

    def test_parses_iso_date(self) -> None:
        """Test parsing ISO format date."""
        result = parse_date("2024-01-15")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_parses_iso_datetime(self) -> None:
        """Test parsing ISO format datetime."""
        result = parse_date("2024-01-15T12:30:00")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 12
        assert result.minute == 30

    def test_parses_relative_hours(self) -> None:
        """Test parsing relative time in hours."""
        result = parse_date("24h")
        now = datetime.now()
        expected = now - timedelta(hours=24)
        # Allow 1 second tolerance
        assert abs((result - expected).total_seconds()) < 1

    def test_parses_relative_days(self) -> None:
        """Test parsing relative time in days."""
        result = parse_date("7d")
        now = datetime.now()
        expected = now - timedelta(days=7)
        assert abs((result - expected).total_seconds()) < 1

    def test_parses_relative_weeks(self) -> None:
        """Test parsing relative time in weeks."""
        result = parse_date("2w")
        now = datetime.now()
        expected = now - timedelta(weeks=2)
        assert abs((result - expected).total_seconds()) < 1

    def test_parses_relative_months(self) -> None:
        """Test parsing relative time in months."""
        result = parse_date("1m")
        now = datetime.now()
        expected = now - timedelta(days=30)
        assert abs((result - expected).total_seconds()) < 1

    def test_raises_on_invalid_format(self) -> None:
        """Test that invalid format raises BadParameter."""
        import typer
        with pytest.raises(typer.BadParameter) as excinfo:
            parse_date("invalid-date")
        assert "Invalid date format" in str(excinfo.value)


class TestHistoryCommandBasic:
    """Test basic history command functionality."""

    def test_history_shows_all_findings(self, populated_db: Path) -> None:
        """Test that history shows all findings when no filters applied."""
        result = runner.invoke(app, ["history", "--db-path", str(populated_db)])
        assert result.exit_code == 0

    def test_history_with_no_database(self, tmp_path: Path) -> None:
        """Test that history handles missing database gracefully."""
        nonexistent_db = tmp_path / "nonexistent.db"
        result = runner.invoke(app, ["history", "--db-path", str(nonexistent_db)])
        assert result.exit_code == 2  # EXIT_NO_FINDINGS
        assert "No database found" in result.output

    def test_history_with_empty_database(self, tmp_path: Path) -> None:
        """Test history command with empty database."""
        db_path = tmp_path / "empty.db"
        # Create an empty database
        with SqliteStorage(db_path) as storage:
            pass  # Just initialize the schema

        result = runner.invoke(app, ["history", "--db-path", str(db_path)])
        assert result.exit_code == 2  # EXIT_NO_FINDINGS
        assert "No findings match" in result.output

    def test_history_quiet_mode(self, populated_db: Path) -> None:
        """Test that quiet mode suppresses output."""
        result = runner.invoke(app, ["history", "--db-path", str(populated_db), "--quiet"])
        # Quiet mode should still return success but no output
        assert result.exit_code == 0
        assert result.output == ""

    def test_history_verbose_mode(self, populated_db: Path) -> None:
        """Test that verbose mode shows extra information."""
        result = runner.invoke(app, ["history", "--db-path", str(populated_db), "--verbose"])
        assert result.exit_code == 0
        assert "Database:" in result.output
        assert "Found" in result.output


class TestHistoryFilters:
    """Test history command filtering options."""

    def test_filter_by_severity_single(self, populated_db: Path) -> None:
        """Test filtering by a single severity level."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--severity", "critical", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "critical"

    def test_filter_by_severity_multiple(self, populated_db: Path) -> None:
        """Test filtering by multiple severity levels."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--severity", "critical,high", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2
        severities = {f["severity"] for f in data["findings"]}
        assert severities == {"critical", "high"}

    def test_filter_by_detector(self, populated_db: Path) -> None:
        """Test filtering by detector name."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--detector", "aws_access_key", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["detector_name"] == "aws_access_key"

    def test_filter_by_path(self, populated_db: Path) -> None:
        """Test filtering by file path prefix."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--path", "/test/path1", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2
        for finding in data["findings"]:
            assert finding["file_path"].startswith("/test/path1")

    def test_filter_by_target(self, populated_db: Path) -> None:
        """Test filtering by scan target path."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--target", "/test/path2", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2
        for finding in data["findings"]:
            assert finding["file_path"].startswith("/test/path2")

    def test_filter_by_limit(self, populated_db: Path) -> None:
        """Test limiting number of findings."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--limit", "2", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2

    def test_filter_with_no_matches(self, populated_db: Path) -> None:
        """Test that no matches returns appropriate exit code."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--detector", "nonexistent_detector"],
        )
        assert result.exit_code == 2  # EXIT_NO_FINDINGS
        assert "No findings match" in result.output

    def test_invalid_severity_filter(self, populated_db: Path) -> None:
        """Test that invalid severity filter shows error."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--severity", "invalid"],
        )
        assert result.exit_code == 1  # EXIT_ERROR

    def test_invalid_date_filter(self, populated_db: Path) -> None:
        """Test that invalid date filter shows error."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--since", "not-a-date"],
        )
        assert result.exit_code == 1  # EXIT_ERROR


class TestHistoryOutputFormats:
    """Test history command output formats."""

    def test_format_json(self, populated_db: Path) -> None:
        """Test JSON output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data
        assert "target_path" in data
        assert data["target_path"] == "history"

    def test_format_table(self, populated_db: Path) -> None:
        """Test table output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "table"],
        )
        assert result.exit_code == 0
        # Table output should contain detector names
        assert "aws_access_key" in result.output or "api_key" in result.output

    def test_format_csv(self, populated_db: Path) -> None:
        """Test CSV output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "csv"],
        )
        assert result.exit_code == 0
        # CSV should have headers
        assert "file,detector,match,severity" in result.output.lower() or "file_path" in result.output.lower()

    def test_format_sarif(self, populated_db: Path) -> None:
        """Test SARIF output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "sarif"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "$schema" in data
        assert "runs" in data

    def test_format_html(self, populated_db: Path) -> None:
        """Test HTML output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "html"],
        )
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output
        assert "<html" in result.output

    def test_format_markdown(self, populated_db: Path) -> None:
        """Test Markdown output format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "markdown"],
        )
        assert result.exit_code == 0
        # Markdown should have headers
        assert "#" in result.output

    def test_invalid_format(self, populated_db: Path) -> None:
        """Test that invalid format shows error."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "invalid"],
        )
        assert result.exit_code == 1  # EXIT_ERROR

    def test_format_case_insensitive(self, populated_db: Path) -> None:
        """Test that format is case insensitive."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--format", "JSON"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data


class TestHistoryOutput:
    """Test history command file output options."""

    def test_output_to_file(self, populated_db: Path, tmp_path: Path) -> None:
        """Test writing output to a file."""
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--format", "json",
                "--output", str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        assert "Output written to" in result.output

        # Verify file contents
        data = json.loads(output_file.read_text())
        assert "findings" in data

    def test_output_quiet_mode(self, populated_db: Path, tmp_path: Path) -> None:
        """Test that quiet mode with output file produces no console output."""
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--format", "json",
                "--output", str(output_file),
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        assert result.output == ""
        assert output_file.exists()


class TestHistoryStats:
    """Test history command statistics mode."""

    def test_stats_mode_shows_summary(self, populated_db: Path) -> None:
        """Test that --stats shows statistics summary."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--stats"],
        )
        assert result.exit_code == 0
        assert "Total Scans" in result.output or "total_scans" in result.output
        assert "Total Findings" in result.output or "total_findings" in result.output

    def test_stats_mode_json_format(self, populated_db: Path) -> None:
        """Test that --stats with JSON format returns valid JSON."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--stats", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "total_scans" in data
        assert "total_findings" in data
        assert data["total_scans"] == 2
        assert data["total_findings"] == 4

    def test_stats_mode_csv_format(self, populated_db: Path) -> None:
        """Test that --stats with CSV format returns valid CSV."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--stats", "--format", "csv"],
        )
        assert result.exit_code == 0
        assert "metric,value" in result.output
        assert "total_scans" in result.output
        assert "total_findings" in result.output

    def test_stats_includes_severity_breakdown(self, populated_db: Path) -> None:
        """Test that stats include severity breakdown."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--stats", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings_by_severity" in data
        assert "critical" in data["findings_by_severity"]

    def test_stats_includes_detector_breakdown(self, populated_db: Path) -> None:
        """Test that stats include detector breakdown."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--stats", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings_by_detector" in data
        assert "aws_access_key" in data["findings_by_detector"]

    def test_stats_with_empty_db(self, tmp_path: Path) -> None:
        """Test stats with empty database."""
        db_path = tmp_path / "empty.db"
        with SqliteStorage(db_path) as storage:
            pass  # Just initialize

        result = runner.invoke(
            app,
            ["history", "--db-path", str(db_path), "--stats", "--format", "json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_scans"] == 0
        assert data["total_findings"] == 0


class TestHistoryDateFilters:
    """Test history command date filters."""

    def test_since_relative_days(self, populated_db: Path) -> None:
        """Test --since with relative days format."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--since", "7d", "--format", "json"],
        )
        # Should succeed as test data is recent
        assert result.exit_code == 0

    def test_since_iso_format(self, populated_db: Path) -> None:
        """Test --since with ISO date format."""
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--since", yesterday, "--format", "json"],
        )
        assert result.exit_code == 0

    def test_until_with_since(self, populated_db: Path) -> None:
        """Test combining --since and --until."""
        now = datetime.now()
        yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")
        tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%d")

        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--since", yesterday,
                "--until", tomorrow,
                "--format", "json",
            ],
        )
        assert result.exit_code == 0


class TestHistoryHelp:
    """Test history command help text."""

    def test_history_help(self) -> None:
        """Test that history --help shows usage information."""
        result = runner.invoke(app, ["history", "--help"])
        assert result.exit_code == 0
        assert "history" in result.output.lower()
        assert "--since" in result.output
        assert "--severity" in result.output
        assert "--detector" in result.output
        assert "--stats" in result.output
        assert "--format" in result.output

    def test_main_help_includes_history(self) -> None:
        """Test that main help includes history command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "history" in result.output


class TestHistoryVerboseOutput:
    """Test history command verbose output."""

    def test_verbose_shows_filter_info(self, populated_db: Path) -> None:
        """Test that verbose mode shows filter information."""
        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--severity", "high",
                "--detector", "private_key",
                "--verbose",
            ],
        )
        assert result.exit_code == 0
        assert "Severities:" in result.output
        assert "Detector:" in result.output

    def test_verbose_shows_since_until(self, populated_db: Path) -> None:
        """Test that verbose mode shows date filter info."""
        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--since", "7d",
                "--verbose",
            ],
        )
        assert result.exit_code == 0
        assert "Since:" in result.output

    def test_verbose_shows_result_count(self, populated_db: Path) -> None:
        """Test that verbose mode shows the number of matching findings."""
        result = runner.invoke(
            app,
            ["history", "--db-path", str(populated_db), "--verbose"],
        )
        assert result.exit_code == 0
        assert "Found" in result.output
        assert "findings" in result.output


class TestHistoryCombinedFilters:
    """Test history command with multiple filters combined."""

    def test_severity_and_detector(self, populated_db: Path) -> None:
        """Test combining severity and detector filters."""
        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--severity", "critical",
                "--detector", "aws_access_key",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "critical"
        assert data["findings"][0]["detector_name"] == "aws_access_key"

    def test_path_and_severity(self, populated_db: Path) -> None:
        """Test combining path and severity filters."""
        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--path", "/test/path1",
                "--severity", "critical,high",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) == 2
        for finding in data["findings"]:
            assert finding["file_path"].startswith("/test/path1")
            assert finding["severity"] in ["critical", "high"]

    def test_all_filters_combined(self, populated_db: Path) -> None:
        """Test combining multiple filters."""
        result = runner.invoke(
            app,
            [
                "history",
                "--db-path", str(populated_db),
                "--path", "/test/path1",
                "--severity", "critical",
                "--limit", "1",
                "--format", "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["findings"]) <= 1
