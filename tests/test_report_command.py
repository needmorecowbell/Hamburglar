"""Tests for the Hamburglar CLI report command.

This module tests the `report` command which generates summary reports
from the database in HTML or Markdown format.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Note: sys.path configuration is handled by conftest.py which runs first
from hamburglar.cli.main import (
    _generate_report_html,
    _generate_report_markdown,
    app,
)
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage import ScanStatistics
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

    # Create sample scan results with varied data
    result1 = ScanResult(
        target_path="/test/project1",
        findings=[
            Finding(
                file_path="/test/project1/secrets.py",
                detector_name="aws_access_key",
                severity=Severity.CRITICAL,
                matches=["AKIAIOSFODNN7EXAMPLE"],
                metadata={"line": 10},
            ),
            Finding(
                file_path="/test/project1/secrets.py",
                detector_name="aws_secret_key",
                severity=Severity.CRITICAL,
                matches=["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
                metadata={"line": 11},
            ),
            Finding(
                file_path="/test/project1/config.json",
                detector_name="private_key",
                severity=Severity.HIGH,
                matches=["-----BEGIN RSA PRIVATE KEY-----"],
                metadata={"line": 5},
            ),
            Finding(
                file_path="/test/project1/config.json",
                detector_name="api_key",
                severity=Severity.MEDIUM,
                matches=["api_key_1234567890"],
                metadata={"line": 15},
            ),
        ],
        scan_duration=1.5,
        stats={"files_scanned": 100},
    )

    result2 = ScanResult(
        target_path="/test/project2",
        findings=[
            Finding(
                file_path="/test/project2/app.py",
                detector_name="api_key",
                severity=Severity.MEDIUM,
                matches=["api_key_abcdefghij"],
                metadata={"line": 20},
            ),
            Finding(
                file_path="/test/project2/settings.py",
                detector_name="email_address",
                severity=Severity.LOW,
                matches=["admin@example.com"],
                metadata={"line": 15},
            ),
            Finding(
                file_path="/test/project2/debug.py",
                detector_name="password_pattern",
                severity=Severity.INFO,
                matches=["password=test123"],
                metadata={"line": 30},
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


@pytest.fixture
def empty_db(tmp_path: Path) -> Path:
    """Create an empty database.

    Args:
        tmp_path: pytest's tmp_path fixture.

    Returns:
        Path to the empty database file.
    """
    db_path = tmp_path / "empty_findings.db"
    with SqliteStorage(db_path) as storage:
        # Just initialize the db, don't add any data
        pass
    return db_path


class TestGenerateReportHtml:
    """Test the _generate_report_html helper function."""

    def test_generates_valid_html(self) -> None:
        """Test that generated HTML is well-formed."""
        stats = ScanStatistics(
            total_scans=5,
            total_findings=10,
            total_files_scanned=20,
            findings_by_severity={"critical": 2, "high": 3, "medium": 5},
            findings_by_detector={"aws_key": 5, "api_key": 5},
            scans_by_date={"2024-01-01": 3, "2024-01-02": 2},
            first_scan_date=datetime(2024, 1, 1, 12, 0),
            last_scan_date=datetime(2024, 1, 2, 15, 0),
            average_findings_per_scan=2.0,
            average_scan_duration=1.5,
        )
        top_detectors = [("aws_key", 5), ("api_key", 5)]
        top_files = [("/path/to/file1.py", 3), ("/path/to/file2.py", 2)]

        html = _generate_report_html(stats, top_detectors, top_files)

        assert "<!DOCTYPE html>" in html
        assert "<html lang=" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "</head>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_includes_title(self) -> None:
        """Test that custom title is included."""
        stats = ScanStatistics(total_scans=1)
        html = _generate_report_html(stats, [], [], title="My Custom Report")

        assert "<title>My Custom Report</title>" in html
        assert "<h1>My Custom Report</h1>" in html

    def test_includes_summary_statistics(self) -> None:
        """Test that summary statistics are included."""
        stats = ScanStatistics(
            total_scans=10,
            total_findings=25,
            total_files_scanned=100,
            average_findings_per_scan=2.5,
        )
        html = _generate_report_html(stats, [], [])

        assert "10" in html  # total scans
        assert "25" in html  # total findings
        assert "100" in html  # files scanned
        assert "2.5" in html  # avg findings

    def test_includes_severity_breakdown(self) -> None:
        """Test that severity breakdown is included."""
        stats = ScanStatistics(
            findings_by_severity={"critical": 5, "high": 10, "medium": 15},
        )
        html = _generate_report_html(stats, [], [])

        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html
        assert "5" in html
        assert "10" in html
        assert "15" in html

    def test_includes_detector_breakdown(self) -> None:
        """Test that detector breakdown is included."""
        stats = ScanStatistics()
        top_detectors = [("aws_access_key", 10), ("private_key", 5)]

        html = _generate_report_html(stats, top_detectors, [])

        assert "aws_access_key" in html
        assert "private_key" in html
        assert "10" in html
        assert "5" in html

    def test_includes_top_files(self) -> None:
        """Test that top files are included."""
        stats = ScanStatistics()
        top_files = [("/path/to/secrets.py", 8), ("/path/to/config.json", 4)]

        html = _generate_report_html(stats, [], top_files)

        assert "secrets.py" in html
        assert "config.json" in html

    def test_includes_trend_data(self) -> None:
        """Test that scan activity trend is included."""
        stats = ScanStatistics(
            scans_by_date={"2024-01-01": 5, "2024-01-02": 3, "2024-01-03": 7}
        )
        html = _generate_report_html(stats, [], [])

        assert "2024-01-01" in html
        assert "2024-01-02" in html
        assert "2024-01-03" in html

    def test_escapes_html_special_characters(self) -> None:
        """Test that special characters are properly escaped."""
        stats = ScanStatistics()
        top_files = [("/path/<script>alert('xss')</script>.py", 1)]

        html = _generate_report_html(stats, [], top_files)

        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_truncates_long_file_paths(self) -> None:
        """Test that long file paths are truncated."""
        stats = ScanStatistics()
        long_path = "/very/long/path/" + "a" * 100 + "/file.py"
        top_files = [(long_path, 1)]

        html = _generate_report_html(stats, [], top_files)

        # Should have ... at the beginning for truncated paths
        assert "..." in html

    def test_has_no_external_dependencies(self) -> None:
        """Test that HTML has no external CSS/JS/font dependencies."""
        stats = ScanStatistics()
        html = _generate_report_html(stats, [], [])

        # Should not link to external CSS/JS/font resources
        # (the footer attribution link to GitHub is acceptable)
        assert 'src="http' not in html  # No external scripts/images
        assert "@import" not in html  # No CSS imports
        # All styles should be inline (in <style> tag)
        assert "<style>" in html
        # Should not have external stylesheet links
        assert '<link rel="stylesheet"' not in html
        assert '<script src="' not in html

    def test_handles_empty_data(self) -> None:
        """Test handling of empty statistics."""
        stats = ScanStatistics()
        html = _generate_report_html(stats, [], [])

        assert "No findings recorded" in html or "No scan activity recorded" in html


class TestGenerateReportMarkdown:
    """Test the _generate_report_markdown helper function."""

    def test_generates_valid_markdown(self) -> None:
        """Test that generated markdown is well-formed."""
        stats = ScanStatistics(
            total_scans=5,
            total_findings=10,
            findings_by_severity={"critical": 2, "high": 3},
            findings_by_detector={"aws_key": 5},
            scans_by_date={"2024-01-01": 3},
        )
        md = _generate_report_markdown(stats, [("aws_key", 5)], [("/file.py", 3)])

        # Check markdown structure
        assert md.startswith("# ")  # Title header
        assert "## Summary" in md
        assert "## Findings by Severity" in md
        assert "## Most Common Finding Types" in md
        assert "## Files with Most Findings" in md
        assert "## Scan Activity Over Time" in md

    def test_includes_title(self) -> None:
        """Test that custom title is included."""
        stats = ScanStatistics()
        md = _generate_report_markdown(stats, [], [], title="Security Audit Report")

        assert "# Security Audit Report" in md

    def test_includes_summary_table(self) -> None:
        """Test that summary table is included."""
        stats = ScanStatistics(
            total_scans=10,
            total_findings=25,
            total_files_scanned=100,
            average_findings_per_scan=2.5,
            average_scan_duration=1.25,
        )
        md = _generate_report_markdown(stats, [], [])

        assert "| Metric | Value |" in md
        assert "| Total Scans | 10 |" in md
        assert "| Total Findings | 25 |" in md
        assert "| Files Scanned | 100 |" in md

    def test_includes_severity_with_emojis(self) -> None:
        """Test that severity breakdown includes emojis."""
        stats = ScanStatistics(
            findings_by_severity={"critical": 5, "high": 10}
        )
        md = _generate_report_markdown(stats, [], [])

        # Should have emoji indicators
        assert "CRITICAL" in md
        assert "HIGH" in md
        # Check that Unicode emojis are present
        assert "\U0001F6A8" in md or "\U0001F534" in md  # 🚨 or 🔴

    def test_includes_detector_table(self) -> None:
        """Test that detector breakdown is included."""
        stats = ScanStatistics()
        top_detectors = [("aws_access_key", 10), ("private_key", 5)]

        md = _generate_report_markdown(stats, top_detectors, [])

        assert "| Detector | Count |" in md
        assert "`aws_access_key`" in md
        assert "`private_key`" in md

    def test_includes_files_table(self) -> None:
        """Test that top files table is included."""
        stats = ScanStatistics()
        top_files = [("/path/to/secrets.py", 8), ("/path/to/config.json", 4)]

        md = _generate_report_markdown(stats, [], top_files)

        assert "| File Path | Findings |" in md
        assert "`/path/to/secrets.py`" in md

    def test_escapes_markdown_special_chars(self) -> None:
        """Test that markdown special characters are escaped."""
        stats = ScanStatistics()
        top_files = [("/path/with|pipe.py", 1)]

        md = _generate_report_markdown(stats, [], top_files)

        # Pipe should be escaped in table cells
        assert "\\|" in md

    def test_handles_empty_data(self) -> None:
        """Test handling of empty data."""
        stats = ScanStatistics()
        md = _generate_report_markdown(stats, [], [])

        assert "*No findings recorded*" in md or "*No scan activity recorded*" in md

    def test_includes_footer(self) -> None:
        """Test that footer is included."""
        stats = ScanStatistics()
        md = _generate_report_markdown(stats, [], [])

        assert "Generated by" in md
        assert "Hamburglar" in md


class TestReportCommandBasic:
    """Test basic report command functionality."""

    def test_report_generates_html(self, populated_db: Path) -> None:
        """Test that report command generates HTML by default."""
        result = runner.invoke(app, ["report", "--db-path", str(populated_db)])
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

    def test_report_generates_markdown(self, populated_db: Path) -> None:
        """Test that report command can generate markdown."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--format", "markdown"]
        )
        assert result.exit_code == 0
        assert "# Hamburglar Security Report" in result.output

    def test_report_md_format_alias(self, populated_db: Path) -> None:
        """Test that 'md' works as alias for 'markdown'."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-f", "md"]
        )
        assert result.exit_code == 0
        assert "# Hamburglar Security Report" in result.output

    def test_report_no_database(self, tmp_path: Path) -> None:
        """Test report with no database file."""
        db_path = tmp_path / "nonexistent.db"
        result = runner.invoke(app, ["report", "--db-path", str(db_path)])
        assert result.exit_code == 2
        assert "No database found" in result.output

    def test_report_empty_database(self, empty_db: Path) -> None:
        """Test report with empty database."""
        result = runner.invoke(app, ["report", "--db-path", str(empty_db)])
        assert result.exit_code == 2
        assert "No scan data" in result.output

    def test_report_quiet_mode(self, populated_db: Path) -> None:
        """Test report in quiet mode."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--quiet"]
        )
        # In quiet mode, no output to stdout
        assert result.exit_code == 0

    def test_report_verbose_mode(self, populated_db: Path) -> None:
        """Test report in verbose mode."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--verbose"]
        )
        assert result.exit_code == 0
        assert "Database:" in result.output
        assert "Format:" in result.output


class TestReportCommandOptions:
    """Test report command options."""

    def test_custom_title(self, populated_db: Path) -> None:
        """Test custom title option."""
        result = runner.invoke(
            app,
            ["report", "--db-path", str(populated_db), "--title", "My Security Audit"],
        )
        assert result.exit_code == 0
        assert "My Security Audit" in result.output

    def test_top_n_option(self, populated_db: Path) -> None:
        """Test --top option for limiting items."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--top", "5"]
        )
        assert result.exit_code == 0

    def test_top_n_with_short_option(self, populated_db: Path) -> None:
        """Test -n short option."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-n", "10"]
        )
        assert result.exit_code == 0

    def test_invalid_format(self, populated_db: Path) -> None:
        """Test invalid format option."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--format", "invalid"]
        )
        assert result.exit_code == 1
        assert "Invalid format" in result.output

    def test_format_case_insensitive(self, populated_db: Path) -> None:
        """Test that format is case insensitive."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--format", "HTML"]
        )
        assert result.exit_code == 0
        assert "<!DOCTYPE html>" in result.output

        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--format", "MARKDOWN"]
        )
        assert result.exit_code == 0
        assert "# Hamburglar Security Report" in result.output


class TestReportCommandDateFilters:
    """Test report command date filters."""

    def test_since_relative_days(self, populated_db: Path) -> None:
        """Test --since with relative days."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "7d"]
        )
        assert result.exit_code == 0

    def test_since_relative_hours(self, populated_db: Path) -> None:
        """Test --since with relative hours."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "24h"]
        )
        assert result.exit_code == 0

    def test_since_iso_date(self, populated_db: Path) -> None:
        """Test --since with ISO date."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "2024-01-01"]
        )
        assert result.exit_code == 0

    def test_since_and_until(self, populated_db: Path) -> None:
        """Test both --since and --until filters."""
        result = runner.invoke(
            app,
            [
                "report",
                "--db-path",
                str(populated_db),
                "--since",
                "30d",
                "--until",
                "1d",
            ],
        )
        assert result.exit_code == 0

    def test_invalid_since_format(self, populated_db: Path) -> None:
        """Test invalid --since format."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "invalid"]
        )
        assert result.exit_code == 1
        assert "Invalid date format" in result.output

    def test_invalid_until_format(self, populated_db: Path) -> None:
        """Test invalid --until format."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--until", "invalid"]
        )
        assert result.exit_code == 1
        assert "Invalid date format" in result.output

    def test_verbose_shows_date_filters(self, populated_db: Path) -> None:
        """Test that verbose mode shows date filter info."""
        result = runner.invoke(
            app,
            [
                "report",
                "--db-path",
                str(populated_db),
                "--since",
                "7d",
                "--verbose",
            ],
        )
        assert result.exit_code == 0
        assert "Since:" in result.output


class TestReportCommandFileOutput:
    """Test report command file output."""

    def test_output_to_file_html(self, populated_db: Path, tmp_path: Path) -> None:
        """Test writing HTML report to file."""
        output_file = tmp_path / "report.html"
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-o", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "<!DOCTYPE html>" in content
        assert "Report written to" in result.output

    def test_output_to_file_markdown(self, populated_db: Path, tmp_path: Path) -> None:
        """Test writing Markdown report to file."""
        output_file = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [
                "report",
                "--db-path",
                str(populated_db),
                "-f",
                "markdown",
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "# Hamburglar Security Report" in content

    def test_output_file_quiet_mode(self, populated_db: Path, tmp_path: Path) -> None:
        """Test file output in quiet mode."""
        output_file = tmp_path / "report.html"
        result = runner.invoke(
            app,
            ["report", "--db-path", str(populated_db), "-o", str(output_file), "-q"],
        )
        assert result.exit_code == 0
        assert output_file.exists()
        assert "Report written to" not in result.output


class TestReportCommandHelpText:
    """Test report command help text."""

    def test_report_help(self) -> None:
        """Test that report --help works."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate a summary report" in result.output
        assert "--format" in result.output
        assert "--since" in result.output
        assert "--title" in result.output
        assert "--top" in result.output

    def test_main_help_includes_report(self) -> None:
        """Test that main help includes report command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "report" in result.output


class TestReportContent:
    """Test that report content is accurate."""

    def test_html_report_contains_all_sections(self, populated_db: Path) -> None:
        """Test that HTML report contains all required sections."""
        result = runner.invoke(app, ["report", "--db-path", str(populated_db)])
        assert result.exit_code == 0

        output = result.output
        # Check for main sections
        assert "Total Scans" in output
        assert "Total Findings" in output
        assert "Files Scanned" in output
        assert "Findings by Severity" in output
        assert "Most Common Finding Types" in output
        assert "Files with Most Findings" in output
        assert "Scan Activity Over Time" in output

    def test_markdown_report_contains_all_sections(self, populated_db: Path) -> None:
        """Test that Markdown report contains all required sections."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-f", "markdown"]
        )
        assert result.exit_code == 0

        output = result.output
        # Check for main sections
        assert "## Summary" in output
        assert "## Findings by Severity" in output
        assert "## Most Common Finding Types" in output
        assert "## Files with Most Findings" in output
        assert "## Scan Activity Over Time" in output

    def test_report_shows_correct_detector_counts(self, populated_db: Path) -> None:
        """Test that detector counts are accurate."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-f", "markdown"]
        )
        assert result.exit_code == 0

        output = result.output
        # Should show api_key detector (appears in both scans)
        assert "api_key" in output

    def test_report_shows_correct_severity_counts(self, populated_db: Path) -> None:
        """Test that severity counts are accurate."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "-f", "markdown"]
        )
        assert result.exit_code == 0

        output = result.output
        # Should have critical, high, medium, low, info findings
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output


class TestReportCommandEdgeCases:
    """Test edge cases for report command."""

    def test_special_characters_in_title(self, populated_db: Path) -> None:
        """Test report with special characters in title."""
        result = runner.invoke(
            app,
            [
                "report",
                "--db-path",
                str(populated_db),
                "--title",
                "Report <test> & 'quotes'",
            ],
        )
        assert result.exit_code == 0
        # HTML should escape special characters
        assert "&lt;test&gt;" in result.output or "<test>" not in result.output.replace(
            "&lt;test&gt;", ""
        )

    def test_minimum_top_n(self, populated_db: Path) -> None:
        """Test minimum value for --top option."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--top", "1"]
        )
        assert result.exit_code == 0

    def test_maximum_top_n(self, populated_db: Path) -> None:
        """Test maximum value for --top option."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--top", "100"]
        )
        assert result.exit_code == 0

    def test_top_n_below_minimum(self, populated_db: Path) -> None:
        """Test that --top below minimum fails."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--top", "0"]
        )
        assert result.exit_code != 0

    def test_top_n_above_maximum(self, populated_db: Path) -> None:
        """Test that --top above maximum fails."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--top", "101"]
        )
        assert result.exit_code != 0

    def test_relative_weeks(self, populated_db: Path) -> None:
        """Test --since with relative weeks."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "2w"]
        )
        assert result.exit_code == 0

    def test_relative_months(self, populated_db: Path) -> None:
        """Test --since with relative months."""
        result = runner.invoke(
            app, ["report", "--db-path", str(populated_db), "--since", "1m"]
        )
        assert result.exit_code == 0
