"""Tests for the scan-web CLI command.

This module tests the scan-web command for scanning web URLs
for secrets and sensitive information.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from hamburglar.cli.main import app
from hamburglar.core.models import Finding, ScanResult, Severity

runner = CliRunner()


@pytest.fixture
def mock_web_scan_result() -> ScanResult:
    """Create a mock scan result with some findings."""
    return ScanResult(
        target_path="https://example.com",
        findings=[
            Finding(
                file_path="https://example.com",
                detector_name="regex",
                matches=["sk_live_1234567890abcdef"],
                severity=Severity.HIGH,
                metadata={"finding_type": "api_key", "line_number": 42},
            ),
            Finding(
                file_path="https://example.com/page",
                detector_name="regex",
                matches=["test@example.com"],
                severity=Severity.LOW,
                metadata={"finding_type": "email", "line_number": 10},
            ),
        ],
        scan_duration=1.5,
        stats={
            "urls_scanned": 3,
            "scripts_scanned": 2,
            "total_findings": 2,
            "cancelled": False,
            "errors": [],
            "depth": 1,
            "include_scripts": True,
        },
    )


@pytest.fixture
def mock_web_scan_no_findings() -> ScanResult:
    """Create a mock scan result with no findings."""
    return ScanResult(
        target_path="https://example.com",
        findings=[],
        scan_duration=0.5,
        stats={
            "urls_scanned": 1,
            "scripts_scanned": 0,
            "total_findings": 0,
            "cancelled": False,
            "errors": [],
            "depth": 1,
            "include_scripts": True,
        },
    )


class TestScanWebCommand:
    """Test scan-web command basic functionality."""

    def test_scan_web_help(self) -> None:
        """Test that scan-web --help shows help information."""
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0
        assert "scan-web" in result.output.lower() or "web url" in result.output.lower()
        assert "--depth" in result.output
        assert "--include-scripts" in result.output or "--no-scripts" in result.output
        assert "--user-agent" in result.output
        assert "--timeout" in result.output
        assert "--auth" in result.output

    def test_scan_web_finds_secrets(self, mock_web_scan_result: ScanResult) -> None:
        """Test that scan-web finds secrets in a URL."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "json"])
            assert result.exit_code == 0

            data = json.loads(result.output)
            assert "findings" in data
            assert len(data["findings"]) > 0

    def test_scan_web_no_findings(self, mock_web_scan_no_findings: ScanResult) -> None:
        """Test that scan-web returns exit code 2 for clean URL."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_no_findings

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "json"])
            # Exit code 2 means no findings
            assert result.exit_code == 2

            data = json.loads(result.output)
            assert data["findings"] == []

    def test_scan_web_invalid_url_scheme_fails(self) -> None:
        """Test that scanning with invalid URL scheme fails."""
        from hamburglar.core.exceptions import ScanError

        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = ScanError("Invalid URL scheme: ftp")

            result = runner.invoke(app, ["scan-web", "ftp://example.com"])
            assert result.exit_code == 1
            assert "Error" in result.output or "error" in result.output.lower()


class TestScanWebDepthOption:
    """Test --depth option for limiting link following."""

    def test_depth_option_zero(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --depth 0 is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                ["scan-web", "https://example.com", "--depth", "0", "--format", "json"],
            )
            assert result.exit_code == 0

    def test_depth_option_custom(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --depth accepts custom value."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                ["scan-web", "https://example.com", "--depth", "3", "--format", "json"],
            )
            assert result.exit_code == 0


class TestScanWebIncludeScriptsOption:
    """Test --include-scripts/--no-scripts option."""

    def test_include_scripts_default(self, mock_web_scan_result: ScanResult) -> None:
        """Test that script scanning is enabled by default."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "json"])
            assert result.exit_code == 0

    def test_no_scripts_flag(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --no-scripts is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                ["scan-web", "https://example.com", "--no-scripts", "--format", "json"],
            )
            assert result.exit_code == 0


class TestScanWebUserAgentOption:
    """Test --user-agent option."""

    def test_custom_user_agent(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --user-agent is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--user-agent",
                    "CustomBot/1.0",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code == 0


class TestScanWebTimeoutOption:
    """Test --timeout option."""

    def test_custom_timeout(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --timeout is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--timeout",
                    "60",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code == 0


class TestScanWebAuthOption:
    """Test --auth option for basic authentication."""

    def test_auth_with_valid_format(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --auth with valid format is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--auth",
                    "user:pass",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code == 0

    def test_auth_with_password_containing_colon(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --auth handles password containing colon."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--auth",
                    "user:pass:with:colons",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code == 0

    def test_auth_invalid_format_fails(self) -> None:
        """Test that --auth with invalid format fails."""
        result = runner.invoke(
            app,
            ["scan-web", "https://example.com", "--auth", "invalid_no_colon"],
        )
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "error" in result.output.lower()


class TestScanWebRespectRobotsOption:
    """Test --respect-robots/--ignore-robots option."""

    def test_respect_robots_default(self, mock_web_scan_result: ScanResult) -> None:
        """Test that robots.txt is respected by default."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "json"])
            assert result.exit_code == 0

    def test_ignore_robots_flag(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --ignore-robots is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                ["scan-web", "https://example.com", "--ignore-robots", "--format", "json"],
            )
            assert result.exit_code == 0


class TestScanWebOutputFormats:
    """Test output format options."""

    def test_json_format(self, mock_web_scan_result: ScanResult) -> None:
        """Test JSON output format."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "json"])
            assert result.exit_code == 0

            data = json.loads(result.output)
            assert "target_path" in data
            assert "findings" in data
            assert "scan_duration" in data
            assert "stats" in data

    def test_table_format(self, mock_web_scan_result: ScanResult) -> None:
        """Test table output format."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "table"])
            assert result.exit_code == 0
            # Table output should not be valid JSON
            with pytest.raises(json.JSONDecodeError):
                json.loads(result.output)

    def test_invalid_format_fails(self) -> None:
        """Test that invalid format option fails."""
        result = runner.invoke(app, ["scan-web", "https://example.com", "--format", "xml"])
        assert result.exit_code == 1


class TestScanWebOutputFile:
    """Test output file option."""

    def test_output_to_file(self, mock_web_scan_result: ScanResult, tmp_path: Path) -> None:
        """Test writing output to file."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            output_file = tmp_path / "output.json"
            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
            )
            assert result.exit_code == 0
            assert output_file.exists()

            content = output_file.read_text()
            data = json.loads(content)
            assert "findings" in data


class TestScanWebQuietMode:
    """Test quiet mode."""

    def test_quiet_suppresses_output(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --quiet suppresses stdout output."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--quiet"])
            assert result.exit_code == 0
            assert result.output == ""

    def test_quiet_with_output_file(self, mock_web_scan_result: ScanResult, tmp_path: Path) -> None:
        """Test that --quiet still writes to output file."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            output_file = tmp_path / "output.json"
            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--quiet",
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                ],
            )
            assert result.exit_code == 0
            assert output_file.exists()


class TestScanWebVerboseMode:
    """Test verbose mode."""

    def test_verbose_shows_details(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --verbose shows additional details."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com", "--verbose"])
            assert result.exit_code == 0
            # Verbose should show URL info
            assert "URL" in result.output or "https://example.com" in result.output


class TestScanWebStreamingMode:
    """Test streaming output mode."""

    def test_stream_option_accepted(self) -> None:
        """Test that --stream option is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            # Streaming mode handles exit itself via asyncio.run
            mock_run.return_value = None

            result = runner.invoke(app, ["scan-web", "https://example.com", "--stream"])
            # Streaming mode should have called asyncio.run
            assert mock_run.called


class TestScanWebCategoryFilters:
    """Test category filtering options."""

    def test_categories_filter(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --categories is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--categories",
                    "cloud",
                    "--format",
                    "json",
                ],
            )
            # Should succeed
            assert result.exit_code in (0, 2)

    def test_no_categories_filter(self, mock_web_scan_result: ScanResult) -> None:
        """Test that --no-categories is accepted."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--no-categories",
                    "generic",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code in (0, 2)


class TestScanWebMinConfidence:
    """Test minimum confidence filtering."""

    def test_min_confidence_high(self, mock_web_scan_result: ScanResult) -> None:
        """Test filtering with high confidence level."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(
                app,
                [
                    "scan-web",
                    "https://example.com",
                    "--min-confidence",
                    "high",
                    "--format",
                    "json",
                ],
            )
            assert result.exit_code in (0, 2)


class TestScanWebExitCodes:
    """Test exit codes for various scenarios."""

    def test_exit_code_0_with_findings(self, mock_web_scan_result: ScanResult) -> None:
        """Test exit code 0 when findings are found."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_result

            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == 0

    def test_exit_code_2_no_findings(self, mock_web_scan_no_findings: ScanResult) -> None:
        """Test exit code 2 when no findings."""
        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.return_value = mock_web_scan_no_findings

            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == 2

    def test_exit_code_1_on_error(self) -> None:
        """Test exit code 1 on error."""
        from hamburglar.core.exceptions import ScanError

        with patch("hamburglar.cli.main.asyncio.run") as mock_run:
            mock_run.side_effect = ScanError("Network error")

            result = runner.invoke(app, ["scan-web", "https://example.com"])
            assert result.exit_code == 1
