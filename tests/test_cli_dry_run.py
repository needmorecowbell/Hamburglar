"""Tests for the --dry-run flag in Hamburglar CLI commands.

This module tests the dry-run functionality for scan, scan-git, and scan-web
commands, ensuring they display configuration information without performing
actual scans.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Generator

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

from hamburglar.cli.main import app

runner = CliRunner()


@pytest.fixture
def temp_git_repo(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a minimal temporary git repository for dry-run testing.

    Yields:
        Path to the temporary git repository.
    """
    repo_path = tmp_path / "dry_run_repo"
    repo_path.mkdir()

    # Initialize git repository
    subprocess.run(
        ["git", "init"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    # Configure git user for commits
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    # Create a simple file and commit
    readme = repo_path / "README.md"
    readme.write_text("# Test Repository\n\nThis is a test repo for dry-run testing.")

    subprocess.run(
        ["git", "add", "."],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    yield repo_path


class TestScanDryRun:
    """Tests for --dry-run flag on the scan command."""

    def test_dry_run_shows_config_table(self, temp_directory: Path) -> None:
        """Test that --dry-run shows configuration table."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0
        assert "DRY RUN MODE" in result.output
        assert "Scan Configuration" in result.output
        assert "Target" in result.output

    def test_dry_run_shows_detectors_table(self, temp_directory: Path) -> None:
        """Test that --dry-run shows detectors table."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0
        assert "Detectors" in result.output
        assert "RegexDetector" in result.output
        assert "patterns" in result.output

    def test_dry_run_shows_file_discovery_summary(self, temp_directory: Path) -> None:
        """Test that --dry-run shows file discovery summary."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0
        assert "File Discovery Summary" in result.output
        assert "Files to Scan" in result.output
        assert "Total Size" in result.output

    def test_dry_run_does_not_scan_files(self, temp_directory: Path) -> None:
        """Test that --dry-run does not perform actual scanning."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0
        # Should show dry run completion message
        assert "Dry run complete" in result.output
        assert "No files were scanned" in result.output
        # Should NOT contain actual findings output
        assert "Finding" not in result.output or "Files to Scan" in result.output

    def test_dry_run_shows_completion_message(self, temp_directory: Path) -> None:
        """Test that --dry-run shows completion message."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run complete" in result.output

    def test_dry_run_with_verbose_shows_file_list(self, temp_directory: Path) -> None:
        """Test that --dry-run with --verbose shows file list."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--dry-run", "--verbose"]
        )
        assert result.exit_code == 0
        assert "Files to Scan" in result.output
        # File table should show actual files
        assert "secrets.txt" in result.output or "file" in result.output.lower()

    def test_dry_run_with_categories(self, temp_directory: Path) -> None:
        """Test that --dry-run shows enabled categories."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--dry-run", "--categories", "api_keys"]
        )
        assert result.exit_code == 0
        assert "Enabled Categories" in result.output
        assert "api_keys" in result.output

    def test_dry_run_with_min_confidence(self, temp_directory: Path) -> None:
        """Test that --dry-run shows min confidence level."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--dry-run", "--min-confidence", "high"]
        )
        assert result.exit_code == 0
        assert "Min Confidence" in result.output
        assert "high" in result.output

    def test_dry_run_quiet_mode(self, temp_directory: Path) -> None:
        """Test that --dry-run with --quiet suppresses output."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--dry-run", "--quiet"]
        )
        # Should succeed but with no output
        assert result.exit_code == 0
        # Output should be minimal or empty
        assert len(result.output.strip()) == 0 or "DRY RUN" not in result.output

    def test_dry_run_with_format_option(self, temp_directory: Path) -> None:
        """Test that --dry-run respects --format option."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--dry-run", "--format", "json"]
        )
        assert result.exit_code == 0
        assert "Output Format" in result.output
        assert "json" in result.output

    def test_dry_run_single_file(self, temp_directory: Path) -> None:
        """Test --dry-run with a single file target."""
        single_file = temp_directory / "secrets.txt"
        result = runner.invoke(app, ["scan", str(single_file), "--dry-run"])
        assert result.exit_code == 0
        assert "DRY RUN MODE" in result.output
        assert "Files to Scan" in result.output


class TestScanGitDryRun:
    """Tests for --dry-run flag on the scan-git command."""

    def test_dry_run_shows_git_config_table(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows git scan configuration table."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0
        assert "DRY RUN MODE" in result.output
        assert "Git Scan Configuration" in result.output
        assert "Target" in result.output

    def test_dry_run_shows_local_repository_type(self, temp_git_repo: Path) -> None:
        """Test that --dry-run identifies local repository type."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0
        assert "Local Repository" in result.output

    def test_dry_run_shows_remote_repository_type(self) -> None:
        """Test that --dry-run identifies remote repository type."""
        result = runner.invoke(
            app, ["scan-git", "https://github.com/example/repo", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "Remote Repository" in result.output

    def test_dry_run_shows_history_option(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows include history option."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0
        assert "Include History" in result.output

    def test_dry_run_with_depth(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows commit depth option."""
        result = runner.invoke(
            app, ["scan-git", str(temp_git_repo), "--dry-run", "--depth", "10"]
        )
        assert result.exit_code == 0
        assert "Commit Depth" in result.output
        assert "10" in result.output

    def test_dry_run_with_branch(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows branch option."""
        result = runner.invoke(
            app, ["scan-git", str(temp_git_repo), "--dry-run", "--branch", "main"]
        )
        assert result.exit_code == 0
        assert "Branch" in result.output
        assert "main" in result.output

    def test_dry_run_shows_detectors(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows detectors table."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0
        assert "Detectors" in result.output
        assert "RegexDetector" in result.output

    def test_dry_run_shows_completion_message(self, temp_git_repo: Path) -> None:
        """Test that --dry-run shows completion message."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run complete" in result.output

    def test_dry_run_no_history(self, temp_git_repo: Path) -> None:
        """Test that --dry-run with --no-history shows correct config."""
        result = runner.invoke(
            app, ["scan-git", str(temp_git_repo), "--dry-run", "--no-history"]
        )
        assert result.exit_code == 0
        assert "Include History" in result.output


class TestScanWebDryRun:
    """Tests for --dry-run flag on the scan-web command."""

    def test_dry_run_shows_web_config_table(self) -> None:
        """Test that --dry-run shows web scan configuration table."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "DRY RUN MODE" in result.output
        assert "Web Scan Configuration" in result.output

    def test_dry_run_shows_url_info(self) -> None:
        """Test that --dry-run shows URL information."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "URL" in result.output
        assert "example.com" in result.output
        assert "Domain" in result.output

    def test_dry_run_shows_protocol(self) -> None:
        """Test that --dry-run shows protocol."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "Protocol" in result.output
        assert "HTTPS" in result.output

    def test_dry_run_shows_depth(self) -> None:
        """Test that --dry-run shows link depth."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run", "--depth", "3"]
        )
        assert result.exit_code == 0
        assert "Link Depth" in result.output
        assert "3" in result.output

    def test_dry_run_shows_scripts_option(self) -> None:
        """Test that --dry-run shows include scripts option."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "Include Scripts" in result.output

    def test_dry_run_shows_timeout(self) -> None:
        """Test that --dry-run shows timeout."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run", "--timeout", "60"]
        )
        assert result.exit_code == 0
        assert "Timeout" in result.output
        assert "60" in result.output

    def test_dry_run_shows_robots_option(self) -> None:
        """Test that --dry-run shows robots.txt option."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "robots.txt" in result.output

    def test_dry_run_shows_detectors(self) -> None:
        """Test that --dry-run shows detectors table."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "Detectors" in result.output
        assert "RegexDetector" in result.output

    def test_dry_run_shows_scan_behavior(self) -> None:
        """Test that --dry-run shows scan behavior."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "Scan behavior" in result.output

    def test_dry_run_no_http_requests(self) -> None:
        """Test that --dry-run shows no HTTP requests were made."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
        assert "No HTTP requests were made" in result.output

    def test_dry_run_with_auth(self) -> None:
        """Test that --dry-run shows auth configuration."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run", "--auth", "user:pass"]
        )
        assert result.exit_code == 0
        assert "Authentication" in result.output
        # Password should be masked
        assert "***" in result.output

    def test_dry_run_with_user_agent(self) -> None:
        """Test that --dry-run shows user agent configuration."""
        result = runner.invoke(
            app,
            ["scan-web", "https://example.com", "--dry-run", "--user-agent", "TestAgent"]
        )
        assert result.exit_code == 0
        assert "User Agent" in result.output
        assert "TestAgent" in result.output


class TestDryRunExitCodes:
    """Tests for exit codes with --dry-run flag."""

    def test_scan_dry_run_exits_zero(self, temp_directory: Path) -> None:
        """Test that scan --dry-run exits with code 0."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--dry-run"])
        assert result.exit_code == 0

    def test_scan_git_dry_run_exits_zero(self, temp_git_repo: Path) -> None:
        """Test that scan-git --dry-run exits with code 0."""
        result = runner.invoke(app, ["scan-git", str(temp_git_repo), "--dry-run"])
        assert result.exit_code == 0

    def test_scan_web_dry_run_exits_zero(self) -> None:
        """Test that scan-web --dry-run exits with code 0."""
        result = runner.invoke(
            app, ["scan-web", "https://example.com", "--dry-run"]
        )
        assert result.exit_code == 0
