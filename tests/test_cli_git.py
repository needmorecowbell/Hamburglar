"""Tests for the scan-git CLI command.

This module tests the scan-git command for scanning git repositories
for secrets and sensitive information.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Generator

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

from hamburglar.cli.main import app

runner = CliRunner()


@pytest.fixture
def git_repo_with_secrets(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a temporary git repository with secrets for testing.

    Creates a git repository with:
    - Initial commit with secrets
    - Second commit that removes some secrets
    - Commit message with secret

    Yields:
        Path to the temporary git repository.
    """
    repo_path = tmp_path / "test_repo"
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

    # Create file with secrets
    secrets_file = repo_path / "config.py"
    secrets_file.write_text('''
# Configuration with secrets
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://user:password@localhost/db"
''')

    # Add and commit
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit with secrets"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    # Modify file to remove some secrets
    secrets_file.write_text('''
# Configuration - secrets removed
AWS_ACCESS_KEY = "REDACTED"
DATABASE_URL = "postgresql://localhost/db"
''')

    # Add and commit with secret in message
    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Remove secrets, old key was AKIAIOSFODNN7EXAMPLE"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    yield repo_path


@pytest.fixture
def git_repo_clean(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a clean git repository without secrets.

    Yields:
        Path to the clean git repository.
    """
    repo_path = tmp_path / "clean_repo"
    repo_path.mkdir()

    subprocess.run(
        ["git", "init"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

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

    clean_file = repo_path / "readme.txt"
    clean_file.write_text("This is a clean repository with no secrets.\n")

    subprocess.run(["git", "add", "."], cwd=repo_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        capture_output=True,
        check=True,
    )

    yield repo_path


class TestScanGitCommand:
    """Test scan-git command basic functionality."""

    def test_scan_git_help(self) -> None:
        """Test that scan-git --help shows help information."""
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "scan-git" in result.output.lower() or "git repository" in result.output.lower()
        assert "--depth" in result.output
        assert "--branch" in result.output
        assert "--include-history" in result.output or "--no-history" in result.output
        assert "--clone-dir" in result.output

    def test_scan_git_local_repo_finds_secrets(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that scan-git finds secrets in a local repository."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--format", "json"]
        )
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_scan_git_clean_repo_no_findings(
        self, git_repo_clean: Path
    ) -> None:
        """Test that scan-git returns exit code 2 for clean repo."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_clean), "--format", "json"]
        )
        # Exit code 2 means no findings
        assert result.exit_code == 2

        data = json.loads(result.output)
        assert data["findings"] == []

    def test_scan_git_nonexistent_path_fails(self, tmp_path: Path) -> None:
        """Test that scanning nonexistent path fails appropriately."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(app, ["scan-git", str(nonexistent)])
        assert result.exit_code == 1
        # Should show some error indication
        assert "Error" in result.output or "error" in result.output.lower()

    def test_scan_git_not_a_repo_fails(self, tmp_path: Path) -> None:
        """Test that scanning a non-git directory fails."""
        # Create a regular directory (not a git repo)
        not_repo = tmp_path / "not_a_repo"
        not_repo.mkdir()
        (not_repo / "file.txt").write_text("just a file")

        result = runner.invoke(app, ["scan-git", str(not_repo)])
        assert result.exit_code == 1
        assert "Error" in result.output or "error" in result.output.lower()


class TestScanGitDepthOption:
    """Test --depth option for limiting commit history."""

    def test_depth_option_limits_commits(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --depth limits the number of commits scanned."""
        result = runner.invoke(
            app,
            ["scan-git", str(git_repo_with_secrets), "--depth", "1", "--format", "json"],
        )
        assert result.exit_code in (0, 2)  # Either findings or no findings

        data = json.loads(result.output)
        # With depth=1, should scan fewer commits
        assert "stats" in data
        # The stats should reflect limited commit scanning
        assert data["stats"].get("commits_scanned", 0) <= 2


class TestScanGitBranchOption:
    """Test --branch option for scanning specific branches."""

    def test_branch_option_accepted(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --branch option is accepted."""
        # Get the current branch name (usually 'main' or 'master')
        branch_result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=git_repo_with_secrets,
            capture_output=True,
            text=True,
        )
        current_branch = branch_result.stdout.strip() or "master"

        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--branch",
                current_branch,
                "--format",
                "json",
            ],
        )
        assert result.exit_code in (0, 2)


class TestScanGitIncludeHistoryOption:
    """Test --include-history/--no-history option."""

    def test_include_history_default(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that history scanning is enabled by default."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--format", "json"]
        )
        assert result.exit_code == 0

        data = json.loads(result.output)
        # Default should include history scanning
        assert data["stats"].get("include_history", True) is True

    def test_no_history_flag(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --no-history disables history scanning."""
        result = runner.invoke(
            app,
            ["scan-git", str(git_repo_with_secrets), "--no-history", "--format", "json"],
        )
        assert result.exit_code in (0, 2)

        data = json.loads(result.output)
        assert data["stats"].get("include_history", True) is False


class TestScanGitOutputFormats:
    """Test output format options."""

    def test_json_format(self, git_repo_with_secrets: Path) -> None:
        """Test JSON output format."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--format", "json"]
        )
        assert result.exit_code == 0

        data = json.loads(result.output)
        assert "target_path" in data
        assert "findings" in data
        assert "scan_duration" in data
        assert "stats" in data

    def test_table_format(self, git_repo_with_secrets: Path) -> None:
        """Test table output format."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--format", "table"]
        )
        assert result.exit_code == 0
        # Table output should not be valid JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.output)

    def test_invalid_format_fails(self, git_repo_with_secrets: Path) -> None:
        """Test that invalid format option fails."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--format", "xml"]
        )
        assert result.exit_code == 1


class TestScanGitOutputFile:
    """Test output file option."""

    def test_output_to_file(
        self, git_repo_with_secrets: Path, tmp_path: Path
    ) -> None:
        """Test writing output to file."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
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


class TestScanGitQuietMode:
    """Test quiet mode."""

    def test_quiet_suppresses_output(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --quiet suppresses stdout output."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--quiet"]
        )
        assert result.exit_code == 0
        assert result.output == ""

    def test_quiet_with_output_file(
        self, git_repo_with_secrets: Path, tmp_path: Path
    ) -> None:
        """Test that --quiet still writes to output file."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--quiet",
                "--format",
                "json",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestScanGitVerboseMode:
    """Test verbose mode."""

    def test_verbose_shows_details(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --verbose shows additional details."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--verbose"]
        )
        assert result.exit_code == 0
        # Verbose should show target info
        assert "Target" in result.output or str(git_repo_with_secrets) in result.output


class TestScanGitStreamingMode:
    """Test streaming output mode."""

    def test_stream_produces_ndjson(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --stream produces newline-delimited JSON."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets), "--stream"]
        )
        assert result.exit_code == 0

        # Each line should be valid JSON (NDJSON format)
        lines = result.output.strip().split("\n")
        for line in lines:
            if line:  # Skip empty lines
                json.loads(line)  # Should not raise


class TestScanGitCategoryFilters:
    """Test category filtering options."""

    def test_categories_filter(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --categories filters results."""
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--categories",
                "cloud",
                "--format",
                "json",
            ],
        )
        # Should succeed or have no findings for that category
        assert result.exit_code in (0, 2)

    def test_no_categories_filter(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test that --no-categories excludes categories."""
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--no-categories",
                "generic",
                "--format",
                "json",
            ],
        )
        assert result.exit_code in (0, 2)


class TestScanGitMinConfidence:
    """Test minimum confidence filtering."""

    def test_min_confidence_high(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test filtering with high confidence level."""
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--min-confidence",
                "high",
                "--format",
                "json",
            ],
        )
        assert result.exit_code in (0, 2)


class TestScanGitExitCodes:
    """Test exit codes for various scenarios."""

    def test_exit_code_0_with_findings(
        self, git_repo_with_secrets: Path
    ) -> None:
        """Test exit code 0 when findings are found."""
        result = runner.invoke(
            app, ["scan-git", str(git_repo_with_secrets)]
        )
        assert result.exit_code == 0

    def test_exit_code_2_no_findings(
        self, git_repo_clean: Path
    ) -> None:
        """Test exit code 2 when no findings."""
        result = runner.invoke(app, ["scan-git", str(git_repo_clean)])
        assert result.exit_code == 2

    def test_exit_code_1_on_error(self, tmp_path: Path) -> None:
        """Test exit code 1 on error."""
        nonexistent = tmp_path / "nonexistent"
        result = runner.invoke(app, ["scan-git", str(nonexistent)])
        assert result.exit_code == 1


class TestScanGitCloneDirOption:
    """Test --clone-dir option."""

    def test_clone_dir_option_accepted(
        self, git_repo_with_secrets: Path, tmp_path: Path
    ) -> None:
        """Test that --clone-dir is accepted (for local repos, doesn't affect behavior)."""
        clone_dir = tmp_path / "clone_target"
        result = runner.invoke(
            app,
            [
                "scan-git",
                str(git_repo_with_secrets),
                "--clone-dir",
                str(clone_dir),
                "--format",
                "json",
            ],
        )
        # For local repos, clone-dir is not used, but option should be accepted
        assert result.exit_code in (0, 2)
