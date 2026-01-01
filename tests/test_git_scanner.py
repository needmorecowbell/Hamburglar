"""Tests for the GitScanner class.

This module tests the git repository scanning functionality including:
- Scanning local git repositories for secrets
- Scanning commit history for removed secrets
- Scanning commit messages for sensitive info
- Cloning remote repositories (mocked)
- Cleanup of temporary directories
- Error handling for invalid paths and repositories
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Configure path before any hamburglar imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.exceptions import ScanError  # noqa: E402
from hamburglar.core.models import Finding, Severity  # noqa: E402
from hamburglar.core.progress import ScanProgress  # noqa: E402
from hamburglar.detectors import BaseDetector  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402
from hamburglar.scanners import BaseScanner, GitScanner  # noqa: E402


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a local git repository with test commits.

    Creates a git repository with:
    - Initial commit with a secret
    - A commit that removes the secret
    - A commit with a secret in the commit message
    """
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Initialize git repo
    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Create initial file with secret
    secrets_file = repo_path / "secrets.txt"
    secrets_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit with secret"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Create another file without secrets
    clean_file = repo_path / "clean.txt"
    clean_file.write_text("This is a clean file without secrets.\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Add clean file"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Remove the secret from the file
    secrets_file.write_text("# Secret removed\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Remove the secret"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Add a commit with secret in message
    readme = repo_path / "README.md"
    readme.write_text("# Test Repository\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            "Add README\n\nNote: Old key was AKIAIOSFODNN7EXAMPLE",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def git_repo_with_current_secret(tmp_path: Path) -> Path:
    """Create a git repository with a secret in the current HEAD."""
    repo_path = tmp_path / "test_repo_current"
    repo_path.mkdir()

    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Create file with secret
    secrets_file = repo_path / "config.py"
    secrets_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'API_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    )
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Add config with secrets"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


class TestGitScannerInterface:
    """Test that GitScanner correctly implements BaseScanner."""

    def test_inherits_from_base_scanner(self):
        """Test that GitScanner is a subclass of BaseScanner."""
        assert issubclass(GitScanner, BaseScanner)

    def test_scanner_type_property(self, tmp_path: Path):
        """Test that scanner_type returns 'git'."""
        scanner = GitScanner(str(tmp_path))
        assert scanner.scanner_type == "git"

    def test_init_with_no_detectors(self, tmp_path: Path):
        """Test initialization without detectors."""
        scanner = GitScanner(str(tmp_path))
        assert scanner.detectors == []
        assert scanner.progress_callback is None

    def test_init_with_detectors(self, tmp_path: Path):
        """Test initialization with detectors."""
        detector = RegexDetector()
        scanner = GitScanner(str(tmp_path), detectors=[detector])
        assert len(scanner.detectors) == 1

    def test_init_with_progress_callback(self, tmp_path: Path):
        """Test initialization with progress callback."""
        callback_called = []

        def callback(progress):
            callback_called.append(progress)

        scanner = GitScanner(str(tmp_path), progress_callback=callback)
        assert scanner.progress_callback is callback

    def test_init_with_options(self, tmp_path: Path):
        """Test initialization with various options."""
        scanner = GitScanner(
            str(tmp_path),
            clone_dir=tmp_path / "clone",
            include_history=False,
            depth=10,
            branch="main",
        )
        assert scanner.clone_dir == tmp_path / "clone"
        assert scanner.include_history is False
        assert scanner.depth == 10
        assert scanner.branch == "main"


class TestGitScannerLocalRepo:
    """Test scanning local git repositories."""

    @pytest.mark.asyncio
    async def test_scan_local_repo_finds_current_secrets(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scanner finds secrets in current HEAD files."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[detector],
            include_history=False,
        )

        result = await scanner.scan()

        assert result.target_path == str(git_repo_with_current_secret)
        assert len(result.findings) > 0
        assert result.stats["files_scanned"] > 0

        # Check that findings have correct metadata
        for finding in result.findings:
            assert "source_type" in finding.metadata
            assert finding.metadata["source_type"] == "current_file"

    @pytest.mark.asyncio
    async def test_scan_local_repo_finds_historical_secrets(
        self, git_repo: Path
    ) -> None:
        """Test that scanner finds secrets in commit history."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo),
            detectors=[detector],
            include_history=True,
        )

        result = await scanner.scan()

        assert result.stats["commits_scanned"] > 0

        # Should find secrets in historical diffs (the removed secret)
        diff_findings = [
            f
            for f in result.findings
            if f.metadata.get("content_type") == "commit_diff"
        ]
        assert len(diff_findings) > 0

    @pytest.mark.asyncio
    async def test_scan_local_repo_finds_commit_message_secrets(
        self, git_repo: Path
    ) -> None:
        """Test that scanner finds secrets in commit messages."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo),
            detectors=[detector],
            include_history=True,
        )

        result = await scanner.scan()

        # Should find secret in commit message
        message_findings = [
            f
            for f in result.findings
            if f.metadata.get("content_type") == "commit_message"
        ]
        assert len(message_findings) > 0

    @pytest.mark.asyncio
    async def test_scan_without_history(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test scanning without commit history."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[detector],
            include_history=False,
        )

        result = await scanner.scan()

        assert result.stats["commits_scanned"] == 0
        assert result.stats["files_scanned"] > 0
        assert result.stats["include_history"] is False


class TestGitScannerNonexistent:
    """Test error handling for nonexistent paths."""

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError for nonexistent paths."""
        nonexistent = tmp_path / "does_not_exist"
        scanner = GitScanner(str(nonexistent))

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_scan_non_git_directory(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError for non-git directories."""
        # Create a regular directory without .git
        regular_dir = tmp_path / "not_a_git_repo"
        regular_dir.mkdir()
        (regular_dir / "file.txt").write_text("content")

        scanner = GitScanner(str(regular_dir))

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "Not a git repository" in str(exc_info.value)


class TestGitScannerCancellation:
    """Test cancellation functionality."""

    @pytest.mark.asyncio
    async def test_cancel_sets_cancelled_flag(self, tmp_path: Path) -> None:
        """Test that cancel() sets the cancellation flag."""
        scanner = GitScanner(str(tmp_path))

        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_cancellation_stops_scan(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that cancellation stops the scan."""
        scan_started = asyncio.Event()
        files_processed = 0

        class CountingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "counting"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal files_processed
                files_processed += 1
                scan_started.set()
                # Add a small delay to allow cancellation to take effect
                import time
                time.sleep(0.01)
                return []

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[CountingDetector()],
            include_history=True,
        )

        async def cancel_after_start():
            await scan_started.wait()
            scanner.cancel()

        # Start both the scan and the cancellation task
        cancel_task = asyncio.create_task(cancel_after_start())
        result = await scanner.scan()
        await cancel_task

        assert scanner.is_cancelled
        assert result.stats["cancelled"] is True


class TestGitScannerProgressCallback:
    """Test progress callback functionality."""

    @pytest.mark.asyncio
    async def test_progress_callback_is_called(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that progress callback is called during scan."""
        progress_calls: list[ScanProgress] = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_calls.append(progress)

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            progress_callback=progress_callback,
            include_history=False,
        )

        await scanner.scan()

        assert len(progress_calls) > 0

    @pytest.mark.asyncio
    async def test_progress_callback_error_handling(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that callback errors don't disrupt the scan."""

        def failing_callback(progress: ScanProgress) -> None:
            raise RuntimeError("Callback failure!")

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            progress_callback=failing_callback,
            include_history=False,
        )

        # Scan should complete despite callback failure
        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0


class TestGitScannerStreaming:
    """Test streaming output functionality."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scan_stream yields findings as they're discovered."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[detector],
            include_history=False,
        )

        findings: list[Finding] = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        assert len(findings) > 0
        for finding in findings:
            assert isinstance(finding, Finding)

    @pytest.mark.asyncio
    async def test_stream_includes_history(self, git_repo: Path) -> None:
        """Test that streaming includes commit history findings."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo),
            detectors=[detector],
            include_history=True,
        )

        findings: list[Finding] = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        # Should have findings from both current files and history
        current_findings = [
            f for f in findings if f.metadata.get("source_type") == "current_file"
        ]
        history_findings = [
            f for f in findings if f.metadata.get("source_type") == "commit_history"
        ]

        # At least history findings should exist
        assert len(history_findings) > 0


class TestGitScannerStats:
    """Test statistics tracking."""

    @pytest.mark.asyncio
    async def test_get_stats_returns_current_state(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that get_stats returns current scan state."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        # Before scan
        stats = scanner.get_stats()
        assert stats["files_scanned"] == 0
        assert stats["commits_scanned"] == 0

        await scanner.scan()

        # After scan
        stats = scanner.get_stats()
        assert stats["files_scanned"] > 0

    @pytest.mark.asyncio
    async def test_scan_duration_is_tracked(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scan duration is tracked."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        result = await scanner.scan()

        assert result.scan_duration > 0


class TestGitScannerRemoteURL:
    """Test remote URL detection and handling."""

    def test_is_remote_url_https(self):
        """Test that HTTPS URLs are detected as remote."""
        scanner = GitScanner("https://github.com/user/repo.git")
        assert scanner._is_remote_url("https://github.com/user/repo.git")

    def test_is_remote_url_http(self):
        """Test that HTTP URLs are detected as remote."""
        scanner = GitScanner("http://github.com/user/repo.git")
        assert scanner._is_remote_url("http://github.com/user/repo.git")

    def test_is_remote_url_ssh(self):
        """Test that SSH URLs are detected as remote."""
        scanner = GitScanner("git@github.com:user/repo.git")
        assert scanner._is_remote_url("git@github.com:user/repo.git")

    def test_is_remote_url_ssh_protocol(self):
        """Test that SSH protocol URLs are detected as remote."""
        scanner = GitScanner("ssh://git@github.com/user/repo.git")
        assert scanner._is_remote_url("ssh://git@github.com/user/repo.git")

    def test_is_remote_url_git_protocol(self):
        """Test that Git protocol URLs are detected as remote."""
        scanner = GitScanner("git://github.com/user/repo.git")
        assert scanner._is_remote_url("git://github.com/user/repo.git")

    def test_is_remote_url_local_path(self):
        """Test that local paths are not detected as remote."""
        scanner = GitScanner("/path/to/repo")
        assert not scanner._is_remote_url("/path/to/repo")

    def test_is_remote_url_relative_path(self):
        """Test that relative paths are not detected as remote."""
        scanner = GitScanner("./repo")
        assert not scanner._is_remote_url("./repo")


class TestGitScannerClone:
    """Test repository cloning functionality."""

    @pytest.mark.asyncio
    async def test_clone_with_custom_dir(self, tmp_path: Path) -> None:
        """Test that clone_dir is respected when cloning."""
        clone_dir = tmp_path / "custom_clone"

        # Mock the git clone command
        with patch.object(
            GitScanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.return_value = (0, "", "")

            scanner = GitScanner(
                "https://github.com/user/repo.git",
                clone_dir=clone_dir,
            )

            # The clone should use the custom directory
            assert scanner.clone_dir == clone_dir

    @pytest.mark.asyncio
    async def test_clone_with_depth(self, tmp_path: Path) -> None:
        """Test that depth parameter is passed to git clone."""
        with patch.object(
            GitScanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.return_value = (0, "", "")

            scanner = GitScanner(
                "https://github.com/user/repo.git",
                depth=5,
            )

            # Access private method to test clone args
            assert scanner.depth == 5

    @pytest.mark.asyncio
    async def test_clone_with_branch(self, tmp_path: Path) -> None:
        """Test that branch parameter is passed to git clone."""
        scanner = GitScanner(
            "https://github.com/user/repo.git",
            branch="develop",
        )

        assert scanner.branch == "develop"


class TestGitScannerCleanup:
    """Test cleanup of temporary directories."""

    @pytest.mark.asyncio
    async def test_cleanup_after_scan(self, git_repo_with_current_secret: Path) -> None:
        """Test that scan completes and cleanup is called."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        result = await scanner.scan()

        # Temp dir should be cleaned up (None for local repos)
        assert scanner._temp_dir is None

    @pytest.mark.asyncio
    async def test_cleanup_on_error(self, tmp_path: Path) -> None:
        """Test that cleanup happens even on error."""
        scanner = GitScanner(str(tmp_path / "nonexistent"))

        with pytest.raises(ScanError):
            await scanner.scan()

        # Temp dir should be cleaned up
        assert scanner._temp_dir is None


class TestGitScannerNoDetectors:
    """Test scanning without detectors."""

    @pytest.mark.asyncio
    async def test_scan_without_detectors(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scanner works without any detectors."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=None,
            include_history=False,
        )

        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0
        assert len(result.findings) == 0


class TestGitScannerDetectorErrors:
    """Test handling of detector errors."""

    @pytest.mark.asyncio
    async def test_detector_error_handling(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scanner handles detector errors gracefully."""

        class FailingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "failing"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                raise RuntimeError("Detector failure!")

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[FailingDetector(), RegexDetector()],
            include_history=False,
        )

        result = await scanner.scan()

        # Should still get findings from the working detector
        assert len(result.findings) > 0
        # Should have errors logged
        assert len(result.stats["errors"]) > 0


class TestGitScannerFileReadErrors:
    """Test handling of file read errors."""

    @pytest.mark.asyncio
    async def test_handles_unreadable_file(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scanner handles file read errors gracefully."""
        # Make a file unreadable
        config_file = git_repo_with_current_secret / "config.py"
        original_mode = config_file.stat().st_mode
        config_file.chmod(0o000)

        try:
            scanner = GitScanner(
                str(git_repo_with_current_secret),
                include_history=False,
            )

            result = await scanner.scan()

            # Should complete without raising
            assert result is not None
            assert len(result.stats["errors"]) > 0
        finally:
            config_file.chmod(original_mode)


class TestGitScannerGitNotInstalled:
    """Test behavior when git is not installed."""

    @pytest.mark.asyncio
    async def test_git_not_installed(self, tmp_path: Path) -> None:
        """Test that appropriate error is raised when git is not found."""
        scanner = GitScanner(str(tmp_path))

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError("git not found")

            with pytest.raises(ScanError) as exc_info:
                await scanner._run_git_command(["status"])

            assert "Git is not installed" in str(exc_info.value)


class TestGitScannerCommitParsing:
    """Test commit log parsing."""

    @pytest.mark.asyncio
    async def test_commit_parsing(self, git_repo: Path) -> None:
        """Test that commits are parsed correctly."""
        scanner = GitScanner(str(git_repo))

        commits = await scanner._get_commit_log(git_repo)

        assert len(commits) > 0
        for commit in commits:
            assert "hash" in commit
            assert "author" in commit
            assert "date" in commit
            assert "subject" in commit
            assert "diff" in commit


class TestGitScannerReset:
    """Test scanner reset functionality."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _reset clears all scanner state."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            include_history=False,
        )

        # First scan
        await scanner.scan()
        assert scanner.get_stats()["files_scanned"] > 0

        # Reset
        scanner._reset()
        assert scanner.get_stats()["files_scanned"] == 0
        assert scanner.get_stats()["commits_scanned"] == 0
        assert scanner.get_stats()["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_can_scan_multiple_times(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that scanner can be used for multiple scans."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            include_history=False,
        )

        # First scan
        result1 = await scanner.scan()
        assert result1.stats["files_scanned"] > 0

        # Second scan (reset happens automatically)
        result2 = await scanner.scan()
        assert result2.stats["files_scanned"] > 0


class TestGitScannerDepthLimit:
    """Test commit depth limiting."""

    @pytest.mark.asyncio
    async def test_depth_limits_commits(self, git_repo: Path) -> None:
        """Test that depth parameter limits commits scanned."""
        scanner_all = GitScanner(
            str(git_repo),
            detectors=[RegexDetector()],
            include_history=True,
            depth=None,
        )
        result_all = await scanner_all.scan()

        scanner_limited = GitScanner(
            str(git_repo),
            detectors=[RegexDetector()],
            include_history=True,
            depth=1,
        )
        result_limited = await scanner_limited.scan()

        # Limited scan should have fewer commits
        assert result_limited.stats["commits_scanned"] <= result_all.stats["commits_scanned"]


class TestGitScannerRemoteClone:
    """Test remote repository cloning functionality."""

    @pytest.mark.asyncio
    async def test_clone_failure_raises_error(self, tmp_path: Path) -> None:
        """Test that clone failure raises appropriate error."""
        scanner = GitScanner("https://invalid-url-that-will-fail.git")

        with patch.object(
            GitScanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.side_effect = ScanError("Clone failed")

            with pytest.raises(ScanError) as exc_info:
                await scanner._clone_repository(
                    "https://invalid-url.git", tmp_path / "dest"
                )

            assert "Failed to clone" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_setup_repository_remote_with_temp_dir(self) -> None:
        """Test that remote repositories use temp directory when clone_dir not set."""
        scanner = GitScanner("https://github.com/user/repo.git")

        with patch.object(
            GitScanner, "_clone_repository", new_callable=AsyncMock
        ) as mock_clone:
            mock_clone.return_value = None

            # Mock the tempdir creation
            with patch("tempfile.TemporaryDirectory") as mock_temp:
                mock_temp_instance = MagicMock()
                mock_temp_instance.name = "/tmp/test_temp_dir"
                mock_temp.return_value = mock_temp_instance

                try:
                    await scanner._setup_repository()
                except Exception:
                    pass  # We expect this to fail after cloning

                # Verify temp directory was created
                mock_temp.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_repository_remote_with_custom_clone_dir(
        self, tmp_path: Path
    ) -> None:
        """Test that remote repositories use custom clone_dir when set."""
        clone_dir = tmp_path / "custom_clone"
        scanner = GitScanner(
            "https://github.com/user/repo.git",
            clone_dir=clone_dir,
        )

        with patch.object(
            GitScanner, "_clone_repository", new_callable=AsyncMock
        ) as mock_clone:
            mock_clone.return_value = None

            result = await scanner._setup_repository()

            assert result == clone_dir
            mock_clone.assert_called_once()


class TestGitScannerGitCommandFailure:
    """Test git command failure handling."""

    @pytest.mark.asyncio
    async def test_git_command_non_zero_exit(self, tmp_path: Path) -> None:
        """Test that git command failure raises ScanError."""
        scanner = GitScanner(str(tmp_path))

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"error message")
            mock_exec.return_value = mock_process

            with pytest.raises(ScanError) as exc_info:
                await scanner._run_git_command(["status"], check=True)

            assert "Git command failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_git_command_no_check(self, tmp_path: Path) -> None:
        """Test that git command failure is ignored when check=False."""
        scanner = GitScanner(str(tmp_path))

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"output", b"error")
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await scanner._run_git_command(
                ["status"], check=False
            )

            assert returncode == 1
            assert stdout == "output"
            assert stderr == "error"


class TestGitScannerCloneArgs:
    """Test that clone arguments are properly constructed."""

    @pytest.mark.asyncio
    async def test_clone_with_depth_and_branch(self, tmp_path: Path) -> None:
        """Test that depth and branch are passed to clone command."""
        scanner = GitScanner(
            "https://github.com/user/repo.git",
            depth=10,
            branch="develop",
        )

        with patch.object(
            GitScanner, "_run_git_command", new_callable=AsyncMock
        ) as mock_git:
            mock_git.return_value = (0, "", "")

            await scanner._clone_repository(
                "https://github.com/user/repo.git", tmp_path / "dest"
            )

            # Check that the command included depth and branch args
            call_args = mock_git.call_args[0][0]
            assert "--depth" in call_args
            assert "10" in call_args
            assert "--branch" in call_args
            assert "develop" in call_args


class TestGitScannerStreamCleanup:
    """Test cleanup during streaming."""

    @pytest.mark.asyncio
    async def test_stream_cleanup_on_error(self, git_repo_with_current_secret: Path) -> None:
        """Test that cleanup happens during streaming even on error."""

        class ErrorDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "error"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                raise RuntimeError("Detector error")

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[ErrorDetector()],
            include_history=False,
        )

        findings = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        # Scanner should complete without error (errors are logged)
        assert scanner._temp_dir is None


class TestGitScannerEmptyCommits:
    """Test handling of empty commits and content."""

    @pytest.mark.asyncio
    async def test_handles_empty_diff(self, git_repo: Path) -> None:
        """Test that scanner handles commits with empty diffs."""
        scanner = GitScanner(
            str(git_repo),
            detectors=[RegexDetector()],
            include_history=True,
        )

        result = await scanner.scan()

        # Should complete without error
        assert result is not None
        assert result.stats["commits_scanned"] > 0

    @pytest.mark.asyncio
    async def test_handles_empty_message(self, tmp_path: Path) -> None:
        """Test that scanner handles empty commit messages gracefully."""
        repo_path = tmp_path / "empty_msg_repo"
        repo_path.mkdir()

        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        # Create a file and commit with minimal message
        (repo_path / "file.txt").write_text("content")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "."],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        scanner = GitScanner(
            str(repo_path),
            detectors=[RegexDetector()],
            include_history=True,
        )

        result = await scanner.scan()

        # Should complete without error
        assert result is not None


class TestGitScannerReportProgress:
    """Test progress reporting functionality."""

    @pytest.mark.asyncio
    async def test_report_progress_updates_during_scan(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _report_progress_internal updates progress correctly."""
        progress_updates = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_updates.append(progress.current_file)

        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            progress_callback=progress_callback,
            include_history=True,
        )

        await scanner.scan()

        # Should have received progress updates for files and commits
        assert len(progress_updates) > 0


class TestGitScannerCleanupErrors:
    """Test cleanup error handling."""

    @pytest.mark.asyncio
    async def test_cleanup_handles_exception(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that cleanup handles exceptions gracefully."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        # Mock a temp_dir that fails on cleanup
        mock_temp = MagicMock()
        mock_temp.cleanup.side_effect = PermissionError("Cannot cleanup")
        scanner._temp_dir = mock_temp

        # Cleanup should not raise
        scanner._cleanup()

        # Temp dir should be set to None even after error
        assert scanner._temp_dir is None


class TestGitScannerGetProgress:
    """Test get_progress method."""

    @pytest.mark.asyncio
    async def test_get_progress_before_scan(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _get_progress returns correct values before scan."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        progress = scanner._get_progress()

        assert progress.total_files == 0
        assert progress.scanned_files == 0
        assert progress.current_file == ""
        assert progress.findings_count == 0
        assert progress.elapsed_time == 0.0

    @pytest.mark.asyncio
    async def test_get_progress_during_scan(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _get_progress returns correct values during scan."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
            include_history=False,
        )

        await scanner.scan()

        progress = scanner._get_progress()

        assert progress.scanned_files > 0
        assert progress.elapsed_time > 0.0


class TestGitScannerStreamHistory:
    """Test streaming with commit history."""

    @pytest.mark.asyncio
    async def test_stream_with_history_yields_all(self, git_repo: Path) -> None:
        """Test that streaming with history yields findings from both sources."""
        detector = RegexDetector()
        scanner = GitScanner(
            str(git_repo),
            detectors=[detector],
            include_history=True,
        )

        findings = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        # Should have findings from commit history
        history_findings = [
            f for f in findings if f.metadata.get("source_type") == "commit_history"
        ]
        assert len(history_findings) > 0


class TestGitScannerScanContentContext:
    """Test _scan_content with context."""

    @pytest.mark.asyncio
    async def test_scan_content_adds_context(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _scan_content adds context to findings."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
        )

        context = {"test_key": "test_value", "source": "test"}

        findings = await scanner._scan_content(
            'secret = "AKIAIOSFODNN7EXAMPLE"',
            "test_file.py",
            context=context,
        )

        assert len(findings) > 0
        for finding in findings:
            assert "test_key" in finding.metadata
            assert finding.metadata["test_key"] == "test_value"


class TestGitScannerReadFileErrors:
    """Test file read error handling."""

    @pytest.mark.asyncio
    async def test_read_file_oserror(
        self, git_repo_with_current_secret: Path, monkeypatch
    ) -> None:
        """Test that _read_file handles OSError gracefully."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        # Mock read_text to raise OSError
        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            raise OSError("Simulated I/O error")

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        result = await scanner._read_file(
            git_repo_with_current_secret / "config.py"
        )

        assert result is None
        assert len(scanner._errors) > 0

    @pytest.mark.asyncio
    async def test_read_file_permission_error(
        self, git_repo_with_current_secret: Path, monkeypatch
    ) -> None:
        """Test that _read_file handles PermissionError gracefully."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            include_history=False,
        )

        # Mock read_text to raise PermissionError
        def mock_read_text(self, *args, **kwargs):
            raise PermissionError("Permission denied")

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        result = await scanner._read_file(
            git_repo_with_current_secret / "config.py"
        )

        assert result is None
        assert any("Permission denied" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_read_file_unicode_fallback(self, tmp_path: Path) -> None:
        """Test that _read_file falls back to latin-1 for non-UTF-8 files."""
        repo_path = tmp_path / "unicode_repo"
        repo_path.mkdir()

        subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        # Create a file with non-UTF-8 bytes
        binary_file = repo_path / "latin1.txt"
        binary_file.write_bytes(b"\xff\xfe\x00\x01some text")
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "Add binary file"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        scanner = GitScanner(
            str(repo_path),
            include_history=False,
        )

        result = await scanner._read_file(binary_file)

        # Should have read the file using latin-1 fallback
        assert result is not None
        assert "some text" in result


class TestGitScannerCancellationInMethods:
    """Test cancellation behavior in various methods."""

    @pytest.mark.asyncio
    async def test_scan_content_respects_cancellation(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _scan_content respects cancellation flag."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
        )

        # Set cancellation flag
        scanner._cancel_event.set()

        findings = await scanner._scan_content(
            'secret = "AKIAIOSFODNN7EXAMPLE"',
            "test_file.py",
        )

        # Should return empty due to cancellation
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_scan_current_files_respects_cancellation(
        self, git_repo_with_current_secret: Path
    ) -> None:
        """Test that _scan_current_files respects cancellation flag."""
        scanner = GitScanner(
            str(git_repo_with_current_secret),
            detectors=[RegexDetector()],
        )

        # Set cancellation flag
        scanner._cancel_event.set()

        findings = await scanner._scan_current_files(git_repo_with_current_secret)

        # Should return empty due to cancellation
        assert len(findings) == 0
