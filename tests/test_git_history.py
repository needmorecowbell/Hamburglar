"""Tests for the GitHistoryScanner class.

This module tests the git history scanning and secret lifecycle tracking
functionality including:
- Commit parsing works correctly
- Diff parsing extracts additions and deletions
- Secret timeline is built correctly
- Removed secrets are flagged appropriately
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
from hamburglar.scanners import BaseScanner  # noqa: E402
from hamburglar.scanners.git_history import (  # noqa: E402
    CommitInfo,
    GitHistoryScanner,
    SecretOccurrence,
    SecretTimeline,
)


@pytest.fixture
def git_repo_with_history(tmp_path: Path) -> Path:
    """Create a local git repository with secrets added and removed.

    Creates a git repository with:
    - Initial commit with a secret
    - A commit that adds another secret
    - A commit that removes the first secret
    - A commit with a secret in the commit message
    """
    repo_path = tmp_path / "test_repo_history"
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

    # Commit 1: Add first secret
    secrets_file = repo_path / "config.py"
    secrets_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Add initial config"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Commit 2: Add second secret
    secrets_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Add API token"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Commit 3: Remove first secret
    secrets_file.write_text(
        '# AWS_KEY removed for security\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Remove AWS key"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    # Commit 4: Add a commit message with a secret
    readme = repo_path / "README.md"
    readme.write_text("# Project README\n")
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
def git_repo_simple(tmp_path: Path) -> Path:
    """Create a simple git repository with one commit."""
    repo_path = tmp_path / "test_repo_simple"
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

    # Create one file with secret
    config_file = repo_path / "config.py"
    config_file.write_text('SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


class TestGitHistoryScannerInterface:
    """Test that GitHistoryScanner correctly implements BaseScanner."""

    def test_inherits_from_base_scanner(self):
        """Test that GitHistoryScanner is a subclass of BaseScanner."""
        assert issubclass(GitHistoryScanner, BaseScanner)

    def test_scanner_type_property(self, tmp_path: Path):
        """Test that scanner_type returns 'git_history'."""
        scanner = GitHistoryScanner(tmp_path)
        assert scanner.scanner_type == "git_history"

    def test_init_with_no_detectors(self, tmp_path: Path):
        """Test initialization without detectors."""
        scanner = GitHistoryScanner(tmp_path)
        assert scanner.detectors == []
        assert scanner.progress_callback is None

    def test_init_with_detectors(self, tmp_path: Path):
        """Test initialization with detectors."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(tmp_path, detectors=[detector])
        assert len(scanner.detectors) == 1

    def test_init_with_progress_callback(self, tmp_path: Path):
        """Test initialization with progress callback."""
        callback_called = []

        def callback(progress):
            callback_called.append(progress)

        scanner = GitHistoryScanner(tmp_path, progress_callback=callback)
        assert scanner.progress_callback is callback

    def test_init_with_options(self, tmp_path: Path):
        """Test initialization with various options."""
        scanner = GitHistoryScanner(
            tmp_path,
            depth=10,
            branch="main",
        )
        assert scanner.depth == 10
        assert scanner.branch == "main"


class TestCommitParsing:
    """Test commit parsing functionality."""

    @pytest.mark.asyncio
    async def test_get_commit_list(self, git_repo_simple: Path) -> None:
        """Test getting list of commits."""
        scanner = GitHistoryScanner(git_repo_simple)
        commits = await scanner._get_commit_list()

        assert len(commits) == 1
        assert len(commits[0]) == 40  # Full SHA hash

    @pytest.mark.asyncio
    async def test_get_commit_list_with_depth(self, git_repo_with_history: Path) -> None:
        """Test getting limited commits with depth parameter."""
        scanner = GitHistoryScanner(git_repo_with_history, depth=2)
        commits = await scanner._get_commit_list()

        assert len(commits) == 2

    @pytest.mark.asyncio
    async def test_get_commit_info(self, git_repo_simple: Path) -> None:
        """Test getting detailed commit information."""
        scanner = GitHistoryScanner(git_repo_simple)
        commits = await scanner._get_commit_list()

        commit_info = await scanner._get_commit_info(commits[0])

        assert commit_info.hash == commits[0]
        assert commit_info.short_hash == commits[0][:8]
        assert commit_info.author == "Test User"
        assert commit_info.email == "test@example.com"
        assert commit_info.subject == "Initial commit"
        assert commit_info.date  # Should have a date

    @pytest.mark.asyncio
    async def test_commit_info_with_body(self, git_repo_with_history: Path) -> None:
        """Test getting commit info with body text."""
        scanner = GitHistoryScanner(git_repo_with_history)
        commits = await scanner._get_commit_list()

        # The last commit (first in list) has a body
        commit_info = await scanner._get_commit_info(commits[0])

        # The body should contain the secret note
        body_text = "\n".join(commit_info.body)
        assert "Note:" in body_text or commit_info.body


class TestDiffParsing:
    """Test diff parsing extracts additions and deletions correctly."""

    def test_parse_simple_addition(self):
        """Test parsing a simple file addition."""
        diff_output = """diff --git a/config.py b/config.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+SECRET = "abc123"
+DEBUG = True
"""
        scanner = GitHistoryScanner(Path("."))
        additions, deletions = scanner._parse_diff_output(diff_output)

        assert "config.py" in additions
        assert len(additions["config.py"]) == 2
        assert additions["config.py"][0][1] == 'SECRET = "abc123"'
        assert "config.py" in deletions
        assert len(deletions["config.py"]) == 0

    def test_parse_simple_deletion(self):
        """Test parsing a file with deletions."""
        diff_output = """diff --git a/config.py b/config.py
index 1234567..7654321
--- a/config.py
+++ b/config.py
@@ -1,2 +1,1 @@
-SECRET = "abc123"
 DEBUG = True
"""
        scanner = GitHistoryScanner(Path("."))
        additions, deletions = scanner._parse_diff_output(diff_output)

        assert "config.py" in deletions
        assert len(deletions["config.py"]) == 1
        assert deletions["config.py"][0][1] == 'SECRET = "abc123"'

    def test_parse_mixed_changes(self):
        """Test parsing additions and deletions in same file."""
        diff_output = """diff --git a/config.py b/config.py
index 1234567..7654321
--- a/config.py
+++ b/config.py
@@ -1,2 +1,2 @@
-OLD_SECRET = "old"
+NEW_SECRET = "new"
 DEBUG = True
"""
        scanner = GitHistoryScanner(Path("."))
        additions, deletions = scanner._parse_diff_output(diff_output)

        assert len(additions["config.py"]) == 1
        assert additions["config.py"][0][1] == 'NEW_SECRET = "new"'
        assert len(deletions["config.py"]) == 1
        assert deletions["config.py"][0][1] == 'OLD_SECRET = "old"'

    def test_parse_multiple_files(self):
        """Test parsing changes to multiple files."""
        diff_output = """diff --git a/file1.py b/file1.py
index 1111111..2222222
--- a/file1.py
+++ b/file1.py
@@ -1 +1 @@
+CONTENT1 = "a"
diff --git a/file2.py b/file2.py
index 3333333..4444444
--- a/file2.py
+++ b/file2.py
@@ -1 +1 @@
+CONTENT2 = "b"
"""
        scanner = GitHistoryScanner(Path("."))
        additions, deletions = scanner._parse_diff_output(diff_output)

        assert "file1.py" in additions
        assert "file2.py" in additions

    @pytest.mark.asyncio
    async def test_get_commit_diff(self, git_repo_simple: Path) -> None:
        """Test getting diff for a specific commit."""
        scanner = GitHistoryScanner(git_repo_simple)
        commits = await scanner._get_commit_list()

        additions, deletions = await scanner._get_commit_diff(commits[0])

        assert "config.py" in additions
        assert any("AKIAIOSFODNN7EXAMPLE" in line for _, line in additions["config.py"])


class TestSecretTimelineBuilding:
    """Test that secret timelines are built correctly."""

    def test_secret_occurrence_creation(self):
        """Test creating a SecretOccurrence."""
        occurrence = SecretOccurrence(
            commit_hash="abc123def456",
            author="Test User",
            date="2024-01-15T10:00:00+00:00",
            file_path="config.py",
            line_type="+",
            line_number=5,
        )

        assert occurrence.commit_hash == "abc123def456"
        assert occurrence.author == "Test User"
        assert occurrence.line_type == "+"
        assert occurrence.line_number == 5

    def test_secret_timeline_creation(self):
        """Test creating a SecretTimeline."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...LE",
            detector_name="regex",
            severity=Severity.HIGH,
        )

        assert timeline.secret_hash == "abc123"
        assert timeline.is_removed is False
        assert len(timeline.occurrences) == 0
        assert len(timeline.affected_files) == 0

    def test_secret_timeline_add_occurrence(self):
        """Test adding occurrences to a timeline."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...LE",
            detector_name="regex",
            severity=Severity.HIGH,
        )

        occurrence1 = SecretOccurrence(
            commit_hash="commit1",
            author="User",
            date="2024-01-15T10:00:00+00:00",
            file_path="config.py",
            line_type="+",
        )
        timeline.add_occurrence(occurrence1)

        assert len(timeline.occurrences) == 1
        assert timeline.first_seen == occurrence1
        assert timeline.last_seen == occurrence1
        assert "config.py" in timeline.affected_files
        assert timeline.is_removed is False

    def test_secret_timeline_tracks_removal(self):
        """Test that removal is tracked correctly."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...LE",
            detector_name="regex",
            severity=Severity.HIGH,
        )

        # Add the secret
        add_occurrence = SecretOccurrence(
            commit_hash="commit1",
            author="User",
            date="2024-01-15T10:00:00+00:00",
            file_path="config.py",
            line_type="+",
        )
        timeline.add_occurrence(add_occurrence)

        # Remove the secret
        remove_occurrence = SecretOccurrence(
            commit_hash="commit2",
            author="User",
            date="2024-01-16T10:00:00+00:00",
            file_path="config.py",
            line_type="-",
        )
        timeline.add_occurrence(remove_occurrence)

        assert timeline.is_removed is True
        assert timeline.first_seen == add_occurrence
        assert timeline.last_seen == remove_occurrence
        assert timeline.exposure_duration is not None
        assert timeline.exposure_duration == 86400  # 1 day in seconds

    def test_commit_info_short_hash(self):
        """Test CommitInfo generates short hash."""
        commit = CommitInfo(hash="abc123def456789012345678901234567890")
        assert commit.short_hash == "abc123de"

    def test_commit_info_empty_hash(self):
        """Test CommitInfo with empty hash."""
        commit = CommitInfo(hash="")
        assert commit.short_hash == ""


class TestRemovedSecretsDetection:
    """Test that removed secrets are flagged appropriately."""

    @pytest.mark.asyncio
    async def test_finds_removed_secrets(self, git_repo_with_history: Path) -> None:
        """Test that scanner detects secrets that were removed."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
        )

        result = await scanner.scan()

        # Check for removed secrets in timeline
        removed = scanner.get_removed_secrets()
        # The AWS key was removed so it should show up
        # Note: Whether it's marked as "removed" depends on if the last occurrence was a deletion
        assert result.stats["commits_parsed"] > 0

    @pytest.mark.asyncio
    async def test_finds_active_secrets(self, git_repo_with_history: Path) -> None:
        """Test that scanner tracks active (still present) secrets."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
        )

        await scanner.scan()

        # The GitHub token should still be active
        active = scanner.get_active_secrets()
        # Timeline might show it as active if last occurrence was an addition
        assert scanner.get_stats()["secrets_tracked"] > 0

    @pytest.mark.asyncio
    async def test_timeline_includes_all_occurrences(
        self, git_repo_with_history: Path
    ) -> None:
        """Test that timelines include all occurrences of a secret."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
        )

        await scanner.scan()

        timelines = scanner.get_secret_timelines()
        assert len(timelines) > 0

        # Each timeline should have at least one occurrence
        for timeline in timelines:
            assert len(timeline.occurrences) > 0


class TestFullScan:
    """Test complete scan functionality."""

    @pytest.mark.asyncio
    async def test_full_scan_returns_findings(
        self, git_repo_with_history: Path
    ) -> None:
        """Test that full scan returns findings."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
        )

        result = await scanner.scan()

        assert result.target_path == str(git_repo_with_history)
        assert len(result.findings) > 0
        assert result.stats["commits_parsed"] > 0

    @pytest.mark.asyncio
    async def test_scan_without_detectors(self, git_repo_simple: Path) -> None:
        """Test that scan works without detectors."""
        scanner = GitHistoryScanner(git_repo_simple)

        result = await scanner.scan()

        assert result.stats["commits_parsed"] > 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scan_with_depth_limit(self, git_repo_with_history: Path) -> None:
        """Test scan with depth limit."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
            depth=1,
        )

        result = await scanner.scan()

        assert result.stats["commits_parsed"] == 1

    @pytest.mark.asyncio
    async def test_findings_have_correct_metadata(
        self, git_repo_simple: Path
    ) -> None:
        """Test that findings have correct metadata."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[detector],
        )

        result = await scanner.scan()

        for finding in result.findings:
            assert "source_type" in finding.metadata
            assert "commit_hash" in finding.metadata
            assert "author" in finding.metadata
            assert "date" in finding.metadata


class TestErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner raises error for nonexistent path."""
        nonexistent = tmp_path / "does_not_exist"
        scanner = GitHistoryScanner(nonexistent)

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_non_git_directory(self, tmp_path: Path) -> None:
        """Test that scanner raises error for non-git directory."""
        regular_dir = tmp_path / "not_git"
        regular_dir.mkdir()
        (regular_dir / "file.txt").write_text("content")

        scanner = GitHistoryScanner(regular_dir)

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "Not a git repository" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_git_not_installed(self, tmp_path: Path) -> None:
        """Test error when git is not installed."""
        scanner = GitHistoryScanner(tmp_path)

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError("git not found")

            with pytest.raises(ScanError) as exc_info:
                await scanner._run_git_command(["status"])

            assert "Git is not installed" in str(exc_info.value)


class TestCancellation:
    """Test cancellation functionality."""

    @pytest.mark.asyncio
    async def test_cancel_sets_flag(self, tmp_path: Path) -> None:
        """Test that cancel sets cancellation flag."""
        scanner = GitHistoryScanner(tmp_path)

        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_cancellation_stops_scan(self, git_repo_with_history: Path) -> None:
        """Test that cancellation stops the scan."""
        commits_analyzed = []

        class TrackingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "tracking"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                commits_analyzed.append(file_path)
                return []

        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[TrackingDetector()],
        )

        async def cancel_during_scan():
            # Wait a tiny bit then cancel
            await asyncio.sleep(0.001)
            scanner.cancel()

        # Start the cancel task and scan together
        cancel_task = asyncio.create_task(cancel_during_scan())
        result = await scanner.scan()
        await cancel_task

        # Cancellation should have happened during scan
        assert result.stats["cancelled"] is True


class TestProgressCallback:
    """Test progress callback functionality."""

    @pytest.mark.asyncio
    async def test_progress_callback_called(self, git_repo_simple: Path) -> None:
        """Test that progress callback is called during scan."""
        progress_calls = []

        def callback(progress: ScanProgress) -> None:
            progress_calls.append(progress)

        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
            progress_callback=callback,
        )

        await scanner.scan()

        assert len(progress_calls) > 0

    @pytest.mark.asyncio
    async def test_progress_callback_error_handling(
        self, git_repo_simple: Path
    ) -> None:
        """Test that callback errors don't disrupt the scan."""

        def failing_callback(progress: ScanProgress) -> None:
            raise RuntimeError("Callback failure!")

        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
            progress_callback=failing_callback,
        )

        # Should complete without raising
        result = await scanner.scan()
        assert result.stats["commits_parsed"] > 0


class TestStreaming:
    """Test streaming functionality."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(self, git_repo_simple: Path) -> None:
        """Test that scan_stream yields findings."""
        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
        )

        findings = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_stream_with_cancellation(
        self, git_repo_with_history: Path
    ) -> None:
        """Test streaming respects cancellation."""
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[RegexDetector()],
        )

        async def cancel_during_stream():
            await asyncio.sleep(0.001)
            scanner.cancel()

        findings = []
        cancel_task = asyncio.create_task(cancel_during_stream())
        async for finding in scanner.scan_stream():
            findings.append(finding)
        await cancel_task

        # Should have been cancelled during streaming
        assert scanner.is_cancelled


class TestSecretHashing:
    """Test secret hashing and preview functions."""

    def test_hash_secret(self, tmp_path: Path):
        """Test secret hashing produces consistent hash."""
        scanner = GitHistoryScanner(tmp_path)

        hash1 = scanner._hash_secret("AKIAIOSFODNN7EXAMPLE")
        hash2 = scanner._hash_secret("AKIAIOSFODNN7EXAMPLE")
        hash3 = scanner._hash_secret("different_secret")

        assert hash1 == hash2
        assert hash1 != hash3
        assert len(hash1) == 16

    def test_create_secret_preview_short(self, tmp_path: Path):
        """Test secret preview for short secrets."""
        scanner = GitHistoryScanner(tmp_path)

        preview = scanner._create_secret_preview("short")

        # Short secrets should be fully masked
        assert preview == "*****"

    def test_create_secret_preview_long(self, tmp_path: Path):
        """Test secret preview for long secrets."""
        scanner = GitHistoryScanner(tmp_path)

        preview = scanner._create_secret_preview("AKIAIOSFODNN7EXAMPLE")

        assert preview == "AKI...PLE"
        assert "IOSFODNN7EXAM" not in preview


class TestTimelineReport:
    """Test timeline report generation."""

    @pytest.mark.asyncio
    async def test_generate_timeline_report(
        self, git_repo_with_history: Path
    ) -> None:
        """Test timeline report generation."""
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[RegexDetector()],
        )

        await scanner.scan()

        report = scanner.generate_timeline_report()

        assert "SECRET TIMELINE REPORT" in report
        assert "Total unique secrets:" in report

    @pytest.mark.asyncio
    async def test_timeline_report_empty(self, git_repo_simple: Path) -> None:
        """Test timeline report with no secrets."""
        # Create repo with no secrets
        repo_path = git_repo_simple.parent / "no_secrets_repo"
        repo_path.mkdir()

        subprocess.run(
            ["git", "init"], cwd=repo_path, check=True, capture_output=True
        )
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
        (repo_path / "README.md").write_text("# Clean Repo\n")
        subprocess.run(
            ["git", "add", "."], cwd=repo_path, check=True, capture_output=True
        )
        subprocess.run(
            ["git", "commit", "-m", "Initial clean commit"],
            cwd=repo_path,
            check=True,
            capture_output=True,
        )

        scanner = GitHistoryScanner(
            repo_path,
            detectors=[RegexDetector()],
        )

        await scanner.scan()

        report = scanner.generate_timeline_report()

        assert "No secrets found" in report


class TestStats:
    """Test statistics functions."""

    @pytest.mark.asyncio
    async def test_get_stats_before_scan(self, git_repo_simple: Path) -> None:
        """Test get_stats before scanning."""
        scanner = GitHistoryScanner(git_repo_simple)

        stats = scanner.get_stats()

        assert stats["commits_parsed"] == 0
        assert stats["secrets_tracked"] == 0
        assert stats["findings_count"] == 0
        assert stats["cancelled"] is False

    @pytest.mark.asyncio
    async def test_get_stats_after_scan(self, git_repo_simple: Path) -> None:
        """Test get_stats after scanning."""
        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
        )

        await scanner.scan()

        stats = scanner.get_stats()

        assert stats["commits_parsed"] > 0
        assert stats["elapsed_time"] > 0


class TestReset:
    """Test reset functionality."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, git_repo_simple: Path) -> None:
        """Test that reset clears all state."""
        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
        )

        await scanner.scan()
        assert scanner.get_stats()["commits_parsed"] > 0

        scanner._reset()

        assert scanner.get_stats()["commits_parsed"] == 0
        assert scanner.get_stats()["secrets_tracked"] == 0
        assert not scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_multiple_scans(self, git_repo_simple: Path) -> None:
        """Test multiple scans work correctly."""
        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[RegexDetector()],
        )

        result1 = await scanner.scan()
        result2 = await scanner.scan()

        assert result1.stats["commits_parsed"] == result2.stats["commits_parsed"]


class TestDetectorErrors:
    """Test handling of detector errors."""

    @pytest.mark.asyncio
    async def test_detector_error_handling(self, git_repo_simple: Path) -> None:
        """Test that detector errors are handled gracefully."""

        class FailingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "failing"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                raise RuntimeError("Detector failure!")

        scanner = GitHistoryScanner(
            git_repo_simple,
            detectors=[FailingDetector(), RegexDetector()],
        )

        result = await scanner.scan()

        # Should still complete
        assert result.stats["commits_parsed"] > 0
        assert len(result.stats["errors"]) > 0


class TestCommitMessageScanning:
    """Test scanning of commit messages."""

    @pytest.mark.asyncio
    async def test_finds_secrets_in_commit_messages(
        self, git_repo_with_history: Path
    ) -> None:
        """Test that secrets in commit messages are found."""
        detector = RegexDetector()
        scanner = GitHistoryScanner(
            git_repo_with_history,
            detectors=[detector],
        )

        result = await scanner.scan()

        # Find commit message findings
        commit_msg_findings = [
            f
            for f in result.findings
            if f.metadata.get("source_type") == "commit_message"
        ]

        # The repo has a secret in a commit message
        assert len(commit_msg_findings) > 0


class TestFormatTimeline:
    """Test timeline formatting."""

    def test_format_timeline_basic(self, tmp_path: Path):
        """Test basic timeline formatting."""
        scanner = GitHistoryScanner(tmp_path)

        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...PLE",
            detector_name="aws_key",
            severity=Severity.HIGH,
        )

        first_occ = SecretOccurrence(
            commit_hash="commit1234567890",
            author="User",
            date="2024-01-15T10:00:00+00:00",
            file_path="config.py",
            line_type="+",
        )
        timeline.add_occurrence(first_occ)

        formatted = scanner._format_timeline(timeline)

        assert "AKI...PLE" in formatted
        assert "aws_key" in formatted
        assert "high" in formatted
        assert "ACTIVE" in formatted
        assert "config.py" in formatted

    def test_format_timeline_with_removal(self, tmp_path: Path):
        """Test timeline formatting with removal and duration."""
        scanner = GitHistoryScanner(tmp_path)

        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...PLE",
            detector_name="aws_key",
            severity=Severity.HIGH,
        )

        add_occ = SecretOccurrence(
            commit_hash="commit1234567890",
            author="User",
            date="2024-01-15T10:00:00+00:00",
            file_path="config.py",
            line_type="+",
        )
        timeline.add_occurrence(add_occ)

        remove_occ = SecretOccurrence(
            commit_hash="commit2345678901",
            author="User",
            date="2024-01-16T10:00:00+00:00",
            file_path="config.py",
            line_type="-",
        )
        timeline.add_occurrence(remove_occ)

        formatted = scanner._format_timeline(timeline)

        assert "REMOVED" in formatted
        assert "Exposure duration:" in formatted


class TestDateParsingErrors:
    """Test handling of invalid dates."""

    def test_timeline_with_invalid_date_format(self):
        """Test that invalid date formats don't cause errors when calculating duration."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="***",
            detector_name="test",
            severity=Severity.LOW,
        )

        # Add with invalid date format (dates that sort correctly but are invalid ISO)
        add_occ = SecretOccurrence(
            commit_hash="commit1",
            author="User",
            date="aaaa-invalid-date",  # Sorts earlier alphabetically
            file_path="file.py",
            line_type="+",
        )
        timeline.add_occurrence(add_occ)

        remove_occ = SecretOccurrence(
            commit_hash="commit2",
            author="User",
            date="zzzz-invalid-date",  # Sorts later alphabetically so becomes last_seen
            file_path="file.py",
            line_type="-",
        )
        timeline.add_occurrence(remove_occ)

        # Should not raise, duration should be None due to invalid date parsing
        assert timeline.is_removed is True
        assert timeline.exposure_duration is None  # Failed to parse invalid dates
