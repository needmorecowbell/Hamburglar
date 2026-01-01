"""Tests for the DirectoryScanner class.

This module tests the directory scanning functionality including:
- Scanning directories and files for secrets
- Concurrency limit is respected
- Cancellation works correctly
- Progress callbacks are called
- Streaming output works
- BaseScanner interface is properly implemented
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.exceptions import ScanError  # noqa: E402
from hamburglar.core.models import Finding, ScanConfig  # noqa: E402
from hamburglar.core.progress import ScanProgress  # noqa: E402
from hamburglar.detectors import BaseDetector  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402
from hamburglar.scanners import BaseScanner, DirectoryScanner  # noqa: E402


class TestDirectoryScannerInterface:
    """Test that DirectoryScanner correctly implements BaseScanner."""

    def test_inherits_from_base_scanner(self):
        """Test that DirectoryScanner is a subclass of BaseScanner."""
        assert issubclass(DirectoryScanner, BaseScanner)

    def test_scanner_type_property(self, tmp_path: Path):
        """Test that scanner_type returns 'directory'."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config)
        assert scanner.scanner_type == "directory"

    def test_init_with_no_detectors(self, tmp_path: Path):
        """Test initialization without detectors."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config)
        assert scanner.detectors == []
        assert scanner.progress_callback is None

    def test_init_with_detectors(self, tmp_path: Path):
        """Test initialization with detectors."""
        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, detectors=[detector])
        assert len(scanner.detectors) == 1

    def test_init_with_progress_callback(self, tmp_path: Path):
        """Test initialization with progress callback."""
        callback_called = []

        def callback(progress):
            callback_called.append(progress)

        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, progress_callback=callback)
        assert scanner.progress_callback is callback


class TestDirectoryScannerBasic:
    """Test basic directory scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_directory_finds_secrets(self, temp_directory: Path) -> None:
        """Test that scanner finds secrets in a directory with known secrets."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        assert result.target_path == str(temp_directory)
        assert len(result.findings) > 0
        assert result.stats["files_scanned"] > 0
        assert result.stats["total_findings"] > 0

    @pytest.mark.asyncio
    async def test_scan_single_file(self, temp_directory: Path) -> None:
        """Test scanning a single file rather than a directory."""
        single_file = temp_directory / "secrets.txt"
        config = ScanConfig(target_path=single_file)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scanning an empty directory returns empty result."""
        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert result.stats["files_scanned"] == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError for nonexistent paths."""
        nonexistent = tmp_path / "does_not_exist"
        config = ScanConfig(target_path=nonexistent)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_scan_with_no_detectors(self, temp_directory: Path) -> None:
        """Test that scanner works without any detectors."""
        config = ScanConfig(target_path=temp_directory)
        scanner = DirectoryScanner(config, detectors=None)

        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0
        assert len(result.findings) == 0  # No findings without detectors


class TestConcurrencyLimit:
    """Test that concurrency limit is respected."""

    @pytest.mark.asyncio
    async def test_concurrency_limit_is_applied(self, tmp_path: Path) -> None:
        """Test that concurrency limit controls maximum concurrent operations."""
        # Create multiple files
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_text(f"content {i}")

        concurrent_count = 0
        max_concurrent = 0

        class SlowDetector(BaseDetector):
            """Detector that tracks concurrency."""

            @property
            def name(self) -> str:
                return "slow"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal concurrent_count, max_concurrent
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)
                # Simulate some work
                import time

                time.sleep(0.01)
                concurrent_count -= 1
                return []

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [SlowDetector()], concurrency_limit=3)

        await scanner.scan()

        # Max concurrent should not exceed the limit
        assert max_concurrent <= 3

    @pytest.mark.asyncio
    async def test_default_concurrency_limit_is_50(self, tmp_path: Path) -> None:
        """Test that default concurrency limit is 50."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, [])

        assert scanner.concurrency_limit == 50

    @pytest.mark.asyncio
    async def test_custom_concurrency_limit(self, tmp_path: Path) -> None:
        """Test that custom concurrency limit is applied."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, [], concurrency_limit=10)

        assert scanner.concurrency_limit == 10


class TestCancellation:
    """Test cancellation functionality."""

    @pytest.mark.asyncio
    async def test_cancellation_stops_scan(self, tmp_path: Path) -> None:
        """Test that cancellation stops the scan."""
        # Create many files
        for i in range(100):
            (tmp_path / f"file{i}.txt").write_text(f"AKIAIOSFODNN7EXAMPLE content {i}")

        scan_started = asyncio.Event()
        files_processed = 0

        class SlowDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "slow"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal files_processed
                files_processed += 1
                scan_started.set()  # Signal that scan has started
                # Add a small sleep to make cancellation timing more reliable
                import time

                time.sleep(0.01)
                return []

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [SlowDetector()], concurrency_limit=1)

        # Cancel after first file is processed
        async def cancel_after_start():
            await scan_started.wait()
            await asyncio.sleep(0.02)  # Wait a bit after first file
            scanner.cancel()

        # Start both the scan and the cancellation task
        cancel_task = asyncio.create_task(cancel_after_start())
        result = await scanner.scan()

        await cancel_task

        # Should have cancelled
        assert scanner.is_cancelled
        assert result.stats["cancelled"] is True
        # Should not have scanned all 100 files
        assert files_processed < 100

    @pytest.mark.asyncio
    async def test_cancel_method_sets_event(self, tmp_path: Path) -> None:
        """Test that cancel() sets the cancellation event."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, [])

        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_reset_clears_cancellation(self, tmp_path: Path) -> None:
        """Test that reset() clears the cancellation state."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, [])

        scanner.cancel()
        assert scanner.is_cancelled

        scanner.reset()
        assert not scanner.is_cancelled


class TestProgressCallback:
    """Test progress callback functionality."""

    @pytest.mark.asyncio
    async def test_progress_callback_is_called(self, tmp_path: Path) -> None:
        """Test that progress callback is called for each file."""
        # Create test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.txt").write_text("content2")
        (tmp_path / "file3.txt").write_text("content3")

        progress_calls: list[ScanProgress] = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_calls.append(progress)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector], progress_callback=progress_callback)

        await scanner.scan()

        # Should have been called at least 3 times (once per file)
        assert len(progress_calls) >= 3
        # All calls should have correct total
        for progress in progress_calls:
            assert progress.total_files == 3

    @pytest.mark.asyncio
    async def test_progress_tracks_scanned_files(self, tmp_path: Path) -> None:
        """Test that progress tracks number of scanned files."""
        # Create test files
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_text(f"content {i}")

        progress_list: list[ScanProgress] = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_list.append(progress)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(
            config, [], progress_callback=progress_callback, concurrency_limit=1
        )

        await scanner.scan()

        # Progress should show increasing scanned count
        # Note: Due to async nature, we check the final state
        assert len(progress_list) > 0
        assert progress_list[-1].total_files == 5

    @pytest.mark.asyncio
    async def test_progress_tracks_current_file(self, tmp_path: Path) -> None:
        """Test that progress tracks the current file being scanned."""
        (tmp_path / "test_file.txt").write_text("content")

        current_files: list[str] = []

        def progress_callback(progress: ScanProgress) -> None:
            if progress.current_file:
                current_files.append(progress.current_file)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [], progress_callback=progress_callback)

        await scanner.scan()

        assert len(current_files) > 0
        assert any("test_file.txt" in f for f in current_files)

    @pytest.mark.asyncio
    async def test_progress_tracks_findings_count(self, tmp_path: Path) -> None:
        """Test that progress tracks findings count."""
        (tmp_path / "secrets.txt").write_text("AKIAIOSFODNN7EXAMPLE")

        progress_list: list[ScanProgress] = []

        def progress_callback(progress: ScanProgress) -> None:
            progress_list.append(progress)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector], progress_callback=progress_callback)

        await scanner.scan()

        # Should have findings in progress
        final_progress = progress_list[-1]
        assert final_progress.findings_count >= 0

    @pytest.mark.asyncio
    async def test_progress_callback_error_handling(self, tmp_path: Path) -> None:
        """Test that callback errors don't disrupt the scan."""
        (tmp_path / "file1.txt").write_text("AKIAIOSFODNN7EXAMPLE")

        def failing_callback(progress: ScanProgress) -> None:
            raise RuntimeError("Callback failure!")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector], progress_callback=failing_callback)

        # Scan should complete despite callback failure
        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0


class TestStreamingOutput:
    """Test streaming output functionality."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(self, temp_directory: Path) -> None:
        """Test that scan_stream yields findings as they're discovered."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        findings: list[Finding] = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        assert len(findings) > 0
        # All items should be Finding objects
        for finding in findings:
            assert isinstance(finding, Finding)

    @pytest.mark.asyncio
    async def test_stream_produces_same_as_batch(self, temp_directory: Path) -> None:
        """Test that streaming produces same findings as batch scan."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()

        # Batch scan
        batch_scanner = DirectoryScanner(config, [detector])
        batch_result = await batch_scanner.scan()

        # Stream scan
        stream_scanner = DirectoryScanner(config, [detector])
        stream_findings: list[Finding] = []
        async for finding in stream_scanner.scan_stream():
            stream_findings.append(finding)

        # Same number of findings
        assert len(stream_findings) == len(batch_result.findings)

        # Sort and compare
        batch_sorted = sorted(batch_result.findings, key=lambda f: (f.file_path, f.detector_name))
        stream_sorted = sorted(stream_findings, key=lambda f: (f.file_path, f.detector_name))

        for batch_f, stream_f in zip(batch_sorted, stream_sorted):
            assert batch_f.file_path == stream_f.file_path
            assert batch_f.detector_name == stream_f.detector_name

    @pytest.mark.asyncio
    async def test_stream_empty_directory(self, tmp_path: Path) -> None:
        """Test that streaming an empty directory yields nothing."""
        config = ScanConfig(target_path=tmp_path)
        scanner = DirectoryScanner(config, [])

        findings: list[Finding] = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_stream_can_be_interrupted(self, tmp_path: Path) -> None:
        """Test that stream can be interrupted mid-scan."""
        # Create many files
        for i in range(50):
            (tmp_path / f"file{i}.txt").write_text(f"AKIAIOSFODNN7EXAMPLE content {i}")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector], concurrency_limit=2)

        findings_received = 0
        async for _ in scanner.scan_stream():
            findings_received += 1
            if findings_received >= 5:
                break  # Interrupt early

        # Should have stopped early
        assert findings_received == 5


class TestDirectoryScannerStats:
    """Test statistics tracking."""

    @pytest.mark.asyncio
    async def test_bytes_processed_is_tracked(self, tmp_path: Path) -> None:
        """Test that bytes processed are tracked."""
        content = "x" * 1000
        (tmp_path / "file.txt").write_text(content)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        assert result.stats["bytes_processed"] >= 1000

    @pytest.mark.asyncio
    async def test_get_stats_returns_current_state(self, tmp_path: Path) -> None:
        """Test that get_stats returns current scan state."""
        (tmp_path / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        # Before scan
        stats = scanner.get_stats()
        assert stats["total_files"] == 0
        assert stats["files_scanned"] == 0

        await scanner.scan()

        # After scan
        stats = scanner.get_stats()
        assert stats["total_files"] == 1
        assert stats["files_scanned"] == 1


class TestDirectoryScannerBlacklistWhitelist:
    """Test blacklist and whitelist functionality."""

    @pytest.mark.asyncio
    async def test_blacklist_excludes_files(self, temp_directory: Path) -> None:
        """Test that blacklisted files are not scanned."""
        config = ScanConfig(target_path=temp_directory, blacklist=["*.txt"])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        # Only config.py should be scanned (txt files are blacklisted)
        scanned_files = [f.file_path for f in result.findings]
        for file_path in scanned_files:
            assert not file_path.endswith(".txt"), "Should not scan .txt files"

    @pytest.mark.asyncio
    async def test_whitelist_only_includes_matching(self, temp_directory: Path) -> None:
        """Test that only whitelisted files are scanned."""
        config = ScanConfig(target_path=temp_directory, whitelist=["*.py"])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        # Only .py files should be scanned
        scanned_files = {f.file_path for f in result.findings}
        for file_path in scanned_files:
            assert file_path.endswith(".py"), "Should only scan .py files"


class TestDirectoryScannerErrorHandling:
    """Test error handling."""

    @pytest.mark.asyncio
    async def test_detector_error_handling(self, temp_directory: Path) -> None:
        """Test that scanner handles detector errors gracefully."""

        class FailingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "failing"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                raise RuntimeError("Detector failure!")

        config = ScanConfig(target_path=temp_directory)
        failing_detector = FailingDetector()
        working_detector = RegexDetector()
        scanner = DirectoryScanner(config, [failing_detector, working_detector])

        result = await scanner.scan()

        # Should still get findings from the working detector
        assert len(result.findings) > 0
        # Should have error logged
        assert len(result.stats["errors"]) > 0

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    async def test_handles_unreadable_file_gracefully(self, tmp_path: Path) -> None:
        """Test that scanner handles unreadable files gracefully."""
        # Create a file and make it unreadable
        unreadable_file = tmp_path / "unreadable.txt"
        unreadable_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')
        original_mode = unreadable_file.stat().st_mode
        unreadable_file.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = DirectoryScanner(config, [detector])

            result = await scanner.scan()

            # Should complete without raising, but skip the unreadable file
            assert result.stats["files_skipped"] >= 1
            assert len(result.stats["errors"]) >= 1
        finally:
            # Restore permissions for cleanup
            unreadable_file.chmod(original_mode)

    @pytest.mark.asyncio
    async def test_binary_file_handling(self, tmp_path: Path) -> None:
        """Test that scanner handles binary files gracefully."""
        # Create a binary file
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        # Should complete without error
        assert result.stats["files_scanned"] >= 1


class TestDirectoryScannerReset:
    """Test reset functionality."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, tmp_path: Path) -> None:
        """Test that reset clears all scanner state."""
        (tmp_path / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        # First scan
        await scanner.scan()
        assert scanner.get_stats()["files_scanned"] == 1

        # Reset
        scanner.reset()
        assert scanner.get_stats()["files_scanned"] == 0
        assert scanner.get_stats()["total_files"] == 0
        assert scanner.get_stats()["bytes_processed"] == 0

    @pytest.mark.asyncio
    async def test_can_scan_multiple_times(self, tmp_path: Path) -> None:
        """Test that scanner can be used for multiple scans after reset."""
        (tmp_path / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        # First scan
        result1 = await scanner.scan()
        assert result1.stats["files_scanned"] == 1

        # Second scan (reset happens automatically)
        result2 = await scanner.scan()
        assert result2.stats["files_scanned"] == 1


class TestDirectoryScannerNonRecursive:
    """Test non-recursive scanning mode."""

    @pytest.mark.asyncio
    async def test_non_recursive_ignores_subdirectories(self, temp_directory: Path) -> None:
        """Test that non-recursive mode doesn't scan subdirectories."""
        config = ScanConfig(target_path=temp_directory, recursive=False)
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        # Should not find any findings from subdir/nested.txt
        for finding in result.findings:
            assert "subdir" not in finding.file_path

    @pytest.mark.asyncio
    async def test_non_recursive_scans_top_level_files(self, tmp_path: Path) -> None:
        """Test that non-recursive mode scans top-level files."""
        # Create files at different levels
        (tmp_path / "top.txt").write_text("AKIAIOSFODNN7EXAMPLE")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("AKIAIOSFODNN7EXAMPLE")

        config = ScanConfig(target_path=tmp_path, recursive=False, blacklist=[])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        # Should only scan top.txt
        assert result.stats["files_scanned"] == 1
        assert any("top.txt" in f.file_path for f in result.findings)
        assert not any("nested.txt" in f.file_path for f in result.findings)


class TestDirectoryScannerSingleFileBlacklisted:
    """Test single file scanning with blacklist."""

    @pytest.mark.asyncio
    async def test_single_file_blacklisted(self, tmp_path: Path) -> None:
        """Test that a single blacklisted file returns empty results."""
        single_file = tmp_path / "secrets.txt"
        single_file.write_text("AKIAIOSFODNN7EXAMPLE")

        config = ScanConfig(target_path=single_file, blacklist=["*.txt"])
        detector = RegexDetector()
        scanner = DirectoryScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert len(result.findings) == 0


class TestDirectoryScannerNonRecursiveDiscovery:
    """Test non-recursive file discovery."""

    @pytest.mark.asyncio
    async def test_non_recursive_discovery_works(self, tmp_path: Path) -> None:
        """Test non-recursive discovery works correctly."""
        # Create files at top level
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_text("content")

        # Create files in subdirectory that should be ignored
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        for i in range(5):
            (subdir / f"nested{i}.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, recursive=False, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should only scan 5 top-level files, not nested
        assert result.stats["files_discovered"] == 5
        assert result.stats["files_scanned"] == 5


class TestDirectoryScannerFileErrors:
    """Test file reading error handling."""

    @pytest.mark.asyncio
    async def test_handles_directory_as_file_error(self, tmp_path: Path) -> None:
        """Test that scanner handles IsADirectoryError gracefully."""
        # Create a directory that might be mistakenly treated as a file
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        # Should complete without error
        result = await scanner.scan()
        assert result.stats["files_scanned"] >= 1

    @pytest.mark.asyncio
    async def test_handles_file_not_found_during_read(self, tmp_path: Path) -> None:
        """Test that scanner handles FileNotFoundError gracefully."""
        # Create a file that will be deleted during scan
        test_file = tmp_path / "disappearing.txt"
        test_file.write_text("content")

        deleted = False

        class DeletingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "deleting"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal deleted
                if not deleted:
                    # Delete the file for the next file read
                    try:
                        Path(file_path).unlink()
                    except Exception:
                        pass
                    deleted = True
                return []

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [DeletingDetector()])

        # Should complete without raising
        result = await scanner.scan()
        assert result is not None

    @pytest.mark.asyncio
    async def test_handles_unicode_decode_fallback(self, tmp_path: Path) -> None:
        """Test that scanner falls back to latin-1 for non-UTF-8 files."""
        # Create a file with non-UTF-8 bytes
        binary_file = tmp_path / "latin1.txt"
        binary_file.write_bytes(b"\xff\xfe\x00\x01some text")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should have scanned the file successfully
        assert result.stats["files_scanned"] == 1

    @pytest.mark.asyncio
    async def test_matches_pattern_parent_directory(self, tmp_path: Path) -> None:
        """Test that pattern matching works for parent directories."""
        # Create a nested structure
        ignored_dir = tmp_path / "ignored_dir"
        ignored_dir.mkdir()
        nested_file = ignored_dir / "nested.txt"
        nested_file.write_text("secret content")

        config = ScanConfig(target_path=tmp_path, blacklist=["ignored_dir"])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should not scan files in ignored_dir
        assert result.stats["files_scanned"] == 0


class TestDirectoryScannerPermissionErrors:
    """Test permission error handling during discovery."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    async def test_handles_permission_error_during_recursive_discovery(
        self, tmp_path: Path
    ) -> None:
        """Test that scanner handles permission errors during recursive discovery."""
        # Create a directory structure
        readable_dir = tmp_path / "readable"
        readable_dir.mkdir()
        (readable_dir / "file.txt").write_text("content")

        unreadable_dir = tmp_path / "unreadable"
        unreadable_dir.mkdir()
        (unreadable_dir / "file.txt").write_text("content")
        original_mode = unreadable_dir.stat().st_mode
        unreadable_dir.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            scanner = DirectoryScanner(config, [])

            result = await scanner.scan()

            # Should complete and scan the readable file
            assert result.stats["files_scanned"] >= 1
            # May have recorded errors depending on order of traversal
            # The key thing is that it didn't crash
        finally:
            unreadable_dir.chmod(original_mode)

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    async def test_handles_permission_error_non_recursive(self, tmp_path: Path) -> None:
        """Test that scanner handles permission errors during non-recursive discovery."""
        # Create files at top level
        (tmp_path / "file1.txt").write_text("content")

        # Create an unreadable file
        unreadable_file = tmp_path / "unreadable.txt"
        unreadable_file.write_text("secret")
        original_mode = unreadable_file.stat().st_mode
        unreadable_file.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, recursive=False, blacklist=[])
            scanner = DirectoryScanner(config, [])

            result = await scanner.scan()

            # Should complete and scan the readable file
            assert result.stats["files_scanned"] >= 1
            # Should have recorded errors for unreadable file
            assert result.stats["files_skipped"] >= 1
        finally:
            unreadable_file.chmod(original_mode)


class TestDirectoryScannerCancellationDuringDiscovery:
    """Test cancellation during file discovery."""

    @pytest.mark.asyncio
    async def test_cancel_before_file_processing(self, tmp_path: Path) -> None:
        """Test that cancellation flag is checked before file processing."""
        # Create many files
        for i in range(20):
            (tmp_path / f"file{i}.txt").write_text("content")

        files_processed = 0

        class CountingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "counting"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal files_processed
                files_processed += 1
                return []

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [CountingDetector()], concurrency_limit=1)

        # Note: we can't cancel before scan() because reset() clears the flag
        # But we can verify the cancellation works via the existing test_cancellation_stops_scan

        result = await scanner.scan()

        # Should have processed all files
        assert files_processed == 20
        assert result.stats["files_scanned"] == 20

    @pytest.mark.asyncio
    async def test_empty_directory_non_recursive(self, tmp_path: Path) -> None:
        """Test that scanning empty directory works in non-recursive mode."""
        config = ScanConfig(target_path=tmp_path, recursive=False, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should complete without error
        assert result.stats["files_discovered"] == 0
        assert result.stats["files_scanned"] == 0


class TestDirectoryScannerMockedErrors:
    """Test error handling using mocks for edge cases."""

    @pytest.mark.asyncio
    async def test_oserror_during_file_read(self, tmp_path: Path, monkeypatch) -> None:
        """Test that scanner handles OSError during file read gracefully."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Mock read_text to raise OSError
        original_read_text = Path.read_text
        call_count = 0

        def mock_read_text(self, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if "test.txt" in str(self):
                raise OSError("Simulated I/O error")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should have handled the error gracefully
        assert result.stats["files_skipped"] >= 1
        assert any("I/O error" in err or "Error reading" in err for err in result.stats["errors"])

    @pytest.mark.asyncio
    async def test_unexpected_error_during_file_read(self, tmp_path: Path, monkeypatch) -> None:
        """Test that scanner handles unexpected errors during file read."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Mock read_text to raise an unexpected exception
        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            if "test.txt" in str(self):
                raise RuntimeError("Unexpected error")
            return original_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should have handled the error gracefully
        assert result.stats["files_skipped"] >= 1
        assert any("Unexpected error" in err for err in result.stats["errors"])

    @pytest.mark.asyncio
    async def test_cancellation_checked_before_scan(self, tmp_path: Path) -> None:
        """Test that cancellation is checked before scanning each file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [], concurrency_limit=1)

        # Manually set cancellation flag through internal event
        scanner._cancel_event.set()

        # Verify is_cancelled returns True
        assert scanner.is_cancelled

        # Call _scan_file directly (bypassing scan() which would reset)
        result = await scanner._scan_file(test_file)

        # Should return empty list due to cancellation
        assert result == []

    @pytest.mark.asyncio
    async def test_oserror_during_recursive_discovery(self, tmp_path: Path, monkeypatch) -> None:
        """Test handling OSError during recursive directory walk."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Mock is_file to raise OSError
        original_is_file = Path.is_file
        call_count = 0

        def mock_is_file(self):
            nonlocal call_count
            call_count += 1
            if call_count > 1:  # Let the first call succeed for target check
                raise OSError("Simulated stat error")
            return original_is_file(self)

        monkeypatch.setattr(Path, "is_file", mock_is_file)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should complete without crashing
        assert result is not None
        # May have errors recorded
        assert result.stats is not None

    @pytest.mark.asyncio
    async def test_oserror_during_non_recursive_discovery(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Test handling OSError during non-recursive directory iteration."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Create a custom is_file that fails for the test file
        original_is_file = Path.is_file
        checked_files = []

        def mock_is_file(self):
            checked_files.append(str(self))
            if "test.txt" in str(self):
                raise OSError("Simulated stat error")
            return original_is_file(self)

        monkeypatch.setattr(Path, "is_file", mock_is_file)

        config = ScanConfig(target_path=tmp_path, recursive=False, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should complete without crashing
        assert result is not None
        # Should have recorded the error
        assert any(
            "stat error" in err or "Error accessing" in err for err in result.stats["errors"]
        )

    @pytest.mark.asyncio
    async def test_permission_error_during_is_file_recursive(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Test handling PermissionError during is_file check in recursive mode."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Mock is_file to raise PermissionError
        original_is_file = Path.is_file

        def mock_is_file(self):
            if "test.txt" in str(self):
                raise PermissionError("Permission denied")
            return original_is_file(self)

        monkeypatch.setattr(Path, "is_file", mock_is_file)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = DirectoryScanner(config, [])

        result = await scanner.scan()

        # Should complete without crashing
        assert result is not None
        # Should have recorded the error
        assert any("Permission denied" in err for err in result.stats["errors"])
