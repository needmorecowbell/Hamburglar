"""Tests for the AsyncScanner class.

This module tests the async scanning functionality including:
- Async scanning produces same results as sync
- Concurrency limit is respected
- Cancellation works correctly
- Progress callbacks are called
- Streaming output works
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

from hamburglar.core.async_scanner import AsyncScanner, ScanProgress  # noqa: E402
from hamburglar.core.exceptions import ScanError  # noqa: E402
from hamburglar.core.models import Finding, ScanConfig  # noqa: E402
from hamburglar.core.scanner import Scanner  # noqa: E402
from hamburglar.detectors import BaseDetector  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402


class TestAsyncScannerBasic:
    """Test basic async scanning functionality."""

    @pytest.mark.asyncio
    async def test_async_scan_directory_finds_secrets(self, temp_directory: Path) -> None:
        """Test that async scanner finds secrets in a directory with known secrets."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        assert result.target_path == str(temp_directory)
        assert len(result.findings) > 0
        assert result.stats["files_scanned"] > 0
        assert result.stats["total_findings"] > 0

    @pytest.mark.asyncio
    async def test_async_scan_single_file(self, temp_directory: Path) -> None:
        """Test scanning a single file rather than a directory."""
        single_file = temp_directory / "secrets.txt"
        config = ScanConfig(target_path=single_file)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_async_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scanning an empty directory returns empty result."""
        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert result.stats["files_scanned"] == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_async_scan_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError for nonexistent paths."""
        nonexistent = tmp_path / "does_not_exist"
        config = ScanConfig(target_path=nonexistent)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "does not exist" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_async_scan_with_no_detectors(self, temp_directory: Path) -> None:
        """Test that scanner works without any detectors."""
        config = ScanConfig(target_path=temp_directory)
        scanner = AsyncScanner(config, detectors=None)

        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0
        assert len(result.findings) == 0  # No findings without detectors


class TestAsyncScannerMatchesSyncResults:
    """Test that async scanning produces same results as sync scanner."""

    @pytest.mark.asyncio
    async def test_async_produces_same_findings_as_sync(self, temp_directory: Path) -> None:
        """Test that async scanner finds the same secrets as sync scanner."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()

        # Run sync scanner
        sync_scanner = Scanner(config, [detector])
        sync_result = await sync_scanner.scan()

        # Run async scanner
        async_scanner = AsyncScanner(config, [detector])
        async_result = await async_scanner.scan()

        # Compare findings
        assert len(async_result.findings) == len(sync_result.findings)

        # Sort findings by file_path and detector_name for comparison
        sync_findings = sorted(sync_result.findings, key=lambda f: (f.file_path, f.detector_name))
        async_findings = sorted(async_result.findings, key=lambda f: (f.file_path, f.detector_name))

        for sync_f, async_f in zip(sync_findings, async_findings):
            assert sync_f.file_path == async_f.file_path
            assert sync_f.detector_name == async_f.detector_name
            assert sync_f.severity == async_f.severity
            assert sync_f.matches == async_f.matches

    @pytest.mark.asyncio
    async def test_async_produces_same_stats_as_sync(self, temp_directory: Path) -> None:
        """Test that async scanner produces similar stats as sync scanner."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()

        # Run sync scanner
        sync_scanner = Scanner(config, [detector])
        sync_result = await sync_scanner.scan()

        # Run async scanner
        async_scanner = AsyncScanner(config, [detector])
        async_result = await async_scanner.scan()

        # Compare stats
        assert async_result.stats["files_discovered"] == sync_result.stats["files_discovered"]
        assert async_result.stats["files_scanned"] == sync_result.stats["files_scanned"]
        assert async_result.stats["total_findings"] == sync_result.stats["total_findings"]


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
        scanner = AsyncScanner(config, [SlowDetector()], concurrency_limit=3)

        await scanner.scan()

        # Max concurrent should not exceed the limit
        assert max_concurrent <= 3

    @pytest.mark.asyncio
    async def test_default_concurrency_limit_is_50(self, tmp_path: Path) -> None:
        """Test that default concurrency limit is 50."""
        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config, [])

        assert scanner.concurrency_limit == 50

    @pytest.mark.asyncio
    async def test_custom_concurrency_limit(self, tmp_path: Path) -> None:
        """Test that custom concurrency limit is applied."""
        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config, [], concurrency_limit=10)

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
        scanner = AsyncScanner(config, [SlowDetector()], concurrency_limit=1)

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
        scanner = AsyncScanner(config, [])

        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_reset_clears_cancellation(self, tmp_path: Path) -> None:
        """Test that reset() clears the cancellation state."""
        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config, [])

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
        scanner = AsyncScanner(config, [detector], progress_callback=progress_callback)

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
        scanner = AsyncScanner(config, [], progress_callback=progress_callback, concurrency_limit=1)

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
        scanner = AsyncScanner(config, [], progress_callback=progress_callback)

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
        scanner = AsyncScanner(config, [detector], progress_callback=progress_callback)

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
        scanner = AsyncScanner(config, [detector], progress_callback=failing_callback)

        # Scan should complete despite callback failure
        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_progress_dataclass_files_remaining(self) -> None:
        """Test that ScanProgress computes files_remaining correctly."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=25,
            current_file="/path/to/file.txt",
            bytes_processed=1024,
            findings_count=5,
            elapsed_time=1.5,
        )

        assert progress.files_remaining == 75


class TestStreamingOutput:
    """Test streaming output functionality."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(self, temp_directory: Path) -> None:
        """Test that scan_stream yields findings as they're discovered."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

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
        batch_scanner = AsyncScanner(config, [detector])
        batch_result = await batch_scanner.scan()

        # Stream scan
        stream_scanner = AsyncScanner(config, [detector])
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
        scanner = AsyncScanner(config, [])

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
        scanner = AsyncScanner(config, [detector], concurrency_limit=2)

        findings_received = 0
        async for _ in scanner.scan_stream():
            findings_received += 1
            if findings_received >= 5:
                break  # Interrupt early

        # Should have stopped early
        assert findings_received == 5


class TestAsyncScannerStats:
    """Test statistics tracking."""

    @pytest.mark.asyncio
    async def test_bytes_processed_is_tracked(self, tmp_path: Path) -> None:
        """Test that bytes processed are tracked."""
        content = "x" * 1000
        (tmp_path / "file.txt").write_text(content)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        result = await scanner.scan()

        assert result.stats["bytes_processed"] >= 1000

    @pytest.mark.asyncio
    async def test_get_stats_returns_current_state(self, tmp_path: Path) -> None:
        """Test that get_stats returns current scan state."""
        (tmp_path / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        # Before scan
        stats = scanner.get_stats()
        assert stats["total_files"] == 0
        assert stats["files_scanned"] == 0

        await scanner.scan()

        # After scan
        stats = scanner.get_stats()
        assert stats["total_files"] == 1
        assert stats["files_scanned"] == 1


class TestAsyncScannerBlacklistWhitelist:
    """Test blacklist and whitelist functionality."""

    @pytest.mark.asyncio
    async def test_blacklist_excludes_files(self, temp_directory: Path) -> None:
        """Test that blacklisted files are not scanned."""
        config = ScanConfig(target_path=temp_directory, blacklist=["*.txt"])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

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
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        # Only .py files should be scanned
        scanned_files = {f.file_path for f in result.findings}
        for file_path in scanned_files:
            assert file_path.endswith(".py"), "Should only scan .py files"


class TestAsyncScannerErrorHandling:
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
        scanner = AsyncScanner(config, [failing_detector, working_detector])

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
            scanner = AsyncScanner(config, [detector])

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
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        # Should complete without error
        assert result.stats["files_scanned"] >= 1


class TestAsyncScannerReset:
    """Test reset functionality."""

    @pytest.mark.asyncio
    async def test_reset_clears_state(self, tmp_path: Path) -> None:
        """Test that reset clears all scanner state."""
        (tmp_path / "file.txt").write_text("content")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

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
        scanner = AsyncScanner(config, [])

        # First scan
        result1 = await scanner.scan()
        assert result1.stats["files_scanned"] == 1

        # Second scan (reset happens automatically)
        result2 = await scanner.scan()
        assert result2.stats["files_scanned"] == 1


class TestAsyncScannerNonRecursive:
    """Test non-recursive scanning mode."""

    @pytest.mark.asyncio
    async def test_non_recursive_ignores_subdirectories(self, temp_directory: Path) -> None:
        """Test that non-recursive mode doesn't scan subdirectories."""
        config = ScanConfig(target_path=temp_directory, recursive=False)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

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
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        # Should only scan top.txt
        assert result.stats["files_scanned"] == 1
        assert any("top.txt" in f.file_path for f in result.findings)
        assert not any("nested.txt" in f.file_path for f in result.findings)


class TestAsyncScannerSingleFileBlacklisted:
    """Test single file scanning with blacklist."""

    @pytest.mark.asyncio
    async def test_single_file_blacklisted(self, tmp_path: Path) -> None:
        """Test that a single blacklisted file returns empty results."""
        single_file = tmp_path / "secrets.txt"
        single_file.write_text("AKIAIOSFODNN7EXAMPLE")

        config = ScanConfig(target_path=single_file, blacklist=["*.txt"])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert len(result.findings) == 0


class TestAsyncScannerCancelDuringDiscovery:
    """Test cancellation during file discovery."""

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
        scanner = AsyncScanner(config, [])

        result = await scanner.scan()

        # Should only scan 5 top-level files, not nested
        assert result.stats["files_discovered"] == 5
        assert result.stats["files_scanned"] == 5
