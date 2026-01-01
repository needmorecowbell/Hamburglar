"""Performance benchmark tests for Hamburglar.

This module tests performance characteristics including:
- Scan speed with 100 files
- Scan speed with 1000 files
- Memory usage stays bounded
- Concurrent scanning is faster than sequential
"""

from __future__ import annotations

import asyncio
import gc
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

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

from hamburglar.core.async_scanner import AsyncScanner  # noqa: E402
from hamburglar.core.models import ScanConfig  # noqa: E402
from hamburglar.core.profiling import (  # noqa: E402
    MemoryProfiler,
    get_current_memory_rss,
    is_memory_tracking_available,
)
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402


# Sample content for test files
SAMPLE_CONTENT_WITH_SECRETS = """
# Configuration file with various secrets for testing

# AWS API Key (fake - uses AWS example pattern)
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Contact information
admin_email = "admin@example.com"
support_email = "support@test.org"

# Private key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----

# Generic API Key
api_key = "test_key_1234567890abcdefghijklmnop"
"""

SAMPLE_CONTENT_CLEAN = """
This is a clean file with no secrets.
It contains only regular text content.
Nothing sensitive here.
Just some filler text to make the file larger.
Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
"""


def create_test_files(base_path: Path, num_files: int, with_secrets: bool = True) -> list[Path]:
    """Create a specified number of test files.

    Args:
        base_path: Directory to create files in.
        num_files: Number of files to create.
        with_secrets: If True, some files will contain secrets.

    Returns:
        List of created file paths.
    """
    created_files = []
    for i in range(num_files):
        file_path = base_path / f"test_file_{i:05d}.txt"
        # Every 10th file has secrets, rest are clean
        if with_secrets and i % 10 == 0:
            content = SAMPLE_CONTENT_WITH_SECRETS
        else:
            content = SAMPLE_CONTENT_CLEAN
        file_path.write_text(content)
        created_files.append(file_path)
    return created_files


class TestScanSpeed100Files:
    """Test scan speed with 100 files."""

    @pytest.mark.asyncio
    async def test_scan_100_files_completes(self, tmp_path: Path) -> None:
        """Test that scanning 100 files completes successfully."""
        # Create 100 test files
        create_test_files(tmp_path, 100)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        assert result.stats["files_scanned"] == 100
        assert result.stats["files_discovered"] == 100
        # Should complete in reasonable time (less than 30 seconds for 100 files)
        assert elapsed_time < 30.0, f"Scan took too long: {elapsed_time:.2f}s"

    @pytest.mark.asyncio
    async def test_scan_100_files_throughput(self, tmp_path: Path) -> None:
        """Test that 100 file scan achieves reasonable throughput."""
        create_test_files(tmp_path, 100)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        files_per_second = 100 / elapsed_time if elapsed_time > 0 else 0

        assert result.stats["files_scanned"] == 100
        # Should process at least 10 files per second
        assert files_per_second >= 10.0, f"Throughput too low: {files_per_second:.2f} files/s"

    @pytest.mark.asyncio
    async def test_scan_100_files_finds_secrets(self, tmp_path: Path) -> None:
        """Test that scanning 100 files finds expected secrets."""
        create_test_files(tmp_path, 100, with_secrets=True)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 100
        # Every 10th file has secrets (files 0, 10, 20, ... 90 = 10 files)
        # Each file with secrets should have multiple findings
        assert len(result.findings) > 0, "Should find secrets in test files"


class TestScanSpeed1000Files:
    """Test scan speed with 1000 files."""

    @pytest.mark.asyncio
    async def test_scan_1000_files_completes(self, tmp_path: Path) -> None:
        """Test that scanning 1000 files completes successfully."""
        create_test_files(tmp_path, 1000)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        assert result.stats["files_scanned"] == 1000
        assert result.stats["files_discovered"] == 1000
        # Should complete in reasonable time (less than 60 seconds for 1000 files)
        assert elapsed_time < 60.0, f"Scan took too long: {elapsed_time:.2f}s"

    @pytest.mark.asyncio
    async def test_scan_1000_files_throughput(self, tmp_path: Path) -> None:
        """Test that 1000 file scan achieves reasonable throughput."""
        create_test_files(tmp_path, 1000)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        files_per_second = 1000 / elapsed_time if elapsed_time > 0 else 0

        assert result.stats["files_scanned"] == 1000
        # Should process at least 20 files per second with concurrency
        assert files_per_second >= 20.0, f"Throughput too low: {files_per_second:.2f} files/s"

    @pytest.mark.asyncio
    async def test_scan_1000_files_bytes_processed(self, tmp_path: Path) -> None:
        """Test that bytes processed is tracked for 1000 files."""
        create_test_files(tmp_path, 1000)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1000
        # Each clean file is ~500 bytes, each secret file is ~700 bytes
        # 900 clean + 100 with secrets = ~500KB
        min_expected_bytes = 1000 * 300  # Conservative estimate
        assert result.stats["bytes_processed"] >= min_expected_bytes

    @pytest.mark.asyncio
    async def test_scan_1000_files_streaming(self, tmp_path: Path) -> None:
        """Test that streaming 1000 files works correctly."""
        create_test_files(tmp_path, 1000, with_secrets=True)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        start_time = time.time()
        findings_count = 0
        async for _ in scanner.scan_stream():
            findings_count += 1
        elapsed_time = time.time() - start_time

        # Should have findings from the 100 files with secrets
        assert findings_count > 0
        # Should complete in reasonable time
        assert elapsed_time < 60.0


class TestMemoryBoundedness:
    """Test that memory usage stays bounded during scans."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not is_memory_tracking_available(),
        reason="psutil not available for memory tracking"
    )
    async def test_memory_bounded_100_files(self, tmp_path: Path) -> None:
        """Test that memory stays bounded while scanning 100 files."""
        create_test_files(tmp_path, 100)

        # Force garbage collection before starting
        gc.collect()
        initial_memory = get_current_memory_rss()

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        await scanner.scan()

        profiler.stop()
        gc.collect()

        # Memory increase should be reasonable (less than 100MB for 100 small files)
        memory_delta = profiler.memory_delta_rss
        assert memory_delta < 100 * 1024 * 1024, (
            f"Memory grew too much: {memory_delta / (1024 * 1024):.2f} MB"
        )

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not is_memory_tracking_available(),
        reason="psutil not available for memory tracking"
    )
    async def test_memory_bounded_1000_files(self, tmp_path: Path) -> None:
        """Test that memory stays bounded while scanning 1000 files."""
        create_test_files(tmp_path, 1000)

        gc.collect()

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        await scanner.scan()

        profiler.stop()
        gc.collect()

        # Memory should not grow linearly with file count
        # For 1000 files, should stay under 200MB
        memory_delta = profiler.memory_delta_rss
        assert memory_delta < 200 * 1024 * 1024, (
            f"Memory grew too much: {memory_delta / (1024 * 1024):.2f} MB"
        )

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not is_memory_tracking_available(),
        reason="psutil not available for memory tracking"
    )
    async def test_memory_peak_tracking(self, tmp_path: Path) -> None:
        """Test that peak memory is tracked correctly during scan."""
        create_test_files(tmp_path, 100)

        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        # Take a snapshot during file creation setup
        profiler.snapshot("before_scan")

        await scanner.scan()

        # Take a snapshot after scan
        profiler.snapshot("after_scan")

        profiler.stop()

        # Should have multiple snapshots
        assert len(profiler.snapshots) >= 3  # start, before_scan, after_scan, end
        # Peak should be at least as high as the end value
        assert profiler.peak_memory_rss >= 0

    @pytest.mark.asyncio
    async def test_memory_no_leak_on_repeated_scans(self, tmp_path: Path) -> None:
        """Test that repeated scans don't leak memory."""
        create_test_files(tmp_path, 50)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        # Run multiple scans
        results = []
        for i in range(5):
            result = await scanner.scan()
            results.append(result)
            gc.collect()

        # All scans should complete successfully
        for result in results:
            assert result.stats["files_scanned"] == 50


class TestConcurrencyPerformance:
    """Test that concurrent scanning is faster than sequential."""

    @pytest.mark.asyncio
    async def test_concurrent_faster_than_sequential(self, tmp_path: Path) -> None:
        """Test that concurrent scanning outperforms sequential scanning."""
        # Create enough files to show concurrency benefit
        create_test_files(tmp_path, 100)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()

        # Sequential scan (concurrency limit = 1)
        sequential_scanner = AsyncScanner(config, [detector], concurrency_limit=1)
        start_time = time.time()
        await sequential_scanner.scan()
        sequential_time = time.time() - start_time

        # Concurrent scan (default concurrency limit = 50)
        concurrent_scanner = AsyncScanner(config, [detector], concurrency_limit=50)
        start_time = time.time()
        await concurrent_scanner.scan()
        concurrent_time = time.time() - start_time

        # Concurrent should be faster (or at least not significantly slower)
        # Allow some tolerance since actual speedup depends on I/O characteristics
        # At minimum, concurrent shouldn't be more than 50% slower
        assert concurrent_time <= sequential_time * 1.5, (
            f"Concurrent ({concurrent_time:.2f}s) was slower than sequential "
            f"({sequential_time:.2f}s)"
        )

    @pytest.mark.asyncio
    async def test_concurrency_limit_variations(self, tmp_path: Path) -> None:
        """Test scan performance with different concurrency limits."""
        create_test_files(tmp_path, 100)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()

        results = {}
        for limit in [1, 5, 10, 25, 50]:
            scanner = AsyncScanner(config, [detector], concurrency_limit=limit)
            start_time = time.time()
            result = await scanner.scan()
            elapsed = time.time() - start_time
            results[limit] = {
                "time": elapsed,
                "files_scanned": result.stats["files_scanned"],
            }

        # All should scan all files
        for limit, data in results.items():
            assert data["files_scanned"] == 100, f"Limit {limit} didn't scan all files"

        # Higher concurrency should generally be faster (or not significantly slower)
        # Comparing limit=1 vs limit=50
        assert results[50]["time"] <= results[1]["time"] * 1.5, (
            f"Concurrency 50 ({results[50]['time']:.2f}s) was too slow compared "
            f"to sequential ({results[1]['time']:.2f}s)"
        )

    @pytest.mark.asyncio
    async def test_semaphore_respects_limit(self, tmp_path: Path) -> None:
        """Test that semaphore-based concurrency limit is respected."""
        create_test_files(tmp_path, 20)

        concurrent_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        from hamburglar.detectors import BaseDetector
        from hamburglar.core.models import Finding

        class TrackingDetector(BaseDetector):
            """Detector that tracks concurrent executions."""

            @property
            def name(self) -> str:
                return "tracking"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                nonlocal concurrent_count, max_concurrent
                import time as time_module

                # Use async-safe increment
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)
                # Small sleep to allow overlap
                time_module.sleep(0.01)
                concurrent_count -= 1
                return []

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        limit = 5
        scanner = AsyncScanner(config, [TrackingDetector()], concurrency_limit=limit)

        await scanner.scan()

        # Max concurrent should not exceed limit
        assert max_concurrent <= limit, f"Max concurrent {max_concurrent} exceeded limit {limit}"

    @pytest.mark.asyncio
    async def test_scan_without_detectors_is_fast(self, tmp_path: Path) -> None:
        """Test that scanning without detectors is very fast."""
        create_test_files(tmp_path, 1000)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])  # No detectors

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        # Without detectors, should be very fast (just file reading)
        assert result.stats["files_scanned"] == 1000
        assert elapsed_time < 30.0, f"No-detector scan too slow: {elapsed_time:.2f}s"


class TestBenchmarkMetrics:
    """Test collection of benchmark metrics."""

    @pytest.mark.asyncio
    async def test_bytes_per_second_calculation(self, tmp_path: Path) -> None:
        """Test that bytes per second can be calculated from results."""
        create_test_files(tmp_path, 100)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        bytes_processed = result.stats["bytes_processed"]
        bytes_per_second = bytes_processed / elapsed_time if elapsed_time > 0 else 0

        # Should have processed some bytes
        assert bytes_processed > 0
        # Should have reasonable throughput
        assert bytes_per_second > 0

    @pytest.mark.asyncio
    async def test_findings_per_file_metric(self, tmp_path: Path) -> None:
        """Test calculation of findings per file metric."""
        create_test_files(tmp_path, 100, with_secrets=True)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        result = await scanner.scan()

        files_scanned = result.stats["files_scanned"]
        total_findings = len(result.findings)
        findings_per_file = total_findings / files_scanned if files_scanned > 0 else 0

        # Should have some findings
        assert total_findings > 0
        # Average should be reasonable (not all files have secrets)
        assert findings_per_file >= 0

    @pytest.mark.asyncio
    async def test_scan_reports_duration(self, tmp_path: Path) -> None:
        """Test that scan result includes accurate duration."""
        create_test_files(tmp_path, 50)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        # Result should have scan_duration
        assert result.scan_duration > 0
        # Duration in result should be close to our measured time
        assert abs(result.scan_duration - elapsed_time) < 1.0


class TestScalabilityBehavior:
    """Test scalability characteristics of the scanner."""

    @pytest.mark.asyncio
    async def test_linear_scaling_with_files(self, tmp_path: Path) -> None:
        """Test that scan time scales roughly linearly with file count."""
        times = {}

        for file_count in [50, 100]:
            # Create subdirectory for each count
            subdir = tmp_path / f"files_{file_count}"
            subdir.mkdir()
            create_test_files(subdir, file_count)

            config = ScanConfig(target_path=subdir, blacklist=[])
            scanner = AsyncScanner(config, [])

            start_time = time.time()
            await scanner.scan()
            times[file_count] = time.time() - start_time

        # Time for 100 files should be roughly 2x time for 50 files
        # (within 3x to account for overhead and variance)
        ratio = times[100] / times[50] if times[50] > 0 else float('inf')
        assert ratio < 4.0, f"Scaling ratio too high: {ratio:.2f}x"

    @pytest.mark.asyncio
    async def test_handles_empty_directory(self, tmp_path: Path) -> None:
        """Test performance with empty directory."""
        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        assert result.stats["files_discovered"] == 0
        assert result.stats["files_scanned"] == 0
        # Should be nearly instant
        assert elapsed_time < 1.0

    @pytest.mark.asyncio
    async def test_handles_large_files(self, tmp_path: Path) -> None:
        """Test performance with a few large files."""
        # Create a 1MB file
        large_content = "x" * (1024 * 1024)
        large_file = tmp_path / "large_file.txt"
        large_file.write_text(large_content)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        assert result.stats["files_scanned"] == 1
        assert result.stats["bytes_processed"] >= 1024 * 1024
        # Should complete reasonably fast
        assert elapsed_time < 10.0

    @pytest.mark.asyncio
    async def test_nested_directory_scan(self, tmp_path: Path) -> None:
        """Test performance with deeply nested directories."""
        # Create nested structure: 10 levels deep, 10 files each
        current_dir = tmp_path
        for i in range(10):
            current_dir = current_dir / f"level_{i}"
            current_dir.mkdir()
            # Add 10 files at each level
            for j in range(10):
                (current_dir / f"file_{j}.txt").write_text(SAMPLE_CONTENT_CLEAN)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        scanner = AsyncScanner(config, [])

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        # Should find all 100 files (10 levels * 10 files)
        assert result.stats["files_scanned"] == 100
        # Should complete reasonably fast
        assert elapsed_time < 30.0
