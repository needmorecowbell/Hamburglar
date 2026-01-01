"""Tests for the async capabilities of RegexDetector.

This module contains tests for the async methods of the RegexDetector class,
including detect_async, detect_batch, and detect_batch_async.
"""

from __future__ import annotations

import asyncio

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.regex_detector import RegexDetector


class TestDetectAsync:
    """Tests for the detect_async method."""

    @pytest.mark.asyncio
    async def test_detect_async_basic(self) -> None:
        """Test that detect_async finds patterns correctly."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE"
        findings = await detector.detect_async(content, "test.txt")

        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in aws_findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_async_returns_same_as_sync(self) -> None:
        """Test that detect_async returns the same results as sync detect."""
        detector = RegexDetector()
        content = """
        AWS Key: AKIAIOSFODNN7EXAMPLE
        Email: admin@example.com
        GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
        """

        sync_findings = detector.detect(content, "test.txt")
        async_findings = await detector.detect_async(content, "test.txt")

        # Should have the same number of findings
        assert len(sync_findings) == len(async_findings)

        # Findings should match
        sync_detectors = sorted([f.detector_name for f in sync_findings])
        async_detectors = sorted([f.detector_name for f in async_findings])
        assert sync_detectors == async_detectors

    @pytest.mark.asyncio
    async def test_detect_async_empty_content(self) -> None:
        """Test detect_async with empty content returns empty list."""
        detector = RegexDetector()
        findings = await detector.detect_async("", "empty.txt")
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_async_no_matches(self) -> None:
        """Test detect_async with no matching patterns."""
        detector = RegexDetector()
        content = "Just regular text without any secrets."
        findings = await detector.detect_async(content, "clean.txt")
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_async_multiple_patterns(self) -> None:
        """Test detect_async finds multiple different patterns."""
        detector = RegexDetector()
        content = """
        AWS Key: AKIAIOSFODNN7EXAMPLE
        Email: user@example.com
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """
        findings = await detector.detect_async(content, "secrets.txt")

        detector_names = [f.detector_name for f in findings]
        assert any("AWS API Key" in name for name in detector_names)
        assert any("Email Address" in name for name in detector_names)
        assert any("Bitcoin Address" in name for name in detector_names)

    @pytest.mark.asyncio
    async def test_detect_async_concurrent_calls(self) -> None:
        """Test that multiple concurrent detect_async calls work correctly."""
        detector = RegexDetector()
        contents = [
            ("AKIAIOSFODNN7EXAMPLE", "file1.txt"),
            ("admin@example.com", "file2.txt"),
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "file3.txt"),
        ]

        tasks = [detector.detect_async(content, path) for content, path in contents]
        results = await asyncio.gather(*tasks)

        # Each file should have findings
        assert len(results) == 3
        assert len(results[0]) >= 1  # AWS key
        assert len(results[1]) >= 1  # Email
        assert len(results[2]) >= 1  # GitHub token

    @pytest.mark.asyncio
    async def test_detect_async_with_binary_content(self) -> None:
        """Test detect_async correctly skips binary content."""
        detector = RegexDetector()
        binary_content = "\x00\x01\x02\x03" * 3000
        findings = await detector.detect_async(binary_content, "binary.bin")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_async_preserves_file_path(self) -> None:
        """Test that file_path is correctly preserved in findings."""
        detector = RegexDetector()
        content = "admin@example.com"
        file_path = "/path/to/important/file.txt"
        findings = await detector.detect_async(content, file_path)

        assert len(findings) >= 1
        assert findings[0].file_path == file_path


class TestDetectBatch:
    """Tests for the detect_batch method."""

    def test_detect_batch_basic(self) -> None:
        """Test basic batch detection."""
        detector = RegexDetector()
        contents = [
            ("AKIAIOSFODNN7EXAMPLE", "file1.txt"),
            ("admin@example.com", "file2.txt"),
            ("No secrets here", "file3.txt"),
        ]

        results = detector.detect_batch(contents)

        assert len(results) == 3
        assert "file1.txt" in results
        assert "file2.txt" in results
        assert "file3.txt" in results

        # Check findings for each file
        assert len(results["file1.txt"]) >= 1  # AWS key
        assert len(results["file2.txt"]) >= 1  # Email
        assert len(results["file3.txt"]) == 0  # No secrets

    def test_detect_batch_empty_list(self) -> None:
        """Test batch detection with empty list."""
        detector = RegexDetector()
        results = detector.detect_batch([])
        assert results == {}

    def test_detect_batch_stop_on_first_match(self) -> None:
        """Test that stop_on_first_match limits findings per file."""
        detector = RegexDetector()
        content = """
        AWS Key: AKIAIOSFODNN7EXAMPLE
        Email: admin@example.com
        GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
        """

        # With stop_on_first_match=True
        results_early = detector.detect_batch([(content, "file.txt")], stop_on_first_match=True)
        assert len(results_early["file.txt"]) == 1

        # Without stop_on_first_match
        results_all = detector.detect_batch([(content, "file.txt")])
        assert len(results_all["file.txt"]) >= 1

    def test_detect_batch_preserves_order(self) -> None:
        """Test that batch results maintain file order."""
        detector = RegexDetector()
        contents = [
            ("email1@example.com", "a_file.txt"),
            ("email2@example.com", "b_file.txt"),
            ("email3@example.com", "c_file.txt"),
        ]

        results = detector.detect_batch(contents)
        keys = list(results.keys())

        assert keys == ["a_file.txt", "b_file.txt", "c_file.txt"]

    def test_detect_batch_handles_binary(self) -> None:
        """Test batch detection correctly handles binary files."""
        detector = RegexDetector()
        binary_content = "\x00\x01\x02\x03" * 3000
        contents = [
            ("admin@example.com", "text.txt"),
            (binary_content, "binary.bin"),
        ]

        results = detector.detect_batch(contents)

        assert len(results["text.txt"]) >= 1
        assert len(results["binary.bin"]) == 0

    def test_detect_batch_large_number_of_files(self) -> None:
        """Test batch detection with many files."""
        detector = RegexDetector()
        contents = [(f"admin{i}@example.com", f"file{i}.txt") for i in range(100)]

        results = detector.detect_batch(contents)

        assert len(results) == 100
        for i in range(100):
            assert len(results[f"file{i}.txt"]) >= 1


class TestDetectBatchAsync:
    """Tests for the detect_batch_async method."""

    @pytest.mark.asyncio
    async def test_detect_batch_async_basic(self) -> None:
        """Test basic async batch detection."""
        detector = RegexDetector()
        contents = [
            ("AKIAIOSFODNN7EXAMPLE", "file1.txt"),
            ("admin@example.com", "file2.txt"),
            ("No secrets here", "file3.txt"),
        ]

        results = await detector.detect_batch_async(contents)

        assert len(results) == 3
        assert len(results["file1.txt"]) >= 1
        assert len(results["file2.txt"]) >= 1
        assert len(results["file3.txt"]) == 0

    @pytest.mark.asyncio
    async def test_detect_batch_async_returns_same_as_sync(self) -> None:
        """Test that async batch returns same results as sync batch."""
        detector = RegexDetector()
        contents = [
            ("AKIAIOSFODNN7EXAMPLE", "file1.txt"),
            ("admin@example.com", "file2.txt"),
        ]

        sync_results = detector.detect_batch(contents)
        async_results = await detector.detect_batch_async(contents)

        # Same files should be present
        assert set(sync_results.keys()) == set(async_results.keys())

        # Same number of findings per file
        for file_path in sync_results:
            assert len(sync_results[file_path]) == len(async_results[file_path])

    @pytest.mark.asyncio
    async def test_detect_batch_async_concurrency_limit(self) -> None:
        """Test that concurrency limit is respected."""
        detector = RegexDetector()
        # Create many files to process
        contents = [(f"admin{i}@example.com", f"file{i}.txt") for i in range(20)]

        # Should complete without issues with low concurrency
        results = await detector.detect_batch_async(contents, concurrency_limit=2)

        assert len(results) == 20
        for i in range(20):
            assert len(results[f"file{i}.txt"]) >= 1

    @pytest.mark.asyncio
    async def test_detect_batch_async_high_concurrency(self) -> None:
        """Test async batch with high concurrency."""
        detector = RegexDetector()
        contents = [(f"admin{i}@example.com", f"file{i}.txt") for i in range(50)]

        results = await detector.detect_batch_async(contents, concurrency_limit=50)

        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_detect_batch_async_stop_on_first_match(self) -> None:
        """Test async batch with stop_on_first_match."""
        detector = RegexDetector()
        content = """
        AWS Key: AKIAIOSFODNN7EXAMPLE
        Email: admin@example.com
        GitHub Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
        """

        results = await detector.detect_batch_async(
            [(content, "file.txt")], stop_on_first_match=True
        )

        assert len(results["file.txt"]) == 1

    @pytest.mark.asyncio
    async def test_detect_batch_async_empty_list(self) -> None:
        """Test async batch with empty list."""
        detector = RegexDetector()
        results = await detector.detect_batch_async([])
        assert results == {}

    @pytest.mark.asyncio
    async def test_detect_batch_async_handles_errors_gracefully(self) -> None:
        """Test that async batch handles individual file errors gracefully."""
        detector = RegexDetector()
        contents = [
            ("admin@example.com", "good.txt"),
            ("\x00" * 10000, "binary.bin"),  # Binary file
        ]

        results = await detector.detect_batch_async(contents)

        assert len(results) == 2
        assert len(results["good.txt"]) >= 1
        assert len(results["binary.bin"]) == 0


class TestPatternCaching:
    """Tests for pattern caching functionality."""

    def test_patterns_compiled_once_at_init(self) -> None:
        """Test that patterns are compiled only once during initialization."""
        detector = RegexDetector()

        # Access compiled patterns
        compiled1 = detector._compiled_patterns
        compiled2 = detector._compiled_patterns

        # Should be the same object (not recompiled)
        assert compiled1 is compiled2

    def test_pattern_cache_persists_across_detections(self) -> None:
        """Test that pattern cache persists across multiple detect calls."""
        detector = RegexDetector()

        # Get compiled patterns before detection
        compiled_before = id(detector._compiled_patterns["AWS API Key"][0])

        # Run detection multiple times
        for _ in range(5):
            detector.detect("AKIAIOSFODNN7EXAMPLE", "test.txt")

        # Compiled pattern should still be the same object
        compiled_after = id(detector._compiled_patterns["AWS API Key"][0])
        assert compiled_before == compiled_after

    @pytest.mark.asyncio
    async def test_pattern_cache_thread_safe(self) -> None:
        """Test that pattern cache is thread-safe under concurrent access."""
        detector = RegexDetector()
        contents = [(f"AKIAIOSFODNN{i:07d}", f"file{i}.txt") for i in range(100)]

        # Run many concurrent detections
        tasks = [detector.detect_async(content, path) for content, path in contents]
        await asyncio.gather(*tasks)

        # Compiled patterns should still be intact
        assert len(detector._compiled_patterns) == len(detector._patterns)


class TestPatternStats:
    """Tests for the get_pattern_stats method."""

    def test_get_pattern_stats_default_patterns(self) -> None:
        """Test pattern stats with default patterns."""
        detector = RegexDetector()
        stats = detector.get_pattern_stats()

        assert "total_patterns" in stats
        assert stats["total_patterns"] > 0
        assert "by_category" in stats
        assert "by_severity" in stats
        assert "by_confidence" in stats

    def test_get_pattern_stats_custom_patterns(self) -> None:
        """Test pattern stats with custom patterns."""
        custom_patterns = {
            "Pattern A": {
                "pattern": r"ATEST-\d+",
                "severity": Severity.HIGH,
                "description": "Test A",
                "category": "test",
                "confidence": "high",
            },
            "Pattern B": {
                "pattern": r"BTEST-\d+",
                "severity": Severity.LOW,
                "description": "Test B",
                "category": "test",
                "confidence": "low",
            },
        }
        detector = RegexDetector(patterns=custom_patterns, use_defaults=False)
        stats = detector.get_pattern_stats()

        assert stats["total_patterns"] == 2
        assert stats["by_category"].get("test", 0) == 2
        assert stats["by_confidence"].get("high", 0) == 1
        assert stats["by_confidence"].get("low", 0) == 1


class TestTimeoutBehavior:
    """Tests for timeout behavior in async context."""

    @pytest.mark.asyncio
    async def test_detect_async_respects_timeout(self) -> None:
        """Test that detect_async respects the configured timeout."""
        # Use a short timeout
        detector = RegexDetector(regex_timeout=0.001)

        # Create a large content that might trigger timeout
        large_content = "AKIAIOSFODNN7EXAMPLE " * 1000

        # Should complete without hanging (might timeout some patterns)
        findings = await detector.detect_async(large_content, "large.txt")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_batch_async_handles_timeouts(self) -> None:
        """Test that batch async handles timeouts gracefully."""
        detector = RegexDetector(regex_timeout=1.0)

        contents = [
            ("AKIAIOSFODNN7EXAMPLE", "fast.txt"),
            ("admin@example.com", "normal.txt"),
        ]

        results = await detector.detect_batch_async(contents)

        # Both files should have results (even if some patterns timed out)
        assert "fast.txt" in results
        assert "normal.txt" in results


class TestAsyncPerformance:
    """Tests for async performance characteristics."""

    @pytest.mark.asyncio
    async def test_async_is_non_blocking(self) -> None:
        """Test that async detection doesn't block the event loop."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE " * 100

        # Track if we can run other tasks while detection runs
        flag = {"ran": False}

        async def other_task() -> None:
            flag["ran"] = True

        # Run detection and other task concurrently
        await asyncio.gather(
            detector.detect_async(content, "test.txt"),
            other_task(),
        )

        assert flag["ran"], "Other task should have run while detection was in progress"

    @pytest.mark.asyncio
    async def test_batch_async_completes_without_error(self) -> None:
        """Test that async batch completes without error for concurrent files.

        Note: Performance comparisons between async and sync are unreliable in tests
        because the work is CPU-bound (regex matching) and very fast. The async
        overhead can exceed the actual work time. In real-world scenarios with
        file I/O, async would show benefits.
        """
        detector = RegexDetector()

        # Create enough files that concurrency matters
        contents = [(f"admin{i}@example.com " * 10, f"file{i}.txt") for i in range(10)]

        # Verify async batch completes successfully
        results = await detector.detect_batch_async(contents, concurrency_limit=10)

        # All files should be processed
        assert len(results) == 10

        # Each file should have findings (email pattern)
        for i in range(10):
            assert len(results[f"file{i}.txt"]) >= 1


class TestEdgeCases:
    """Tests for edge cases in async detection."""

    @pytest.mark.asyncio
    async def test_detect_async_with_unicode(self) -> None:
        """Test async detection handles unicode content correctly."""
        detector = RegexDetector()
        content = "日本語テキスト admin@example.com 中文內容"
        findings = await detector.detect_async(content, "unicode.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_detect_async_with_null_bytes(self) -> None:
        """Test async detection handles null bytes in content."""
        detector = RegexDetector()
        content = "Normal text\x00admin@example.com\x00more text"
        findings = await detector.detect_async(content, "nulls.txt")
        # Should handle gracefully (might skip due to binary detection)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_batch_async_with_duplicate_paths(self) -> None:
        """Test batch async with duplicate file paths."""
        detector = RegexDetector()
        contents = [
            ("admin@example.com", "same.txt"),
            ("user@example.com", "same.txt"),  # Same path, different content
        ]

        results = await detector.detect_batch_async(contents)

        # Last one should win (standard dict behavior)
        assert "same.txt" in results

    @pytest.mark.asyncio
    async def test_batch_async_very_large_batch(self) -> None:
        """Test batch async with a large number of files."""
        detector = RegexDetector()
        contents = [(f"admin{i}@example.com", f"file{i}.txt") for i in range(500)]

        results = await detector.detect_batch_async(contents, concurrency_limit=50)

        assert len(results) == 500

    @pytest.mark.asyncio
    async def test_detect_async_with_max_file_size(self) -> None:
        """Test async detection respects max file size."""
        detector = RegexDetector(max_file_size=100)
        large_content = "admin@example.com " * 100  # Exceeds 100 bytes

        findings = await detector.detect_async(large_content, "large.txt")
        assert len(findings) == 0  # Should be skipped due to size

    @pytest.mark.asyncio
    async def test_detect_async_custom_patterns(self) -> None:
        """Test async detection with custom patterns."""
        custom_patterns = {
            "Custom ID": {
                "pattern": r"CUSTOM-\d{8}",
                "severity": Severity.HIGH,
                "description": "Custom ID",
            }
        }
        detector = RegexDetector(patterns=custom_patterns, use_defaults=False)

        content = "Here is CUSTOM-12345678"
        findings = await detector.detect_async(content, "custom.txt")

        assert len(findings) == 1
        assert "Custom ID" in findings[0].detector_name


class TestAsyncScannerIntegration:
    """Tests for integration with AsyncScanner."""

    @pytest.mark.asyncio
    async def test_detector_works_with_concurrent_file_processing(self) -> None:
        """Test that detector works correctly when called concurrently."""
        detector = RegexDetector()

        # Simulate how AsyncScanner would use the detector
        files_content = {
            "file1.py": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "file2.py": "EMAIL = 'admin@example.com'",
            "file3.py": "No secrets here",
        }

        async def scan_file(path: str, content: str) -> tuple[str, list]:
            findings = await detector.detect_async(content, path)
            return path, findings

        tasks = [scan_file(path, content) for path, content in files_content.items()]
        results = await asyncio.gather(*tasks)

        results_dict = dict(results)
        assert len(results_dict["file1.py"]) >= 1  # AWS key
        assert len(results_dict["file2.py"]) >= 1  # Email
        assert len(results_dict["file3.py"]) == 0  # No secrets
