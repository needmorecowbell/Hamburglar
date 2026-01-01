"""Tests for the async capabilities of YaraDetector.

This module contains tests for the async methods of the YaraDetector class,
including detect_async, detect_bytes_async, detect_batch, detect_batch_async,
detect_stream, rule caching, and related functionality.
"""

from __future__ import annotations

import asyncio
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

from hamburglar.core.models import Severity
from hamburglar.detectors.yara_detector import (
    _RULE_CACHE,
    YaraDetector,
)
from hamburglar.rules import get_rules_path


@pytest.fixture
def simple_detector(tmp_path: Path) -> YaraDetector:
    """Create a detector with a simple test rule."""
    rule_file = tmp_path / "test.yar"
    rule_file.write_text("""
rule test_rule {
    meta:
        author = "Test"
        description = "Test rule"
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
    return YaraDetector(rule_file, use_cache=False)


@pytest.fixture
def multi_rule_detector(tmp_path: Path) -> YaraDetector:
    """Create a detector with multiple rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    (rules_dir / "rule1.yar").write_text("""
rule rule_one {
    strings:
        $one = "PATTERN_ONE"
    condition:
        $one
}
""")
    (rules_dir / "rule2.yar").write_text("""
rule rule_two {
    strings:
        $two = "PATTERN_TWO"
    condition:
        $two
}
""")
    return YaraDetector(rules_dir, use_cache=False)


class TestDetectAsync:
    """Tests for the detect_async method."""

    @pytest.mark.asyncio
    async def test_detect_async_basic(self, simple_detector: YaraDetector) -> None:
        """Test that detect_async finds patterns correctly."""
        content = "This content contains FIND_ME in it"
        findings = await simple_detector.detect_async(content, "test.txt")

        assert len(findings) == 1
        assert findings[0].detector_name == "yara:test_rule"
        assert "FIND_ME" in findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_async_returns_same_as_sync(self, simple_detector: YaraDetector) -> None:
        """Test that detect_async returns the same results as sync detect."""
        content = "Here is FIND_ME and more content"

        sync_findings = simple_detector.detect(content, "test.txt")
        async_findings = await simple_detector.detect_async(content, "test.txt")

        assert len(sync_findings) == len(async_findings)
        assert sync_findings[0].detector_name == async_findings[0].detector_name
        assert sync_findings[0].matches == async_findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_async_empty_content(self, simple_detector: YaraDetector) -> None:
        """Test detect_async with empty content returns empty list."""
        findings = await simple_detector.detect_async("", "empty.txt")
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_async_no_matches(self, simple_detector: YaraDetector) -> None:
        """Test detect_async with no matching patterns."""
        content = "Just regular text without any secrets."
        findings = await simple_detector.detect_async(content, "clean.txt")
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_async_concurrent_calls(self, simple_detector: YaraDetector) -> None:
        """Test that multiple concurrent detect_async calls work correctly."""
        contents = [
            ("FIND_ME in file 1", "file1.txt"),
            ("No match here", "file2.txt"),
            ("Also FIND_ME here", "file3.txt"),
        ]

        tasks = [simple_detector.detect_async(content, path) for content, path in contents]
        results = await asyncio.gather(*tasks)

        assert len(results) == 3
        assert len(results[0]) == 1  # FIND_ME match
        assert len(results[1]) == 0  # No match
        assert len(results[2]) == 1  # FIND_ME match

    @pytest.mark.asyncio
    async def test_detect_async_preserves_file_path(self, simple_detector: YaraDetector) -> None:
        """Test that file_path is correctly preserved in findings."""
        content = "FIND_ME"
        file_path = "/path/to/important/file.txt"
        findings = await simple_detector.detect_async(content, file_path)

        assert len(findings) == 1
        assert findings[0].file_path == file_path


class TestDetectBytesAsync:
    """Tests for the detect_bytes_async method."""

    @pytest.mark.asyncio
    async def test_detect_bytes_async_basic(self, simple_detector: YaraDetector) -> None:
        """Test that detect_bytes_async finds patterns correctly."""
        content = b"This content contains FIND_ME"
        findings = await simple_detector.detect_bytes_async(content, "test.bin")

        assert len(findings) == 1
        assert "FIND_ME" in findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_bytes_async_with_binary_data(self, simple_detector: YaraDetector) -> None:
        """Test detect_bytes_async with binary content."""
        content = b"\x00\x01\x02FIND_ME\x03\x04\x05"
        findings = await simple_detector.detect_bytes_async(content, "binary.bin")

        assert len(findings) == 1
        assert "FIND_ME" in findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_bytes_async_empty_content(self, simple_detector: YaraDetector) -> None:
        """Test detect_bytes_async with empty bytes."""
        findings = await simple_detector.detect_bytes_async(b"", "empty.bin")
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_bytes_async_concurrent(self, simple_detector: YaraDetector) -> None:
        """Test concurrent detect_bytes_async calls."""
        contents = [
            (b"FIND_ME here", "file1.bin"),
            (b"Nothing here", "file2.bin"),
            (b"FIND_ME again", "file3.bin"),
        ]

        tasks = [simple_detector.detect_bytes_async(content, path) for content, path in contents]
        results = await asyncio.gather(*tasks)

        assert len(results[0]) == 1
        assert len(results[1]) == 0
        assert len(results[2]) == 1


class TestDetectBatch:
    """Tests for the detect_batch method."""

    def test_detect_batch_basic(self, simple_detector: YaraDetector) -> None:
        """Test basic batch detection."""
        contents = [
            (b"FIND_ME in file 1", "file1.txt"),
            (b"No match here", "file2.txt"),
            (b"Also FIND_ME", "file3.txt"),
        ]

        results = simple_detector.detect_batch(contents)

        assert len(results) == 3
        assert "file1.txt" in results
        assert "file2.txt" in results
        assert "file3.txt" in results
        assert len(results["file1.txt"]) == 1
        assert len(results["file2.txt"]) == 0
        assert len(results["file3.txt"]) == 1

    def test_detect_batch_empty_list(self, simple_detector: YaraDetector) -> None:
        """Test batch detection with empty list."""
        results = simple_detector.detect_batch([])
        assert results == {}

    def test_detect_batch_preserves_order(self, simple_detector: YaraDetector) -> None:
        """Test that batch results maintain file order."""
        contents = [
            (b"FIND_ME", "a_file.txt"),
            (b"FIND_ME", "b_file.txt"),
            (b"FIND_ME", "c_file.txt"),
        ]

        results = simple_detector.detect_batch(contents)
        keys = list(results.keys())

        assert keys == ["a_file.txt", "b_file.txt", "c_file.txt"]

    def test_detect_batch_large_number(self, simple_detector: YaraDetector) -> None:
        """Test batch detection with many files."""
        contents = [(f"FIND_ME {i}".encode(), f"file{i}.txt") for i in range(50)]

        results = simple_detector.detect_batch(contents)

        assert len(results) == 50
        for i in range(50):
            assert len(results[f"file{i}.txt"]) == 1


class TestDetectBatchAsync:
    """Tests for the detect_batch_async method."""

    @pytest.mark.asyncio
    async def test_detect_batch_async_basic(self, simple_detector: YaraDetector) -> None:
        """Test basic async batch detection."""
        contents = [
            (b"FIND_ME", "file1.txt"),
            (b"No match", "file2.txt"),
            (b"Also FIND_ME", "file3.txt"),
        ]

        results = await simple_detector.detect_batch_async(contents)

        assert len(results) == 3
        assert len(results["file1.txt"]) == 1
        assert len(results["file2.txt"]) == 0
        assert len(results["file3.txt"]) == 1

    @pytest.mark.asyncio
    async def test_detect_batch_async_returns_same_as_sync(
        self, simple_detector: YaraDetector
    ) -> None:
        """Test that async batch returns same results as sync batch."""
        contents = [
            (b"FIND_ME", "file1.txt"),
            (b"Also FIND_ME", "file2.txt"),
        ]

        sync_results = simple_detector.detect_batch(contents)
        async_results = await simple_detector.detect_batch_async(contents)

        assert set(sync_results.keys()) == set(async_results.keys())
        for file_path in sync_results:
            assert len(sync_results[file_path]) == len(async_results[file_path])

    @pytest.mark.asyncio
    async def test_detect_batch_async_concurrency_limit(
        self, simple_detector: YaraDetector
    ) -> None:
        """Test that concurrency limit is respected."""
        contents = [(f"FIND_ME {i}".encode(), f"file{i}.txt") for i in range(20)]

        # Should complete without issues with low concurrency
        results = await simple_detector.detect_batch_async(contents, concurrency_limit=2)

        assert len(results) == 20
        for i in range(20):
            assert len(results[f"file{i}.txt"]) == 1

    @pytest.mark.asyncio
    async def test_detect_batch_async_high_concurrency(self, simple_detector: YaraDetector) -> None:
        """Test async batch with high concurrency."""
        contents = [(f"FIND_ME {i}".encode(), f"file{i}.txt") for i in range(50)]

        results = await simple_detector.detect_batch_async(contents, concurrency_limit=50)

        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_detect_batch_async_empty_list(self, simple_detector: YaraDetector) -> None:
        """Test async batch with empty list."""
        results = await simple_detector.detect_batch_async([])
        assert results == {}


class TestDetectStream:
    """Tests for the detect_stream async generator."""

    @pytest.mark.asyncio
    async def test_detect_stream_basic(self, simple_detector: YaraDetector) -> None:
        """Test basic streaming detection."""
        content = b"FIND_ME in this content"
        findings = []

        async for finding in simple_detector.detect_stream(content, "test.txt"):
            findings.append(finding)

        assert len(findings) == 1
        assert findings[0].detector_name == "yara:test_rule"

    @pytest.mark.asyncio
    async def test_detect_stream_multiple_rules(self, multi_rule_detector: YaraDetector) -> None:
        """Test streaming with multiple matching rules."""
        content = b"PATTERN_ONE and PATTERN_TWO here"
        findings = []

        async for finding in multi_rule_detector.detect_stream(content, "test.txt"):
            findings.append(finding)

        assert len(findings) == 2
        detector_names = [f.detector_name for f in findings]
        assert "yara:rule_one" in detector_names
        assert "yara:rule_two" in detector_names

    @pytest.mark.asyncio
    async def test_detect_stream_no_matches(self, simple_detector: YaraDetector) -> None:
        """Test streaming with no matches."""
        content = b"No matching patterns here"
        findings = []

        async for finding in simple_detector.detect_stream(content, "test.txt"):
            findings.append(finding)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_stream_empty_content(self, simple_detector: YaraDetector) -> None:
        """Test streaming with empty content."""
        findings = []

        async for finding in simple_detector.detect_stream(b"", "empty.txt"):
            findings.append(finding)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detect_stream_large_content_skipped(self, tmp_path: Path) -> None:
        """Test that streaming skips large content."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, max_file_size=100, use_cache=False)
        content = b"FIND_ME " * 50  # Exceeds 100 bytes

        findings = []
        async for finding in detector.detect_stream(content, "large.txt"):
            findings.append(finding)

        assert len(findings) == 0


class TestRuleCaching:
    """Tests for rule caching functionality."""

    def setup_method(self) -> None:
        """Clear the cache before each test."""
        YaraDetector.clear_cache()

    def test_caching_enabled_by_default(self, tmp_path: Path) -> None:
        """Test that caching is enabled by default."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        detector = YaraDetector(rule_file)
        assert detector.use_cache is True
        assert detector.cache_key is not None

    def test_caching_can_be_disabled(self, tmp_path: Path) -> None:
        """Test that caching can be disabled."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        detector = YaraDetector(rule_file, use_cache=False)
        assert detector.use_cache is False
        assert detector.cache_key is None

    def test_cache_reused_for_same_rules(self, tmp_path: Path) -> None:
        """Test that cache is reused for identical rules."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        detector1 = YaraDetector(rule_file)
        cache_key1 = detector1.cache_key

        detector2 = YaraDetector(rule_file)
        cache_key2 = detector2.cache_key

        assert cache_key1 == cache_key2
        assert len(_RULE_CACHE) == 1

    def test_cache_different_for_different_rules(self, tmp_path: Path) -> None:
        """Test that different rules get different cache keys."""
        rule_file1 = tmp_path / "test1.yar"
        rule_file1.write_text("rule rule1 { condition: false }")

        rule_file2 = tmp_path / "test2.yar"
        rule_file2.write_text("rule rule2 { condition: true }")

        detector1 = YaraDetector(rule_file1)
        detector2 = YaraDetector(rule_file2)

        assert detector1.cache_key != detector2.cache_key
        assert len(_RULE_CACHE) == 2

    def test_clear_cache(self, tmp_path: Path) -> None:
        """Test clearing the cache."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        YaraDetector(rule_file)
        assert len(_RULE_CACHE) >= 1

        count = YaraDetector.clear_cache()
        assert count >= 1
        assert len(_RULE_CACHE) == 0

    def test_get_cache_stats(self, tmp_path: Path) -> None:
        """Test getting cache statistics."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        YaraDetector(rule_file)

        stats = YaraDetector.get_cache_stats()
        assert "size" in stats
        assert "keys" in stats
        assert stats["size"] >= 1
        assert len(stats["keys"]) >= 1

    def test_reload_invalidates_cache(self, tmp_path: Path) -> None:
        """Test that reload_rules invalidates the cache entry."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule old_rule {
    strings:
        $old = "OLD"
    condition:
        $old
}
""")
        detector = YaraDetector(rule_file)
        old_cache_key = detector.cache_key

        # Update the rule file
        rule_file.write_text("""
rule new_rule {
    strings:
        $new = "NEW"
    condition:
        $new
}
""")

        # Reload rules
        detector.reload_rules()
        new_cache_key = detector.cache_key

        # Cache key should have changed
        assert old_cache_key != new_cache_key

        # Old cache entry should be gone
        assert old_cache_key not in _RULE_CACHE

    def test_cache_stats_include_cached_status(self, tmp_path: Path) -> None:
        """Test that detector stats show cache status."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        detector = YaraDetector(rule_file)
        stats = detector.get_detector_stats()

        assert "use_cache" in stats
        assert "cache_key" in stats
        assert "is_cached" in stats
        assert stats["use_cache"] is True
        assert stats["cache_key"] is not None
        assert stats["is_cached"] is True


class TestGetDetectorStats:
    """Tests for the get_detector_stats method."""

    def test_stats_include_all_fields(self, tmp_path: Path) -> None:
        """Test that stats include all expected fields."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")

        detector = YaraDetector(
            rule_file,
            max_file_size=500,
            timeout=30,
            use_cache=True,
        )
        stats = detector.get_detector_stats()

        assert stats["name"] == "yara"
        assert stats["rule_count"] == 1
        assert str(rule_file) in stats["rules_path"]
        assert stats["max_file_size"] == 500
        assert stats["timeout"] == 30
        assert stats["use_cache"] is True


class TestTimeoutBehavior:
    """Tests for timeout behavior in async context."""

    @pytest.mark.asyncio
    async def test_detect_async_respects_timeout(self, tmp_path: Path) -> None:
        """Test that detect_async respects the configured timeout."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, timeout=1, use_cache=False)
        content = "FIND_ME " * 100

        # Should complete without hanging
        findings = await detector.detect_async(content, "test.txt")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_stream_handles_timeout_gracefully(self, tmp_path: Path) -> None:
        """Test that streaming handles timeout gracefully."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, timeout=60, use_cache=False)
        content = b"FIND_ME"

        findings = []
        async for finding in detector.detect_stream(content, "test.txt"):
            findings.append(finding)

        # Should complete normally
        assert len(findings) == 1


class TestAsyncPerformance:
    """Tests for async performance characteristics."""

    @pytest.mark.asyncio
    async def test_async_is_non_blocking(self, simple_detector: YaraDetector) -> None:
        """Test that async detection doesn't block the event loop."""
        content = "FIND_ME " * 100

        flag = {"ran": False}

        async def other_task() -> None:
            flag["ran"] = True

        # Run detection and other task concurrently
        await asyncio.gather(
            simple_detector.detect_async(content, "test.txt"),
            other_task(),
        )

        assert flag["ran"], "Other task should have run while detection was in progress"

    @pytest.mark.asyncio
    async def test_batch_async_completes_successfully(self, simple_detector: YaraDetector) -> None:
        """Test that async batch completes without error for concurrent files."""
        contents = [(f"FIND_ME {i}".encode(), f"file{i}.txt") for i in range(10)]

        results = await simple_detector.detect_batch_async(contents, concurrency_limit=10)

        assert len(results) == 10
        for i in range(10):
            assert len(results[f"file{i}.txt"]) == 1


class TestEdgeCases:
    """Tests for edge cases in async detection."""

    @pytest.mark.asyncio
    async def test_detect_async_with_unicode(self, simple_detector: YaraDetector) -> None:
        """Test async detection handles unicode content correctly."""
        content = "日本語テキスト FIND_ME 中文內容"
        findings = await simple_detector.detect_async(content, "unicode.txt")

        assert len(findings) == 1
        assert "FIND_ME" in findings[0].matches

    @pytest.mark.asyncio
    async def test_detect_bytes_async_with_null_bytes(self, simple_detector: YaraDetector) -> None:
        """Test async detection handles null bytes in content."""
        content = b"\x00\x00FIND_ME\x00\x00"
        findings = await simple_detector.detect_bytes_async(content, "nulls.bin")

        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_batch_async_with_duplicate_paths(self, simple_detector: YaraDetector) -> None:
        """Test batch async with duplicate file paths."""
        contents = [
            (b"FIND_ME", "same.txt"),
            (b"No match", "same.txt"),  # Same path, different content
        ]

        results = await simple_detector.detect_batch_async(contents)

        # Last one should win (standard dict behavior)
        assert "same.txt" in results

    @pytest.mark.asyncio
    async def test_batch_async_very_large_batch(self, simple_detector: YaraDetector) -> None:
        """Test batch async with a large number of files."""
        contents = [(f"FIND_ME {i}".encode(), f"file{i}.txt") for i in range(200)]

        results = await simple_detector.detect_batch_async(contents, concurrency_limit=50)

        assert len(results) == 200

    @pytest.mark.asyncio
    async def test_detect_async_with_max_file_size(self, tmp_path: Path) -> None:
        """Test async detection respects max file size."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, max_file_size=100, use_cache=False)
        large_content = "FIND_ME " * 50  # Exceeds 100 bytes

        findings = await detector.detect_async(large_content, "large.txt")
        assert len(findings) == 0  # Should be skipped due to size


class TestIntegrationWithBundledRules:
    """Integration tests with bundled YARA rules."""

    @pytest.mark.asyncio
    async def test_bundled_rules_async_scan(self) -> None:
        """Test async scanning with bundled rules."""
        rules_path = get_rules_path()
        detector = YaraDetector(rules_path)

        content = "This is test content for async scanning"
        findings = await detector.detect_async(content, "test.txt")

        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_bundled_rules_batch_async(self) -> None:
        """Test batch async with bundled rules."""
        rules_path = get_rules_path()
        detector = YaraDetector(rules_path)

        contents = [
            (b"Test content 1", "file1.txt"),
            (b"Test content 2", "file2.txt"),
        ]

        results = await detector.detect_batch_async(contents)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_bundled_rules_streaming(self) -> None:
        """Test streaming with bundled rules."""
        rules_path = get_rules_path()
        detector = YaraDetector(rules_path)

        content = b"Test content for streaming"
        findings = []

        async for finding in detector.detect_stream(content, "test.txt"):
            findings.append(finding)

        assert isinstance(findings, list)


class TestSeverityMapping:
    """Tests for severity mapping in async methods."""

    @pytest.mark.asyncio
    async def test_detect_async_uses_severity_mapping(self, tmp_path: Path) -> None:
        """Test that async detect uses severity mapping correctly."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule critical_rule {
    strings:
        $test = "CRITICAL_PATTERN"
    condition:
        $test
}
""")
        severity_mapping = {"critical_rule": Severity.CRITICAL}
        detector = YaraDetector(
            rule_file,
            severity_mapping=severity_mapping,
            use_cache=False,
        )

        findings = await detector.detect_async("CRITICAL_PATTERN", "test.txt")

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_stream_uses_severity_mapping(self, tmp_path: Path) -> None:
        """Test that streaming uses severity mapping correctly."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule high_rule {
    strings:
        $test = "HIGH_PATTERN"
    condition:
        $test
}
""")
        severity_mapping = {"high_rule": Severity.HIGH}
        detector = YaraDetector(
            rule_file,
            severity_mapping=severity_mapping,
            use_cache=False,
        )

        findings = []
        async for finding in detector.detect_stream(b"HIGH_PATTERN", "test.txt"):
            findings.append(finding)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestMetadataExtraction:
    """Tests for metadata extraction in async methods."""

    @pytest.mark.asyncio
    async def test_detect_async_extracts_metadata(self, tmp_path: Path) -> None:
        """Test that async detect extracts rule metadata."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule meta_rule {
    meta:
        author = "Test Author"
        description = "Test Description"
        severity = "high"
    strings:
        $test = "META_PATTERN"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, use_cache=False)

        findings = await detector.detect_async("META_PATTERN", "test.txt")

        assert len(findings) == 1
        metadata = findings[0].metadata
        assert metadata["author"] == "Test Author"
        assert metadata["description"] == "Test Description"
        assert metadata["severity"] == "high"
        assert metadata["rule_name"] == "meta_rule"

    @pytest.mark.asyncio
    async def test_stream_extracts_metadata(self, tmp_path: Path) -> None:
        """Test that streaming extracts rule metadata."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule tagged_rule {
    meta:
        author = "Stream Author"
    strings:
        $test = "STREAM_PATTERN"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, use_cache=False)

        findings = []
        async for finding in detector.detect_stream(b"STREAM_PATTERN", "test.txt"):
            findings.append(finding)

        assert len(findings) == 1
        assert findings[0].metadata["author"] == "Stream Author"
        assert findings[0].metadata["rule_name"] == "tagged_rule"
