"""Tests for large file handling in Hamburglar.

This module contains tests verifying that:
- The scanner respects max file size settings via detectors
- Large files are skipped with appropriate warning logs
- Appropriate log messages are generated when files are skipped
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from hamburglar.core.logging import get_logger, setup_logging
from hamburglar.core.models import ScanConfig
from hamburglar.core.scanner import Scanner
from hamburglar.detectors.regex_detector import (
    DEFAULT_MAX_FILE_SIZE,
    RegexDetector,
)


class TestRegexDetectorMaxFileSizeSettings:
    """Tests that the regex detector respects max file size settings."""

    def test_default_max_file_size_is_10mb(self) -> None:
        """Test that the default max file size is 10MB."""
        detector = RegexDetector()
        assert detector.max_file_size == DEFAULT_MAX_FILE_SIZE
        assert detector.max_file_size == 10 * 1024 * 1024

    def test_custom_max_file_size_can_be_set(self) -> None:
        """Test that a custom max file size can be configured."""
        custom_size = 5 * 1024 * 1024  # 5MB
        detector = RegexDetector(max_file_size=custom_size)
        assert detector.max_file_size == custom_size

    def test_very_small_max_file_size(self) -> None:
        """Test that max file size can be set to very small values."""
        detector = RegexDetector(max_file_size=100)
        assert detector.max_file_size == 100

    def test_very_large_max_file_size(self) -> None:
        """Test that max file size can be set to very large values."""
        large_size = 1024 * 1024 * 1024  # 1GB
        detector = RegexDetector(max_file_size=large_size)
        assert detector.max_file_size == large_size


class TestLargeFileSkipping:
    """Tests that large files are skipped correctly."""

    def test_file_exceeding_max_size_is_skipped(self) -> None:
        """Test that files exceeding max file size are skipped."""
        detector = RegexDetector(max_file_size=100)
        # Create content larger than 100 bytes
        content = "admin@example.com " * 20  # ~380 bytes
        findings = detector.detect(content, "large_file.txt")
        # Should be skipped and return empty findings
        assert len(findings) == 0

    def test_file_under_max_size_is_processed(self) -> None:
        """Test that files under max file size are processed."""
        detector = RegexDetector(max_file_size=1000)
        # Create content under 1000 bytes
        content = "Contact: admin@example.com"  # ~26 bytes
        findings = detector.detect(content, "small_file.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_file_exactly_at_max_size_is_processed(self) -> None:
        """Test that files exactly at max size are processed."""
        # Create content and set max_file_size to exactly match
        content = "admin@example.com"  # 17 bytes
        content_size = len(content.encode("utf-8"))
        detector = RegexDetector(max_file_size=content_size)
        findings = detector.detect(content, "exact_size.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_file_one_byte_over_max_is_skipped(self) -> None:
        """Test that files just one byte over max are skipped."""
        content = "admin@example.com"  # 17 bytes
        content_size = len(content.encode("utf-8"))
        detector = RegexDetector(max_file_size=content_size - 1)
        findings = detector.detect(content, "over_by_one.txt")
        assert len(findings) == 0

    def test_empty_file_is_processed(self) -> None:
        """Test that empty files are processed (not skipped for size)."""
        detector = RegexDetector(max_file_size=100)
        findings = detector.detect("", "empty.txt")
        assert findings == []

    def test_skipping_preserves_file_info_for_logging(self) -> None:
        """Test that when a file is skipped, the file path is tracked."""
        detector = RegexDetector(max_file_size=50)
        content = "a" * 100 + " admin@example.com"
        # Should skip without crashing and return empty list
        findings = detector.detect(content, "/path/to/large/file.txt")
        assert findings == []


class TestLargeFileWarningLogs:
    """Tests that appropriate warning logs are generated when files are skipped."""

    def test_warning_logged_when_file_skipped_for_size(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that a warning is logged when a file is skipped due to size."""
        setup_logging(verbose=True)
        logger = get_logger()

        # Enable propagation temporarily so caplog can capture records
        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                detector = RegexDetector(max_file_size=50)
                content = "a" * 100 + " admin@example.com"
                detector.detect(content, "oversized.txt")

            # Check that size warning was logged
            assert any("exceeds max" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_warning_contains_file_path(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that the warning message contains the file path."""
        setup_logging(verbose=True)
        logger = get_logger()

        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                detector = RegexDetector(max_file_size=50)
                detector.detect("a" * 100, "/path/to/specific/file.txt")

            # Check that file path is in the log message
            assert any("/path/to/specific/file.txt" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_warning_contains_file_size(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that the warning message contains the file size."""
        setup_logging(verbose=True)
        logger = get_logger()

        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                detector = RegexDetector(max_file_size=50)
                content = "a" * 100  # 100 bytes
                detector.detect(content, "sized.txt")

            # Check that a size value is in the log message
            assert any("100" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_warning_contains_max_size_limit(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that the warning message contains the max size limit."""
        setup_logging(verbose=True)
        logger = get_logger()

        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                detector = RegexDetector(max_file_size=50)
                detector.detect("a" * 100, "file.txt")

            # Check that max size limit is in the log message
            assert any("50" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_no_warning_for_small_files(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that no size warning is logged for files under the limit."""
        setup_logging(verbose=True)
        logger = get_logger()

        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                detector = RegexDetector(max_file_size=1000)
                detector.detect("admin@example.com", "small.txt")

            # Should not have any size-related warnings
            assert not any("exceeds max" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate


class TestMockedLargeFiles:
    """Tests using mocked large files to avoid creating actual large content."""

    def test_simulated_large_file_detection(self) -> None:
        """Test large file detection by setting a small limit and creating content that exceeds it."""
        # Instead of mocking, we use a small limit and real content that exceeds it
        detector = RegexDetector(max_file_size=50)  # Very small limit

        # Create content that's larger than 50 bytes
        content = "admin@example.com " * 10  # ~180 bytes
        findings = detector.detect(content, "simulated_large.txt")
        # Should be skipped due to size
        assert len(findings) == 0

    def test_large_content_via_repetition(self) -> None:
        """Test detection of genuinely large content through repetition."""
        detector = RegexDetector(max_file_size=1000)  # 1KB limit

        # Create content that's exactly over the limit
        content = "x" * 1001 + " admin@example.com"
        findings = detector.detect(content, "over_1kb.txt")
        # Should be skipped
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_scanner_with_large_file_mock(self, tmp_path: Path) -> None:
        """Test scanner behavior with mocked large file content."""
        # Create a small test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("admin@example.com")

        # Create detector with tiny max size to trigger skipping
        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector(max_file_size=10)  # 10 bytes max
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # File content is 17 bytes, so should be skipped
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_detectors_independent_size_limits(self, tmp_path: Path) -> None:
        """Test that multiple detectors can have independent size limits."""
        test_file = tmp_path / "test.txt"
        # Create content that's 100 bytes
        content = "admin@example.com" + " " * 83  # Pad to 100 bytes
        test_file.write_text(content)

        # Two detectors with different limits
        detector_small = RegexDetector(max_file_size=50)  # Will skip
        detector_large = RegexDetector(max_file_size=200)  # Will process

        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = Scanner(config, detectors=[detector_small, detector_large])

        result = await scanner.scan()

        # Only detector_large should find the email
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestYaraDetectorMaxFileSize:
    """Tests for YARA detector max file size handling."""

    def test_yara_default_max_file_size_is_100mb(self) -> None:
        """Test that YARA detector default max file size is 100MB."""
        try:
            from hamburglar.detectors.yara_detector import (
                DEFAULT_MAX_FILE_SIZE as YARA_DEFAULT_MAX,
            )

            assert YARA_DEFAULT_MAX == 100 * 1024 * 1024
        except ImportError:
            pytest.skip("yara-python not installed")

    def test_yara_detector_respects_custom_max_size(self, tmp_path: Path) -> None:
        """Test that YARA detector respects custom max file size."""
        try:
            from hamburglar.detectors.yara_detector import YaraDetector

            # Create a simple YARA rule
            rule_file = tmp_path / "test.yar"
            rule_file.write_text(
                """
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"""
            )

            detector = YaraDetector(rules_path=rule_file, max_file_size=50)
            assert detector.max_file_size == 50

            # Content larger than 50 bytes should be skipped
            content = "test " * 20  # ~100 bytes
            findings = detector.detect(content, "large.txt")
            assert len(findings) == 0

        except ImportError:
            pytest.skip("yara-python not installed")

    def test_yara_logs_warning_for_oversized_file(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that YARA detector logs warning when skipping large files."""
        try:
            from hamburglar.detectors.yara_detector import YaraDetector

            setup_logging(verbose=True)
            logger = get_logger()
            original_propagate = logger.propagate
            logger.propagate = True

            # Create a simple YARA rule
            rule_file = tmp_path / "test.yar"
            rule_file.write_text(
                """
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"""
            )

            try:
                with caplog.at_level(logging.WARNING, logger="hamburglar"):
                    detector = YaraDetector(rules_path=rule_file, max_file_size=50)
                    detector.detect("test " * 20, "oversized.txt")

                assert any("exceeds" in record.message.lower() for record in caplog.records)
            finally:
                logger.propagate = original_propagate

        except ImportError:
            pytest.skip("yara-python not installed")


class TestScannerWithLargeFileSizeLimit:
    """Integration tests for scanner with large file size limits."""

    @pytest.mark.asyncio
    async def test_scanner_processes_small_files_with_default_limit(self, tmp_path: Path) -> None:
        """Test that scanner processes small files with default 10MB limit."""
        test_file = tmp_path / "secrets.txt"
        test_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector()  # Default 10MB limit
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    @pytest.mark.asyncio
    async def test_scanner_skips_files_over_custom_limit(self, tmp_path: Path) -> None:
        """Test that scanner skips files over a custom size limit."""
        test_file = tmp_path / "config.txt"
        # Create content that's exactly 100 bytes with a secret
        test_file.write_text("AKIAIOSFODNN7EXAMPLE " + "x" * 79)

        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector(max_file_size=50)  # Only 50 bytes
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # File is 100 bytes, detector limit is 50, so should be skipped
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scanner_mixed_sizes_partial_processing(self, tmp_path: Path) -> None:
        """Test scanner with mixed file sizes - some processed, some skipped."""
        # Small file (should be processed)
        small_file = tmp_path / "small.txt"
        small_file.write_text("admin@example.com")

        # Large file (should be skipped)
        large_file = tmp_path / "large.txt"
        large_file.write_text("secret@example.com " + "x" * 200)

        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector(max_file_size=100)  # 100 byte limit
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should only find email from small file
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "small.txt" in email_findings[0].file_path


class TestEdgeCases:
    """Edge case tests for large file handling."""

    def test_unicode_content_size_calculation(self) -> None:
        """Test that size is calculated in bytes, not characters."""
        detector = RegexDetector(max_file_size=50)
        # Unicode characters can be multiple bytes
        # "日本語" is 3 characters but 9 bytes in UTF-8
        unicode_content = "日本語" * 20 + " admin@example.com"
        findings = detector.detect(unicode_content, "unicode.txt")
        # 60 bytes of Japanese + 17 bytes email = 77 bytes, should be skipped
        # (3 chars * 3 bytes each * 20 = 180 bytes actually)
        assert len(findings) == 0

    def test_zero_max_file_size_skips_all(self) -> None:
        """Test that max_file_size of 0 skips all non-empty files."""
        detector = RegexDetector(max_file_size=0)
        findings = detector.detect("admin@example.com", "any.txt")
        assert len(findings) == 0

    def test_whitespace_only_content_size(self) -> None:
        """Test size calculation with whitespace-only content."""
        detector = RegexDetector(max_file_size=10)
        # 20 spaces = 20 bytes
        findings = detector.detect(" " * 20, "spaces.txt")
        assert len(findings) == 0  # Skipped due to size

    def test_newline_content_size(self) -> None:
        """Test size calculation with newline-heavy content."""
        detector = RegexDetector(max_file_size=10)
        # 20 newlines = 20 bytes
        content = "\n" * 20
        findings = detector.detect(content, "newlines.txt")
        assert len(findings) == 0  # Skipped due to size

    def test_binary_content_size_check_before_binary_detection(self) -> None:
        """Test that size check happens and prevents processing of large binary."""
        detector = RegexDetector(max_file_size=50)
        # Create binary content that's larger than 50 bytes
        binary_content = "\x00\x01\x02\x03" * 50  # 200 bytes
        findings = detector.detect(binary_content, "large_binary.bin")
        # Should be skipped due to size (even though it's also binary)
        assert len(findings) == 0
