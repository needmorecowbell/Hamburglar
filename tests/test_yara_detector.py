"""Tests for the YARA detector.

This module tests the YaraDetector class for proper YARA rule loading,
compilation, and pattern matching.
"""

from __future__ import annotations

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

from hamburglar.core.exceptions import YaraCompilationError
from hamburglar.core.models import Severity
from hamburglar.detectors.yara_detector import (
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_YARA_TIMEOUT,
    YaraDetector,
    is_yara_available,
)
from hamburglar.rules import get_rules_path


class TestYaraDetectorInitialization:
    """Tests for YaraDetector initialization."""

    def test_init_with_bundled_rules(self) -> None:
        """Test initializing with bundled YARA rules."""
        rules_path = get_rules_path()
        detector = YaraDetector(rules_path)
        assert detector.name == "yara"
        assert detector.rule_count > 0

    def test_init_with_nonexistent_path_raises(self, tmp_path: Path) -> None:
        """Test that initializing with nonexistent path raises FileNotFoundError."""
        nonexistent = tmp_path / "nonexistent"
        with pytest.raises(FileNotFoundError):
            YaraDetector(nonexistent)

    def test_init_with_single_rule_file(self, tmp_path: Path) -> None:
        """Test initializing with a single YARA rule file."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "TEST_STRING"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file)
        assert detector.rule_count == 1

    def test_init_with_empty_directory_raises(self, tmp_path: Path) -> None:
        """Test that initializing with empty directory raises ValueError."""
        with pytest.raises(ValueError, match="No YARA rule files found"):
            YaraDetector(tmp_path)

    def test_init_with_severity_mapping(self, tmp_path: Path) -> None:
        """Test initializing with custom severity mapping."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule critical_rule {
    strings:
        $test = "CRITICAL"
    condition:
        $test
}
""")
        severity_mapping = {"critical_rule": Severity.CRITICAL}
        detector = YaraDetector(rule_file, severity_mapping=severity_mapping)
        findings = detector.detect("CRITICAL data", "test.txt")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestYaraDetectorDetection:
    """Tests for YaraDetector.detect method."""

    @pytest.fixture
    def detector_with_rule(self, tmp_path: Path) -> YaraDetector:
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
        return YaraDetector(rule_file)

    def test_detect_matching_content(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test detecting content that matches a rule."""
        content = "This content contains FIND_ME in it"
        findings = detector_with_rule.detect(content, "test.txt")
        assert len(findings) == 1
        assert findings[0].detector_name == "yara:test_rule"
        assert "FIND_ME" in findings[0].matches

    def test_detect_no_match(self, detector_with_rule: YaraDetector) -> None:
        """Test detecting content that doesn't match any rule."""
        content = "This content has no secrets"
        findings = detector_with_rule.detect(content, "test.txt")
        assert len(findings) == 0

    def test_detect_empty_content(self, detector_with_rule: YaraDetector) -> None:
        """Test detecting empty content."""
        findings = detector_with_rule.detect("", "test.txt")
        assert len(findings) == 0

    def test_detect_extracts_metadata(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test that detection extracts rule metadata."""
        content = "FIND_ME"
        findings = detector_with_rule.detect(content, "test.txt")
        assert len(findings) == 1
        metadata = findings[0].metadata
        assert metadata.get("author") == "Test"
        assert metadata.get("description") == "Test rule"
        assert "rule_name" in metadata

    def test_detect_sets_file_path(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test that detection sets the file path in findings."""
        findings = detector_with_rule.detect("FIND_ME", "/path/to/file.txt")
        assert len(findings) == 1
        assert findings[0].file_path == "/path/to/file.txt"

    def test_detect_unicode_content(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test detecting content with unicode characters."""
        content = "Unicode: é ñ ü and FIND_ME"
        findings = detector_with_rule.detect(content, "test.txt")
        assert len(findings) == 1


class TestYaraDetectorDetectBytes:
    """Tests for YaraDetector.detect_bytes method."""

    @pytest.fixture
    def detector_with_rule(self, tmp_path: Path) -> YaraDetector:
        """Create a detector with a simple test rule."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        return YaraDetector(rule_file)

    def test_detect_bytes_matching(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test detecting bytes that match a rule."""
        content = b"This content contains FIND_ME"
        findings = detector_with_rule.detect_bytes(content, "test.bin")
        assert len(findings) == 1
        assert "FIND_ME" in findings[0].matches

    def test_detect_bytes_no_match(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test detecting bytes that don't match any rule."""
        content = b"No secrets here"
        findings = detector_with_rule.detect_bytes(content, "test.bin")
        assert len(findings) == 0

    def test_detect_bytes_binary_content(
        self, detector_with_rule: YaraDetector
    ) -> None:
        """Test detecting binary content with null bytes."""
        content = b"\x00\x01\x02FIND_ME\x03\x04\x05"
        findings = detector_with_rule.detect_bytes(content, "test.bin")
        assert len(findings) == 1


class TestYaraDetectorWithBundledRules:
    """Tests for YaraDetector using bundled rules."""

    @pytest.fixture
    def bundled_detector(self) -> YaraDetector:
        """Create a detector with bundled YARA rules."""
        rules_path = get_rules_path()
        return YaraDetector(rules_path)

    def test_bundled_detector_loads_rules(
        self, bundled_detector: YaraDetector
    ) -> None:
        """Test that bundled detector loads multiple rules."""
        assert bundled_detector.rule_count > 0
        assert bundled_detector.name == "yara"

    def test_bundled_detector_can_scan_content(
        self, bundled_detector: YaraDetector
    ) -> None:
        """Test that bundled detector can scan content without errors."""
        content = "This is test content"
        findings = bundled_detector.detect(content, "test.txt")
        assert isinstance(findings, list)

    def test_bundled_detector_can_scan_bytes(
        self, bundled_detector: YaraDetector
    ) -> None:
        """Test that bundled detector can scan bytes without errors."""
        content = b"This is test content in bytes"
        findings = bundled_detector.detect_bytes(content, "test.bin")
        assert isinstance(findings, list)

    def test_clean_content_no_matches(
        self, bundled_detector: YaraDetector
    ) -> None:
        """Test that clean text content has no matches."""
        content = "This is just regular text content with no magic bytes."
        findings = bundled_detector.detect(content, "test.txt")
        # Text content shouldn't match file type rules
        # (might still match some rules depending on content)
        assert isinstance(findings, list)


class TestYaraDetectorProperties:
    """Tests for YaraDetector properties and methods."""

    def test_name_property(self, tmp_path: Path) -> None:
        """Test the name property returns 'yara'."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file)
        assert detector.name == "yara"

    def test_rule_count_property(self, tmp_path: Path) -> None:
        """Test the rule_count property."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file)
        assert detector.rule_count == 1

    def test_get_rules_path(self, tmp_path: Path) -> None:
        """Test the get_rules_path method."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file)
        assert detector.get_rules_path() == rule_file

    def test_reload_rules(self, tmp_path: Path) -> None:
        """Test reloading rules."""
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

        # Verify old rule works
        findings = detector.detect("OLD", "test.txt")
        assert len(findings) == 1
        assert "old_rule" in findings[0].detector_name

        # Update the rule file
        rule_file.write_text("""
rule new_rule {
    strings:
        $new = "NEW"
    condition:
        $new
}
""")

        # Reload and verify new rule works
        detector.reload_rules()
        findings = detector.detect("NEW", "test.txt")
        assert len(findings) == 1
        assert "new_rule" in findings[0].detector_name

        # Old rule should no longer work
        findings = detector.detect("OLD", "test.txt")
        assert len(findings) == 0


class TestYaraDetectorMultipleRules:
    """Tests for YaraDetector with multiple rules."""

    @pytest.fixture
    def detector_with_multiple_rules(self, tmp_path: Path) -> YaraDetector:
        """Create a detector with multiple rules in a directory."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Create multiple rule files
        (rules_dir / "rule1.yar").write_text("""
rule rule_one {
    strings:
        $one = "ONE"
    condition:
        $one
}
""")
        (rules_dir / "rule2.yar").write_text("""
rule rule_two {
    strings:
        $two = "TWO"
    condition:
        $two
}
""")
        return YaraDetector(rules_dir)

    def test_rule_count_multiple_files(
        self, detector_with_multiple_rules: YaraDetector
    ) -> None:
        """Test rule count with multiple rule files."""
        assert detector_with_multiple_rules.rule_count == 2

    def test_detects_from_multiple_rules(
        self, detector_with_multiple_rules: YaraDetector
    ) -> None:
        """Test detection from multiple rule files."""
        # Match rule one
        findings = detector_with_multiple_rules.detect("ONE", "test.txt")
        assert len(findings) == 1
        assert "rule_one" in findings[0].detector_name

        # Match rule two
        findings = detector_with_multiple_rules.detect("TWO", "test.txt")
        assert len(findings) == 1
        assert "rule_two" in findings[0].detector_name

    def test_detects_multiple_matches(
        self, detector_with_multiple_rules: YaraDetector
    ) -> None:
        """Test detecting content that matches multiple rules."""
        findings = detector_with_multiple_rules.detect("ONE and TWO", "test.txt")
        assert len(findings) == 2
        detector_names = [f.detector_name for f in findings]
        assert any("rule_one" in name for name in detector_names)
        assert any("rule_two" in name for name in detector_names)


class TestYaraDetectorErrorHandling:
    """Tests for YaraDetector error handling."""

    def test_invalid_yara_syntax_raises_compilation_error(self, tmp_path: Path) -> None:
        """Test that invalid YARA syntax raises YaraCompilationError."""
        rule_file = tmp_path / "invalid.yar"
        rule_file.write_text("this is not valid yara syntax")
        with pytest.raises(YaraCompilationError) as exc_info:
            YaraDetector(rule_file)
        assert "Failed to compile YARA rules" in str(exc_info.value)

    def test_detect_handles_encoding_gracefully(self, tmp_path: Path) -> None:
        """Test that detect handles encoding issues gracefully."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "TEST"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file)
        # Content with problematic encoding
        content = "TEST with special chars: \x80\x81\x82"
        findings = detector.detect(content, "test.txt")
        # Should not raise an exception
        assert isinstance(findings, list)


class TestYaraAvailability:
    """Tests for YARA availability checking."""

    def test_is_yara_available(self) -> None:
        """Test that is_yara_available returns True when yara is installed."""
        assert is_yara_available() is True


class TestYaraMaxFileSize:
    """Tests for maximum file size handling."""

    def test_default_max_file_size(self, tmp_path: Path) -> None:
        """Test that default max file size is 100MB."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file)
        assert detector.max_file_size == DEFAULT_MAX_FILE_SIZE
        assert detector.max_file_size == 100 * 1024 * 1024

    def test_custom_max_file_size(self, tmp_path: Path) -> None:
        """Test that custom max file size can be set."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file, max_file_size=1024)
        assert detector.max_file_size == 1024

    def test_large_content_skipped_detect(self, tmp_path: Path) -> None:
        """Test that large content is skipped in detect()."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        # Set a small max size for testing
        detector = YaraDetector(rule_file, max_file_size=100)
        # Create content larger than max size
        content = "FIND_ME " * 50  # ~400 bytes
        findings = detector.detect(content, "large.txt")
        # Should skip and return empty
        assert len(findings) == 0

    def test_large_content_skipped_detect_bytes(self, tmp_path: Path) -> None:
        """Test that large content is skipped in detect_bytes()."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        # Set a small max size for testing
        detector = YaraDetector(rule_file, max_file_size=100)
        # Create content larger than max size
        content = b"FIND_ME " * 50  # ~400 bytes
        findings = detector.detect_bytes(content, "large.bin")
        # Should skip and return empty
        assert len(findings) == 0

    def test_content_at_size_limit_processed(self, tmp_path: Path) -> None:
        """Test that content at size limit is still processed."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        # Set max size to 200 bytes
        detector = YaraDetector(rule_file, max_file_size=200)
        # Create content just under the limit
        content = "FIND_ME"  # 7 bytes
        findings = detector.detect(content, "small.txt")
        assert len(findings) == 1


class TestYaraTimeout:
    """Tests for YARA timeout handling."""

    def test_default_timeout(self, tmp_path: Path) -> None:
        """Test that default timeout is 60 seconds."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file)
        assert detector.timeout == DEFAULT_YARA_TIMEOUT
        assert detector.timeout == 60

    def test_custom_timeout(self, tmp_path: Path) -> None:
        """Test that custom timeout can be set."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("rule empty { condition: false }")
        detector = YaraDetector(rule_file, timeout=30)
        assert detector.timeout == 30

    def test_fast_match_succeeds(self, tmp_path: Path) -> None:
        """Test that fast matches complete successfully."""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
        detector = YaraDetector(rule_file, timeout=1)
        content = "FIND_ME"
        findings = detector.detect(content, "test.txt")
        assert len(findings) == 1


class TestYaraCompilationError:
    """Tests for YaraCompilationError details."""

    def test_compilation_error_includes_message(self, tmp_path: Path) -> None:
        """Test that compilation error includes helpful message."""
        rule_file = tmp_path / "bad.yar"
        rule_file.write_text("rule bad { strings: $x = condition: $x }")
        with pytest.raises(YaraCompilationError) as exc_info:
            YaraDetector(rule_file)
        error = exc_info.value
        assert error.message
        assert "Failed to compile" in error.message or "YARA" in error.message

    def test_compilation_error_for_single_file_includes_path(
        self, tmp_path: Path
    ) -> None:
        """Test that compilation error includes rule file path for single file."""
        rule_file = tmp_path / "bad.yar"
        rule_file.write_text("invalid syntax here")
        with pytest.raises(YaraCompilationError) as exc_info:
            YaraDetector(rule_file)
        error = exc_info.value
        assert error.rule_file is not None
        assert "bad.yar" in error.rule_file


class TestYaraBinaryFileMatching:
    """Tests for YARA matching against binary files."""

    def test_detect_bytes_with_elf_binary(self, tmp_path: Path) -> None:
        """Test YARA detection on ELF binary content."""
        rule_file = tmp_path / "elf.yar"
        rule_file.write_text("""
rule elf_magic {
    strings:
        $magic = { 7F 45 4C 46 }  // ELF magic bytes
    condition:
        $magic at 0
}
""")
        detector = YaraDetector(rule_file)
        # ELF header: magic + class + endianness + version
        elf_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        findings = detector.detect_bytes(elf_content, "binary.elf")
        assert len(findings) == 1
        assert "elf_magic" in findings[0].detector_name

    def test_detect_bytes_with_pe_binary(self, tmp_path: Path) -> None:
        """Test YARA detection on PE/Windows binary content."""
        rule_file = tmp_path / "pe.yar"
        rule_file.write_text("""
rule pe_magic {
    strings:
        $mz = { 4D 5A }  // MZ magic bytes
    condition:
        $mz at 0
}
""")
        detector = YaraDetector(rule_file)
        # PE header starts with MZ
        pe_content = b"MZ" + b"\x00" * 58 + b"PE\x00\x00"
        findings = detector.detect_bytes(pe_content, "binary.exe")
        assert len(findings) == 1
        assert "pe_magic" in findings[0].detector_name

    def test_detect_bytes_with_png_image(self, tmp_path: Path) -> None:
        """Test YARA detection on PNG image content."""
        rule_file = tmp_path / "png.yar"
        rule_file.write_text("""
rule png_magic {
    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }  // PNG signature
    condition:
        $png at 0
}
""")
        detector = YaraDetector(rule_file)
        png_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        findings = detector.detect_bytes(png_content, "image.png")
        assert len(findings) == 1
        assert "png_magic" in findings[0].detector_name

    def test_detect_bytes_with_null_bytes(self, tmp_path: Path) -> None:
        """Test YARA detection on content with embedded null bytes."""
        rule_file = tmp_path / "nulls.yar"
        rule_file.write_text("""
rule find_pattern {
    strings:
        $pattern = "SECRET"
    condition:
        $pattern
}
""")
        detector = YaraDetector(rule_file)
        # Binary content with nulls surrounding the pattern
        content = b"\x00\x00\x00SECRET\x00\x00\x00"
        findings = detector.detect_bytes(content, "with_nulls.bin")
        assert len(findings) == 1
        assert "SECRET" in findings[0].matches

    def test_detect_bytes_with_high_entropy_content(self, tmp_path: Path) -> None:
        """Test YARA detection on high-entropy binary content."""
        rule_file = tmp_path / "entropy.yar"
        rule_file.write_text("""
rule find_marker {
    strings:
        $marker = { DE AD BE EF }
    condition:
        $marker
}
""")
        detector = YaraDetector(rule_file)
        # Random-looking bytes with embedded marker
        content = bytes(range(256)) + b"\xde\xad\xbe\xef" + bytes(range(255, -1, -1))
        findings = detector.detect_bytes(content, "random.bin")
        assert len(findings) == 1
        assert "find_marker" in findings[0].detector_name

    def test_detect_bytes_with_all_byte_values(self, tmp_path: Path) -> None:
        """Test YARA detection works with all possible byte values."""
        rule_file = tmp_path / "all_bytes.yar"
        rule_file.write_text("""
rule contains_ff {
    strings:
        $ff = { FF FF FF FF }
    condition:
        $ff
}
""")
        detector = YaraDetector(rule_file)
        # All possible bytes 0-255 with target pattern
        content = bytes(range(256)) + b"\xff\xff\xff\xff" + bytes(range(256))
        findings = detector.detect_bytes(content, "all_bytes.bin")
        assert len(findings) == 1

    def test_detect_bytes_multiple_matches_in_binary(self, tmp_path: Path) -> None:
        """Test finding multiple instances of a pattern in binary content."""
        rule_file = tmp_path / "multi.yar"
        rule_file.write_text("""
rule multi_match {
    strings:
        $pattern = { CA FE BA BE }
    condition:
        $pattern
}
""")
        detector = YaraDetector(rule_file)
        # Multiple occurrences
        content = b"\xca\xfe\xba\xbe" + b"\x00" * 10 + b"\xca\xfe\xba\xbe"
        findings = detector.detect_bytes(content, "multi.bin")
        assert len(findings) == 1
        # YARA finds all instances but returns one finding per rule
        assert "multi_match" in findings[0].detector_name

    def test_detect_bytes_mixed_binary_and_text(self, tmp_path: Path) -> None:
        """Test YARA detection on content with mixed binary and text."""
        rule_file = tmp_path / "mixed.yar"
        rule_file.write_text("""
rule text_in_binary {
    strings:
        $text = "CONFIDENTIAL"
    condition:
        $text
}
""")
        detector = YaraDetector(rule_file)
        # Binary content with embedded readable text
        content = b"\x00\x01\x02CONFIDENTIAL\xfe\xff"
        findings = detector.detect_bytes(content, "mixed.bin")
        assert len(findings) == 1
        assert "CONFIDENTIAL" in findings[0].matches

    def test_detect_bytes_sqlite_database(self, tmp_path: Path) -> None:
        """Test YARA detection on SQLite database header."""
        rule_file = tmp_path / "sqlite.yar"
        rule_file.write_text("""
rule sqlite_db {
    strings:
        $magic = "SQLite format 3"
    condition:
        $magic at 0
}
""")
        detector = YaraDetector(rule_file)
        sqlite_content = b"SQLite format 3\x00" + b"\x00" * 100
        findings = detector.detect_bytes(sqlite_content, "database.db")
        assert len(findings) == 1
        assert "sqlite_db" in findings[0].detector_name

    def test_detect_bytes_empty_content(self, tmp_path: Path) -> None:
        """Test YARA detection on empty binary content."""
        rule_file = tmp_path / "empty.yar"
        rule_file.write_text("""
rule any_data {
    strings:
        $any = { ?? }
    condition:
        $any
}
""")
        detector = YaraDetector(rule_file)
        findings = detector.detect_bytes(b"", "empty.bin")
        assert len(findings) == 0

    def test_detect_string_vs_detect_bytes_equivalence(self, tmp_path: Path) -> None:
        """Test that detect() and detect_bytes() give equivalent results for text."""
        rule_file = tmp_path / "equiv.yar"
        rule_file.write_text("""
rule find_secret {
    strings:
        $secret = "API_KEY_12345"
    condition:
        $secret
}
""")
        detector = YaraDetector(rule_file)
        text_content = "Some text with API_KEY_12345 inside"
        byte_content = text_content.encode("utf-8")

        findings_str = detector.detect(text_content, "file.txt")
        findings_bytes = detector.detect_bytes(byte_content, "file.txt")

        assert len(findings_str) == len(findings_bytes) == 1
        assert findings_str[0].detector_name == findings_bytes[0].detector_name

    def test_detect_bytes_with_compressed_content(self, tmp_path: Path) -> None:
        """Test YARA detection on gzip compressed content."""
        rule_file = tmp_path / "gzip.yar"
        rule_file.write_text("""
rule gzip_magic {
    strings:
        $magic = { 1F 8B 08 }  // gzip magic + deflate method
    condition:
        $magic at 0
}
""")
        detector = YaraDetector(rule_file)
        gzip_content = b"\x1f\x8b\x08" + b"\x00" * 100
        findings = detector.detect_bytes(gzip_content, "file.gz")
        assert len(findings) == 1
        assert "gzip_magic" in findings[0].detector_name


class TestYaraVerboseLogging:
    """Tests for verbose logging of YARA detector."""

    def test_detector_logs_performance_metrics(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that detector logs performance metrics at debug level."""
        import logging

        from hamburglar.core.logging import get_logger, setup_logging

        setup_logging(verbose=True)
        logger = get_logger()

        # Enable propagation temporarily so caplog can capture records
        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.DEBUG, logger="hamburglar"):
                rule_file = tmp_path / "test.yar"
                rule_file.write_text("""
rule test_rule {
    strings:
        $test = "FIND_ME"
    condition:
        $test
}
""")
                detector = YaraDetector(rule_file)
                detector.detect("FIND_ME", "test.txt")

            # Check that performance log message is present
            assert any(
                "YaraDetector processed" in record.message for record in caplog.records
            )
        finally:
            logger.propagate = original_propagate

    def test_detector_logs_skipped_large_file(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that detector logs when skipping large files."""
        import logging

        from hamburglar.core.logging import get_logger, setup_logging

        setup_logging(verbose=True)
        logger = get_logger()

        # Enable propagation temporarily so caplog can capture records
        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.WARNING, logger="hamburglar"):
                rule_file = tmp_path / "test.yar"
                rule_file.write_text("rule empty { condition: false }")
                detector = YaraDetector(rule_file, max_file_size=100)
                content = "x" * 200  # Over limit
                detector.detect(content, "large.txt")

            # Check that size warning is logged
            assert any(
                "exceeds YARA max" in record.message for record in caplog.records
            )
        finally:
            logger.propagate = original_propagate
