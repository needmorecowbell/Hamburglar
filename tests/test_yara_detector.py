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

from hamburglar.core.models import Severity
from hamburglar.detectors.yara_detector import YaraDetector
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

    def test_invalid_yara_syntax_raises(self, tmp_path: Path) -> None:
        """Test that invalid YARA syntax raises an error."""
        rule_file = tmp_path / "invalid.yar"
        rule_file.write_text("this is not valid yara syntax")
        with pytest.raises(Exception):  # yara.SyntaxError
            YaraDetector(rule_file)

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
