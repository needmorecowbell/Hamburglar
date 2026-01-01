"""Tests for the DetectorPlugin base class.

This module tests the DetectorPlugin abstract base class and its utility methods
for building custom detector plugins.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# Ensure src path is in sys.path for imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector, default_registry
from hamburglar.plugins.detector_plugin import DetectorPlugin


class SimpleDetectorPlugin(DetectorPlugin):
    """A simple detector plugin for testing."""

    __version__ = "2.0.0"
    __author__ = "Test Author"

    @property
    def name(self) -> str:
        return "simple_test_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return self.match_pattern(
            content=content,
            file_path=file_path,
            pattern=r"TEST_SECRET_[A-Z0-9]{8}",
            severity=Severity.HIGH,
        )


class ConfigurableDetectorPlugin(DetectorPlugin):
    """A configurable detector plugin for testing."""

    @property
    def name(self) -> str:
        return "configurable_detector"

    @property
    def description(self) -> str:
        return "A configurable test detector"

    @property
    def supported_extensions(self) -> list[str]:
        return self.get_config("extensions", [".py", ".js"])

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        pattern = self.get_config("pattern", r"SECRET_\w+")
        severity_str = self.get_config("severity", "medium")
        severity = Severity(severity_str)
        return self.match_pattern(
            content=content,
            file_path=file_path,
            pattern=pattern,
            severity=severity,
        )


class MultiPatternDetectorPlugin(DetectorPlugin):
    """A multi-pattern detector plugin for testing."""

    @property
    def name(self) -> str:
        return "multi_pattern_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return self.match_patterns(
            content=content,
            file_path=file_path,
            patterns=[
                r"API_KEY_[A-Z0-9]+",
                r"TOKEN_[A-Z0-9]+",
                r"SECRET_[A-Z0-9]+",
            ],
            severity=Severity.HIGH,
        )


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset detector registry before each test."""
    # Store original detectors
    original = dict(default_registry._detectors)
    yield
    # Restore original detectors
    default_registry._detectors = original


class TestDetectorPluginBasics:
    """Basic tests for DetectorPlugin class."""

    def test_init_default(self) -> None:
        """Test DetectorPlugin initialization with defaults."""
        detector = SimpleDetectorPlugin()
        assert detector.name == "simple_test_detector"
        assert detector.config == {}

    def test_init_with_config(self) -> None:
        """Test DetectorPlugin initialization with configuration."""
        detector = ConfigurableDetectorPlugin(
            pattern=r"CUSTOM_\w+",
            severity="high",
            extensions=[".txt"],
        )
        assert detector.config == {
            "pattern": r"CUSTOM_\w+",
            "severity": "high",
            "extensions": [".txt"],
        }

    def test_name_property(self) -> None:
        """Test name property returns correct value."""
        detector = SimpleDetectorPlugin()
        assert detector.name == "simple_test_detector"

    def test_description_property_from_docstring(self) -> None:
        """Test description property from docstring."""
        detector = SimpleDetectorPlugin()
        assert "simple detector plugin" in detector.description.lower()

    def test_description_property_override(self) -> None:
        """Test overridden description property."""
        detector = ConfigurableDetectorPlugin()
        assert detector.description == "A configurable test detector"

    def test_version_property(self) -> None:
        """Test version property."""
        detector = SimpleDetectorPlugin()
        assert detector.version == "2.0.0"

    def test_version_property_default(self) -> None:
        """Test version property default value."""
        detector = ConfigurableDetectorPlugin()
        assert detector.version == "1.0.0"

    def test_author_property(self) -> None:
        """Test author property."""
        detector = SimpleDetectorPlugin()
        assert detector.author == "Test Author"

    def test_author_property_default(self) -> None:
        """Test author property default value."""
        detector = ConfigurableDetectorPlugin()
        assert detector.author == ""


class TestDetectorPluginConfig:
    """Tests for DetectorPlugin configuration."""

    def test_get_config_existing_key(self) -> None:
        """Test get_config with existing key."""
        detector = ConfigurableDetectorPlugin(pattern=r"CUSTOM_\w+")
        assert detector.get_config("pattern") == r"CUSTOM_\w+"

    def test_get_config_missing_key(self) -> None:
        """Test get_config with missing key returns None."""
        detector = ConfigurableDetectorPlugin()
        assert detector.get_config("nonexistent") is None

    def test_get_config_with_default(self) -> None:
        """Test get_config with default value."""
        detector = ConfigurableDetectorPlugin()
        assert detector.get_config("nonexistent", "default") == "default"

    def test_config_property_returns_copy(self) -> None:
        """Test that config property returns a copy."""
        detector = ConfigurableDetectorPlugin(key="value")
        config = detector.config
        config["key"] = "modified"
        assert detector.get_config("key") == "value"


class TestDetectorPluginFileFiltering:
    """Tests for file filtering functionality."""

    def test_should_scan_file_no_extensions(self) -> None:
        """Test should_scan_file with no extension filter."""
        detector = SimpleDetectorPlugin()
        assert detector.should_scan_file("test.py") is True
        assert detector.should_scan_file("test.txt") is True
        assert detector.should_scan_file("test") is True

    def test_should_scan_file_with_extensions(self) -> None:
        """Test should_scan_file with extension filter."""
        detector = ConfigurableDetectorPlugin()
        assert detector.should_scan_file("test.py") is True
        assert detector.should_scan_file("test.js") is True
        assert detector.should_scan_file("test.txt") is False
        assert detector.should_scan_file("test.go") is False

    def test_should_scan_file_custom_extensions(self) -> None:
        """Test should_scan_file with custom extensions."""
        detector = ConfigurableDetectorPlugin(extensions=[".txt", ".md"])
        assert detector.should_scan_file("test.txt") is True
        assert detector.should_scan_file("test.md") is True
        assert detector.should_scan_file("test.py") is False


class TestDetectorPluginCreateFinding:
    """Tests for create_finding utility method."""

    def test_create_finding_basic(self) -> None:
        """Test create_finding with basic parameters."""
        detector = SimpleDetectorPlugin()
        finding = detector.create_finding(
            file_path="test.py",
            matches=["SECRET123"],
        )
        assert finding.file_path == "test.py"
        assert finding.detector_name == "simple_test_detector"
        assert finding.matches == ["SECRET123"]
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata == {}

    def test_create_finding_with_severity(self) -> None:
        """Test create_finding with custom severity."""
        detector = SimpleDetectorPlugin()
        finding = detector.create_finding(
            file_path="test.py",
            matches=["SECRET123"],
            severity=Severity.CRITICAL,
        )
        assert finding.severity == Severity.CRITICAL

    def test_create_finding_with_metadata(self) -> None:
        """Test create_finding with metadata."""
        detector = SimpleDetectorPlugin()
        finding = detector.create_finding(
            file_path="test.py",
            matches=["SECRET123"],
            metadata={"line": 42, "column": 10},
        )
        assert finding.metadata == {"line": 42, "column": 10}

    def test_create_finding_multiple_matches(self) -> None:
        """Test create_finding with multiple matches."""
        detector = SimpleDetectorPlugin()
        finding = detector.create_finding(
            file_path="test.py",
            matches=["SECRET1", "SECRET2", "SECRET3"],
        )
        assert finding.matches == ["SECRET1", "SECRET2", "SECRET3"]


class TestDetectorPluginPatternCompilation:
    """Tests for pattern compilation and caching."""

    def test_compile_pattern_basic(self) -> None:
        """Test compile_pattern returns compiled pattern."""
        detector = SimpleDetectorPlugin()
        pattern = detector.compile_pattern(r"SECRET_\w+")
        assert isinstance(pattern, re.Pattern)

    def test_compile_pattern_with_flags(self) -> None:
        """Test compile_pattern with regex flags."""
        detector = SimpleDetectorPlugin()
        pattern = detector.compile_pattern(r"secret_\w+", re.IGNORECASE)
        assert pattern.search("SECRET_abc") is not None
        assert pattern.search("secret_abc") is not None

    def test_compile_pattern_caching(self) -> None:
        """Test pattern compilation caching."""
        detector = SimpleDetectorPlugin()
        pattern1 = detector.compile_pattern(r"SECRET_\w+")
        pattern2 = detector.compile_pattern(r"SECRET_\w+")
        assert pattern1 is pattern2

    def test_compile_pattern_different_flags_not_cached(self) -> None:
        """Test patterns with different flags are cached separately."""
        detector = SimpleDetectorPlugin()
        pattern1 = detector.compile_pattern(r"secret_\w+", 0)
        pattern2 = detector.compile_pattern(r"secret_\w+", re.IGNORECASE)
        assert pattern1 is not pattern2


class TestDetectorPluginPatternMatching:
    """Tests for pattern matching methods."""

    def test_match_pattern_no_match(self) -> None:
        """Test match_pattern with no matches."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="no secrets here",
            file_path="test.py",
            pattern=r"SECRET_\w+",
        )
        assert findings == []

    def test_match_pattern_single_match(self) -> None:
        """Test match_pattern with single match."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="found SECRET_ABC123 here",
            file_path="test.py",
            pattern=r"SECRET_\w+",
        )
        assert len(findings) == 1
        assert findings[0].matches == ["SECRET_ABC123"]
        assert findings[0].detector_name == "simple_test_detector"

    def test_match_pattern_multiple_matches(self) -> None:
        """Test match_pattern with multiple matches."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="found SECRET_ABC and SECRET_XYZ",
            file_path="test.py",
            pattern=r"SECRET_\w+",
        )
        assert len(findings) == 2
        assert findings[0].matches == ["SECRET_ABC"]
        assert findings[1].matches == ["SECRET_XYZ"]

    def test_match_pattern_with_metadata(self) -> None:
        """Test match_pattern includes position metadata."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="found SECRET_ABC here",
            file_path="test.py",
            pattern=r"SECRET_\w+",
        )
        assert len(findings) == 1
        assert "start" in findings[0].metadata
        assert "end" in findings[0].metadata
        assert findings[0].metadata["start"] == 6
        assert findings[0].metadata["end"] == 16

    def test_match_pattern_with_named_groups(self) -> None:
        """Test match_pattern captures named groups."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="API_KEY=abc123",
            file_path="test.py",
            pattern=r"(?P<key>\w+)=(?P<value>\w+)",
        )
        assert len(findings) == 1
        assert "groups" in findings[0].metadata
        assert findings[0].metadata["groups"] == {"key": "API_KEY", "value": "abc123"}

    def test_match_pattern_with_compiled_pattern(self) -> None:
        """Test match_pattern with pre-compiled pattern."""
        detector = SimpleDetectorPlugin()
        compiled = re.compile(r"SECRET_\w+")
        findings = detector.match_pattern(
            content="found SECRET_ABC here",
            file_path="test.py",
            pattern=compiled,
        )
        assert len(findings) == 1
        assert findings[0].matches == ["SECRET_ABC"]

    def test_match_pattern_case_insensitive(self) -> None:
        """Test match_pattern with case insensitive flag."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_pattern(
            content="found secret_abc here",
            file_path="test.py",
            pattern=r"SECRET_\w+",
            flags=re.IGNORECASE,
        )
        assert len(findings) == 1
        assert findings[0].matches == ["secret_abc"]


class TestDetectorPluginMultiPatternMatching:
    """Tests for multi-pattern matching."""

    def test_match_patterns_no_match(self) -> None:
        """Test match_patterns with no matches."""
        detector = MultiPatternDetectorPlugin()
        findings = detector.match_patterns(
            content="no secrets here",
            file_path="test.py",
            patterns=[r"SECRET_\w+", r"TOKEN_\w+"],
        )
        assert findings == []

    def test_match_patterns_multiple_patterns(self) -> None:
        """Test match_patterns matches multiple patterns."""
        detector = MultiPatternDetectorPlugin()
        findings = detector.match_patterns(
            content="found SECRET_ABC and TOKEN_XYZ",
            file_path="test.py",
            patterns=[r"SECRET_\w+", r"TOKEN_\w+"],
        )
        assert len(findings) == 2
        matches = [f.matches[0] for f in findings]
        assert "SECRET_ABC" in matches
        assert "TOKEN_XYZ" in matches

    def test_match_patterns_same_pattern_multiple_matches(self) -> None:
        """Test match_patterns with same pattern matching multiple times."""
        detector = MultiPatternDetectorPlugin()
        findings = detector.match_patterns(
            content="SECRET_A SECRET_B SECRET_C",
            file_path="test.py",
            patterns=[r"SECRET_\w+"],
        )
        assert len(findings) == 3


class TestDetectorPluginLiteralMatching:
    """Tests for literal string matching."""

    def test_match_literal_no_match(self) -> None:
        """Test match_literal with no matches."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="no match here",
            file_path="test.py",
            literal="SECRET",
        )
        assert findings == []

    def test_match_literal_single_match(self) -> None:
        """Test match_literal with single match."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="found SECRET here",
            file_path="test.py",
            literal="SECRET",
        )
        assert len(findings) == 1
        assert findings[0].matches == ["SECRET"]

    def test_match_literal_multiple_matches(self) -> None:
        """Test match_literal with multiple matches."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="SECRET and another SECRET",
            file_path="test.py",
            literal="SECRET",
        )
        assert len(findings) == 2

    def test_match_literal_case_sensitive(self) -> None:
        """Test match_literal case sensitivity."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="secret SECRET Secret",
            file_path="test.py",
            literal="SECRET",
            case_sensitive=True,
        )
        assert len(findings) == 1

    def test_match_literal_case_insensitive(self) -> None:
        """Test match_literal case insensitivity."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="secret SECRET Secret",
            file_path="test.py",
            literal="SECRET",
            case_sensitive=False,
        )
        assert len(findings) == 3

    def test_match_literal_special_regex_chars(self) -> None:
        """Test match_literal escapes special regex characters."""
        detector = SimpleDetectorPlugin()
        findings = detector.match_literal(
            content="found [SECRET] here",
            file_path="test.py",
            literal="[SECRET]",
        )
        assert len(findings) == 1
        assert findings[0].matches == ["[SECRET]"]


class TestDetectorPluginDetect:
    """Tests for detect method implementation."""

    def test_detect_no_match(self) -> None:
        """Test detect with no matches."""
        detector = SimpleDetectorPlugin()
        findings = detector.detect("no secrets here", "test.py")
        assert findings == []

    def test_detect_single_match(self) -> None:
        """Test detect with single match."""
        detector = SimpleDetectorPlugin()
        findings = detector.detect("found TEST_SECRET_ABCD1234 here", "test.py")
        assert len(findings) == 1
        assert findings[0].matches == ["TEST_SECRET_ABCD1234"]
        assert findings[0].severity == Severity.HIGH

    def test_detect_configurable(self) -> None:
        """Test detect with configuration."""
        detector = ConfigurableDetectorPlugin(
            pattern=r"CUSTOM_[A-Z]+",
            severity="critical",
        )
        findings = detector.detect("found CUSTOM_ABC here", "test.py")
        assert len(findings) == 1
        assert findings[0].matches == ["CUSTOM_ABC"]
        assert findings[0].severity == Severity.CRITICAL

    def test_detect_multi_pattern(self) -> None:
        """Test detect with multiple patterns."""
        detector = MultiPatternDetectorPlugin()
        findings = detector.detect(
            "found API_KEY_123 and TOKEN_456 and SECRET_789",
            "test.py",
        )
        assert len(findings) == 3


class TestDetectorPluginRegistry:
    """Tests for registry integration."""

    def test_register(self) -> None:
        """Test registering detector with registry."""
        detector = SimpleDetectorPlugin()
        detector.register()
        assert "simple_test_detector" in default_registry

    def test_register_duplicate_raises(self) -> None:
        """Test registering duplicate detector raises error."""
        detector1 = SimpleDetectorPlugin()
        detector2 = SimpleDetectorPlugin()
        detector1.register()
        with pytest.raises(ValueError, match="already registered"):
            detector2.register()

    def test_unregister(self) -> None:
        """Test unregistering detector from registry."""
        detector = SimpleDetectorPlugin()
        detector.register()
        assert "simple_test_detector" in default_registry
        detector.unregister()
        assert "simple_test_detector" not in default_registry

    def test_unregister_not_registered_raises(self) -> None:
        """Test unregistering non-existent detector raises error."""
        detector = SimpleDetectorPlugin()
        with pytest.raises(KeyError, match="not registered"):
            detector.unregister()


class TestDetectorPluginInheritance:
    """Tests for DetectorPlugin inheritance from BaseDetector."""

    def test_is_base_detector(self) -> None:
        """Test DetectorPlugin inherits from BaseDetector."""
        detector = SimpleDetectorPlugin()
        # Use the already imported BaseDetector to avoid module isolation issues
        assert isinstance(detector, BaseDetector)
        # Also verify via MRO
        assert any(
            cls.__name__ == "BaseDetector" for cls in type(detector).__mro__
        )

    def test_abstract_methods_required(self) -> None:
        """Test that abstract methods must be implemented."""
        # This should raise TypeError because name and detect are abstract
        with pytest.raises(TypeError):
            class IncompletePlugin(DetectorPlugin):
                pass

            IncompletePlugin()

    def test_abstract_name_required(self) -> None:
        """Test that name property must be implemented."""
        with pytest.raises(TypeError):
            class NoNamePlugin(DetectorPlugin):
                def detect(self, content: str, file_path: str = "") -> list[Finding]:
                    return []

            NoNamePlugin()

    def test_abstract_detect_required(self) -> None:
        """Test that detect method must be implemented."""
        with pytest.raises(TypeError):
            class NoDetectPlugin(DetectorPlugin):
                @property
                def name(self) -> str:
                    return "no_detect"

            NoDetectPlugin()
