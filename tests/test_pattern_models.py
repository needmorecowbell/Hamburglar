"""Tests for pattern model definitions.

This module contains tests for the Pattern dataclass and PatternCategory enum
used for organizing detection patterns.
"""

from __future__ import annotations

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import (
    Confidence,
    Pattern,
    PatternCategory,
)


class TestPatternCategoryEnum:
    """Tests for the PatternCategory enumeration."""

    def test_category_values(self) -> None:
        """Test that all expected categories exist with correct values."""
        assert PatternCategory.CREDENTIALS.value == "credentials"
        assert PatternCategory.API_KEYS.value == "api_keys"
        assert PatternCategory.CRYPTO.value == "crypto"
        assert PatternCategory.NETWORK.value == "network"
        assert PatternCategory.PRIVATE_KEYS.value == "private_keys"
        assert PatternCategory.CLOUD.value == "cloud"
        assert PatternCategory.GENERIC.value == "generic"

    def test_category_is_string_enum(self) -> None:
        """Test that PatternCategory values can be used as strings."""
        assert PatternCategory.CREDENTIALS == "credentials"
        assert PatternCategory.API_KEYS == "api_keys"
        assert PatternCategory.CLOUD == "cloud"

    def test_all_categories_defined(self) -> None:
        """Test that all expected categories are defined."""
        expected_categories = {
            "credentials",
            "api_keys",
            "crypto",
            "network",
            "private_keys",
            "cloud",
            "generic",
        }
        actual_categories = {cat.value for cat in PatternCategory}
        assert actual_categories == expected_categories


class TestConfidenceEnum:
    """Tests for the Confidence enumeration."""

    def test_confidence_values(self) -> None:
        """Test that all expected confidence levels exist with correct values."""
        assert Confidence.HIGH.value == "high"
        assert Confidence.MEDIUM.value == "medium"
        assert Confidence.LOW.value == "low"

    def test_confidence_is_string_enum(self) -> None:
        """Test that Confidence values can be used as strings."""
        assert Confidence.HIGH == "high"
        assert Confidence.MEDIUM == "medium"
        assert Confidence.LOW == "low"

    def test_all_confidence_levels_defined(self) -> None:
        """Test that all expected confidence levels are defined."""
        expected_levels = {"high", "medium", "low"}
        actual_levels = {conf.value for conf in Confidence}
        assert actual_levels == expected_levels


class TestPatternDataclass:
    """Tests for the Pattern dataclass."""

    def test_pattern_creation_minimal(self) -> None:
        """Test creating a Pattern with only required fields."""
        pattern = Pattern(
            name="test_pattern",
            regex=r"TEST-[0-9]+",
            severity=Severity.HIGH,
            category=PatternCategory.GENERIC,
        )
        assert pattern.name == "test_pattern"
        assert pattern.regex == r"TEST-[0-9]+"
        assert pattern.severity == Severity.HIGH
        assert pattern.category == PatternCategory.GENERIC
        assert pattern.description == ""
        assert pattern.confidence == Confidence.MEDIUM

    def test_pattern_creation_full(self) -> None:
        """Test creating a Pattern with all fields specified."""
        pattern = Pattern(
            name="aws_access_key",
            regex=r"AKIA[0-9A-Z]{16}",
            severity=Severity.CRITICAL,
            category=PatternCategory.API_KEYS,
            description="AWS Access Key ID",
            confidence=Confidence.HIGH,
        )
        assert pattern.name == "aws_access_key"
        assert pattern.regex == r"AKIA[0-9A-Z]{16}"
        assert pattern.severity == Severity.CRITICAL
        assert pattern.category == PatternCategory.API_KEYS
        assert pattern.description == "AWS Access Key ID"
        assert pattern.confidence == Confidence.HIGH

    def test_pattern_default_description(self) -> None:
        """Test that default description is empty string."""
        pattern = Pattern(
            name="test",
            regex=r"test",
            severity=Severity.LOW,
            category=PatternCategory.GENERIC,
        )
        assert pattern.description == ""

    def test_pattern_default_confidence(self) -> None:
        """Test that default confidence is MEDIUM."""
        pattern = Pattern(
            name="test",
            regex=r"test",
            severity=Severity.LOW,
            category=PatternCategory.GENERIC,
        )
        assert pattern.confidence == Confidence.MEDIUM

    def test_pattern_to_dict(self) -> None:
        """Test that Pattern can be converted to dictionary format."""
        pattern = Pattern(
            name="github_token",
            regex=r"ghp_[0-9a-zA-Z]{36}",
            severity=Severity.CRITICAL,
            category=PatternCategory.API_KEYS,
            description="GitHub Personal Access Token",
            confidence=Confidence.HIGH,
        )
        data = pattern.to_dict()

        assert isinstance(data, dict)
        assert data["pattern"] == r"ghp_[0-9a-zA-Z]{36}"
        assert data["severity"] == Severity.CRITICAL
        assert data["description"] == "GitHub Personal Access Token"
        assert data["category"] == "api_keys"
        assert data["confidence"] == "high"

    def test_pattern_to_dict_default_values(self) -> None:
        """Test that to_dict includes default values correctly."""
        pattern = Pattern(
            name="test",
            regex=r"test",
            severity=Severity.MEDIUM,
            category=PatternCategory.GENERIC,
        )
        data = pattern.to_dict()

        assert data["description"] == ""
        assert data["confidence"] == "medium"

    def test_pattern_with_each_category(self) -> None:
        """Test creating patterns with each category."""
        categories = [
            PatternCategory.CREDENTIALS,
            PatternCategory.API_KEYS,
            PatternCategory.CRYPTO,
            PatternCategory.NETWORK,
            PatternCategory.PRIVATE_KEYS,
            PatternCategory.CLOUD,
            PatternCategory.GENERIC,
        ]
        for category in categories:
            pattern = Pattern(
                name=f"test_{category.value}",
                regex=r"test",
                severity=Severity.MEDIUM,
                category=category,
            )
            assert pattern.category == category

    def test_pattern_with_each_severity(self) -> None:
        """Test creating patterns with each severity level."""
        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for severity in severities:
            pattern = Pattern(
                name=f"test_{severity.value}",
                regex=r"test",
                severity=severity,
                category=PatternCategory.GENERIC,
            )
            assert pattern.severity == severity

    def test_pattern_with_each_confidence(self) -> None:
        """Test creating patterns with each confidence level."""
        confidences = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]
        for confidence in confidences:
            pattern = Pattern(
                name=f"test_{confidence.value}",
                regex=r"test",
                severity=Severity.MEDIUM,
                category=PatternCategory.GENERIC,
                confidence=confidence,
            )
            assert pattern.confidence == confidence

    def test_pattern_complex_regex(self) -> None:
        """Test pattern with complex regex that includes special characters."""
        complex_regex = r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,64}['\"]"
        pattern = Pattern(
            name="complex_pattern",
            regex=complex_regex,
            severity=Severity.HIGH,
            category=PatternCategory.API_KEYS,
            description="Complex API key pattern",
        )
        assert pattern.regex == complex_regex
        data = pattern.to_dict()
        assert data["pattern"] == complex_regex

    def test_pattern_equality(self) -> None:
        """Test that patterns with same values are equal."""
        pattern1 = Pattern(
            name="test",
            regex=r"test",
            severity=Severity.HIGH,
            category=PatternCategory.GENERIC,
            description="Test pattern",
            confidence=Confidence.HIGH,
        )
        pattern2 = Pattern(
            name="test",
            regex=r"test",
            severity=Severity.HIGH,
            category=PatternCategory.GENERIC,
            description="Test pattern",
            confidence=Confidence.HIGH,
        )
        assert pattern1 == pattern2

    def test_pattern_inequality_different_name(self) -> None:
        """Test that patterns with different names are not equal."""
        pattern1 = Pattern(
            name="test1",
            regex=r"test",
            severity=Severity.HIGH,
            category=PatternCategory.GENERIC,
        )
        pattern2 = Pattern(
            name="test2",
            regex=r"test",
            severity=Severity.HIGH,
            category=PatternCategory.GENERIC,
        )
        assert pattern1 != pattern2


class TestPatternModuleExports:
    """Tests for pattern module exports."""

    def test_severity_reexported(self) -> None:
        """Test that Severity is re-exported from the patterns module."""
        from hamburglar.detectors.patterns import Severity as ExportedSeverity

        # Verify the re-exported Severity works correctly
        assert ExportedSeverity.CRITICAL.value == "critical"
        assert ExportedSeverity.HIGH.value == "high"
        # Values should be equal (enum string comparison)
        assert ExportedSeverity.CRITICAL == Severity.CRITICAL

    def test_all_exports_available(self) -> None:
        """Test that all documented exports are available."""
        from hamburglar.detectors import patterns

        assert hasattr(patterns, "PatternCategory")
        assert hasattr(patterns, "Confidence")
        assert hasattr(patterns, "Pattern")
        assert hasattr(patterns, "Severity")
