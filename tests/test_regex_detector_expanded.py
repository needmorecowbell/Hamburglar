"""Tests for the expanded RegexDetector features.

This module contains tests for the new features added to RegexDetector:
- Expanded pattern library with categories
- Category-based filtering (enabled/disabled)
- Confidence-based filtering
- Custom pattern files (JSON/YAML)
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory
from hamburglar.detectors.regex_detector import (
    ALL_PATTERN_CATEGORIES,
    RegexDetector,
    get_all_patterns,
    get_patterns_by_category,
    load_patterns_from_file,
)


class TestExpandedPatternLibrary:
    """Tests for the expanded pattern library."""

    def test_all_pattern_categories_populated(self) -> None:
        """Test that all pattern categories are populated."""
        assert len(ALL_PATTERN_CATEGORIES) == 7
        assert PatternCategory.API_KEYS in ALL_PATTERN_CATEGORIES
        assert PatternCategory.CLOUD in ALL_PATTERN_CATEGORIES
        assert PatternCategory.CREDENTIALS in ALL_PATTERN_CATEGORIES
        assert PatternCategory.CRYPTO in ALL_PATTERN_CATEGORIES
        assert PatternCategory.GENERIC in ALL_PATTERN_CATEGORIES
        assert PatternCategory.NETWORK in ALL_PATTERN_CATEGORIES
        assert PatternCategory.PRIVATE_KEYS in ALL_PATTERN_CATEGORIES

    def test_get_all_patterns_returns_patterns(self) -> None:
        """Test that get_all_patterns returns all patterns from all categories."""
        all_patterns = get_all_patterns()
        assert len(all_patterns) > 100  # We have many patterns
        # Check that we have patterns from different categories
        categories = {p.category for p in all_patterns}
        assert len(categories) == 7

    def test_get_patterns_by_category(self) -> None:
        """Test that get_patterns_by_category returns correct patterns."""
        api_patterns = get_patterns_by_category(PatternCategory.API_KEYS)
        assert len(api_patterns) > 0
        for pattern in api_patterns:
            assert pattern.category == PatternCategory.API_KEYS

    def test_use_expanded_patterns_flag(self) -> None:
        """Test that use_expanded_patterns loads all patterns."""
        detector = RegexDetector(use_expanded_patterns=True)
        patterns = detector.get_patterns()
        assert len(patterns) > 100  # Should have many patterns

    def test_expanded_patterns_have_categories(self) -> None:
        """Test that expanded patterns include category information."""
        detector = RegexDetector(use_expanded_patterns=True)
        patterns = detector.get_patterns()
        # Check that patterns have category metadata
        for name, config in patterns.items():
            assert "category" in config
            assert config["category"] != ""  # Should not be empty


class TestCategoryFiltering:
    """Tests for category-based pattern filtering."""

    def test_enabled_categories_filter(self) -> None:
        """Test that enabled_categories filters patterns correctly."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS],
        )
        patterns = detector.get_patterns()
        # All patterns should be from API_KEYS category
        for name, config in patterns.items():
            assert config.get("category") == "api_keys"

    def test_enabled_multiple_categories(self) -> None:
        """Test enabling multiple categories."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS, PatternCategory.PRIVATE_KEYS],
        )
        patterns = detector.get_patterns()
        categories = {config.get("category") for config in patterns.values()}
        assert categories <= {"api_keys", "private_keys"}

    def test_disabled_categories_filter(self) -> None:
        """Test that disabled_categories excludes patterns correctly."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            disabled_categories=[PatternCategory.GENERIC, PatternCategory.NETWORK],
        )
        patterns = detector.get_patterns()
        # No patterns should be from GENERIC or NETWORK categories
        for name, config in patterns.items():
            assert config.get("category") not in ("generic", "network")

    def test_get_enabled_categories_method(self) -> None:
        """Test the get_enabled_categories method."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS],
        )
        assert detector.get_enabled_categories() == [PatternCategory.API_KEYS]

    def test_get_disabled_categories_method(self) -> None:
        """Test the get_disabled_categories method."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            disabled_categories=[PatternCategory.GENERIC],
        )
        assert detector.get_disabled_categories() == [PatternCategory.GENERIC]

    def test_no_category_filter_returns_none(self) -> None:
        """Test that no category filter returns None."""
        detector = RegexDetector(use_expanded_patterns=True)
        assert detector.get_enabled_categories() is None
        assert detector.get_disabled_categories() is None


class TestConfidenceFiltering:
    """Tests for confidence-based pattern filtering."""

    def test_min_confidence_high(self) -> None:
        """Test filtering by HIGH confidence only."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            min_confidence=Confidence.HIGH,
        )
        patterns = detector.get_patterns()
        # All patterns should have HIGH confidence
        for name, config in patterns.items():
            assert config.get("confidence") == "high"

    def test_min_confidence_medium(self) -> None:
        """Test filtering by MEDIUM or higher confidence."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            min_confidence=Confidence.MEDIUM,
        )
        patterns = detector.get_patterns()
        # All patterns should have MEDIUM or HIGH confidence
        for name, config in patterns.items():
            assert config.get("confidence") in ("medium", "high")

    def test_min_confidence_low_includes_all(self) -> None:
        """Test that LOW confidence includes all patterns."""
        detector_all = RegexDetector(use_expanded_patterns=True)
        detector_low = RegexDetector(
            use_expanded_patterns=True,
            min_confidence=Confidence.LOW,
        )
        # Should have the same number of patterns
        assert len(detector_all.get_patterns()) == len(detector_low.get_patterns())

    def test_get_min_confidence_method(self) -> None:
        """Test the get_min_confidence method."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            min_confidence=Confidence.HIGH,
        )
        assert detector.get_min_confidence() == Confidence.HIGH

    def test_no_confidence_filter_returns_none(self) -> None:
        """Test that no confidence filter returns None."""
        detector = RegexDetector(use_expanded_patterns=True)
        assert detector.get_min_confidence() is None


class TestCustomPatternFiles:
    """Tests for loading custom pattern files."""

    def test_load_json_pattern_file(self) -> None:
        """Test loading patterns from a JSON file."""
        pattern_data = {
            "patterns": [
                {
                    "name": "test_pattern",
                    "regex": r"TEST-\d{4}",
                    "severity": "HIGH",
                    "category": "GENERIC",
                    "description": "Test pattern",
                    "confidence": "HIGH",
                }
            ]
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(pattern_data, f)
            temp_path = f.name

        try:
            patterns = load_patterns_from_file(temp_path)
            assert len(patterns) == 1
            assert patterns[0].name == "test_pattern"
            assert patterns[0].regex == r"TEST-\d{4}"
            assert patterns[0].severity == Severity.HIGH
            assert patterns[0].category == PatternCategory.GENERIC
            assert patterns[0].confidence == Confidence.HIGH
        finally:
            Path(temp_path).unlink()

    def test_load_patterns_with_detector(self) -> None:
        """Test loading custom patterns through the detector."""
        pattern_data = {
            "patterns": [
                {
                    "name": "custom_secret",
                    "regex": r"CUSTOM-[A-Z]{8}",
                    "severity": "CRITICAL",
                    "category": "API_KEYS",
                    "description": "Custom secret pattern",
                    "confidence": "HIGH",
                }
            ]
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(pattern_data, f)
            temp_path = f.name

        try:
            detector = RegexDetector(custom_pattern_files=[temp_path])
            patterns = detector.get_patterns()
            assert "custom_secret" in patterns
        finally:
            Path(temp_path).unlink()

    def test_custom_patterns_detect_content(self) -> None:
        """Test that custom patterns can detect matching content."""
        pattern_data = {
            "patterns": [
                {
                    "name": "custom_token",
                    "regex": r"TOKEN-[0-9]{6}",
                    "severity": "HIGH",
                    "category": "CREDENTIALS",
                    "description": "Custom token",
                    "confidence": "HIGH",
                }
            ]
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(pattern_data, f)
            temp_path = f.name

        try:
            detector = RegexDetector(
                patterns={},
                use_defaults=False,
                custom_pattern_files=[temp_path],
            )
            content = "My secret: TOKEN-123456"
            findings = detector.detect(content, "test.txt")
            assert len(findings) == 1
            assert "TOKEN-123456" in findings[0].matches
        finally:
            Path(temp_path).unlink()

    def test_invalid_pattern_file_not_found(self) -> None:
        """Test that missing pattern file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_patterns_from_file("nonexistent_file.json")

    def test_invalid_pattern_file_format(self) -> None:
        """Test that invalid file format raises ValueError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as f:
            f.write("not a pattern file")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported pattern file format"):
                load_patterns_from_file(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_invalid_json_structure(self) -> None:
        """Test that invalid JSON structure raises ValueError."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"not_patterns": []}, f)
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="'patterns' key"):
                load_patterns_from_file(temp_path)
        finally:
            Path(temp_path).unlink()


class TestConfidenceInFindings:
    """Tests for confidence information in findings."""

    def test_findings_include_category(self) -> None:
        """Test that findings include category metadata."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = "AKIAIOSFODNN7EXAMPLE"  # AWS key
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "aws" in f.detector_name.lower()]
        assert len(aws_findings) >= 1
        assert "category" in aws_findings[0].metadata

    def test_findings_include_confidence(self) -> None:
        """Test that findings include confidence metadata."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"  # GitHub token
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "github" in f.detector_name.lower()]
        assert len(gh_findings) >= 1
        assert "confidence" in gh_findings[0].metadata


class TestPatternCountAndQuery:
    """Tests for pattern count and query methods."""

    def test_get_pattern_count(self) -> None:
        """Test get_pattern_count returns correct number."""
        detector = RegexDetector()
        count = detector.get_pattern_count()
        patterns = detector.get_patterns()
        assert count == len(patterns)

    def test_get_patterns_by_category_method(self) -> None:
        """Test get_patterns_by_category filters correctly."""
        detector = RegexDetector(use_expanded_patterns=True)
        api_patterns = detector.get_patterns_by_category("api_keys")
        assert len(api_patterns) > 0
        for name, config in api_patterns.items():
            assert config.get("category") == "api_keys"

    def test_get_patterns_by_confidence_method(self) -> None:
        """Test get_patterns_by_confidence filters correctly."""
        detector = RegexDetector(use_expanded_patterns=True)
        high_patterns = detector.get_patterns_by_confidence("high")
        assert len(high_patterns) > 0
        for name, config in high_patterns.items():
            assert config.get("confidence") == "high"


class TestAddPatternExtended:
    """Tests for the extended add_pattern method."""

    def test_add_pattern_with_category(self) -> None:
        """Test adding a pattern with category."""
        detector = RegexDetector(patterns={}, use_defaults=False)
        detector.add_pattern(
            name="Custom Pattern",
            pattern=r"CUSTOM-\d{4}",
            severity=Severity.HIGH,
            description="Custom pattern",
            category="custom",
            confidence="high",
        )
        patterns = detector.get_patterns()
        assert "Custom Pattern" in patterns
        assert patterns["Custom Pattern"]["category"] == "custom"
        assert patterns["Custom Pattern"]["confidence"] == "high"

    def test_add_pattern_detects_with_category(self) -> None:
        """Test that added pattern with category can detect content."""
        detector = RegexDetector(patterns={}, use_defaults=False)
        detector.add_pattern(
            name="Custom ID",
            pattern=r"ID-[A-Z]{4}-\d{4}",
            severity=Severity.MEDIUM,
            description="Custom ID pattern",
            category="identifiers",
            confidence="medium",
        )
        content = "Found ID-ABCD-1234"
        findings = detector.detect(content, "test.txt")
        assert len(findings) == 1
        assert findings[0].metadata["category"] == "identifiers"
        assert findings[0].metadata["confidence"] == "medium"


class TestExpandedPatternsDetection:
    """Tests for detection with expanded patterns."""

    def test_detect_aws_key_with_expanded(self) -> None:
        """Test AWS key detection with expanded patterns."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "config.py")
        aws_findings = [f for f in findings if "aws" in f.detector_name.lower()]
        assert len(aws_findings) >= 1

    def test_detect_github_token_with_expanded(self) -> None:
        """Test GitHub token detection with expanded patterns."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = detector.detect(content, "config.yml")
        gh_findings = [f for f in findings if "github" in f.detector_name.lower()]
        assert len(gh_findings) >= 1

    def test_detect_private_key_with_expanded(self) -> None:
        """Test private key detection with expanded patterns."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAtest
        -----END RSA PRIVATE KEY-----
        """
        findings = detector.detect(content, "key.pem")
        key_findings = [f for f in findings if "private" in f.detector_name.lower()]
        assert len(key_findings) >= 1

    def test_detect_database_connection_with_expanded(self) -> None:
        """Test database connection string detection with expanded patterns."""
        detector = RegexDetector(use_expanded_patterns=True)
        content = "DATABASE_URL=postgres://user:password@localhost/db"
        findings = detector.detect(content, ".env")
        db_findings = [f for f in findings if "postgres" in f.detector_name.lower() or "url" in f.detector_name.lower()]
        assert len(db_findings) >= 1


class TestCategoryAndConfidenceCombination:
    """Tests for combining category and confidence filters."""

    def test_category_and_confidence_combined(self) -> None:
        """Test combining category and confidence filters."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS],
            min_confidence=Confidence.HIGH,
        )
        patterns = detector.get_patterns()
        for name, config in patterns.items():
            assert config.get("category") == "api_keys"
            assert config.get("confidence") == "high"

    def test_disabled_category_with_confidence(self) -> None:
        """Test disabled category with confidence filter."""
        detector = RegexDetector(
            use_expanded_patterns=True,
            disabled_categories=[PatternCategory.GENERIC],
            min_confidence=Confidence.MEDIUM,
        )
        patterns = detector.get_patterns()
        for name, config in patterns.items():
            assert config.get("category") != "generic"
            assert config.get("confidence") in ("medium", "high")


class TestBackwardsCompatibility:
    """Tests for backwards compatibility with existing code."""

    def test_default_patterns_still_work(self) -> None:
        """Test that default patterns still work without new features."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_custom_patterns_dict_still_works(self) -> None:
        """Test that custom patterns dictionary still works."""
        custom = {
            "Test Pattern": {
                "pattern": r"TEST-\d{4}",
                "severity": Severity.HIGH,
                "description": "Test",
            }
        }
        detector = RegexDetector(patterns=custom, use_defaults=False)
        content = "Found TEST-1234"
        findings = detector.detect(content, "test.txt")
        assert len(findings) == 1

    def test_use_defaults_flag_still_works(self) -> None:
        """Test that use_defaults flag still works."""
        custom = {
            "Custom": {
                "pattern": r"CUSTOM",
                "severity": Severity.LOW,
                "description": "Custom",
            }
        }
        detector = RegexDetector(patterns=custom, use_defaults=True)
        patterns = detector.get_patterns()
        assert "Custom" in patterns
        assert "AWS API Key" in patterns  # Default still present
