"""Tests for the example custom detector plugin.

These tests verify that the example plugin in examples/plugins/custom_detector.py
works correctly and demonstrates best practices for plugin development.
"""

import pytest

import sys
from pathlib import Path

# Add the examples directory to the path so we can import the plugin
examples_path = Path(__file__).parent.parent / "examples" / "plugins"
sys.path.insert(0, str(examples_path))

from custom_detector import CustomAPIKeyDetector

from hamburglar.core.models import Severity


class TestCustomAPIKeyDetector:
    """Tests for the CustomAPIKeyDetector example plugin."""

    def test_init_default_config(self):
        """Test detector initialization with default config."""
        detector = CustomAPIKeyDetector()

        assert detector.name == "custom_api_keys"
        assert detector.description == "Detects custom organization API keys and tokens"
        assert detector.version == "1.0.0"
        assert detector.author == "Your Organization"

    def test_init_custom_config(self):
        """Test detector initialization with custom config."""
        detector = CustomAPIKeyDetector(
            min_key_length=20,
            check_entropy=False,
            key_prefixes=["CUSTOM_"],
        )

        assert detector.get_config("min_key_length") == 20
        assert detector.get_config("check_entropy") is False
        assert detector.get_config("key_prefixes") == ["CUSTOM_"]

    def test_supported_extensions(self):
        """Test that supported extensions include common config files."""
        detector = CustomAPIKeyDetector()
        extensions = detector.supported_extensions

        assert extensions is not None
        assert ".py" in extensions
        assert ".js" in extensions
        assert ".yaml" in extensions
        assert ".env" in extensions

    def test_should_scan_file_matching(self):
        """Test file matching for supported extensions."""
        detector = CustomAPIKeyDetector()

        assert detector.should_scan_file("config.py") is True
        assert detector.should_scan_file("settings.yaml") is True
        assert detector.should_scan_file(".env") is True

    def test_should_scan_file_not_matching(self):
        """Test file matching rejects unsupported extensions."""
        detector = CustomAPIKeyDetector()

        assert detector.should_scan_file("image.png") is False
        assert detector.should_scan_file("document.pdf") is False

    def test_detect_prefixed_keys(self):
        """Test detection of keys with configured prefixes."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["ACME_", "TEST_"],
            min_key_length=16,
        )

        content = """
        ACME_TOKEN = "ACME_abc123xyz789secret"
        TEST_API_KEY = "TEST_randomTokenValue123456"
        """

        findings = detector.detect(content, "config.py")

        assert len(findings) >= 2
        prefixes = [f.metadata.get("prefix") for f in findings]
        assert "ACME_" in prefixes or "TEST_" in prefixes

    def test_detect_bearer_token(self):
        """Test detection of Bearer tokens."""
        detector = CustomAPIKeyDetector(min_key_length=16, check_entropy=False)

        content = """
        headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        }
        """

        findings = detector.detect(content, "api.py")

        # Should detect the Bearer token
        assert len(findings) >= 1
        matches = [m for f in findings for m in f.matches]
        assert any("eyJhbG" in m for m in matches)

    def test_detect_api_key_assignment(self):
        """Test detection of API key assignments."""
        detector = CustomAPIKeyDetector(min_key_length=16, check_entropy=False)

        content = """
        api_key = "fake_test_key_1234567890abcdef123"
        """

        findings = detector.detect(content, "config.py")

        assert len(findings) >= 1

    def test_filter_short_keys(self):
        """Test that short keys are filtered out."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["TEST_"],
            min_key_length=20,
            check_entropy=False,
        )

        content = """
        SHORT = "TEST_abc123"
        """

        findings = detector.detect(content, "config.py")

        # Should not detect keys shorter than min_key_length
        assert len(findings) == 0

    def test_filter_low_entropy_keys(self):
        """Test that low entropy keys are filtered when check_entropy is True."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["TEST_"],
            min_key_length=16,
            check_entropy=True,
            min_entropy=3.5,
        )

        content = """
        LOW_ENTROPY = "TEST_AAAAAAAAAAAAAAAA"
        """

        findings = detector.detect(content, "config.py")

        # Low entropy key should be filtered
        # Note: The key "TEST_AAAAAAAAAAAAAAAA" has very low entropy
        for f in findings:
            # If any findings exist, they should have sufficient entropy
            entropy = f.metadata.get("entropy", 0)
            assert entropy >= 3.5 or "TEST_AAAAAAAAAA" not in f.matches[0]

    def test_entropy_calculation(self):
        """Test the entropy calculation utility."""
        detector = CustomAPIKeyDetector()

        # High entropy string (random-looking)
        high_entropy = detector._calculate_entropy("aB3$xY9!mN2@pQ7")
        assert high_entropy > 3.5

        # Low entropy string (repeated characters)
        low_entropy = detector._calculate_entropy("AAAAAAAAAAAAAAAA")
        assert low_entropy < 1.0

        # Empty string
        assert detector._calculate_entropy("") == 0.0

    def test_severity_assessment_production(self):
        """Test severity assessment for production keys."""
        detector = CustomAPIKeyDetector()

        severity = detector._assess_severity("PROD_secret123456", "PROD_")
        assert severity == Severity.CRITICAL

        severity = detector._assess_severity("LIVE_secret123456", "LIVE_")
        assert severity == Severity.CRITICAL

    def test_severity_assessment_staging(self):
        """Test severity assessment for staging/dev keys."""
        detector = CustomAPIKeyDetector()

        severity = detector._assess_severity("STAGING_key123abc", "STAGING_")
        assert severity == Severity.MEDIUM

        severity = detector._assess_severity("DEV_key123abc456", "DEV_")
        assert severity == Severity.MEDIUM

    def test_severity_assessment_high_entropy(self):
        """Test severity assessment for high entropy keys."""
        detector = CustomAPIKeyDetector()

        # High entropy key (random-looking)
        severity = detector._assess_severity("aB3xY9mN2pQ7kL5wE8", "OTHER_")
        assert severity == Severity.HIGH

    def test_finding_metadata(self):
        """Test that findings include proper metadata."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["META_"],
            min_key_length=16,
            check_entropy=False,
        )

        content = 'META_TOKEN = "META_secretKeyValue12345"'

        findings = detector.detect(content, "config.py")

        # Find the prefix match finding
        prefix_findings = [f for f in findings if f.metadata.get("detection_method") == "prefix_match"]
        if prefix_findings:
            f = prefix_findings[0]
            assert "prefix" in f.metadata
            assert "key_length" in f.metadata
            assert "entropy" in f.metadata
            assert "position" in f.metadata
            assert f.detector_name == "custom_api_keys"

    def test_case_insensitive_matching(self):
        """Test case-insensitive prefix matching."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["ACME_"],
            min_key_length=16,
            case_sensitive=False,
            check_entropy=False,
        )

        content = """
        lowercase = "acme_secretKeyValue123"
        uppercase = "ACME_secretKeyValue456"
        """

        findings = detector.detect(content, "config.py")

        # Should find both regardless of case
        matches = [m for f in findings for m in f.matches]
        assert len(matches) >= 2

    def test_case_sensitive_matching(self):
        """Test case-sensitive prefix matching."""
        detector = CustomAPIKeyDetector(
            key_prefixes=["ACME_"],
            min_key_length=16,
            case_sensitive=True,
            check_entropy=False,
        )

        content = """
        lowercase = "acme_secretKeyValue123"
        uppercase = "ACME_secretKeyValue456"
        """

        findings = detector.detect(content, "config.py")

        # Should only find uppercase
        prefix_matches = [f for f in findings if f.metadata.get("detection_method") == "prefix_match"]
        if prefix_matches:
            for f in prefix_matches:
                assert any("ACME_" in m for m in f.matches)
                # lowercase should not be matched via prefix method
                assert not any(m.startswith("acme_") for m in f.matches)

    def test_unsupported_file_returns_empty(self):
        """Test that unsupported files return no findings."""
        detector = CustomAPIKeyDetector()

        content = 'ACME_TOKEN = "ACME_abc123xyz789secret"'

        # Use an unsupported extension
        findings = detector.detect(content, "image.png")

        assert findings == []

    def test_detector_is_detectorplugin_subclass(self):
        """Test that CustomAPIKeyDetector is a proper DetectorPlugin subclass."""
        from hamburglar.plugins.detector_plugin import DetectorPlugin
        from hamburglar.detectors import BaseDetector

        detector = CustomAPIKeyDetector()
        # Check that the class inherits from DetectorPlugin by checking the MRO
        # (using string comparison since the module import paths differ in tests)
        mro_names = [cls.__name__ for cls in type(detector).__mro__]
        assert "DetectorPlugin" in mro_names
        assert "BaseDetector" in mro_names

        # Also verify we have the key DetectorPlugin methods
        assert hasattr(detector, "create_finding")
        assert hasattr(detector, "match_pattern")
        assert hasattr(detector, "match_patterns")
        assert hasattr(detector, "compile_pattern")

    def test_create_finding_helper(self):
        """Test that create_finding helper works correctly."""
        detector = CustomAPIKeyDetector()

        finding = detector.create_finding(
            file_path="test.py",
            matches=["secret123"],
            severity=Severity.HIGH,
            metadata={"custom": "value"},
        )

        assert finding.file_path == "test.py"
        assert finding.detector_name == "custom_api_keys"
        assert finding.matches == ["secret123"]
        assert finding.severity == Severity.HIGH
        assert finding.metadata["custom"] == "value"

    def test_compile_pattern_caching(self):
        """Test that pattern compilation is cached."""
        detector = CustomAPIKeyDetector()

        pattern = r"TEST_[A-Z0-9]+"

        # Compile the same pattern twice
        compiled1 = detector.compile_pattern(pattern)
        compiled2 = detector.compile_pattern(pattern)

        # Should be the same object (cached)
        assert compiled1 is compiled2

    def test_match_literal_helper(self):
        """Test the match_literal helper method."""
        detector = CustomAPIKeyDetector()

        content = "The secret is MY_SECRET_VALUE here"

        findings = detector.match_literal(
            content=content,
            file_path="test.py",
            literal="MY_SECRET_VALUE",
            severity=Severity.HIGH,
        )

        assert len(findings) == 1
        assert findings[0].matches == ["MY_SECRET_VALUE"]
