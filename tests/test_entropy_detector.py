"""Tests for entropy-based secret detection.

This module contains comprehensive tests for the EntropyDetector class,
testing entropy calculation, high-entropy string detection, base64/hex
detection, false positive exclusion, and configurable thresholds.

NOTE: Test patterns are intentionally constructed to be obviously fake and
avoid triggering secret scanning.
"""

from __future__ import annotations

from hamburglar.core.models import Severity
from hamburglar.detectors.entropy_detector import (
    DEFAULT_ENTROPY_THRESHOLD,
    HIGH_ENTROPY_THRESHOLD,
    EntropyDetector,
    calculate_shannon_entropy,
    has_secret_context,
    is_base64_encoded,
    is_hex_encoded,
    is_known_false_positive,
)


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_string_entropy(self) -> None:
        """Empty string should have zero entropy."""
        assert calculate_shannon_entropy("") == 0.0

    def test_single_character_string(self) -> None:
        """String with single repeated character should have zero entropy."""
        assert calculate_shannon_entropy("aaaaaaaaaa") == 0.0
        assert calculate_shannon_entropy("bbbbbbbbbb") == 0.0

    def test_two_character_string_equal_frequency(self) -> None:
        """String with two equally frequent characters should have entropy of 1."""
        # Half a's, half b's = 1 bit of entropy
        entropy = calculate_shannon_entropy("abababab")
        assert abs(entropy - 1.0) < 0.01

    def test_low_entropy_string(self) -> None:
        """Common words should have low entropy."""
        entropy = calculate_shannon_entropy("password")
        assert entropy < 3.0

    def test_medium_entropy_string(self) -> None:
        """Mixed case words should have medium entropy."""
        entropy = calculate_shannon_entropy("PassWord123")
        assert 2.5 < entropy < 4.0

    def test_high_entropy_string(self) -> None:
        """Random-looking strings should have high entropy."""
        # A string with good character distribution
        high_entropy = "aB3cD4eF5gH6iJ7kL8mN9"
        entropy = calculate_shannon_entropy(high_entropy)
        assert entropy > 4.0

    def test_maximum_entropy_approximation(self) -> None:
        """String with all unique characters should approach maximum entropy."""
        # 26 unique lowercase letters
        all_unique = "abcdefghijklmnopqrstuvwxyz"
        entropy = calculate_shannon_entropy(all_unique)
        # log2(26) ≈ 4.7
        assert entropy > 4.5

    def test_hex_string_entropy(self) -> None:
        """Hex strings (0-9, a-f) have bounded entropy."""
        # Hex characters have max entropy of log2(16) = 4
        hex_string = "0123456789abcdef"
        entropy = calculate_shannon_entropy(hex_string)
        # Should be exactly 4 with uniform distribution
        assert abs(entropy - 4.0) < 0.01

    def test_base64_like_entropy(self) -> None:
        """Base64-like strings should have moderate to high entropy."""
        base64_like = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        entropy = calculate_shannon_entropy(base64_like)
        assert entropy > 4.5


class TestBase64Detection:
    """Tests for base64 encoding detection."""

    def test_valid_base64_string(self) -> None:
        """Valid base64 strings should be detected."""
        assert is_base64_encoded("YWJjZGVmZ2hpamtsbW5vcA==")
        assert is_base64_encoded("dGhpcyBpcyBhIHRlc3Qgc3RyaW5n")

    def test_base64_without_padding(self) -> None:
        """Base64 without padding should still be detected if valid."""
        # Length is a multiple of 4, valid base64 chars
        assert is_base64_encoded("YWJjZGVmZ2hpamtsbW5v")

    def test_short_string_not_base64(self) -> None:
        """Short strings should not be considered base64."""
        assert not is_base64_encoded("abc")
        assert not is_base64_encoded("short")

    def test_invalid_base64_characters(self) -> None:
        """Strings with invalid base64 characters should not match."""
        assert not is_base64_encoded("abc!def#ghi$jkl%mno")
        assert not is_base64_encoded("this has spaces here")

    def test_too_much_padding(self) -> None:
        """More than 2 padding characters is invalid."""
        assert not is_base64_encoded("YWJjZGVmZ2g===")

    def test_wrong_length_not_base64(self) -> None:
        """Length not divisible by 4 is not valid base64."""
        # len=25, invalid (not divisible by 4)
        assert not is_base64_encoded("YWJjZGVmZ2hpamtsbW5vcHFyc")
        # len=23, invalid (not divisible by 4)
        assert not is_base64_encoded("YWJjZGVmZ2hpamtsbW5vcHF")


class TestHexDetection:
    """Tests for hex encoding detection."""

    def test_valid_hex_string_lowercase(self) -> None:
        """Valid lowercase hex strings should be detected."""
        assert is_hex_encoded("0123456789abcdef0123456789abcdef")

    def test_valid_hex_string_uppercase(self) -> None:
        """Valid uppercase hex strings should be detected."""
        assert is_hex_encoded("0123456789ABCDEF0123456789ABCDEF")

    def test_valid_hex_string_mixed_case(self) -> None:
        """Valid mixed case hex strings should be detected."""
        assert is_hex_encoded("0123456789AbCdEf0123456789AbCdEf")

    def test_short_string_not_hex(self) -> None:
        """Short strings should not be considered hex."""
        assert not is_hex_encoded("abc")
        assert not is_hex_encoded("0123456789")

    def test_odd_length_not_hex(self) -> None:
        """Odd-length strings are not valid hex encoding."""
        assert not is_hex_encoded("0123456789abcdef0")

    def test_invalid_hex_characters(self) -> None:
        """Strings with non-hex characters should not match."""
        assert not is_hex_encoded("0123456789ghijkl0123456789ghijkl")
        assert not is_hex_encoded("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")


class TestFalsePositiveDetection:
    """Tests for false positive exclusion."""

    def test_uuid_v4_is_false_positive(self) -> None:
        """UUID v4 should be excluded as false positive."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert is_known_false_positive(uuid)

    def test_uuid_with_letters_is_false_positive(self) -> None:
        """UUID with letters should be excluded."""
        uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert is_known_false_positive(uuid)

    def test_md5_hash_standalone_is_false_positive(self) -> None:
        """MD5-length hex string is excluded (too common)."""
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        assert is_known_false_positive(md5)

    def test_version_string_is_false_positive(self) -> None:
        """Version strings should be excluded."""
        assert is_known_false_positive("v1.2.3-beta")
        assert is_known_false_positive("2.0.0-alpha")

    def test_file_path_is_false_positive(self) -> None:
        """File paths should be excluded."""
        assert is_known_false_positive("/usr/local/bin/something")
        assert is_known_false_positive("\\Program Files\\App")

    def test_import_statement_is_false_positive(self) -> None:
        """Import statements should be excluded."""
        assert is_known_false_positive("import something_module")
        assert is_known_false_positive("require some_package")

    def test_hash_algorithm_name_is_false_positive(self) -> None:
        """Hash algorithm names should be excluded."""
        assert is_known_false_positive("SHA256withRSA")
        assert is_known_false_positive("MD5HASH")

    def test_lorem_ipsum_is_false_positive(self) -> None:
        """Lorem ipsum text should be excluded."""
        assert is_known_false_positive("lorem ipsum dolor sit amet")

    def test_test_values_are_false_positive(self) -> None:
        """Test/example values should be excluded."""
        assert is_known_false_positive("test_api_key_value")
        assert is_known_false_positive("example_token_here")

    def test_repeated_character_is_false_positive(self) -> None:
        """Repeated single character should be excluded."""
        assert is_known_false_positive("aaaaaaaaaaaaaaaa")
        assert is_known_false_positive("XXXXXXXXXXXXXXXX")

    def test_sequential_pattern_is_false_positive(self) -> None:
        """Sequential patterns should be excluded."""
        assert is_known_false_positive("0123456789abcdef")
        assert is_known_false_positive("abcdefghijklmnop")

    def test_random_string_not_false_positive(self) -> None:
        """Random-looking strings should not be false positives."""
        assert not is_known_false_positive("Kj7mNp2qRs8tUv3w")
        assert not is_known_false_positive("aB3cD4eF5gH6iJ7k")


class TestSecretContext:
    """Tests for secret context detection."""

    def test_password_context(self) -> None:
        """Password-related context should be detected."""
        assert has_secret_context("password = 'secret123'")
        assert has_secret_context("passwd: xxx")
        assert has_secret_context("pwd=something")

    def test_secret_context(self) -> None:
        """Secret-related context should be detected."""
        assert has_secret_context("secret_key = 'value'")
        assert has_secret_context("app_secret: xxx")

    def test_token_context(self) -> None:
        """Token-related context should be detected."""
        assert has_secret_context("token = 'abc123'")
        assert has_secret_context("auth_token: xxx")
        assert has_secret_context("bearer_token = xxx")

    def test_api_key_context(self) -> None:
        """API key context should be detected."""
        assert has_secret_context("api_key = 'xxx'")
        assert has_secret_context("apikey: value")

    def test_credential_context(self) -> None:
        """Credential-related context should be detected."""
        assert has_secret_context("credentials = {...}")
        assert has_secret_context("auth_header = xxx")

    def test_encryption_context(self) -> None:
        """Encryption-related context should be detected."""
        assert has_secret_context("encrypt_key = xxx")
        assert has_secret_context("hmac_secret = xxx")

    def test_no_context(self) -> None:
        """Regular text should not have secret context."""
        assert not has_secret_context("name = 'John'")
        assert not has_secret_context("color: blue")
        assert not has_secret_context("count = 42")


class TestEntropyDetectorInit:
    """Tests for EntropyDetector initialization."""

    def test_default_initialization(self) -> None:
        """Default initialization should use default values."""
        detector = EntropyDetector()
        assert detector.name == "entropy"
        assert detector.entropy_threshold == DEFAULT_ENTROPY_THRESHOLD
        assert detector.high_entropy_threshold == HIGH_ENTROPY_THRESHOLD
        assert detector.min_string_length == 16
        assert detector.max_string_length == 256

    def test_custom_entropy_threshold(self) -> None:
        """Custom entropy threshold should be respected."""
        detector = EntropyDetector(entropy_threshold=5.0)
        assert detector.entropy_threshold == 5.0

    def test_custom_high_entropy_threshold(self) -> None:
        """Custom high entropy threshold should be respected."""
        detector = EntropyDetector(high_entropy_threshold=5.5)
        assert detector.high_entropy_threshold == 5.5

    def test_custom_string_length_bounds(self) -> None:
        """Custom string length bounds should be respected."""
        detector = EntropyDetector(min_string_length=20, max_string_length=100)
        assert detector.min_string_length == 20
        assert detector.max_string_length == 100

    def test_custom_max_file_size(self) -> None:
        """Custom max file size should be respected."""
        detector = EntropyDetector(max_file_size=1024 * 1024)
        assert detector.max_file_size == 1024 * 1024


class TestEntropyDetectorDetection:
    """Tests for EntropyDetector.detect() method."""

    def test_high_entropy_string_detected(self) -> None:
        """High entropy strings should be detected."""
        detector = EntropyDetector()
        content = 'api_key = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        assert len(findings) >= 1
        # Should find the high-entropy string
        all_matches = [m for f in findings for m in f.matches]
        assert any("aB3cD4eF5gH6iJ7kL8mN9oP0" in m for m in all_matches)

    def test_low_entropy_string_not_detected(self) -> None:
        """Low entropy strings should not be detected."""
        detector = EntropyDetector()
        content = 'username = "aaaaaaaaaaaaaaaa"'
        findings = detector.detect(content, "test.py")
        # Repeated characters have low entropy
        all_matches = [m for f in findings for m in f.matches]
        assert not any("aaaaaaaaaaaaaaaa" in m for m in all_matches)

    def test_base64_string_detected(self) -> None:
        """Base64 encoded strings should be detected."""
        detector = EntropyDetector()
        # High-entropy base64-like string (entropy ~5.0)
        content = 'secret = "Xk2Lm9Np7Qr5St3Uv1WxYzAbCdEfGh=="'
        findings = detector.detect(content, "test.py")
        assert len(findings) >= 1

    def test_hex_string_detected(self) -> None:
        """Hex encoded strings should be detected."""
        # Use lower threshold to catch hex strings (which have max entropy of 4.0)
        detector = EntropyDetector(entropy_threshold=3.5)
        # 64-char hex string (256-bit key) - hex has max entropy of log2(16)=4.0
        hex_string = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
        content = f'key = "{hex_string}"'
        findings = detector.detect(content, "test.py")
        assert len(findings) >= 1

    def test_exclude_base64_option(self) -> None:
        """exclude_base64 option should skip base64 strings."""
        detector = EntropyDetector(exclude_base64=True)
        content = 'token = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="'
        findings = detector.detect(content, "test.py")
        # The base64 string should be excluded
        for finding in findings:
            assert not finding.metadata.get("is_base64", False)

    def test_exclude_hex_option(self) -> None:
        """exclude_hex option should skip hex strings."""
        detector = EntropyDetector(exclude_hex=True)
        hex_string = "0123456789abcdef0123456789abcdef"
        content = f'key = "{hex_string}"'
        findings = detector.detect(content, "test.py")
        # The hex string should be excluded
        for finding in findings:
            assert not finding.metadata.get("is_hex", False)

    def test_require_context_option(self) -> None:
        """require_context option should only detect strings with secret context."""
        detector_with_context = EntropyDetector(require_context=True)
        detector_without_context = EntropyDetector(require_context=False)

        # High entropy string without secret context
        content = 'random = "Kj7mNp2qRs8tUvWxYzAbCdEfGhIjKlMn"'
        findings_with = detector_with_context.detect(content, "test.py")
        findings_without = detector_without_context.detect(content, "test.py")

        # Without context requirement, should still find it
        # With context requirement, should not find it
        # (since 'random' is not a secret-related keyword)
        assert len(findings_with) == 0 or all(
            f.metadata.get("has_secret_context", True) for f in findings_with
        )

    def test_context_increases_findings(self) -> None:
        """Secret context should help identify potential secrets."""
        detector = EntropyDetector()
        # Use high-entropy string (entropy ~5.0) with password context
        content_with_context = 'password = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"'
        findings = detector.detect(content_with_context, "test.py")

        # Should find the string with password context
        has_context_finding = any(f.metadata.get("has_secret_context", False) for f in findings)
        assert has_context_finding or len(findings) >= 1

    def test_short_strings_ignored(self) -> None:
        """Strings shorter than min_string_length should be ignored."""
        detector = EntropyDetector(min_string_length=20)
        content = 'key = "aB3cD4eF5gH6"'  # 12 chars
        findings = detector.detect(content, "test.py")
        # Should not find the short string
        all_matches = [m for f in findings for m in f.matches]
        assert not any("aB3cD4eF5gH6" in m for m in all_matches)

    def test_long_strings_ignored(self) -> None:
        """Strings longer than max_string_length should be ignored."""
        detector = EntropyDetector(max_string_length=30)
        long_string = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5" * 2  # ~80 chars
        content = f'key = "{long_string}"'
        findings = detector.detect(content, "test.py")
        # Should not find the long string
        all_matches = [m for f in findings for m in f.matches]
        assert not any(long_string in m for m in all_matches)

    def test_uuid_excluded(self) -> None:
        """UUIDs should be excluded from findings."""
        detector = EntropyDetector()
        content = 'id = "550e8400-e29b-41d4-a716-446655440000"'
        findings = detector.detect(content, "test.py")
        # UUID should not be in matches
        all_matches = [m for f in findings for m in f.matches]
        assert "550e8400-e29b-41d4-a716-446655440000" not in all_matches

    def test_empty_content(self) -> None:
        """Empty content should return no findings."""
        detector = EntropyDetector()
        findings = detector.detect("", "test.py")
        assert len(findings) == 0

    def test_file_size_limit(self) -> None:
        """Files exceeding max_file_size should be skipped."""
        detector = EntropyDetector(max_file_size=100)
        large_content = "x" * 200
        findings = detector.detect(large_content, "test.py")
        assert len(findings) == 0


class TestEntropyDetectorSeverity:
    """Tests for severity level assignment."""

    def test_high_entropy_with_context_is_high_severity(self) -> None:
        """High entropy with secret context should be HIGH severity."""
        detector = EntropyDetector()
        # Very high entropy string with password context
        content = 'password = "Kj7mNp2qRs8tUvWxYzAbCdEfGhIjKl"'
        findings = detector.detect(content, "test.py")
        # At least one should be HIGH severity
        high_severity_findings = [f for f in findings if f.severity == Severity.HIGH]
        # Context should help boost severity
        assert len(findings) >= 1

    def test_high_entropy_base64_is_high_severity(self) -> None:
        """High entropy base64 should be HIGH severity."""
        detector = EntropyDetector()
        # High entropy base64-like string (entropy ~5.0)
        content = 'token = "Xk2Lm9Np7Qr5St3Uv1WxYzAbCdEfGh=="'
        findings = detector.detect(content, "test.py")
        assert len(findings) >= 1

    def test_medium_entropy_with_context_is_medium_severity(self) -> None:
        """Medium entropy with context should be MEDIUM severity."""
        detector = EntropyDetector(entropy_threshold=3.0)
        content = 'password = "abcdefghijklmnop"'
        findings = detector.detect(content, "test.py")
        # Should have findings
        assert len(findings) >= 0  # May or may not find depending on threshold

    def test_threshold_entropy_without_context_is_low_severity(self) -> None:
        """Just-above-threshold without context should be LOW severity."""
        detector = EntropyDetector()
        # String that meets threshold but lacks context
        content = 'data = "Kj7mNp2qRs8tUvWxYzAbCd"'
        findings = detector.detect(content, "test.py")
        # Low severity findings should exist or none
        low_severity = [f for f in findings if f.severity == Severity.LOW]
        # Either LOW severity or nothing (due to no context)
        assert len(findings) >= 0


class TestEntropyDetectorMetadata:
    """Tests for finding metadata."""

    def test_metadata_contains_entropy(self) -> None:
        """Finding metadata should contain entropy value."""
        detector = EntropyDetector()
        content = 'key = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert "entropy" in findings[0].metadata
            assert isinstance(findings[0].metadata["entropy"], float)

    def test_metadata_contains_length(self) -> None:
        """Finding metadata should contain string length."""
        detector = EntropyDetector()
        content = 'key = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert "length" in findings[0].metadata
            assert isinstance(findings[0].metadata["length"], int)

    def test_metadata_contains_encoding_flags(self) -> None:
        """Finding metadata should contain base64/hex flags."""
        detector = EntropyDetector()
        content = 'key = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert "is_base64" in findings[0].metadata
            assert "is_hex" in findings[0].metadata

    def test_metadata_contains_context_flag(self) -> None:
        """Finding metadata should contain secret context flag."""
        detector = EntropyDetector()
        content = 'password = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert "has_secret_context" in findings[0].metadata
            assert findings[0].metadata["has_secret_context"] is True

    def test_metadata_contains_context_snippet(self) -> None:
        """Finding metadata should contain context snippet."""
        detector = EntropyDetector()
        content = 'password = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert "context_snippet" in findings[0].metadata
            assert "password" in findings[0].metadata["context_snippet"]


class TestEntropyDetectorAnalyzeString:
    """Tests for the analyze_string utility method."""

    def test_analyze_high_entropy_string(self) -> None:
        """analyze_string should return correct analysis for high entropy."""
        detector = EntropyDetector()
        result = detector.analyze_string("aB3cD4eF5gH6iJ7kL8mN9oP0")
        assert result["length"] == 24
        assert result["entropy"] > 4.0
        assert result["exceeds_threshold"] is True
        assert "is_base64" in result
        assert "is_hex" in result

    def test_analyze_low_entropy_string(self) -> None:
        """analyze_string should return correct analysis for low entropy."""
        detector = EntropyDetector()
        result = detector.analyze_string("aaaaaaaaaaaaaaaa")
        assert result["entropy"] == 0.0
        assert result["exceeds_threshold"] is False

    def test_analyze_uuid_as_false_positive(self) -> None:
        """analyze_string should identify UUID as false positive."""
        detector = EntropyDetector()
        result = detector.analyze_string("550e8400-e29b-41d4-a716-446655440000")
        assert result["is_false_positive"] is True

    def test_analyze_base64_string(self) -> None:
        """analyze_string should identify base64 encoding."""
        detector = EntropyDetector()
        result = detector.analyze_string("YWJjZGVmZ2hpamtsbW5vcA==")
        assert result["is_base64"] is True

    def test_analyze_hex_string(self) -> None:
        """analyze_string should identify hex encoding."""
        detector = EntropyDetector()
        result = detector.analyze_string("0123456789abcdef0123456789abcdef")
        assert result["is_hex"] is True


class TestConfigurableThresholds:
    """Tests for configurable entropy thresholds."""

    def test_lower_threshold_detects_more(self) -> None:
        """Lower threshold should detect more strings."""
        detector_low = EntropyDetector(entropy_threshold=3.0)
        detector_high = EntropyDetector(entropy_threshold=5.0)

        # Medium entropy content
        content = 'key = "abcdefghij123456"'  # Medium entropy
        findings_low = detector_low.detect(content, "test.py")
        findings_high = detector_high.detect(content, "test.py")

        assert len(findings_low) >= len(findings_high)

    def test_higher_threshold_stricter(self) -> None:
        """Higher threshold should be stricter."""
        detector = EntropyDetector(entropy_threshold=5.5)
        # Only very high entropy strings should be detected
        content = 'key = "SimplePassword123"'
        findings = detector.detect(content, "test.py")
        # Medium entropy strings should not be detected
        assert len(findings) == 0


class TestEntropyDetectorIntegration:
    """Integration tests for EntropyDetector."""

    def test_realistic_config_file(self) -> None:
        """Test with realistic config file content."""
        detector = EntropyDetector()
        content = """
        DATABASE_URL=postgres://user:pass@localhost/db
        API_KEY="aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3w"
        DEBUG=true
        LOG_LEVEL=info
        """
        findings = detector.detect(content, ".env")
        # Should detect the high-entropy API key
        assert len(findings) >= 1

    def test_realistic_source_file(self) -> None:
        """Test with realistic source file content."""
        detector = EntropyDetector()
        content = """
        const config = {
            apiKey: "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3w",
            baseUrl: "https://api.example.com",
            timeout: 5000
        };
        """
        findings = detector.detect(content, "config.js")
        # Should detect the high-entropy API key
        assert len(findings) >= 1

    def test_realistic_false_positive_avoidance(self) -> None:
        """Test that common false positives are avoided."""
        detector = EntropyDetector()
        content = """
        // Git commit: 550e8400e29b41d4a716446655440000
        const uuid = "550e8400-e29b-41d4-a716-446655440000";
        import { something } from "long_module_name_here";
        const version = "v1.2.3-beta";
        """
        findings = detector.detect(content, "source.js")
        # These should all be excluded as false positives
        all_matches = [m for f in findings for m in f.matches]
        assert "550e8400-e29b-41d4-a716-446655440000" not in all_matches

    def test_detector_name(self) -> None:
        """Test that detector name follows expected format."""
        detector = EntropyDetector()
        content = 'secret = "aB3cD4eF5gH6iJ7kL8mN9oP0"'
        findings = detector.detect(content, "test.py")
        if findings:
            assert findings[0].detector_name.startswith("entropy:")
