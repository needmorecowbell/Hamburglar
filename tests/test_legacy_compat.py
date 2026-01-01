"""Tests for legacy compatibility patterns.

This module contains comprehensive tests for all legacy patterns from the original
hamburglar.py implementation. Each pattern is tested to ensure backward compatibility
and zero detection regression.
"""

from __future__ import annotations

import re

import pytest

from hamburglar.compat.legacy_patterns import (
    BITCOIN_CASH_ADDRESS_PATTERN,
    BITCOIN_URI_PATTERN,
    BITCOIN_XPUB_KEY_PATTERN,
    DASH_ADDRESS_PATTERN,
    EMAIL_PATTERN,
    FACEBOOK_OAUTH_PATTERN,
    GENERIC_SECRET_LEGACY_PATTERN,
    GITHUB_LEGACY_PATTERN,
    HEROKU_API_KEY_LEGACY_PATTERN,
    LEGACY_ONLY_PATTERNS,
    LEGACY_REGEX_LIST,
    NEO_ADDRESS_PATTERN,
    PHONE_PATTERN,
    SITE_PATTERN,
    TWITTER_OAUTH_PATTERN,
    get_legacy_pattern,
    get_legacy_pattern_names,
    legacy_patterns_to_detector_format,
)
from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import PatternCategory


class TestEmailPattern:
    """Tests for email address pattern."""

    def test_email_positive_1(self) -> None:
        """Test basic email address."""
        pattern = re.compile(EMAIL_PATTERN.regex)
        result = pattern.search("user@example.com")
        assert result is not None

    def test_email_positive_2(self) -> None:
        """Test email with subdomain."""
        pattern = re.compile(EMAIL_PATTERN.regex)
        result = pattern.search("user@mail.example.co.uk")
        assert result is not None

    def test_email_positive_3(self) -> None:
        """Test email with dots and plus."""
        pattern = re.compile(EMAIL_PATTERN.regex)
        result = pattern.search("user.name+tag@example.org")
        assert result is not None

    def test_email_negative_1(self) -> None:
        """Test missing @ symbol."""
        pattern = re.compile(EMAIL_PATTERN.regex)
        result = pattern.search("userexample.com")
        assert result is None

    def test_email_negative_2(self) -> None:
        """Test missing domain."""
        pattern = re.compile(EMAIL_PATTERN.regex)
        result = pattern.search("user@")
        assert result is None


class TestPhonePattern:
    """Tests for US phone number pattern.

    US phone numbers follow NANP format where area code and exchange
    must start with digits 2-9.
    """

    def test_phone_positive_1(self) -> None:
        """Test phone with parentheses."""
        pattern = re.compile(PHONE_PATTERN.regex)
        # Exchange must start with 2-9, not 1
        result = pattern.search("(555) 234-5678")
        assert result is not None

    def test_phone_positive_2(self) -> None:
        """Test phone with dashes."""
        pattern = re.compile(PHONE_PATTERN.regex)
        result = pattern.search("555-234-5678")
        assert result is not None

    def test_phone_positive_3(self) -> None:
        """Test phone with dots."""
        pattern = re.compile(PHONE_PATTERN.regex)
        result = pattern.search("555.234.5678")
        assert result is not None

    def test_phone_negative_1(self) -> None:
        """Test invalid area code starting with 1."""
        pattern = re.compile(PHONE_PATTERN.regex)
        result = pattern.search("(155) 234-5678")
        assert result is None

    def test_phone_negative_2(self) -> None:
        """Test too short number."""
        pattern = re.compile(PHONE_PATTERN.regex)
        result = pattern.search("555-123")
        assert result is None


class TestSitePattern:
    """Tests for URL/site pattern."""

    def test_site_positive_1(self) -> None:
        """Test basic HTTPS URL."""
        pattern = re.compile(SITE_PATTERN.regex)
        result = pattern.search("https://example.com")
        assert result is not None

    def test_site_positive_2(self) -> None:
        """Test HTTP URL with path."""
        pattern = re.compile(SITE_PATTERN.regex)
        result = pattern.search("http://www.example.org/path/to/page")
        assert result is not None

    def test_site_positive_3(self) -> None:
        """Test URL with encoded characters."""
        pattern = re.compile(SITE_PATTERN.regex)
        result = pattern.search("https://example.com/path%20with%20spaces")
        assert result is not None

    def test_site_negative_1(self) -> None:
        """Test FTP protocol (not HTTP/S)."""
        pattern = re.compile(SITE_PATTERN.regex)
        result = pattern.search("ftp://files.example.com")
        assert result is None

    def test_site_negative_2(self) -> None:
        """Test missing protocol."""
        pattern = re.compile(SITE_PATTERN.regex)
        result = pattern.search("www.example.com")
        assert result is None


class TestBitcoinURIPattern:
    """Tests for Bitcoin URI pattern."""

    def test_bitcoin_uri_positive_1(self) -> None:
        """Test basic Bitcoin URI."""
        pattern = re.compile(BITCOIN_URI_PATTERN.regex)
        result = pattern.search("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert result is not None

    def test_bitcoin_uri_positive_2(self) -> None:
        """Test Bitcoin URI with P2SH address."""
        pattern = re.compile(BITCOIN_URI_PATTERN.regex)
        result = pattern.search("bitcoin:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
        assert result is not None

    def test_bitcoin_uri_negative_1(self) -> None:
        """Test wrong protocol."""
        pattern = re.compile(BITCOIN_URI_PATTERN.regex)
        result = pattern.search("litecoin:LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1")
        assert result is None

    def test_bitcoin_uri_negative_2(self) -> None:
        """Test address too short."""
        pattern = re.compile(BITCOIN_URI_PATTERN.regex)
        result = pattern.search("bitcoin:1BvBMSEYstW")
        assert result is None


class TestBitcoinXpubKeyPattern:
    """Tests for Bitcoin extended public key pattern."""

    def test_xpub_positive_1(self) -> None:
        """Test basic xpub key (101 chars)."""
        pattern = re.compile(BITCOIN_XPUB_KEY_PATTERN.regex)
        # xpub + 97 base58 chars = 101 total
        key = "xpub" + "a" * 100
        result = pattern.search(key)
        assert result is not None

    def test_xpub_positive_2(self) -> None:
        """Test xpub with BIP parameters."""
        pattern = re.compile(BITCOIN_XPUB_KEY_PATTERN.regex)
        key = "xpub" + "B" * 104 + "?c=0&h=bip44"
        result = pattern.search(key)
        assert result is not None

    def test_xpub_negative_1(self) -> None:
        """Test wrong prefix."""
        pattern = re.compile(BITCOIN_XPUB_KEY_PATTERN.regex)
        key = "ypub" + "a" * 100
        result = pattern.search(key)
        assert result is None

    def test_xpub_negative_2(self) -> None:
        """Test too short."""
        pattern = re.compile(BITCOIN_XPUB_KEY_PATTERN.regex)
        key = "xpub" + "a" * 50
        result = pattern.search(key)
        assert result is None


class TestDashAddressPattern:
    """Tests for Dash cryptocurrency address pattern."""

    def test_dash_address_positive_1(self) -> None:
        """Test Dash address starting with X."""
        pattern = re.compile(DASH_ADDRESS_PATTERN.regex)
        # 34 chars total: X + 33 base58
        addr = "X" + "a" * 33
        result = pattern.search(addr)
        assert result is not None

    def test_dash_address_positive_2(self) -> None:
        """Test Dash address with varied base58 chars."""
        pattern = re.compile(DASH_ADDRESS_PATTERN.regex)
        # Base58 excludes 0, O, I, l - use only valid chars
        # Need X + 33 chars = 34 total
        addr = "X" + "B1c2D3e4F5g6H7n8J9ka" + "a" * 13
        result = pattern.search(addr)
        assert result is not None

    def test_dash_address_negative_1(self) -> None:
        """Test wrong prefix."""
        pattern = re.compile(DASH_ADDRESS_PATTERN.regex)
        addr = "Y" + "a" * 33
        result = pattern.search(addr)
        assert result is None

    def test_dash_address_negative_2(self) -> None:
        """Test too short."""
        pattern = re.compile(DASH_ADDRESS_PATTERN.regex)
        addr = "X" + "a" * 20
        result = pattern.search(addr)
        assert result is None


class TestNeoAddressPattern:
    """Tests for NEO blockchain address pattern."""

    def test_neo_address_positive_1(self) -> None:
        """Test NEO address starting with A."""
        pattern = re.compile(NEO_ADDRESS_PATTERN.regex)
        # 34 chars total: A + 33 alphanumeric
        addr = "A" + "a" * 33
        result = pattern.search(addr)
        assert result is not None

    def test_neo_address_positive_2(self) -> None:
        """Test NEO address with numbers."""
        pattern = re.compile(NEO_ADDRESS_PATTERN.regex)
        addr = "A" + "1234567890" + "a" * 23
        result = pattern.search(addr)
        assert result is not None

    def test_neo_address_negative_1(self) -> None:
        """Test wrong prefix."""
        pattern = re.compile(NEO_ADDRESS_PATTERN.regex)
        addr = "B" + "a" * 33
        result = pattern.search(addr)
        assert result is None

    def test_neo_address_negative_2(self) -> None:
        """Test too short."""
        pattern = re.compile(NEO_ADDRESS_PATTERN.regex)
        addr = "A" + "a" * 20
        result = pattern.search(addr)
        assert result is None


class TestFacebookOAuthPattern:
    """Tests for Facebook OAuth token pattern."""

    def test_facebook_oauth_positive_1(self) -> None:
        """Test Facebook OAuth with quotes."""
        pattern = re.compile(FACEBOOK_OAUTH_PATTERN.regex)
        token = "a" * 32
        result = pattern.search(f"facebook_token = '{token}'")
        assert result is not None

    def test_facebook_oauth_positive_2(self) -> None:
        """Test Facebook OAuth with double quotes."""
        pattern = re.compile(FACEBOOK_OAUTH_PATTERN.regex)
        token = "b" * 32
        result = pattern.search(f'FACEBOOK_KEY: "{token}"')
        assert result is not None

    def test_facebook_oauth_negative_1(self) -> None:
        """Test token without context."""
        pattern = re.compile(FACEBOOK_OAUTH_PATTERN.regex)
        token = "a" * 32
        result = pattern.search(f"token = '{token}'")
        assert result is None

    def test_facebook_oauth_negative_2(self) -> None:
        """Test token too short."""
        pattern = re.compile(FACEBOOK_OAUTH_PATTERN.regex)
        token = "a" * 20
        result = pattern.search(f"facebook_token = '{token}'")
        assert result is None


class TestTwitterOAuthPattern:
    """Tests for Twitter OAuth token pattern."""

    def test_twitter_oauth_positive_1(self) -> None:
        """Test Twitter OAuth token."""
        pattern = re.compile(TWITTER_OAUTH_PATTERN.regex)
        token = "a" * 40
        result = pattern.search(f"twitter_secret = '{token}'")
        assert result is not None

    def test_twitter_oauth_positive_2(self) -> None:
        """Test Twitter OAuth with double quotes."""
        pattern = re.compile(TWITTER_OAUTH_PATTERN.regex)
        token = "B" * 35
        result = pattern.search(f'TWITTER_TOKEN: "{token}"')
        assert result is not None

    def test_twitter_oauth_negative_1(self) -> None:
        """Test token without context."""
        pattern = re.compile(TWITTER_OAUTH_PATTERN.regex)
        token = "a" * 40
        result = pattern.search(f"secret = '{token}'")
        assert result is None

    def test_twitter_oauth_negative_2(self) -> None:
        """Test token too short."""
        pattern = re.compile(TWITTER_OAUTH_PATTERN.regex)
        token = "a" * 20
        result = pattern.search(f"twitter_token = '{token}'")
        assert result is None


class TestGenericSecretLegacyPattern:
    """Tests for legacy generic secret pattern."""

    def test_generic_secret_positive_1(self) -> None:
        """Test generic secret with quotes."""
        pattern = re.compile(GENERIC_SECRET_LEGACY_PATTERN.regex)
        secret = "a" * 35
        result = pattern.search(f"secret_key = '{secret}'")
        assert result is not None

    def test_generic_secret_positive_2(self) -> None:
        """Test SECRET keyword case-insensitive."""
        pattern = re.compile(GENERIC_SECRET_LEGACY_PATTERN.regex)
        secret = "B" * 40
        result = pattern.search(f'SECRET: "{secret}"')
        assert result is not None

    def test_generic_secret_negative_1(self) -> None:
        """Test without secret context."""
        pattern = re.compile(GENERIC_SECRET_LEGACY_PATTERN.regex)
        secret = "a" * 35
        result = pattern.search(f"key = '{secret}'")
        assert result is None

    def test_generic_secret_negative_2(self) -> None:
        """Test value too short."""
        pattern = re.compile(GENERIC_SECRET_LEGACY_PATTERN.regex)
        secret = "a" * 20
        result = pattern.search(f"secret = '{secret}'")
        assert result is None


class TestGitHubLegacyPattern:
    """Tests for legacy GitHub token pattern."""

    def test_github_legacy_positive_1(self) -> None:
        """Test GitHub token with quotes."""
        pattern = re.compile(GITHUB_LEGACY_PATTERN.regex)
        token = "a" * 38
        result = pattern.search(f"github_token = '{token}'")
        assert result is not None

    def test_github_legacy_positive_2(self) -> None:
        """Test GitHub token with double quotes."""
        pattern = re.compile(GITHUB_LEGACY_PATTERN.regex)
        token = "B" * 35
        result = pattern.search(f'GITHUB_KEY: "{token}"')
        assert result is not None

    def test_github_legacy_negative_1(self) -> None:
        """Test token without context."""
        pattern = re.compile(GITHUB_LEGACY_PATTERN.regex)
        token = "a" * 38
        result = pattern.search(f"token = '{token}'")
        assert result is None

    def test_github_legacy_negative_2(self) -> None:
        """Test token too short."""
        pattern = re.compile(GITHUB_LEGACY_PATTERN.regex)
        token = "a" * 20
        result = pattern.search(f"github_token = '{token}'")
        assert result is None


class TestHerokuLegacyPattern:
    """Tests for legacy Heroku API key pattern."""

    def test_heroku_legacy_positive_1(self) -> None:
        """Test Heroku API key with UUID (hex chars only)."""
        pattern = re.compile(HEROKU_API_KEY_LEGACY_PATTERN.regex)
        # UUID must use only hex chars: 0-9 and A-F
        result = pattern.search(
            "heroku_api_key = 12345678-ABCD-EF12-3456-123456789ABC"
        )
        assert result is not None

    def test_heroku_legacy_positive_2(self) -> None:
        """Test Heroku API key alternate format."""
        pattern = re.compile(HEROKU_API_KEY_LEGACY_PATTERN.regex)
        result = pattern.search(
            "HEROKU_KEY: ABCDEF12-3456-7890-ABCD-EF1234567890"
        )
        assert result is not None

    def test_heroku_legacy_negative_1(self) -> None:
        """Test UUID without Heroku context."""
        pattern = re.compile(HEROKU_API_KEY_LEGACY_PATTERN.regex)
        result = pattern.search(
            "api_key = 12345678-ABCD-EFGH-IJKL-123456789ABC"
        )
        assert result is None

    def test_heroku_legacy_negative_2(self) -> None:
        """Test malformed UUID."""
        pattern = re.compile(HEROKU_API_KEY_LEGACY_PATTERN.regex)
        result = pattern.search("heroku_key = 12345678-ABC")
        assert result is None


class TestLegacyRegexList:
    """Tests for the LEGACY_REGEX_LIST dictionary."""

    def test_legacy_list_has_all_patterns(self) -> None:
        """Test that legacy list has expected number of patterns."""
        assert len(LEGACY_REGEX_LIST) == 27

    def test_legacy_list_aws_api_key(self) -> None:
        """Test AWS API Key pattern is present."""
        assert "AWS API Key" in LEGACY_REGEX_LIST
        pattern = re.compile(LEGACY_REGEX_LIST["AWS API Key"])
        result = pattern.search("AKIAIOSFODNN7EXAMPLE")
        assert result is not None

    def test_legacy_list_ipv4(self) -> None:
        """Test IPv4 pattern is present."""
        assert "ipv4" in LEGACY_REGEX_LIST
        pattern = re.compile(LEGACY_REGEX_LIST["ipv4"])
        result = pattern.search("192.168.1.1")
        assert result is not None

    def test_legacy_list_rsa_private_key(self) -> None:
        """Test RSA private key pattern is present."""
        assert "RSA private key" in LEGACY_REGEX_LIST
        pattern = re.compile(LEGACY_REGEX_LIST["RSA private key"])
        result = pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert result is not None

    def test_legacy_list_slack_token(self) -> None:
        """Test Slack Token pattern is present."""
        assert "Slack Token" in LEGACY_REGEX_LIST
        pattern = re.compile(LEGACY_REGEX_LIST["Slack Token"])
        result = pattern.search("xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz123456")
        assert result is not None

    def test_all_patterns_valid_regex(self) -> None:
        """Test that all legacy patterns compile."""
        for name, regex in LEGACY_REGEX_LIST.items():
            try:
                re.compile(regex)
            except re.error as e:
                pytest.fail(f"Pattern '{name}' has invalid regex: {e}")


class TestLegacyOnlyPatterns:
    """Tests for LEGACY_ONLY_PATTERNS collection."""

    def test_legacy_only_count(self) -> None:
        """Test expected number of legacy-only patterns."""
        assert len(LEGACY_ONLY_PATTERNS) == 13

    def test_all_patterns_have_names(self) -> None:
        """Test all patterns have non-empty names."""
        for pattern in LEGACY_ONLY_PATTERNS:
            assert pattern.name != ""

    def test_all_patterns_have_descriptions(self) -> None:
        """Test all patterns have descriptions."""
        for pattern in LEGACY_ONLY_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_category(self) -> None:
        """Test all patterns have valid category."""
        for pattern in LEGACY_ONLY_PATTERNS:
            assert pattern.category in PatternCategory

    def test_all_patterns_compile(self) -> None:
        """Test all pattern regexes compile."""
        for pattern in LEGACY_ONLY_PATTERNS:
            try:
                re.compile(pattern.regex)
            except re.error as e:
                pytest.fail(f"Pattern '{pattern.name}' has invalid regex: {e}")


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_legacy_pattern_names(self) -> None:
        """Test getting all pattern names."""
        names = get_legacy_pattern_names()
        assert len(names) == 27
        assert "AWS API Key" in names
        assert "ipv4" in names

    def test_get_legacy_pattern_existing(self) -> None:
        """Test getting an existing pattern."""
        pattern = get_legacy_pattern("email")
        assert pattern is not None
        assert "+" in pattern  # email pattern includes +

    def test_get_legacy_pattern_nonexistent(self) -> None:
        """Test getting a nonexistent pattern."""
        pattern = get_legacy_pattern("nonexistent_pattern")
        assert pattern is None

    def test_legacy_patterns_to_detector_format(self) -> None:
        """Test conversion to detector format."""
        detector_patterns = legacy_patterns_to_detector_format()
        assert len(detector_patterns) == 27

        # Check structure
        for name, data in detector_patterns.items():
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert isinstance(data["severity"], Severity)

    def test_detector_format_severity_assignment(self) -> None:
        """Test that severity is correctly assigned based on pattern type."""
        detector_patterns = legacy_patterns_to_detector_format()

        # Private key patterns should be CRITICAL
        assert detector_patterns["RSA private key"]["severity"] == Severity.CRITICAL
        assert detector_patterns["PGP private key block"]["severity"] == Severity.CRITICAL

        # OAuth patterns should be CRITICAL
        assert detector_patterns["Facebook Oauth"]["severity"] == Severity.CRITICAL
        assert detector_patterns["Twitter Oauth"]["severity"] == Severity.CRITICAL

        # Address patterns should be MEDIUM
        assert detector_patterns["ethereum-address"]["severity"] == Severity.MEDIUM
        assert detector_patterns["dogecoin-address"]["severity"] == Severity.MEDIUM


class TestPatternMetadata:
    """Tests for pattern metadata."""

    def test_email_pattern_metadata(self) -> None:
        """Test email pattern has correct metadata."""
        assert EMAIL_PATTERN.severity == Severity.LOW
        assert EMAIL_PATTERN.category == PatternCategory.GENERIC

    def test_phone_pattern_metadata(self) -> None:
        """Test phone pattern has correct metadata."""
        assert PHONE_PATTERN.severity == Severity.LOW
        assert PHONE_PATTERN.category == PatternCategory.GENERIC

    def test_site_pattern_metadata(self) -> None:
        """Test site pattern has correct metadata."""
        assert SITE_PATTERN.severity == Severity.LOW
        assert SITE_PATTERN.category == PatternCategory.NETWORK

    def test_bitcoin_uri_pattern_metadata(self) -> None:
        """Test Bitcoin URI pattern has correct metadata."""
        assert BITCOIN_URI_PATTERN.severity == Severity.MEDIUM
        assert BITCOIN_URI_PATTERN.category == PatternCategory.CRYPTO

    def test_facebook_oauth_pattern_metadata(self) -> None:
        """Test Facebook OAuth pattern has correct metadata."""
        assert FACEBOOK_OAUTH_PATTERN.severity == Severity.CRITICAL
        assert FACEBOOK_OAUTH_PATTERN.category == PatternCategory.API_KEYS

    def test_twitter_oauth_pattern_metadata(self) -> None:
        """Test Twitter OAuth pattern has correct metadata."""
        assert TWITTER_OAUTH_PATTERN.severity == Severity.CRITICAL
        assert TWITTER_OAUTH_PATTERN.category == PatternCategory.API_KEYS


# =============================================================================
# Hexdump Legacy Compatibility Tests
# =============================================================================


class TestHexdumpLegacyFormat:
    """Tests for hexdump output format compatibility with original hamburglar.py.

    The original hamburglar.py hexdump function (lines 230-255) produced output
    in the format:
        {offset:08x}  {hex_bytes_left}  {hex_bytes_right}  |{ascii}|

    These tests ensure the new hexdump utility maintains this exact format.
    """

    def test_hexdump_offset_format(self, tmp_path: Path) -> None:
        """Test offset is 8-character lowercase hex as in original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"A" * 32)

        result = hexdump(test_file)
        lines = result.split("\n")

        # First line should start with 8 zeros
        assert lines[0].startswith("00000000")
        # Second line should start with 00000010 (16 in hex)
        assert lines[1].startswith("00000010")

    def test_hexdump_ascii_column_pipes(self, tmp_path: Path) -> None:
        """Test ASCII column is pipe-delimited as in original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        result = hexdump(test_file)
        # ASCII should be enclosed in pipes
        assert "|Hello World!|" in result

    def test_hexdump_non_printable_as_dot(self, tmp_path: Path) -> None:
        """Test non-printable characters shown as dots like original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"\x00\x01\x02\x03")

        result = hexdump(test_file)
        # Non-printable should be dots in ASCII column
        assert "|....|" in result

    def test_hexdump_16_bytes_per_line(self, tmp_path: Path) -> None:
        """Test 16 bytes per line as in original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"A" * 16 + b"B" * 16)

        result = hexdump(test_file)
        lines = result.split("\n")
        assert len(lines) == 2

        # First line should have all A's (16 bytes)
        assert lines[0].count("41") == 16  # 0x41 = 'A'
        # Second line should have all B's
        assert lines[1].count("42") == 16  # 0x42 = 'B'

    def test_hexdump_double_space_separator(self, tmp_path: Path) -> None:
        """Test double space between hex halves as in original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(bytes(range(16)))

        result = hexdump(test_file)
        # Should have double space between first 8 bytes and second 8 bytes
        hex_part = result[10:58]  # Skip offset, get hex section
        assert "  " in hex_part

    def test_hexdump_partial_line_padding(self, tmp_path: Path) -> None:
        """Test partial lines maintain structure as in original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"ABC")

        result = hexdump(test_file)
        # Should still have the pipe delimiters
        assert "|ABC|" in result

    def test_hexdump_empty_file(self, tmp_path: Path) -> None:
        """Test empty file returns empty string."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        result = hexdump(test_file)
        assert result == ""

    def test_hexdump_accepts_string_path(self, tmp_path: Path) -> None:
        """Test hexdump accepts string path like original."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test")

        # Original accepted string paths
        result = hexdump(str(test_file))
        assert "test" in result


class TestHexdumpLegacyMagicBytes:
    """Tests for recognizing magic bytes like original hamburglar.py.

    The original hamburglar.py used magic bytes for file type identification.
    These tests verify hexdump correctly displays common magic bytes.
    """

    def test_hexdump_elf_magic(self, tmp_path: Path) -> None:
        """Test ELF magic bytes display correctly."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.elf"
        test_file.write_bytes(b"\x7fELF" + b"\x00" * 12)

        result = hexdump(test_file)
        assert "7f 45 4c 46" in result
        # ELF in ASCII column (with 0x7f as dot)
        assert ".ELF" in result

    def test_hexdump_pdf_magic(self, tmp_path: Path) -> None:
        """Test PDF magic bytes display correctly."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.pdf"
        test_file.write_bytes(b"%PDF-1.4" + b"\x00" * 8)

        result = hexdump(test_file)
        assert "25 50 44 46" in result  # %PDF
        assert "%PDF-1.4" in result

    def test_hexdump_zip_magic(self, tmp_path: Path) -> None:
        """Test ZIP magic bytes display correctly."""
        from hamburglar.utils.hexdump import hexdump

        test_file = tmp_path / "test.zip"
        test_file.write_bytes(b"PK\x03\x04" + b"\x00" * 12)

        result = hexdump(test_file)
        assert "50 4b 03 04" in result  # PK..


# =============================================================================
# IOCExtract Legacy Compatibility Tests
# =============================================================================


class TestIOCExtractLegacyBehavior:
    """Tests for iocextract integration matching original hamburglar.py -i flag.

    The original hamburglar.py used iocextract.extract_* functions directly.
    These tests verify the new iocextract integration maintains compatibility.
    """

    def test_iocextract_availability_check(self) -> None:
        """Test iocextract availability can be checked."""
        from hamburglar.compat.ioc_extract import is_available

        result = is_available()
        assert isinstance(result, bool)

    def test_iocextract_fallback_detector_exists(self) -> None:
        """Test fallback detector is available when iocextract not installed."""
        from hamburglar.compat.ioc_extract import IOCExtractFallbackDetector

        detector = IOCExtractFallbackDetector()
        # Should return empty list, not raise
        findings = detector.detect("http://example.com", "/test/file.txt")
        assert findings == []

    def test_iocextract_get_detector_with_fallback(self) -> None:
        """Test get_detector returns valid detector with fallback."""
        from hamburglar.compat.ioc_extract import get_detector
        from hamburglar.detectors import BaseDetector

        detector = get_detector(fallback=True)
        assert isinstance(detector, BaseDetector)

    def test_iocextract_legacy_extract_function_exists(self) -> None:
        """Test legacy extract_iocs_legacy function exists."""
        from hamburglar.compat.ioc_extract import extract_iocs_legacy

        # Should exist and be callable
        assert callable(extract_iocs_legacy)

    def test_iocextract_exception_class(self) -> None:
        """Test IOCExtractNotAvailable exception is proper ImportError."""
        from hamburglar.compat.ioc_extract import IOCExtractNotAvailable

        assert issubclass(IOCExtractNotAvailable, ImportError)

        exc = IOCExtractNotAvailable()
        assert "iocextract is not installed" in str(exc)


class TestIOCExtractLegacyIOCTypes:
    """Tests for iocextract IOC types matching original hamburglar.py."""

    @pytest.fixture
    def skip_if_unavailable(self) -> None:
        """Skip if iocextract not installed."""
        from hamburglar.compat.ioc_extract import is_available

        if not is_available():
            pytest.skip("iocextract is not installed")

    def test_url_extraction_matches_legacy(self, skip_if_unavailable: None) -> None:
        """Test URL extraction works like original."""
        from hamburglar.compat.ioc_extract import extract_urls

        urls = extract_urls("Check http://example.com and https://test.org")
        assert isinstance(urls, list)

    def test_email_extraction_matches_legacy(self, skip_if_unavailable: None) -> None:
        """Test email extraction works like original."""
        from hamburglar.compat.ioc_extract import extract_emails

        emails = extract_emails("Contact admin@example.com for help")
        assert isinstance(emails, list)
        if emails:
            assert "admin@example.com" in emails

    def test_ip_extraction_matches_legacy(self, skip_if_unavailable: None) -> None:
        """Test IP extraction works like original."""
        from hamburglar.compat.ioc_extract import extract_ips

        ips = extract_ips("Server at 192.168.1.1")
        assert isinstance(ips, list)

    def test_hash_extraction_matches_legacy(self, skip_if_unavailable: None) -> None:
        """Test hash extraction works like original."""
        from hamburglar.compat.ioc_extract import extract_hashes

        # MD5 hash
        hashes = extract_hashes("Hash: d41d8cd98f00b204e9800998ecf8427e")
        assert isinstance(hashes, list)


# =============================================================================
# CLI Flag Compatibility Tests
# =============================================================================


class TestCLIFlagCompatibility:
    """Tests for CLI flag compatibility with original hamburglar.py.

    Original flags (from hamburglar.py lines 72-88):
    - `-g` / `--git` → scan-git command
    - `-x` / `--hexdump` → hexdump command
    - `-v` / `--verbose` → --verbose flag
    - `-w` / `--web` → scan-web command
    - `-i` / `--ioc` → --use-iocextract flag
    - `-o` / `--out` → --output flag
    - `-y` / `--yara` → --yara-rules flag
    """

    def test_verbose_flag_exists(self) -> None:
        """Test --verbose flag is available in new CLI."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--verbose" in result.output

    def test_output_flag_exists(self) -> None:
        """Test --output flag is available (was -o/--out)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output

    def test_yara_flag_exists(self) -> None:
        """Test --yara flag is available (was -y/--yara)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--yara" in result.output

    def test_scan_git_command_exists(self) -> None:
        """Test scan-git command exists (was -g/--git flag)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "scan-git" in result.output.lower() or "git" in result.output.lower()

    def test_scan_web_command_exists(self) -> None:
        """Test scan-web command exists (was -w/--web flag)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0

    def test_hexdump_command_exists(self) -> None:
        """Test hexdump command exists (was -x/--hexdump flag)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["hexdump", "--help"])
        assert result.exit_code == 0
        assert "hexdump" in result.output.lower() or "hex" in result.output.lower()

    def test_iocextract_flag_exists(self) -> None:
        """Test --use-iocextract flag exists (was -i/--ioc)."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--use-iocextract" in result.output


class TestCLIScanCommand:
    """Tests for scan command compatibility with original hamburglar.py behavior."""

    def test_scan_single_file(self, tmp_path: Path) -> None:
        """Test scanning single file works like original."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create a test file with an AWS key
        test_file = tmp_path / "config.txt"
        test_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")

        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(test_file), "--format", "json"])
        assert result.exit_code == 0
        assert "AWS" in result.output or "findings" in result.output.lower()

    def test_scan_directory(self, tmp_path: Path) -> None:
        """Test scanning directory works like original."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create test files
        (tmp_path / "file1.txt").write_text("test content")
        (tmp_path / "file2.txt").write_text("more content")

        runner = CliRunner()
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "table"])
        # Exit code 0 means findings, 2 means no findings - both are valid
        assert result.exit_code in (0, 2)

    def test_scan_with_verbose(self, tmp_path: Path) -> None:
        """Test verbose flag increases output like original -v."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        runner = CliRunner()
        result = runner.invoke(
            app, ["scan", str(test_file), "--verbose", "--format", "table"]
        )
        # Exit code 0 means findings, 2 means no findings - both are valid
        assert result.exit_code in (0, 2)

    def test_scan_output_to_file(self, tmp_path: Path) -> None:
        """Test --output flag writes to file like original -o."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        test_file = tmp_path / "test.txt"
        test_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        output_file = tmp_path / "output.json"

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["scan", str(test_file), "--output", str(output_file), "--format", "json"],
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestHexdumpCommand:
    """Tests for hexdump command compatibility with original -x flag."""

    def test_hexdump_basic_output(self, tmp_path: Path) -> None:
        """Test hexdump command produces expected output."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        runner = CliRunner()
        result = runner.invoke(app, ["hexdump", str(test_file)])
        assert result.exit_code == 0
        assert "Hello World!" in result.output
        assert "00000000" in result.output

    def test_hexdump_with_output_file(self, tmp_path: Path) -> None:
        """Test hexdump --output flag like original file output."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Test data")
        output_file = tmp_path / "hexdump.txt"

        runner = CliRunner()
        result = runner.invoke(
            app, ["hexdump", str(test_file), "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()
        assert "Test data" in output_file.read_text()

    def test_hexdump_file_not_found(self) -> None:
        """Test hexdump handles missing file gracefully."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["hexdump", "/nonexistent/file.bin"])
        assert result.exit_code != 0


class TestLegacyPatternDetection:
    """Tests verifying all original regex patterns still detect correctly."""

    @pytest.fixture
    def detector(self) -> Any:
        """Create a regex detector with all patterns."""
        from hamburglar.detectors.regex_detector import RegexDetector

        return RegexDetector()

    def test_aws_api_key_detection(self, detector: Any) -> None:
        """Test AWS API Key detection (original pattern)."""
        content = "aws_key = AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "/test.txt")
        aws_findings = [f for f in findings if "AWS" in f.detector_name.upper()]
        assert len(aws_findings) > 0

    def test_rsa_private_key_detection(self, detector: Any) -> None:
        """Test RSA private key detection (original pattern)."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nkey data\n-----END RSA PRIVATE KEY-----"
        findings = detector.detect(content, "/test.txt")
        key_findings = [f for f in findings if "RSA" in f.detector_name.upper()]
        assert len(key_findings) > 0

    def test_slack_token_detection(self, detector: Any) -> None:
        """Test Slack token detection (original pattern)."""
        content = "token = xoxp-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz123456"
        findings = detector.detect(content, "/test.txt")
        slack_findings = [f for f in findings if "SLACK" in f.detector_name.upper()]
        assert len(slack_findings) > 0

    def test_ipv4_detection(self, detector: Any) -> None:
        """Test IPv4 detection (original pattern)."""
        content = "Server IP: 192.168.1.1"
        findings = detector.detect(content, "/test.txt")
        ip_findings = [f for f in findings if "IP" in f.detector_name.upper()]
        assert len(ip_findings) > 0

    def test_google_oauth_detection(self, detector: Any) -> None:
        """Test Google OAuth detection (original pattern)."""
        content = '{"client_secret":"abc123def456ghi789jkl012"}'
        findings = detector.detect(content, "/test.txt")
        oauth_findings = [
            f
            for f in findings
            if "GOOGLE" in f.detector_name.upper() or "OAUTH" in f.detector_name.upper()
        ]
        assert len(oauth_findings) > 0

    def test_ethereum_address_detection(self, detector: Any) -> None:
        """Test Ethereum address detection (original pattern)."""
        content = "ETH address: 0x742d35Cc6634C0532925a3b844Bc9e7595f8e5F8"
        findings = detector.detect(content, "/test.txt")
        eth_findings = [f for f in findings if "ETHEREUM" in f.detector_name.upper()]
        assert len(eth_findings) > 0

    def test_pgp_private_key_detection(self, detector: Any) -> None:
        """Test PGP private key detection (original pattern)."""
        content = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        findings = detector.detect(content, "/test.txt")
        pgp_findings = [f for f in findings if "PGP" in f.detector_name.upper()]
        assert len(pgp_findings) > 0


# Required import for Path type hint
from pathlib import Path
from typing import Any