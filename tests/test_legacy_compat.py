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
