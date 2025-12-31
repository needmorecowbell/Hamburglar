"""Tests for the RegexDetector.

This module contains tests for the RegexDetector class, verifying its ability
to detect various patterns including AWS keys, emails, Bitcoin addresses,
RSA private keys, and handling of edge cases.
"""

from __future__ import annotations

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.regex_detector import DEFAULT_PATTERNS, RegexDetector


class TestRegexDetectorBasics:
    """Basic tests for RegexDetector initialization and configuration."""

    def test_detector_name(self) -> None:
        """Test that detector name is 'regex'."""
        detector = RegexDetector()
        assert detector.name == "regex"

    def test_detector_uses_default_patterns(self) -> None:
        """Test that detector loads default patterns by default."""
        detector = RegexDetector()
        patterns = detector.get_patterns()
        assert len(patterns) > 0
        assert "AWS API Key" in patterns
        assert "Email Address" in patterns

    def test_detector_custom_patterns_only(self) -> None:
        """Test detector with only custom patterns (no defaults)."""
        custom_patterns = {
            "Custom Pattern": {
                "pattern": r"CUSTOM-\d{6}",
                "severity": Severity.HIGH,
                "description": "Custom pattern",
            }
        }
        detector = RegexDetector(patterns=custom_patterns, use_defaults=False)
        patterns = detector.get_patterns()
        assert len(patterns) == 1
        assert "Custom Pattern" in patterns
        assert "AWS API Key" not in patterns

    def test_detector_merge_custom_with_defaults(self) -> None:
        """Test that custom patterns are merged with defaults when use_defaults=True."""
        custom_patterns = {
            "Custom Pattern": {
                "pattern": r"CUSTOM-\d{6}",
                "severity": Severity.HIGH,
                "description": "Custom pattern",
            }
        }
        detector = RegexDetector(patterns=custom_patterns, use_defaults=True)
        patterns = detector.get_patterns()
        assert "Custom Pattern" in patterns
        assert "AWS API Key" in patterns  # Default pattern still present


class TestAWSKeyDetection:
    """Tests for AWS API key detection."""

    def test_detect_aws_api_key(self) -> None:
        """Test detection of AWS API keys starting with AKIA."""
        detector = RegexDetector()
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        findings = detector.detect(content, "config.py")

        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in aws_findings[0].matches
        assert aws_findings[0].severity == Severity.CRITICAL

    def test_detect_multiple_aws_keys(self) -> None:
        """Test detection of multiple AWS API keys."""
        detector = RegexDetector()
        content = """
        key1 = "AKIAIOSFODNN7EXAMPLE"
        key2 = "AKIAI44QH8DHBEXAMPLE"
        """
        findings = detector.detect(content, "secrets.txt")

        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert len(aws_findings[0].matches) == 2

    def test_detect_aws_secret_key(self) -> None:
        """Test detection of AWS secret access keys."""
        detector = RegexDetector()
        # Pattern requires: aws followed by 0-20 chars, then quoted 40-char secret
        # The 40-char key must only contain alphanumerics, /, and +
        key_40_chars = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"  # exactly 40 chars
        content = f'aws_secret="{key_40_chars}"'
        findings = detector.detect(content, "config.py")

        secret_findings = [f for f in findings if "AWS Secret Key" in f.detector_name]
        assert len(secret_findings) == 1
        assert secret_findings[0].severity == Severity.CRITICAL

    def test_no_false_positive_short_akia(self) -> None:
        """Test that short strings starting with AKIA don't match."""
        detector = RegexDetector()
        content = 'This mentions AKIA but is too short: "AKIA123"'
        findings = detector.detect(content, "test.txt")

        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 0


class TestEmailDetection:
    """Tests for email address detection."""

    def test_detect_email(self) -> None:
        """Test detection of email addresses."""
        detector = RegexDetector()
        content = "Contact us at admin@example.com for support."
        findings = detector.detect(content, "readme.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "admin@example.com" in email_findings[0].matches
        assert email_findings[0].severity == Severity.MEDIUM

    def test_detect_multiple_emails(self) -> None:
        """Test detection of multiple email addresses."""
        detector = RegexDetector()
        content = """
        Primary: admin@example.com
        Secondary: support@test.org
        Backup: backup.user@company.co.uk
        """
        findings = detector.detect(content, "contacts.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert len(email_findings[0].matches) == 3

    def test_detect_email_variations(self) -> None:
        """Test detection of various email formats."""
        detector = RegexDetector()
        content = """
        user.name@domain.com
        user+tag@domain.com
        user123@sub.domain.org
        """
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert len(email_findings[0].matches) >= 3


class TestBitcoinAddressDetection:
    """Tests for Bitcoin address detection."""

    def test_detect_bitcoin_address_starting_with_1(self) -> None:
        """Test detection of Bitcoin addresses starting with 1."""
        detector = RegexDetector()
        # Satoshi's wallet address (famous example)
        content = "Donate to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        findings = detector.detect(content, "donate.txt")

        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 1
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in btc_findings[0].matches
        assert btc_findings[0].severity == Severity.HIGH

    def test_detect_bitcoin_address_starting_with_3(self) -> None:
        """Test detection of Bitcoin addresses starting with 3 (P2SH)."""
        detector = RegexDetector()
        content = "Multisig wallet: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        findings = detector.detect(content, "wallet.txt")

        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 1
        assert "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" in btc_findings[0].matches

    def test_no_false_positive_short_address(self) -> None:
        """Test that short strings don't match Bitcoin address pattern."""
        detector = RegexDetector()
        content = "Too short: 1ABC123"
        findings = detector.detect(content, "test.txt")

        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 0


class TestRSAPrivateKeyDetection:
    """Tests for RSA private key header detection."""

    def test_detect_rsa_private_key_header(self) -> None:
        """Test detection of RSA private key header."""
        detector = RegexDetector()
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
        More key content here...
        -----END RSA PRIVATE KEY-----
        """
        findings = detector.detect(content, "key.pem")

        rsa_findings = [f for f in findings if "RSA Private Key" in f.detector_name]
        assert len(rsa_findings) == 1
        assert rsa_findings[0].severity == Severity.CRITICAL

    def test_detect_dsa_private_key_header(self) -> None:
        """Test detection of DSA private key header."""
        detector = RegexDetector()
        content = "-----BEGIN DSA PRIVATE KEY-----"
        findings = detector.detect(content, "key.pem")

        dsa_findings = [f for f in findings if "SSH (DSA) Private Key" in f.detector_name]
        assert len(dsa_findings) == 1
        assert dsa_findings[0].severity == Severity.CRITICAL

    def test_detect_ec_private_key_header(self) -> None:
        """Test detection of EC private key header."""
        detector = RegexDetector()
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = detector.detect(content, "key.pem")

        ec_findings = [f for f in findings if "SSH (EC) Private Key" in f.detector_name]
        assert len(ec_findings) == 1
        assert ec_findings[0].severity == Severity.CRITICAL

    def test_detect_openssh_private_key_header(self) -> None:
        """Test detection of OpenSSH private key header."""
        detector = RegexDetector()
        content = "-----BEGIN OPENSSH PRIVATE KEY-----"
        findings = detector.detect(content, "id_ed25519")

        openssh_findings = [f for f in findings if "SSH (OPENSSH) Private Key" in f.detector_name]
        assert len(openssh_findings) == 1
        assert openssh_findings[0].severity == Severity.CRITICAL

    def test_detect_pgp_private_key_block(self) -> None:
        """Test detection of PGP private key block header."""
        detector = RegexDetector()
        content = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        findings = detector.detect(content, "private.asc")

        pgp_findings = [f for f in findings if "PGP Private Key Block" in f.detector_name]
        assert len(pgp_findings) == 1
        assert pgp_findings[0].severity == Severity.CRITICAL


class TestCleanContent:
    """Tests for handling clean content with no secrets."""

    def test_empty_content(self) -> None:
        """Test that empty content returns empty list."""
        detector = RegexDetector()
        findings = detector.detect("", "empty.txt")
        assert findings == []

    def test_clean_content_no_secrets(self) -> None:
        """Test that clean content without secrets returns empty list."""
        detector = RegexDetector()
        content = """
        This is a regular file with no secrets.
        It contains only normal text content.
        Nothing sensitive here at all.
        Just documentation and comments.
        """
        findings = detector.detect(content, "readme.md")
        assert findings == []

    def test_clean_code_file(self) -> None:
        """Test that normal code file without secrets returns empty list."""
        detector = RegexDetector()
        content = '''
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"

def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''
        findings = detector.detect(content, "utils.py")
        assert findings == []

    def test_whitespace_only(self) -> None:
        """Test that whitespace-only content returns empty list."""
        detector = RegexDetector()
        findings = detector.detect("   \n\t\n   ", "blank.txt")
        assert findings == []


class TestBinaryContentHandling:
    """Tests for graceful handling of binary or unusual content."""

    def test_binary_content_graceful(self) -> None:
        """Test that binary content is handled gracefully without errors."""
        detector = RegexDetector()
        # Simulated binary content with null bytes and control characters
        binary_content = "PK\x03\x04\x14\x00\x00\x00\x08\x00some text\x00\xff\xfe"
        # Should not raise an exception
        findings = detector.detect(binary_content, "file.zip")
        # May or may not find matches, but shouldn't crash
        assert isinstance(findings, list)

    def test_null_bytes_in_content(self) -> None:
        """Test handling of content with null bytes."""
        detector = RegexDetector()
        content = "Normal text\x00admin@example.com\x00more text"
        findings = detector.detect(content, "test.bin")
        # Should still find the email
        assert isinstance(findings, list)

    def test_unicode_content(self) -> None:
        """Test handling of unicode content."""
        detector = RegexDetector()
        content = """
        日本語テキスト
        admin@example.com
        中文內容
        """
        findings = detector.detect(content, "unicode.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_mixed_encoding_content(self) -> None:
        """Test handling of mixed encoding content."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE\xe9\xe8"
        findings = detector.detect(content, "mixed.txt")
        # Should find the AWS key despite encoding issues
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1


class TestOtherPatterns:
    """Tests for other pattern types included in default patterns."""

    def test_detect_github_token(self) -> None:
        """Test detection of modern GitHub tokens."""
        detector = RegexDetector()
        content = 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'
        findings = detector.detect(content, "config.yml")

        gh_findings = [f for f in findings if "GitHub Token" in f.detector_name]
        assert len(gh_findings) == 1
        assert gh_findings[0].severity == Severity.CRITICAL

    def test_detect_slack_token(self) -> None:
        """Test detection of Slack OAuth tokens."""
        detector = RegexDetector()
        content = "SLACK_TOKEN=xoxb-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyzabcdef"
        findings = detector.detect(content, ".env")

        slack_findings = [f for f in findings if "Slack Token" in f.detector_name]
        assert len(slack_findings) == 1
        assert slack_findings[0].severity == Severity.CRITICAL

    def test_detect_ipv4_address(self) -> None:
        """Test detection of IPv4 addresses."""
        detector = RegexDetector()
        content = "Server IP: 192.168.1.100"
        findings = detector.detect(content, "config.txt")

        ip_findings = [f for f in findings if "IPv4 Address" in f.detector_name]
        assert len(ip_findings) == 1
        assert "192.168.1.100" in ip_findings[0].matches
        assert ip_findings[0].severity == Severity.LOW

    def test_detect_ethereum_address(self) -> None:
        """Test detection of Ethereum addresses."""
        detector = RegexDetector()
        content = "ETH wallet: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bB2d"
        findings = detector.detect(content, "crypto.txt")

        eth_findings = [f for f in findings if "Ethereum Address" in f.detector_name]
        assert len(eth_findings) == 1
        assert eth_findings[0].severity == Severity.HIGH

    def test_detect_url(self) -> None:
        """Test detection of URLs."""
        detector = RegexDetector()
        content = "API endpoint: https://api.example.com/v1/users"
        findings = detector.detect(content, "api.txt")

        url_findings = [f for f in findings if "URL" in f.detector_name]
        assert len(url_findings) == 1
        assert url_findings[0].severity == Severity.INFO


class TestPatternManagement:
    """Tests for adding and removing patterns."""

    def test_add_pattern(self) -> None:
        """Test adding a new pattern to detector."""
        detector = RegexDetector()
        detector.add_pattern(
            name="Custom ID",
            pattern=r"CUSTOM-\d{8}",
            severity=Severity.MEDIUM,
            description="Custom ID format",
        )
        content = "ID: CUSTOM-12345678"
        findings = detector.detect(content, "test.txt")

        custom_findings = [f for f in findings if "Custom ID" in f.detector_name]
        assert len(custom_findings) == 1

    def test_add_duplicate_pattern_raises(self) -> None:
        """Test that adding a duplicate pattern raises ValueError."""
        detector = RegexDetector()
        with pytest.raises(ValueError, match="already exists"):
            detector.add_pattern(
                name="AWS API Key",  # Already exists in defaults
                pattern=r"test",
                severity=Severity.LOW,
            )

    def test_add_invalid_pattern_raises(self) -> None:
        """Test that adding an invalid regex raises ValueError."""
        detector = RegexDetector()
        with pytest.raises(ValueError, match="Invalid regex"):
            detector.add_pattern(
                name="Invalid",
                pattern=r"[invalid(",  # Invalid regex
                severity=Severity.LOW,
            )

    def test_remove_pattern(self) -> None:
        """Test removing a pattern from detector."""
        detector = RegexDetector()
        assert "Email Address" in detector.get_patterns()

        detector.remove_pattern("Email Address")

        assert "Email Address" not in detector.get_patterns()
        content = "Contact: admin@example.com"
        findings = detector.detect(content, "test.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 0

    def test_remove_nonexistent_pattern_raises(self) -> None:
        """Test that removing a nonexistent pattern raises KeyError."""
        detector = RegexDetector()
        with pytest.raises(KeyError, match="not found"):
            detector.remove_pattern("Nonexistent Pattern")


class TestFindingMetadata:
    """Tests for Finding metadata from RegexDetector."""

    def test_finding_contains_pattern_name(self) -> None:
        """Test that findings include pattern name in metadata."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "test.txt")

        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert aws_findings[0].metadata["pattern_name"] == "AWS API Key"

    def test_finding_contains_description(self) -> None:
        """Test that findings include description in metadata."""
        detector = RegexDetector()
        content = "admin@example.com"
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert email_findings[0].metadata["description"] == "Email Address"

    def test_finding_contains_match_count(self) -> None:
        """Test that findings include match count in metadata."""
        detector = RegexDetector()
        content = "user1@example.com, user2@example.com, user3@example.com"
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert email_findings[0].metadata["match_count"] == 3

    def test_finding_file_path_is_set(self) -> None:
        """Test that findings have the correct file path."""
        detector = RegexDetector()
        content = "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "/path/to/secrets.py")

        assert len(findings) >= 1
        assert findings[0].file_path == "/path/to/secrets.py"

    def test_finding_detector_name_format(self) -> None:
        """Test that detector name follows 'regex:PatternName' format."""
        detector = RegexDetector()
        content = "admin@example.com"
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert email_findings[0].detector_name == "regex:Email Address"


class TestDeduplication:
    """Tests for match deduplication."""

    def test_duplicate_matches_are_deduplicated(self) -> None:
        """Test that duplicate matches are removed."""
        detector = RegexDetector()
        content = "admin@example.com admin@example.com admin@example.com"
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        # Should be deduplicated to single match
        assert len(email_findings[0].matches) == 1
        assert email_findings[0].matches[0] == "admin@example.com"

    def test_unique_matches_preserved(self) -> None:
        """Test that unique matches are all preserved."""
        detector = RegexDetector()
        content = "user1@example.com user2@example.com user1@example.com user3@example.com"
        findings = detector.detect(content, "test.txt")

        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        # Should have 3 unique emails
        assert len(email_findings[0].matches) == 3
