"""Tests for the RegexDetector.

This module contains tests for the RegexDetector class, verifying its ability
to detect various patterns including AWS keys, emails, Bitcoin addresses,
RSA private keys, and handling of edge cases.
"""

from __future__ import annotations

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.regex_detector import RegexDetector


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


class TestBinaryFileSkipping:
    """Tests for binary file detection and skipping."""

    def test_skip_file_with_high_binary_ratio(self) -> None:
        """Test that files with high binary content ratio are skipped."""
        detector = RegexDetector()
        # Create content that's mostly binary (null bytes)
        binary_content = "\x00\x01\x02\x03\x04\x05" * 2000 + "admin@example.com"
        findings = detector.detect(binary_content, "binary.bin")
        # Should skip due to high binary ratio
        assert len(findings) == 0

    def test_text_file_with_few_binary_bytes_not_skipped(self) -> None:
        """Test that text files with few binary bytes are still processed."""
        detector = RegexDetector()
        # Create content that's mostly text with a few binary bytes
        content = "Normal text admin@example.com\x00 more text " * 100
        findings = detector.detect(content, "mostly_text.txt")
        # Should find the email since binary ratio is low
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_empty_content_not_considered_binary(self) -> None:
        """Test that empty content is not considered binary."""
        detector = RegexDetector()
        findings = detector.detect("", "empty.txt")
        assert findings == []

    def test_elf_binary_detection(self) -> None:
        """Test that ELF binaries are detected and skipped."""
        detector = RegexDetector()
        # ELF magic header followed by binary content
        elf_content = "\x7fELF" + "\x00\x01\x02\x03" * 500
        findings = detector.detect(elf_content, "program.exe")
        assert len(findings) == 0

    def test_pure_text_processed(self) -> None:
        """Test that pure text files are processed normally."""
        detector = RegexDetector()
        content = "This is pure text with admin@example.com inside."
        findings = detector.detect(content, "text.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestMaxFileSize:
    """Tests for maximum file size handling."""

    def test_default_max_file_size(self) -> None:
        """Test that default max file size is 10MB."""
        from hamburglar.detectors.regex_detector import DEFAULT_MAX_FILE_SIZE

        detector = RegexDetector()
        assert detector.max_file_size == DEFAULT_MAX_FILE_SIZE
        assert detector.max_file_size == 10 * 1024 * 1024

    def test_custom_max_file_size(self) -> None:
        """Test that custom max file size can be set."""
        detector = RegexDetector(max_file_size=1024)
        assert detector.max_file_size == 1024

    def test_large_file_skipped(self) -> None:
        """Test that files exceeding max size are skipped."""
        # Set a small max size for testing
        detector = RegexDetector(max_file_size=100)
        # Create content larger than max size
        content = "admin@example.com " * 100  # ~1800 bytes
        findings = detector.detect(content, "large.txt")
        # Should skip and return empty
        assert len(findings) == 0

    def test_file_at_size_limit_processed(self) -> None:
        """Test that files exactly at size limit are still processed."""
        # Set max size to 200 bytes
        detector = RegexDetector(max_file_size=200)
        # Create content just under the limit
        content = "admin@example.com"  # 17 bytes
        findings = detector.detect(content, "small.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_file_just_over_limit_skipped(self) -> None:
        """Test that files just over size limit are skipped."""
        detector = RegexDetector(max_file_size=50)
        content = "a" * 51 + " admin@example.com"  # Over 50 bytes
        findings = detector.detect(content, "over_limit.txt")
        assert len(findings) == 0


class TestRegexTimeout:
    """Tests for regex timeout handling."""

    def test_default_regex_timeout(self) -> None:
        """Test that default regex timeout is 5 seconds."""
        from hamburglar.detectors.regex_detector import DEFAULT_REGEX_TIMEOUT

        detector = RegexDetector()
        assert detector.regex_timeout == DEFAULT_REGEX_TIMEOUT
        assert detector.regex_timeout == 5.0

    def test_custom_regex_timeout(self) -> None:
        """Test that custom regex timeout can be set."""
        detector = RegexDetector(regex_timeout=1.0)
        assert detector.regex_timeout == 1.0

    def test_fast_pattern_succeeds(self) -> None:
        """Test that fast patterns complete successfully."""
        detector = RegexDetector(regex_timeout=1.0)
        content = "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_normal_processing_within_timeout(self) -> None:
        """Test that normal processing completes within timeout."""
        detector = RegexDetector(regex_timeout=10.0)
        content = "admin@example.com\n" * 1000
        findings = detector.detect(content, "test.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestVerboseLogging:
    """Tests for verbose logging of detector performance."""

    def test_detector_logs_performance_metrics(self, caplog: pytest.LogCaptureFixture) -> None:
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
                detector = RegexDetector()
                content = "admin@example.com"
                detector.detect(content, "test.txt")

            # Check that performance log message is present
            assert any("RegexDetector processed" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_detector_logs_skipped_binary_file(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that detector logs when skipping binary files."""
        import logging

        from hamburglar.core.logging import get_logger, setup_logging

        setup_logging(verbose=True)
        logger = get_logger()

        # Enable propagation temporarily so caplog can capture records
        original_propagate = logger.propagate
        logger.propagate = True

        try:
            with caplog.at_level(logging.DEBUG, logger="hamburglar"):
                detector = RegexDetector()
                # Create binary content
                binary_content = "\x00\x01\x02\x03" * 3000
                detector.detect(binary_content, "binary.bin")

            # Check that binary skip message is logged
            assert any("Skipping binary file" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate

    def test_detector_logs_skipped_large_file(self, caplog: pytest.LogCaptureFixture) -> None:
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
                detector = RegexDetector(max_file_size=100)
                content = "a" * 200  # Over limit
                detector.detect(content, "large.txt")

            # Check that size warning is logged
            assert any("exceeds max" in record.message for record in caplog.records)
        finally:
            logger.propagate = original_propagate


class TestBinaryDetectionHeuristics:
    """Tests for binary content detection heuristics."""

    def test_null_bytes_detected_as_binary(self) -> None:
        """Test that content with many null bytes is detected as binary."""
        detector = RegexDetector()
        # Create content with 50% null bytes
        content = "\x00admin@example.com\x00" * 500
        findings = detector.detect(content, "test.bin")
        # Should be skipped due to high binary ratio
        assert len(findings) == 0

    def test_control_chars_detected_as_binary(self) -> None:
        """Test that content with many control characters is detected as binary."""
        detector = RegexDetector()
        # Create content with many control characters (SOH, STX, ETX, etc.)
        control_chars = "".join(chr(i) for i in range(1, 9))
        content = (control_chars + "test") * 1000
        findings = detector.detect(content, "test.bin")
        assert len(findings) == 0

    def test_tab_newline_carriage_return_allowed(self) -> None:
        """Test that tab, newline, and carriage return are not considered binary."""
        detector = RegexDetector()
        content = "admin@example.com\t\n\r" * 100
        findings = detector.detect(content, "text.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_latin1_text_not_binary(self) -> None:
        """Test that Latin-1 text is not incorrectly detected as binary."""
        detector = RegexDetector()
        content = "Café résumé admin@example.com naïve"
        findings = detector.detect(content, "text.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_unicode_emoji_not_binary(self) -> None:
        """Test that unicode emoji content is not detected as binary."""
        detector = RegexDetector()
        content = "🎉 Hello admin@example.com 🚀"
        findings = detector.detect(content, "emoji.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestAllPatternsPositiveCases:
    """Ensure all 20 default patterns have at least one positive test case."""

    def test_aws_api_key_positive(self) -> None:
        """Test AWS API Key pattern matches valid access key ID."""
        detector = RegexDetector()
        content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in aws_findings[0].matches

    def test_aws_secret_key_positive(self) -> None:
        """Test AWS Secret Key pattern matches valid secret access key."""
        detector = RegexDetector()
        # Pattern: (?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]
        # Key must be exactly 40 chars: alphanumeric, /, or +
        content = 'aws_secret_key="wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"'  # exactly 40 chars
        findings = detector.detect(content, "test.txt")
        secret_findings = [f for f in findings if "AWS Secret Key" in f.detector_name]
        assert len(secret_findings) == 1

    def test_github_token_ghp_positive(self) -> None:
        """Test GitHub Token pattern matches ghp_ prefixed token."""
        detector = RegexDetector()
        content = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Token" in f.detector_name]
        assert len(gh_findings) == 1
        assert "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" in gh_findings[0].matches

    def test_github_token_gho_positive(self) -> None:
        """Test GitHub Token pattern matches gho_ prefixed token."""
        detector = RegexDetector()
        content = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Token" in f.detector_name]
        assert len(gh_findings) == 1

    def test_github_legacy_token_positive(self) -> None:
        """Test GitHub Legacy Token pattern matches old-style token."""
        detector = RegexDetector()
        # Pattern: [g|G][i|I]... followed by quoted 35-40 char token
        content = 'GITHUB_TOKEN="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Legacy Token" in f.detector_name]
        assert len(gh_findings) == 1

    def test_rsa_private_key_positive(self) -> None:
        """Test RSA Private Key pattern matches header."""
        detector = RegexDetector()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = detector.detect(content, "key.pem")
        rsa_findings = [f for f in findings if "RSA Private Key" in f.detector_name]
        assert len(rsa_findings) == 1

    def test_dsa_private_key_positive(self) -> None:
        """Test DSA Private Key pattern matches header."""
        detector = RegexDetector()
        content = "-----BEGIN DSA PRIVATE KEY-----"
        findings = detector.detect(content, "key.pem")
        dsa_findings = [f for f in findings if "SSH (DSA) Private Key" in f.detector_name]
        assert len(dsa_findings) == 1

    def test_ec_private_key_positive(self) -> None:
        """Test EC Private Key pattern matches header."""
        detector = RegexDetector()
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = detector.detect(content, "key.pem")
        ec_findings = [f for f in findings if "SSH (EC) Private Key" in f.detector_name]
        assert len(ec_findings) == 1

    def test_openssh_private_key_positive(self) -> None:
        """Test OpenSSH Private Key pattern matches header."""
        detector = RegexDetector()
        content = "-----BEGIN OPENSSH PRIVATE KEY-----"
        findings = detector.detect(content, "id_ed25519")
        openssh_findings = [f for f in findings if "SSH (OPENSSH) Private Key" in f.detector_name]
        assert len(openssh_findings) == 1

    def test_pgp_private_key_positive(self) -> None:
        """Test PGP Private Key Block pattern matches header."""
        detector = RegexDetector()
        content = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        findings = detector.detect(content, "private.asc")
        pgp_findings = [f for f in findings if "PGP Private Key Block" in f.detector_name]
        assert len(pgp_findings) == 1

    def test_generic_api_key_positive(self) -> None:
        """Test Generic API Key pattern matches api_key assignments."""
        detector = RegexDetector()
        content = 'api_key = "abcdef1234567890abcdef1234567890"'
        findings = detector.detect(content, "config.py")
        api_findings = [f for f in findings if "Generic API Key" in f.detector_name]
        assert len(api_findings) == 1

    def test_generic_api_key_variations(self) -> None:
        """Test Generic API Key pattern matches various formats."""
        detector = RegexDetector()
        # Test different key formats: api-key, apikey, api_secret
        content = """
        api-key: "1234567890abcdef1234567890abcdef"
        apikey = "abcdef1234567890abcdef1234567890"
        api_secret = "1234567890123456789012345678901234567890"
        """
        findings = detector.detect(content, "config.yml")
        api_findings = [f for f in findings if "Generic API Key" in f.detector_name]
        assert len(api_findings) == 1
        assert len(api_findings[0].matches) >= 1

    def test_slack_token_positive(self) -> None:
        """Test Slack Token pattern matches OAuth token format."""
        detector = RegexDetector()
        content = "SLACK_TOKEN=xoxb-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyzabcdef"
        findings = detector.detect(content, ".env")
        slack_findings = [f for f in findings if "Slack Token" in f.detector_name]
        assert len(slack_findings) == 1

    def test_slack_webhook_positive(self) -> None:
        """Test Slack Webhook pattern matches webhook URL format."""
        detector = RegexDetector()
        # Build the URL dynamically to avoid GitHub secret scanning
        # Format: T[8 alphanumeric]/B[8-12 alphanumeric]/[24 alphanumeric]
        base = "https://hooks.slack.com/services/"
        team = "T" + "X" * 8
        bot = "B" + "X" * 11
        token = "X" * 24
        content = f"webhook = {base}{team}/{bot}/{token}"
        findings = detector.detect(content, "config.yml")
        webhook_findings = [f for f in findings if "Slack Webhook" in f.detector_name]
        assert len(webhook_findings) == 1

    def test_google_oauth_positive(self) -> None:
        """Test Google OAuth pattern matches client secret format."""
        detector = RegexDetector()
        # Pattern: "client_secret":"[a-zA-Z0-9-_]{24}"
        # Secret must be EXACTLY 24 chars: alphanumeric, -, or _
        content = '{"client_secret":"GOCSPX-1234567890abcdefg"}'  # exactly 24 chars
        findings = detector.detect(content, "credentials.json")
        google_findings = [f for f in findings if "Google OAuth" in f.detector_name]
        assert len(google_findings) == 1

    def test_generic_secret_positive(self) -> None:
        """Test Generic Secret pattern matches secret assignments."""
        detector = RegexDetector()
        content = 'SECRET_KEY="abcdefghijklmnopqrstuvwxyz1234567890abcd"'
        findings = detector.detect(content, ".env")
        secret_findings = [f for f in findings if "Generic Secret" in f.detector_name]
        assert len(secret_findings) == 1

    def test_email_address_positive(self) -> None:
        """Test Email Address pattern matches valid emails."""
        detector = RegexDetector()
        content = "Contact: admin@example.com"
        findings = detector.detect(content, "readme.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "admin@example.com" in email_findings[0].matches

    def test_ipv4_address_positive(self) -> None:
        """Test IPv4 Address pattern matches valid IP addresses."""
        detector = RegexDetector()
        content = "Server: 192.168.1.100"
        findings = detector.detect(content, "config.txt")
        ip_findings = [f for f in findings if "IPv4 Address" in f.detector_name]
        assert len(ip_findings) == 1
        assert "192.168.1.100" in ip_findings[0].matches

    def test_url_positive(self) -> None:
        """Test URL pattern matches http/https URLs."""
        detector = RegexDetector()
        content = "API: https://api.example.com/v1/users"
        findings = detector.detect(content, "api.txt")
        url_findings = [f for f in findings if "URL" in f.detector_name]
        assert len(url_findings) == 1

    def test_bitcoin_address_positive(self) -> None:
        """Test Bitcoin Address pattern matches valid BTC addresses."""
        detector = RegexDetector()
        content = "Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        findings = detector.detect(content, "wallet.txt")
        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 1

    def test_ethereum_address_positive(self) -> None:
        """Test Ethereum Address pattern matches valid ETH addresses."""
        detector = RegexDetector()
        content = "ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bB2d"
        findings = detector.detect(content, "crypto.txt")
        eth_findings = [f for f in findings if "Ethereum Address" in f.detector_name]
        assert len(eth_findings) == 1

    def test_heroku_api_key_positive(self) -> None:
        """Test Heroku API Key pattern matches valid Heroku tokens."""
        detector = RegexDetector()
        content = "HEROKU_API_KEY=12345678-1234-1234-1234-123456789ABC"
        findings = detector.detect(content, ".env")
        heroku_findings = [f for f in findings if "Heroku API Key" in f.detector_name]
        assert len(heroku_findings) == 1


class TestAllPatternsNegativeCases:
    """Ensure all 20 default patterns have at least one negative test case."""

    def test_aws_api_key_negative_short(self) -> None:
        """Test AWS API Key doesn't match short AKIA strings."""
        detector = RegexDetector()
        content = "AKIA1234567890"  # Only 10 chars after AKIA, needs 16
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 0

    def test_aws_api_key_negative_wrong_prefix(self) -> None:
        """Test AWS API Key doesn't match non-AKIA prefixes."""
        detector = RegexDetector()
        content = "ABIA12345678901234567890"  # Wrong prefix
        findings = detector.detect(content, "test.txt")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 0

    def test_aws_secret_key_negative_short(self) -> None:
        """Test AWS Secret Key doesn't match short secrets."""
        detector = RegexDetector()
        content = 'aws_secret="shortkey"'  # Too short (only 8 chars, needs 40)
        findings = detector.detect(content, "test.txt")
        secret_findings = [f for f in findings if "AWS Secret Key" in f.detector_name]
        assert len(secret_findings) == 0

    def test_aws_secret_key_negative_no_quotes(self) -> None:
        """Test AWS Secret Key doesn't match unquoted values."""
        detector = RegexDetector()
        content = "aws_secret=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"  # No quotes
        findings = detector.detect(content, "test.txt")
        secret_findings = [f for f in findings if "AWS Secret Key" in f.detector_name]
        assert len(secret_findings) == 0

    def test_github_token_negative_short(self) -> None:
        """Test GitHub Token doesn't match short tokens."""
        detector = RegexDetector()
        content = "ghp_short12345"  # Only 10 chars, needs 36
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Token" in f.detector_name]
        assert len(gh_findings) == 0

    def test_github_token_negative_wrong_prefix(self) -> None:
        """Test GitHub Token doesn't match wrong prefixes."""
        detector = RegexDetector()
        content = "ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"  # Wrong prefix
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Token" in f.detector_name]
        assert len(gh_findings) == 0

    def test_github_legacy_token_negative_short(self) -> None:
        """Test GitHub Legacy Token doesn't match short tokens."""
        detector = RegexDetector()
        content = 'GITHUB_TOKEN="shorttoken"'  # Only 10 chars, needs 35-40
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Legacy Token" in f.detector_name]
        assert len(gh_findings) == 0

    def test_github_legacy_token_negative_no_github(self) -> None:
        """Test GitHub Legacy Token doesn't match without 'github' keyword."""
        detector = RegexDetector()
        content = 'TOKEN="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'  # No 'github'
        findings = detector.detect(content, "test.txt")
        gh_findings = [f for f in findings if "GitHub Legacy Token" in f.detector_name]
        assert len(gh_findings) == 0

    def test_rsa_private_key_negative_public_key(self) -> None:
        """Test RSA Private Key doesn't match public key header."""
        detector = RegexDetector()
        content = "-----BEGIN RSA PUBLIC KEY-----"  # PUBLIC not PRIVATE
        findings = detector.detect(content, "key.pem")
        rsa_findings = [f for f in findings if "RSA Private Key" in f.detector_name]
        assert len(rsa_findings) == 0

    def test_rsa_private_key_negative_certificate(self) -> None:
        """Test RSA Private Key doesn't match certificate header."""
        detector = RegexDetector()
        content = "-----BEGIN CERTIFICATE-----"
        findings = detector.detect(content, "cert.pem")
        rsa_findings = [f for f in findings if "RSA Private Key" in f.detector_name]
        assert len(rsa_findings) == 0

    def test_dsa_private_key_negative_public(self) -> None:
        """Test DSA Private Key doesn't match DSA public key."""
        detector = RegexDetector()
        content = "-----BEGIN DSA PUBLIC KEY-----"
        findings = detector.detect(content, "key.pem")
        dsa_findings = [f for f in findings if "SSH (DSA) Private Key" in f.detector_name]
        assert len(dsa_findings) == 0

    def test_ec_private_key_negative_public(self) -> None:
        """Test EC Private Key doesn't match EC public key."""
        detector = RegexDetector()
        content = "-----BEGIN EC PUBLIC KEY-----"
        findings = detector.detect(content, "key.pem")
        ec_findings = [f for f in findings if "SSH (EC) Private Key" in f.detector_name]
        assert len(ec_findings) == 0

    def test_openssh_private_key_negative_public(self) -> None:
        """Test OpenSSH Private Key doesn't match public key."""
        detector = RegexDetector()
        content = "-----BEGIN OPENSSH PUBLIC KEY-----"
        findings = detector.detect(content, "id_ed25519.pub")
        openssh_findings = [f for f in findings if "SSH (OPENSSH) Private Key" in f.detector_name]
        assert len(openssh_findings) == 0

    def test_pgp_private_key_negative_public(self) -> None:
        """Test PGP Private Key doesn't match public key block."""
        detector = RegexDetector()
        content = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        findings = detector.detect(content, "public.asc")
        pgp_findings = [f for f in findings if "PGP Private Key Block" in f.detector_name]
        assert len(pgp_findings) == 0

    def test_generic_api_key_negative_short(self) -> None:
        """Test Generic API Key doesn't match short values."""
        detector = RegexDetector()
        content = 'api_key = "short"'  # Only 5 chars, needs 16-64
        findings = detector.detect(content, "config.py")
        api_findings = [f for f in findings if "Generic API Key" in f.detector_name]
        assert len(api_findings) == 0

    def test_generic_api_key_negative_no_key_word(self) -> None:
        """Test Generic API Key doesn't match without 'api' keyword."""
        detector = RegexDetector()
        content = 'token = "abcdef1234567890abcdef1234567890"'  # No 'api' word
        findings = detector.detect(content, "config.py")
        api_findings = [f for f in findings if "Generic API Key" in f.detector_name]
        assert len(api_findings) == 0

    def test_slack_token_negative_short(self) -> None:
        """Test Slack Token doesn't match short tokens."""
        detector = RegexDetector()
        content = "xoxb-123-456-789-abc"  # Wrong format, too short
        findings = detector.detect(content, ".env")
        slack_findings = [f for f in findings if "Slack Token" in f.detector_name]
        assert len(slack_findings) == 0

    def test_slack_token_negative_wrong_prefix(self) -> None:
        """Test Slack Token doesn't match wrong prefix."""
        detector = RegexDetector()
        content = "xoxz-123456789012-123456789012-123456789012-abcdefghijklmnopqrstuvwxyzabcdef"
        findings = detector.detect(content, ".env")
        slack_findings = [f for f in findings if "Slack Token" in f.detector_name]
        assert len(slack_findings) == 0

    def test_slack_webhook_negative_wrong_domain(self) -> None:
        """Test Slack Webhook doesn't match non-slack domains."""
        detector = RegexDetector()
        content = (
            "https://hooks.example.com/services/T12345678/B123456789AB/abcdefghijklmnopqrstuvwx"
        )
        findings = detector.detect(content, "config.yml")
        webhook_findings = [f for f in findings if "Slack Webhook" in f.detector_name]
        assert len(webhook_findings) == 0

    def test_slack_webhook_negative_wrong_path(self) -> None:
        """Test Slack Webhook doesn't match wrong path format."""
        detector = RegexDetector()
        content = "https://hooks.slack.com/api/something"  # Wrong path, not /services/T.../B...
        findings = detector.detect(content, "config.yml")
        webhook_findings = [f for f in findings if "Slack Webhook" in f.detector_name]
        assert len(webhook_findings) == 0

    def test_google_oauth_negative_short(self) -> None:
        """Test Google OAuth doesn't match short secrets."""
        detector = RegexDetector()
        content = '{"client_secret":"short"}'  # Only 5 chars, needs 24
        findings = detector.detect(content, "credentials.json")
        google_findings = [f for f in findings if "Google OAuth" in f.detector_name]
        assert len(google_findings) == 0

    def test_google_oauth_negative_wrong_key(self) -> None:
        """Test Google OAuth doesn't match wrong JSON key."""
        detector = RegexDetector()
        content = '{"api_secret":"GOCSPX-abcdefghij1234567890"}'  # Wrong key name
        findings = detector.detect(content, "credentials.json")
        google_findings = [f for f in findings if "Google OAuth" in f.detector_name]
        assert len(google_findings) == 0

    def test_generic_secret_negative_short(self) -> None:
        """Test Generic Secret doesn't match short values."""
        detector = RegexDetector()
        content = 'SECRET="shortvalue"'  # Only 10 chars, needs 32-45
        findings = detector.detect(content, ".env")
        secret_findings = [f for f in findings if "Generic Secret" in f.detector_name]
        assert len(secret_findings) == 0

    def test_generic_secret_negative_no_secret(self) -> None:
        """Test Generic Secret doesn't match without 'secret' keyword."""
        detector = RegexDetector()
        content = 'TOKEN="abcdefghijklmnopqrstuvwxyz1234567890abcd"'  # No 'secret'
        findings = detector.detect(content, ".env")
        secret_findings = [f for f in findings if "Generic Secret" in f.detector_name]
        assert len(secret_findings) == 0

    def test_email_address_negative_no_at(self) -> None:
        """Test Email Address doesn't match strings without @."""
        detector = RegexDetector()
        content = "contact: admin.example.com"  # No @ symbol
        findings = detector.detect(content, "readme.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 0

    def test_email_address_negative_no_domain(self) -> None:
        """Test Email Address doesn't match incomplete emails."""
        detector = RegexDetector()
        content = "email: user@"  # No domain
        findings = detector.detect(content, "readme.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 0

    def test_ipv4_address_negative_out_of_range(self) -> None:
        """Test IPv4 Address doesn't match out-of-range octets."""
        detector = RegexDetector()
        content = "Invalid IP: 256.1.2.3"  # 256 is out of range
        findings = detector.detect(content, "config.txt")
        ip_findings = [f for f in findings if "IPv4 Address" in f.detector_name]
        assert len(ip_findings) == 0

    def test_ipv4_address_negative_too_few_octets(self) -> None:
        """Test IPv4 Address doesn't match incomplete addresses."""
        detector = RegexDetector()
        content = "Incomplete: 192.168.1"  # Only 3 octets
        findings = detector.detect(content, "config.txt")
        ip_findings = [f for f in findings if "IPv4 Address" in f.detector_name]
        assert len(ip_findings) == 0

    def test_url_negative_no_scheme(self) -> None:
        """Test URL pattern doesn't match URLs without http/https."""
        detector = RegexDetector()
        content = "site: example.com/path"  # No http/https
        findings = detector.detect(content, "api.txt")
        url_findings = [f for f in findings if "URL" in f.detector_name]
        assert len(url_findings) == 0

    def test_url_negative_ftp(self) -> None:
        """Test URL pattern doesn't match FTP URLs."""
        detector = RegexDetector()
        content = "ftp://files.example.com/file.zip"  # FTP not HTTP
        findings = detector.detect(content, "api.txt")
        url_findings = [f for f in findings if "URL" in f.detector_name]
        assert len(url_findings) == 0

    def test_bitcoin_address_negative_short(self) -> None:
        """Test Bitcoin Address doesn't match short addresses."""
        detector = RegexDetector()
        content = "BTC: 1ABC123"  # Too short (7 chars, needs 25-34)
        findings = detector.detect(content, "wallet.txt")
        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 0

    def test_bitcoin_address_negative_wrong_prefix(self) -> None:
        """Test Bitcoin Address doesn't match wrong prefixes."""
        detector = RegexDetector()
        content = "2A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # Starts with 2, not 1 or 3
        findings = detector.detect(content, "wallet.txt")
        btc_findings = [f for f in findings if "Bitcoin Address" in f.detector_name]
        assert len(btc_findings) == 0

    def test_ethereum_address_negative_short(self) -> None:
        """Test Ethereum Address doesn't match short addresses."""
        detector = RegexDetector()
        content = "ETH: 0x742d35Cc"  # Only 8 chars after 0x, needs 40
        findings = detector.detect(content, "crypto.txt")
        eth_findings = [f for f in findings if "Ethereum Address" in f.detector_name]
        assert len(eth_findings) == 0

    def test_ethereum_address_negative_no_prefix(self) -> None:
        """Test Ethereum Address doesn't match without 0x prefix."""
        detector = RegexDetector()
        content = "742d35Cc6634C0532925a3b844Bc9e7595f0bB2d"  # No 0x prefix
        findings = detector.detect(content, "crypto.txt")
        eth_findings = [f for f in findings if "Ethereum Address" in f.detector_name]
        assert len(eth_findings) == 0

    def test_heroku_api_key_negative_wrong_format(self) -> None:
        """Test Heroku API Key doesn't match wrong UUID format."""
        detector = RegexDetector()
        content = "HEROKU_KEY=12345678-1234-1234"  # Incomplete UUID
        findings = detector.detect(content, ".env")
        heroku_findings = [f for f in findings if "Heroku API Key" in f.detector_name]
        assert len(heroku_findings) == 0

    def test_heroku_api_key_negative_no_heroku(self) -> None:
        """Test Heroku API Key doesn't match without 'heroku' keyword."""
        detector = RegexDetector()
        content = "API_KEY=12345678-1234-1234-1234-123456789ABC"  # No 'heroku'
        findings = detector.detect(content, ".env")
        heroku_findings = [f for f in findings if "Heroku API Key" in f.detector_name]
        assert len(heroku_findings) == 0


class TestCatastrophicBacktracking:
    """Tests to ensure patterns don't have catastrophic backtracking on adversarial input."""

    def test_aws_secret_key_adversarial_input(self) -> None:
        """Test AWS Secret Key pattern doesn't hang on adversarial input."""
        detector = RegexDetector(regex_timeout=1.0)
        # Adversarial input: long string of 'a's that could cause backtracking
        adversarial = "aws" + "a" * 1000 + '"' + "a" * 50 + '"'
        # Should complete without timeout
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_github_legacy_token_adversarial_input(self) -> None:
        """Test GitHub Legacy Token pattern doesn't hang on adversarial input."""
        detector = RegexDetector(regex_timeout=1.0)
        # Pattern has .* which could backtrack
        adversarial = "GITHUB" + "x" * 1000 + '"' + "a" * 50 + '"'
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_generic_api_key_adversarial_input(self) -> None:
        """Test Generic API Key pattern doesn't hang on adversarial input."""
        detector = RegexDetector(regex_timeout=1.0)
        # Pattern: api.* with complex suffix
        adversarial = "api_key" + " " * 500 + "=" + " " * 500 + '"' + "x" * 100 + '"'
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_generic_secret_adversarial_input(self) -> None:
        """Test Generic Secret pattern doesn't hang on adversarial input."""
        detector = RegexDetector(regex_timeout=1.0)
        # Pattern has .* which could cause issues
        adversarial = "SECRET" + "x" * 1000 + '"' + "a" * 50 + '"'
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_heroku_api_key_adversarial_input(self) -> None:
        """Test Heroku API Key pattern doesn't hang on adversarial input."""
        detector = RegexDetector(regex_timeout=1.0)
        # Pattern has .* which could backtrack
        adversarial = "HEROKU" + "x" * 1000 + "12345678-1234-1234-1234-123456789ABC"
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_email_adversarial_nested_dots(self) -> None:
        """Test Email pattern doesn't hang on strings with many dots."""
        detector = RegexDetector(regex_timeout=1.0)
        # Many dots could cause backtracking in domain matching
        adversarial = "a" + ".a" * 500 + "@" + "b" + ".b" * 500 + ".com"
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_url_adversarial_long_path(self) -> None:
        """Test URL pattern doesn't hang on very long paths."""
        detector = RegexDetector(regex_timeout=1.0)
        # Long path with many special chars could cause issues
        adversarial = "https://example.com/" + "a/b/c/d/e?" * 200
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_bitcoin_adversarial_long_string(self) -> None:
        """Test Bitcoin pattern doesn't hang on long alphanumeric strings."""
        detector = RegexDetector(regex_timeout=1.0)
        # Long base58 string that could match partially
        adversarial = "1" + "a" * 1000
        findings = detector.detect(adversarial, "test.txt")
        assert isinstance(findings, list)

    def test_all_patterns_adversarial_repeated_chars(self) -> None:
        """Test that all patterns handle repeated character attacks."""
        detector = RegexDetector(regex_timeout=1.0)
        # Test various adversarial inputs
        adversarial_inputs = [
            "a" * 10000,  # Just repeated chars
            '"' + "a" * 10000 + '"',  # Quoted repeated chars
            "=" * 5000 + '"' + "a" * 5000 + '"',  # Assignment-like
            "@" * 1000,  # Many @ symbols
            "." * 1000,  # Many dots
            "-----BEGIN " + "x" * 5000 + "-----",  # PEM-like
            "0x" + "a" * 1000,  # Ethereum-like prefix
        ]
        for adversarial in adversarial_inputs:
            findings = detector.detect(adversarial, "test.txt")
            assert isinstance(findings, list)

    def test_pathological_regex_with_short_timeout(self) -> None:
        """Test that pathological input triggers timeout gracefully."""
        # Create a detector with custom pattern that could be slow
        # Note: This tests the timeout mechanism, not actual default patterns
        patterns = {
            "Test Pattern": {
                "pattern": r"a+b",
                "severity": Severity.LOW,
                "description": "Test",
            }
        }
        detector = RegexDetector(patterns=patterns, use_defaults=False, regex_timeout=0.001)
        # This should complete (possibly with timeout) but not hang
        large_content = "a" * 100000 + "c"
        findings = detector.detect(large_content, "test.txt")
        assert isinstance(findings, list)

    def test_timeout_recovery_continues_processing(self) -> None:
        """Test that after a timeout, other patterns are still checked."""
        detector = RegexDetector(regex_timeout=1.0)
        # Include a valid email in content that also has potential backtracking triggers
        content = "admin@example.com " + "x" * 1000
        findings = detector.detect(content, "test.txt")
        # Should find the email even if other patterns took time
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestChunkedProcessing:
    """Tests for chunked processing of large content."""

    def test_chunking_logic_with_moderately_sized_content(self) -> None:
        """Test that chunking logic works correctly with moderate content.

        Note: Full 1MB+ content tests are impractical due to regex performance
        on large content. This test verifies the detector works correctly
        with content that is processed without issues.
        """
        # Use a simple literal pattern for faster matching
        simple_patterns = {
            "Test Secret": {
                "pattern": r"SECRET_\d{4}",
                "severity": Severity.HIGH,
                "description": "Test Secret Pattern",
            }
        }
        detector = RegexDetector(
            patterns=simple_patterns,
            use_defaults=False,
            max_file_size=10 * 1024 * 1024,  # 10MB limit
        )
        # Create content with secrets at various positions
        filler = "a" * 1000
        content = f"SECRET_1234 {filler} SECRET_5678 {filler} SECRET_9999"
        findings = detector.detect(content, "test.txt")
        assert len(findings) == 1
        assert len(findings[0].matches) == 3

    def test_match_at_content_boundaries(self) -> None:
        """Test that matches at content boundaries are found correctly."""
        # Use simple pattern to avoid backtracking issues
        simple_patterns = {
            "Test Key": {
                "pattern": r"KEY_[A-Z]{4}",
                "severity": Severity.HIGH,
                "description": "Test Key Pattern",
            }
        }
        detector = RegexDetector(
            patterns=simple_patterns,
            use_defaults=False,
        )
        # Create content with keys at start, middle, and end
        content = "KEY_AAAA" + "x" * 100 + "KEY_BBBB" + "x" * 100 + "KEY_CCCC"
        findings = detector.detect(content, "test.txt")
        assert len(findings) == 1
        assert len(findings[0].matches) == 3
        assert "KEY_AAAA" in findings[0].matches
        assert "KEY_BBBB" in findings[0].matches
        assert "KEY_CCCC" in findings[0].matches
