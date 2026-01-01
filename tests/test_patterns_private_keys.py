"""Tests for private key detection patterns.

This module contains comprehensive tests for all private key patterns defined in
the private_keys pattern module. Each pattern is tested with at least 2 positive
matches and 2 negative cases to ensure accuracy.

NOTE: Test patterns are intentionally constructed with EXAMPLE/FAKE markers and
truncated content to avoid triggering secret scanning or being mistaken for
real keys.
"""

from __future__ import annotations

import re

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.patterns.private_keys import (
    AWS_EC2_KEY_PAIR,
    DSA_PRIVATE_KEY,
    EC_PRIVATE_KEY,
    OPENSSH_PRIVATE_KEY,
    PGP_PRIVATE_KEY,
    PKCS8_ENCRYPTED_PRIVATE_KEY,
    PKCS8_PRIVATE_KEY,
    PRIVATE_KEY_ASSIGNMENT,
    PRIVATE_KEY_PATH,
    PRIVATE_KEY_PATTERNS,
    PUTTY_PRIVATE_KEY,
    RSA_PRIVATE_KEY,
    SSH2_PRIVATE_KEY,
    SSH_PRIVATE_KEY_GENERIC,
    SSL_PRIVATE_KEY,
    X509_CERTIFICATE,
    X509_CERTIFICATE_REQUEST,
)

# Sample test keys - intentionally fake/example content
FAKE_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAJBAKExample12345FakeKeyForTestingPurposesOnlyDoNotUse
ThisIsNotARealPrivateKeyItIsJustForUnitTestingPattern0123456789
-----END RSA PRIVATE KEY-----"""

FAKE_OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
EXAMPLE_FAKE_KEY_FOR_TESTING_ONLY_NOT_REAL_0123456789ABCDEF
-----END OPENSSH PRIVATE KEY-----"""

FAKE_EC_KEY = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIExampleFakeECKeyForTestingPurposes0123456789ABCDEFgh
ijklmnopqrstuvwxyzNotARealKey
-----END EC PRIVATE KEY-----"""

FAKE_DSA_KEY = """-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDExampleFakeDSAKeyForTestingPurposesOnly
ThisIsNotARealPrivateKeyItIsJustForUnitTesting0123456789
-----END DSA PRIVATE KEY-----"""

FAKE_PGP_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Example 1.0

lQExampleFakePGPKeyBlockForTestingPurposesOnlyNotReal
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno
-----END PGP PRIVATE KEY BLOCK-----"""

FAKE_PKCS8_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCExample
FakeKeyForTestingPurposesOnlyDoNotUse0123456789ABCDEF
-----END PRIVATE KEY-----"""

FAKE_PKCS8_ENCRYPTED_KEY = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIExampleFake
KeyForTestingPurposesOnlyEncrypted0123456789ABCDEF
-----END ENCRYPTED PRIVATE KEY-----"""

FAKE_SSH2_KEY = """---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
Comment: "example@test.local"
P2/56ExampleFakeSSH2KeyForTestingPurposesOnly
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef
---- END SSH2 ENCRYPTED PRIVATE KEY ----"""

FAKE_X509_CERT = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAExampleFakeCert0123456789ABCDEFGHIJKLM
NOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzForTestingOnly
-----END CERTIFICATE-----"""

FAKE_CSR = """-----BEGIN CERTIFICATE REQUEST-----
MIICVjCCAT4CAQAwETEPMA0GA1UEAwwGdGVzdGluZzCCASIwDQYJKoZI
ExampleFakeCSRForTestingPurposes0123456789ABCDEFGHIJ
-----END CERTIFICATE REQUEST-----"""


class TestRSAPrivateKey:
    """Tests for RSA Private Key pattern."""

    def test_rsa_private_key_positive_1(self) -> None:
        """Test RSA private key matches valid key."""
        pattern = re.compile(RSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_RSA_KEY)
        assert result is not None

    def test_rsa_private_key_positive_2(self) -> None:
        """Test RSA private key matches in code context."""
        pattern = re.compile(RSA_PRIVATE_KEY.regex, re.DOTALL)
        code = f"private_key = '''{FAKE_RSA_KEY}'''"
        result = pattern.search(code)
        assert result is not None

    def test_rsa_private_key_positive_3(self) -> None:
        """Test RSA private key matches minimal valid format."""
        pattern = re.compile(RSA_PRIVATE_KEY.regex, re.DOTALL)
        minimal_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        result = pattern.search(minimal_key)
        assert result is not None

    def test_rsa_private_key_negative_1(self) -> None:
        """Test RSA private key doesn't match incomplete header."""
        pattern = re.compile(RSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert result is None

    def test_rsa_private_key_negative_2(self) -> None:
        """Test RSA private key doesn't match public key."""
        pattern = re.compile(RSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(
            "-----BEGIN RSA PUBLIC KEY-----\ntest\n-----END RSA PUBLIC KEY-----"
        )
        assert result is None

    def test_rsa_private_key_metadata(self) -> None:
        """Test RSA private key pattern metadata."""
        assert RSA_PRIVATE_KEY.severity == Severity.CRITICAL
        assert RSA_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert RSA_PRIVATE_KEY.confidence == Confidence.HIGH


class TestOpenSSHPrivateKey:
    """Tests for OpenSSH Private Key pattern."""

    def test_openssh_private_key_positive_1(self) -> None:
        """Test OpenSSH private key matches valid key."""
        pattern = re.compile(OPENSSH_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_OPENSSH_KEY)
        assert result is not None

    def test_openssh_private_key_positive_2(self) -> None:
        """Test OpenSSH private key matches in file content."""
        pattern = re.compile(OPENSSH_PRIVATE_KEY.regex, re.DOTALL)
        content = f"# SSH Key\n{FAKE_OPENSSH_KEY}\n# End key"
        result = pattern.search(content)
        assert result is not None

    def test_openssh_private_key_negative_1(self) -> None:
        """Test OpenSSH private key doesn't match partial header."""
        pattern = re.compile(OPENSSH_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert result is None

    def test_openssh_private_key_negative_2(self) -> None:
        """Test OpenSSH private key doesn't match RSA format."""
        pattern = re.compile(OPENSSH_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_RSA_KEY)
        assert result is None

    def test_openssh_private_key_metadata(self) -> None:
        """Test OpenSSH private key pattern metadata."""
        assert OPENSSH_PRIVATE_KEY.severity == Severity.CRITICAL
        assert OPENSSH_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert OPENSSH_PRIVATE_KEY.confidence == Confidence.HIGH


class TestECPrivateKey:
    """Tests for EC Private Key pattern."""

    def test_ec_private_key_positive_1(self) -> None:
        """Test EC private key matches valid key."""
        pattern = re.compile(EC_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_EC_KEY)
        assert result is not None

    def test_ec_private_key_positive_2(self) -> None:
        """Test EC private key matches in JSON context."""
        pattern = re.compile(EC_PRIVATE_KEY.regex, re.DOTALL)
        # Escape the key for JSON
        escaped = FAKE_EC_KEY.replace("\n", "\\n")
        json_content = f'{{"key": "{escaped}"}}'
        # Need to unescape for pattern matching
        content = json_content.replace("\\n", "\n")
        result = pattern.search(content)
        assert result is not None

    def test_ec_private_key_negative_1(self) -> None:
        """Test EC private key doesn't match header only."""
        pattern = re.compile(EC_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN EC PRIVATE KEY-----")
        assert result is None

    def test_ec_private_key_negative_2(self) -> None:
        """Test EC private key doesn't match EC parameters."""
        pattern = re.compile(EC_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN EC PARAMETERS-----\ntest\n-----END EC PARAMETERS-----")
        assert result is None

    def test_ec_private_key_metadata(self) -> None:
        """Test EC private key pattern metadata."""
        assert EC_PRIVATE_KEY.severity == Severity.CRITICAL
        assert EC_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert EC_PRIVATE_KEY.confidence == Confidence.HIGH


class TestDSAPrivateKey:
    """Tests for DSA Private Key pattern."""

    def test_dsa_private_key_positive_1(self) -> None:
        """Test DSA private key matches valid key."""
        pattern = re.compile(DSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_DSA_KEY)
        assert result is not None

    def test_dsa_private_key_positive_2(self) -> None:
        """Test DSA private key matches in config file context."""
        pattern = re.compile(DSA_PRIVATE_KEY.regex, re.DOTALL)
        config = f"dsa_key: |\n  {FAKE_DSA_KEY}"
        result = pattern.search(config)
        assert result is not None

    def test_dsa_private_key_negative_1(self) -> None:
        """Test DSA private key doesn't match incomplete format."""
        pattern = re.compile(DSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN DSA PRIVATE KEY-----")
        assert result is None

    def test_dsa_private_key_negative_2(self) -> None:
        """Test DSA private key doesn't match DSA parameters."""
        pattern = re.compile(DSA_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(
            "-----BEGIN DSA PARAMETERS-----\ntest\n-----END DSA PARAMETERS-----"
        )
        assert result is None

    def test_dsa_private_key_metadata(self) -> None:
        """Test DSA private key pattern metadata."""
        assert DSA_PRIVATE_KEY.severity == Severity.CRITICAL
        assert DSA_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert DSA_PRIVATE_KEY.confidence == Confidence.HIGH


class TestPGPPrivateKey:
    """Tests for PGP Private Key Block pattern."""

    def test_pgp_private_key_positive_1(self) -> None:
        """Test PGP private key matches valid key block."""
        pattern = re.compile(PGP_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_PGP_KEY)
        assert result is not None

    def test_pgp_private_key_positive_2(self) -> None:
        """Test PGP private key matches in email-like context."""
        pattern = re.compile(PGP_PRIVATE_KEY.regex, re.DOTALL)
        content = f"Here is my key:\n\n{FAKE_PGP_KEY}\n\nBest regards"
        result = pattern.search(content)
        assert result is not None

    def test_pgp_private_key_negative_1(self) -> None:
        """Test PGP private key doesn't match public key."""
        pattern = re.compile(PGP_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----"
        )
        assert result is None

    def test_pgp_private_key_negative_2(self) -> None:
        """Test PGP private key doesn't match message block."""
        pattern = re.compile(PGP_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN PGP MESSAGE-----\ntest\n-----END PGP MESSAGE-----")
        assert result is None

    def test_pgp_private_key_metadata(self) -> None:
        """Test PGP private key pattern metadata."""
        assert PGP_PRIVATE_KEY.severity == Severity.CRITICAL
        assert PGP_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert PGP_PRIVATE_KEY.confidence == Confidence.HIGH


class TestPKCS8PrivateKey:
    """Tests for PKCS#8 Private Key pattern."""

    def test_pkcs8_private_key_positive_1(self) -> None:
        """Test PKCS#8 private key matches valid key."""
        pattern = re.compile(PKCS8_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_PKCS8_KEY)
        assert result is not None

    def test_pkcs8_private_key_positive_2(self) -> None:
        """Test PKCS#8 private key matches in PEM file context."""
        pattern = re.compile(PKCS8_PRIVATE_KEY.regex, re.DOTALL)
        content = f"# Private Key File\n{FAKE_PKCS8_KEY}"
        result = pattern.search(content)
        assert result is not None

    def test_pkcs8_private_key_negative_1(self) -> None:
        """Test PKCS#8 private key doesn't match public key."""
        pattern = re.compile(PKCS8_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----")
        assert result is None

    def test_pkcs8_private_key_negative_2(self) -> None:
        """Test PKCS#8 private key doesn't match encrypted version."""
        pattern = re.compile(PKCS8_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_PKCS8_ENCRYPTED_KEY)
        assert result is None

    def test_pkcs8_private_key_metadata(self) -> None:
        """Test PKCS#8 private key pattern metadata."""
        assert PKCS8_PRIVATE_KEY.severity == Severity.CRITICAL
        assert PKCS8_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert PKCS8_PRIVATE_KEY.confidence == Confidence.HIGH


class TestPKCS8EncryptedPrivateKey:
    """Tests for PKCS#8 Encrypted Private Key pattern."""

    def test_pkcs8_encrypted_private_key_positive_1(self) -> None:
        """Test PKCS#8 encrypted private key matches valid key."""
        pattern = re.compile(PKCS8_ENCRYPTED_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_PKCS8_ENCRYPTED_KEY)
        assert result is not None

    def test_pkcs8_encrypted_private_key_positive_2(self) -> None:
        """Test PKCS#8 encrypted private key matches in file context."""
        pattern = re.compile(PKCS8_ENCRYPTED_PRIVATE_KEY.regex, re.DOTALL)
        content = f"Encrypted Key:\n{FAKE_PKCS8_ENCRYPTED_KEY}"
        result = pattern.search(content)
        assert result is not None

    def test_pkcs8_encrypted_private_key_negative_1(self) -> None:
        """Test PKCS#8 encrypted doesn't match unencrypted."""
        pattern = re.compile(PKCS8_ENCRYPTED_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_PKCS8_KEY)
        assert result is None

    def test_pkcs8_encrypted_private_key_negative_2(self) -> None:
        """Test PKCS#8 encrypted doesn't match header only."""
        pattern = re.compile(PKCS8_ENCRYPTED_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        assert result is None

    def test_pkcs8_encrypted_private_key_metadata(self) -> None:
        """Test PKCS#8 encrypted private key pattern metadata."""
        assert PKCS8_ENCRYPTED_PRIVATE_KEY.severity == Severity.HIGH
        assert PKCS8_ENCRYPTED_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert PKCS8_ENCRYPTED_PRIVATE_KEY.confidence == Confidence.HIGH


class TestSSHPrivateKeyGeneric:
    """Tests for generic SSH Private Key pattern."""

    def test_ssh_private_key_generic_positive_rsa(self) -> None:
        """Test generic SSH key matches RSA header."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert result is not None

    def test_ssh_private_key_generic_positive_ec(self) -> None:
        """Test generic SSH key matches EC header."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN EC PRIVATE KEY-----")
        assert result is not None

    def test_ssh_private_key_generic_positive_openssh(self) -> None:
        """Test generic SSH key matches OpenSSH header."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN OPENSSH PRIVATE KEY-----")
        assert result is not None

    def test_ssh_private_key_generic_positive_dsa(self) -> None:
        """Test generic SSH key matches DSA header."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN DSA PRIVATE KEY-----")
        assert result is not None

    def test_ssh_private_key_generic_positive_pkcs8(self) -> None:
        """Test generic SSH key matches PKCS#8 header."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN PRIVATE KEY-----")
        assert result is not None

    def test_ssh_private_key_generic_negative_1(self) -> None:
        """Test generic SSH key doesn't match public key."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN RSA PUBLIC KEY-----")
        assert result is None

    def test_ssh_private_key_generic_negative_2(self) -> None:
        """Test generic SSH key doesn't match certificate."""
        pattern = re.compile(SSH_PRIVATE_KEY_GENERIC.regex)
        result = pattern.search("-----BEGIN CERTIFICATE-----")
        assert result is None

    def test_ssh_private_key_generic_metadata(self) -> None:
        """Test generic SSH key pattern metadata."""
        assert SSH_PRIVATE_KEY_GENERIC.severity == Severity.CRITICAL
        assert SSH_PRIVATE_KEY_GENERIC.category == PatternCategory.PRIVATE_KEYS
        assert SSH_PRIVATE_KEY_GENERIC.confidence == Confidence.HIGH


class TestSSH2PrivateKey:
    """Tests for SSH2 Private Key pattern."""

    def test_ssh2_private_key_positive_1(self) -> None:
        """Test SSH2 private key matches valid key."""
        pattern = re.compile(SSH2_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_SSH2_KEY)
        assert result is not None

    def test_ssh2_private_key_positive_2(self) -> None:
        """Test SSH2 private key matches in file context."""
        pattern = re.compile(SSH2_PRIVATE_KEY.regex, re.DOTALL)
        content = f"# SSH2 Key\n{FAKE_SSH2_KEY}"
        result = pattern.search(content)
        assert result is not None

    def test_ssh2_private_key_negative_1(self) -> None:
        """Test SSH2 private key doesn't match OpenSSH format."""
        pattern = re.compile(SSH2_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search(FAKE_OPENSSH_KEY)
        assert result is None

    def test_ssh2_private_key_negative_2(self) -> None:
        """Test SSH2 private key doesn't match header only."""
        pattern = re.compile(SSH2_PRIVATE_KEY.regex, re.DOTALL)
        result = pattern.search("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----")
        assert result is None

    def test_ssh2_private_key_metadata(self) -> None:
        """Test SSH2 private key pattern metadata."""
        assert SSH2_PRIVATE_KEY.severity == Severity.CRITICAL
        assert SSH2_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert SSH2_PRIVATE_KEY.confidence == Confidence.HIGH


class TestPuTTYPrivateKey:
    """Tests for PuTTY Private Key pattern."""

    def test_putty_private_key_positive_1(self) -> None:
        """Test PuTTY key matches version 2 format."""
        pattern = re.compile(PUTTY_PRIVATE_KEY.regex)
        result = pattern.search("PuTTY-User-Key-File-2: ssh-rsa")
        assert result is not None

    def test_putty_private_key_positive_2(self) -> None:
        """Test PuTTY key matches version 3 format."""
        pattern = re.compile(PUTTY_PRIVATE_KEY.regex)
        result = pattern.search("PuTTY-User-Key-File-3: ssh-ed25519")
        assert result is not None

    def test_putty_private_key_positive_3(self) -> None:
        """Test PuTTY key matches in file context."""
        pattern = re.compile(PUTTY_PRIVATE_KEY.regex)
        content = "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: test-key"
        result = pattern.search(content)
        assert result is not None

    def test_putty_private_key_negative_1(self) -> None:
        """Test PuTTY key doesn't match wrong version."""
        pattern = re.compile(PUTTY_PRIVATE_KEY.regex)
        result = pattern.search("PuTTY-User-Key-File-1: ssh-rsa")
        assert result is None

    def test_putty_private_key_negative_2(self) -> None:
        """Test PuTTY key doesn't match OpenSSH format."""
        pattern = re.compile(PUTTY_PRIVATE_KEY.regex)
        result = pattern.search(FAKE_OPENSSH_KEY)
        assert result is None

    def test_putty_private_key_metadata(self) -> None:
        """Test PuTTY private key pattern metadata."""
        assert PUTTY_PRIVATE_KEY.severity == Severity.CRITICAL
        assert PUTTY_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert PUTTY_PRIVATE_KEY.confidence == Confidence.HIGH


class TestX509Certificate:
    """Tests for X.509 Certificate pattern."""

    def test_x509_certificate_positive_1(self) -> None:
        """Test X.509 certificate matches valid cert."""
        pattern = re.compile(X509_CERTIFICATE.regex, re.DOTALL)
        result = pattern.search(FAKE_X509_CERT)
        assert result is not None

    def test_x509_certificate_positive_2(self) -> None:
        """Test X.509 certificate matches in PEM chain."""
        pattern = re.compile(X509_CERTIFICATE.regex, re.DOTALL)
        chain = f"{FAKE_X509_CERT}\n{FAKE_X509_CERT}"
        results = pattern.findall(chain)
        assert len(results) == 2

    def test_x509_certificate_negative_1(self) -> None:
        """Test X.509 certificate doesn't match private key."""
        pattern = re.compile(X509_CERTIFICATE.regex, re.DOTALL)
        result = pattern.search(FAKE_RSA_KEY)
        assert result is None

    def test_x509_certificate_negative_2(self) -> None:
        """Test X.509 certificate doesn't match CSR."""
        pattern = re.compile(X509_CERTIFICATE.regex, re.DOTALL)
        result = pattern.search(FAKE_CSR)
        assert result is None

    def test_x509_certificate_metadata(self) -> None:
        """Test X.509 certificate pattern metadata."""
        assert X509_CERTIFICATE.severity == Severity.MEDIUM
        assert X509_CERTIFICATE.category == PatternCategory.PRIVATE_KEYS
        assert X509_CERTIFICATE.confidence == Confidence.HIGH


class TestX509CertificateRequest:
    """Tests for X.509 Certificate Request pattern."""

    def test_x509_csr_positive_1(self) -> None:
        """Test X.509 CSR matches valid request."""
        pattern = re.compile(X509_CERTIFICATE_REQUEST.regex, re.DOTALL)
        result = pattern.search(FAKE_CSR)
        assert result is not None

    def test_x509_csr_positive_2(self) -> None:
        """Test X.509 CSR matches in file context."""
        pattern = re.compile(X509_CERTIFICATE_REQUEST.regex, re.DOTALL)
        content = f"# Certificate Request\n{FAKE_CSR}"
        result = pattern.search(content)
        assert result is not None

    def test_x509_csr_negative_1(self) -> None:
        """Test X.509 CSR doesn't match certificate."""
        pattern = re.compile(X509_CERTIFICATE_REQUEST.regex, re.DOTALL)
        result = pattern.search(FAKE_X509_CERT)
        assert result is None

    def test_x509_csr_negative_2(self) -> None:
        """Test X.509 CSR doesn't match private key."""
        pattern = re.compile(X509_CERTIFICATE_REQUEST.regex, re.DOTALL)
        result = pattern.search(FAKE_RSA_KEY)
        assert result is None

    def test_x509_csr_metadata(self) -> None:
        """Test X.509 CSR pattern metadata."""
        assert X509_CERTIFICATE_REQUEST.severity == Severity.LOW
        assert X509_CERTIFICATE_REQUEST.category == PatternCategory.PRIVATE_KEYS
        assert X509_CERTIFICATE_REQUEST.confidence == Confidence.HIGH


class TestSSLPrivateKey:
    """Tests for SSL/TLS Private Key pattern."""

    def test_ssl_private_key_positive_1(self) -> None:
        """Test SSL private key matches labeled key."""
        pattern = re.compile(SSL_PRIVATE_KEY.regex)
        result = pattern.search("ssl_private_key = '-----BEGIN RSA PRIVATE KEY-----")
        assert result is not None

    def test_ssl_private_key_positive_2(self) -> None:
        """Test TLS private key matches labeled key."""
        pattern = re.compile(SSL_PRIVATE_KEY.regex)
        result = pattern.search("TLS_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----")
        assert result is not None

    def test_ssl_private_key_positive_3(self) -> None:
        """Test SSL key matches EC format."""
        pattern = re.compile(SSL_PRIVATE_KEY.regex)
        result = pattern.search('ssl_key = "-----BEGIN EC PRIVATE KEY-----')
        assert result is not None

    def test_ssl_private_key_negative_1(self) -> None:
        """Test SSL private key doesn't match without label."""
        pattern = re.compile(SSL_PRIVATE_KEY.regex)
        result = pattern.search("-----BEGIN RSA PRIVATE KEY-----")
        assert result is None

    def test_ssl_private_key_negative_2(self) -> None:
        """Test SSL private key doesn't match public key."""
        pattern = re.compile(SSL_PRIVATE_KEY.regex)
        result = pattern.search("ssl_public_key = '-----BEGIN PUBLIC KEY-----")
        assert result is None

    def test_ssl_private_key_metadata(self) -> None:
        """Test SSL private key pattern metadata."""
        assert SSL_PRIVATE_KEY.severity == Severity.CRITICAL
        assert SSL_PRIVATE_KEY.category == PatternCategory.PRIVATE_KEYS
        assert SSL_PRIVATE_KEY.confidence == Confidence.HIGH


class TestPrivateKeyAssignment:
    """Tests for Private Key Assignment pattern."""

    def test_private_key_assignment_positive_1(self) -> None:
        """Test private key assignment matches common pattern."""
        pattern = re.compile(PRIVATE_KEY_ASSIGNMENT.regex)
        result = pattern.search("private_key = '-----BEGIN")
        assert result is not None

    def test_private_key_assignment_positive_2(self) -> None:
        """Test priv_key assignment matches."""
        pattern = re.compile(PRIVATE_KEY_ASSIGNMENT.regex)
        result = pattern.search('priv_key: "-----BEGIN')
        assert result is not None

    def test_private_key_assignment_positive_3(self) -> None:
        """Test key_private assignment matches."""
        pattern = re.compile(PRIVATE_KEY_ASSIGNMENT.regex)
        result = pattern.search("KEY_PRIVATE = '-----BEGIN")
        assert result is not None

    def test_private_key_assignment_negative_1(self) -> None:
        """Test doesn't match public key assignment."""
        pattern = re.compile(PRIVATE_KEY_ASSIGNMENT.regex)
        result = pattern.search("public_key = '-----BEGIN")
        assert result is None

    def test_private_key_assignment_negative_2(self) -> None:
        """Test doesn't match unrelated assignment."""
        pattern = re.compile(PRIVATE_KEY_ASSIGNMENT.regex)
        result = pattern.search("api_key = 'abc123'")
        assert result is None

    def test_private_key_assignment_metadata(self) -> None:
        """Test private key assignment pattern metadata."""
        assert PRIVATE_KEY_ASSIGNMENT.severity == Severity.CRITICAL
        assert PRIVATE_KEY_ASSIGNMENT.category == PatternCategory.PRIVATE_KEYS
        assert PRIVATE_KEY_ASSIGNMENT.confidence == Confidence.HIGH


class TestPrivateKeyPath:
    """Tests for Private Key File Path pattern."""

    def test_private_key_path_positive_1(self) -> None:
        """Test private key path matches .ssh path."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        result = pattern.search("id_rsa = '/home/user/.ssh/id_rsa'")
        assert result is not None

    def test_private_key_path_positive_2(self) -> None:
        """Test private key path matches absolute path."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        result = pattern.search("private_key = '/etc/ssl/private/server.key'")
        assert result is not None

    def test_private_key_path_positive_3(self) -> None:
        """Test private key path matches home path."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        result = pattern.search("key_file: ~/.ssh/id_ed25519")
        assert result is not None

    def test_private_key_path_positive_4(self) -> None:
        """Test private key path matches id_ecdsa."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        result = pattern.search("id_ecdsa = '~/.ssh/id_ecdsa'")
        assert result is not None

    def test_private_key_path_negative_1(self) -> None:
        """Test doesn't match public key path."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        # This checks it doesn't match arbitrary paths
        result = pattern.search("public_key = '/path/to/pub.key'")
        assert result is None

    def test_private_key_path_negative_2(self) -> None:
        """Test doesn't match unrelated config."""
        pattern = re.compile(PRIVATE_KEY_PATH.regex)
        result = pattern.search("log_file = '/var/log/app.log'")
        assert result is None

    def test_private_key_path_metadata(self) -> None:
        """Test private key path pattern metadata."""
        assert PRIVATE_KEY_PATH.severity == Severity.HIGH
        assert PRIVATE_KEY_PATH.category == PatternCategory.PRIVATE_KEYS
        assert PRIVATE_KEY_PATH.confidence == Confidence.MEDIUM


class TestAWSEC2KeyPair:
    """Tests for AWS EC2 Key Pair pattern."""

    def test_aws_ec2_key_pair_positive_1(self) -> None:
        """Test AWS EC2 key pair matches key_pair_name."""
        pattern = re.compile(AWS_EC2_KEY_PAIR.regex)
        result = pattern.search("key_pair_name = 'my-production-key'")
        assert result is not None

    def test_aws_ec2_key_pair_positive_2(self) -> None:
        """Test AWS EC2 key pair matches ec2_key_name."""
        pattern = re.compile(AWS_EC2_KEY_PAIR.regex)
        result = pattern.search("ec2_key_name: 'deploy-key-2023'")
        assert result is not None

    def test_aws_ec2_key_pair_negative_1(self) -> None:
        """Test doesn't match unrelated key reference."""
        pattern = re.compile(AWS_EC2_KEY_PAIR.regex)
        result = pattern.search("api_key = 'abc123'")
        assert result is None

    def test_aws_ec2_key_pair_negative_2(self) -> None:
        """Test doesn't match simple key assignment."""
        pattern = re.compile(AWS_EC2_KEY_PAIR.regex)
        result = pattern.search("key = 'value'")
        assert result is None

    def test_aws_ec2_key_pair_metadata(self) -> None:
        """Test AWS EC2 key pair pattern metadata."""
        assert AWS_EC2_KEY_PAIR.severity == Severity.LOW
        assert AWS_EC2_KEY_PAIR.category == PatternCategory.PRIVATE_KEYS
        assert AWS_EC2_KEY_PAIR.confidence == Confidence.LOW


class TestPrivateKeyPatternsCollection:
    """Tests for the PRIVATE_KEY_PATTERNS collection."""

    def test_all_patterns_included(self) -> None:
        """Test all defined patterns are in the collection."""
        expected_patterns = [
            RSA_PRIVATE_KEY,
            OPENSSH_PRIVATE_KEY,
            EC_PRIVATE_KEY,
            DSA_PRIVATE_KEY,
            PGP_PRIVATE_KEY,
            PKCS8_PRIVATE_KEY,
            PKCS8_ENCRYPTED_PRIVATE_KEY,
            SSH_PRIVATE_KEY_GENERIC,
            SSH2_PRIVATE_KEY,
            PUTTY_PRIVATE_KEY,
            X509_CERTIFICATE,
            X509_CERTIFICATE_REQUEST,
            SSL_PRIVATE_KEY,
            PRIVATE_KEY_ASSIGNMENT,
            PRIVATE_KEY_PATH,
            AWS_EC2_KEY_PAIR,
        ]
        assert len(PRIVATE_KEY_PATTERNS) == len(expected_patterns)
        for pattern in expected_patterns:
            assert pattern in PRIVATE_KEY_PATTERNS

    def test_all_patterns_have_category(self) -> None:
        """Test all patterns have PRIVATE_KEYS category."""
        for pattern in PRIVATE_KEY_PATTERNS:
            assert pattern.category == PatternCategory.PRIVATE_KEYS

    def test_all_patterns_have_valid_severity(self) -> None:
        """Test all patterns have valid severity levels."""
        valid_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        for pattern in PRIVATE_KEY_PATTERNS:
            assert pattern.severity in valid_severities

    def test_all_patterns_have_descriptions(self) -> None:
        """Test all patterns have non-empty descriptions."""
        for pattern in PRIVATE_KEY_PATTERNS:
            assert pattern.description
            assert len(pattern.description) > 10

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test all patterns have compilable regex."""
        for pattern in PRIVATE_KEY_PATTERNS:
            # Should not raise
            compiled = re.compile(pattern.regex, re.DOTALL)
            assert compiled is not None

    def test_pattern_count(self) -> None:
        """Test expected number of patterns."""
        assert len(PRIVATE_KEY_PATTERNS) == 16
