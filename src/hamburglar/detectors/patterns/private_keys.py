"""Private key detection patterns.

This module contains patterns for detecting private keys and certificates
including RSA, OpenSSH, EC, DSA, PGP, PKCS#8, and SSL/TLS formats.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory


# RSA Private Key
RSA_PRIVATE_KEY = Pattern(
    name="rsa_private_key",
    regex=r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="RSA Private Key - traditional PKCS#1 format private key",
    confidence=Confidence.HIGH,
)

# OpenSSH Private Key
OPENSSH_PRIVATE_KEY = Pattern(
    name="openssh_private_key",
    regex=r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="OpenSSH Private Key - modern OpenSSH format private key",
    confidence=Confidence.HIGH,
)

# EC Private Key
EC_PRIVATE_KEY = Pattern(
    name="ec_private_key",
    regex=r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="EC Private Key - Elliptic Curve private key in SEC1 format",
    confidence=Confidence.HIGH,
)

# DSA Private Key
DSA_PRIVATE_KEY = Pattern(
    name="dsa_private_key",
    regex=r"-----BEGIN DSA PRIVATE KEY-----[\s\S]*?-----END DSA PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="DSA Private Key - Digital Signature Algorithm private key",
    confidence=Confidence.HIGH,
)

# PGP Private Key Block
PGP_PRIVATE_KEY = Pattern(
    name="pgp_private_key",
    regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="PGP Private Key Block - OpenPGP format private key",
    confidence=Confidence.HIGH,
)

# PKCS#8 Private Key (unencrypted)
PKCS8_PRIVATE_KEY = Pattern(
    name="pkcs8_private_key",
    regex=r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="PKCS#8 Private Key - unencrypted PKCS#8 format private key",
    confidence=Confidence.HIGH,
)

# PKCS#8 Encrypted Private Key
PKCS8_ENCRYPTED_PRIVATE_KEY = Pattern(
    name="pkcs8_encrypted_private_key",
    regex=r"-----BEGIN ENCRYPTED PRIVATE KEY-----[\s\S]*?-----END ENCRYPTED PRIVATE KEY-----",
    severity=Severity.HIGH,
    category=PatternCategory.PRIVATE_KEYS,
    description="PKCS#8 Encrypted Private Key - password-protected PKCS#8 format private key",
    confidence=Confidence.HIGH,
)

# SSH Private Key (generic, covers various formats)
SSH_PRIVATE_KEY_GENERIC = Pattern(
    name="ssh_private_key_generic",
    regex=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="SSH Private Key - generic detection for SSH private key headers",
    confidence=Confidence.HIGH,
)

# SSH2 Private Key (ssh.com format)
SSH2_PRIVATE_KEY = Pattern(
    name="ssh2_private_key",
    regex=r"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----[\s\S]*?---- END SSH2 ENCRYPTED PRIVATE KEY ----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="SSH2 Private Key - SSH.com format private key",
    confidence=Confidence.HIGH,
)

# PuTTY Private Key
PUTTY_PRIVATE_KEY = Pattern(
    name="putty_private_key",
    regex=r"PuTTY-User-Key-File-[23]:\s+[\w-]+",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="PuTTY Private Key - PuTTY PPK format private key",
    confidence=Confidence.HIGH,
)

# X.509 Certificate (not a private key, but often paired with one)
X509_CERTIFICATE = Pattern(
    name="x509_certificate",
    regex=r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----",
    severity=Severity.MEDIUM,
    category=PatternCategory.PRIVATE_KEYS,
    description="X.509 Certificate - public certificate that may indicate private key nearby",
    confidence=Confidence.HIGH,
)

# X.509 Certificate Request (CSR)
X509_CERTIFICATE_REQUEST = Pattern(
    name="x509_certificate_request",
    regex=r"-----BEGIN CERTIFICATE REQUEST-----[\s\S]*?-----END CERTIFICATE REQUEST-----",
    severity=Severity.LOW,
    category=PatternCategory.PRIVATE_KEYS,
    description="X.509 Certificate Request - Certificate Signing Request (CSR)",
    confidence=Confidence.HIGH,
)

# SSL/TLS Private Key (same as PKCS#8 but explicitly for SSL context)
SSL_PRIVATE_KEY = Pattern(
    name="ssl_private_key",
    regex=r"(?i)(?:ssl|tls)[_-]?(?:private)?[_-]?key['\"]?\s*[:=]\s*['\"]?-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="SSL/TLS Private Key - private key explicitly labeled for SSL/TLS use",
    confidence=Confidence.HIGH,
)

# Private Key in Variable Assignment (contextual detection)
PRIVATE_KEY_ASSIGNMENT = Pattern(
    name="private_key_assignment",
    regex=r"(?i)(?:private[_-]?key|priv[_-]?key|key[_-]?private)['\"]?\s*[:=]\s*['\"]?-----BEGIN",
    severity=Severity.CRITICAL,
    category=PatternCategory.PRIVATE_KEYS,
    description="Private Key Assignment - private key assigned to a variable",
    confidence=Confidence.HIGH,
)

# Private Key File Path (potential leak of key location)
PRIVATE_KEY_PATH = Pattern(
    name="private_key_path",
    regex=r"(?i)(?:private[_-]?key|priv[_-]?key|key[_-]?file|id_rsa|id_dsa|id_ecdsa|id_ed25519)['\"]?\s*[:=]\s*['\"]?(?:/[\w./~-]+|~?/\.ssh/[\w.-]+)['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.PRIVATE_KEYS,
    description="Private Key File Path - file path pointing to a private key",
    confidence=Confidence.MEDIUM,
)

# AWS EC2 Key Pair (appears in console output or config)
AWS_EC2_KEY_PAIR = Pattern(
    name="aws_ec2_key_pair",
    regex=r"(?i)(?:key[_-]?pair|ec2[_-]?key)[_-]?name['\"]?\s*[:=]\s*['\"]?([\w-]{1,255})['\"]?",
    severity=Severity.LOW,
    category=PatternCategory.PRIVATE_KEYS,
    description="AWS EC2 Key Pair Name - name of EC2 SSH key pair",
    confidence=Confidence.LOW,
)


# Collect all patterns for easy import
PRIVATE_KEY_PATTERNS: list[Pattern] = [
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

__all__ = [
    "PRIVATE_KEY_PATTERNS",
    "RSA_PRIVATE_KEY",
    "OPENSSH_PRIVATE_KEY",
    "EC_PRIVATE_KEY",
    "DSA_PRIVATE_KEY",
    "PGP_PRIVATE_KEY",
    "PKCS8_PRIVATE_KEY",
    "PKCS8_ENCRYPTED_PRIVATE_KEY",
    "SSH_PRIVATE_KEY_GENERIC",
    "SSH2_PRIVATE_KEY",
    "PUTTY_PRIVATE_KEY",
    "X509_CERTIFICATE",
    "X509_CERTIFICATE_REQUEST",
    "SSL_PRIVATE_KEY",
    "PRIVATE_KEY_ASSIGNMENT",
    "PRIVATE_KEY_PATH",
    "AWS_EC2_KEY_PAIR",
]
