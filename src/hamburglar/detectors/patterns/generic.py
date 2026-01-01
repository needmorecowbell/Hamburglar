"""Generic secret detection patterns.

This module contains patterns for detecting generic secrets, API keys, tokens,
passwords, encoded secrets, and common data formats that may contain sensitive
information. These patterns use broader matching strategies and are typically
lower confidence than service-specific patterns.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory


# =============================================================================
# Contact Information Patterns (from legacy hamburglar.py)
# =============================================================================

# Email Address Pattern
EMAIL_ADDRESS = Pattern(
    name="email_address",
    regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="Email Address - matches email addresses in text",
    confidence=Confidence.MEDIUM,
)

# US Phone Number Pattern
PHONE_NUMBER_US = Pattern(
    name="phone_number_us",
    regex=r"\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="Phone Number (US) - US format phone numbers",
    confidence=Confidence.MEDIUM,
)

# International Phone Number Pattern
PHONE_NUMBER_INTL = Pattern(
    name="phone_number_intl",
    regex=r"\+[1-9][0-9]{6,14}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="Phone Number (International) - E.164 format phone numbers",
    confidence=Confidence.MEDIUM,
)

# URL/Site Pattern (from legacy)
URL_HTTP = Pattern(
    name="url_http",
    regex=r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:[/?#][^\s]*)?",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="URL - HTTP/HTTPS URLs",
    confidence=Confidence.HIGH,
)

# Generic API Key Patterns
GENERIC_API_KEY = Pattern(
    name="generic_api_key",
    regex=r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic API Key - API key assignment pattern",
    confidence=Confidence.LOW,
)

GENERIC_API_KEY_INLINE = Pattern(
    name="generic_api_key_inline",
    regex=r"(?i)['\"]api[_-]?key['\"]\s*:\s*['\"]([a-zA-Z0-9_-]{20,})['\"]",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic API Key Inline - API key in JSON/config format",
    confidence=Confidence.LOW,
)


# Generic Secret Patterns
GENERIC_SECRET_KEY = Pattern(
    name="generic_secret_key",
    regex=r"(?i)secret[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_/+=.-]{16,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic Secret Key - secret key assignment pattern",
    confidence=Confidence.LOW,
)

GENERIC_SECRET = Pattern(
    name="generic_secret",
    regex=r"(?i)(?:app|application|api)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_/+=.-]{16,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic Secret - secret value assignment pattern",
    confidence=Confidence.LOW,
)


# Generic Token Patterns
GENERIC_TOKEN = Pattern(
    name="generic_token",
    regex=r"(?i)(?:auth|access|api)?[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic Token - token assignment pattern",
    confidence=Confidence.LOW,
)

GENERIC_TOKEN_BEARER = Pattern(
    name="generic_token_bearer",
    regex=r"(?i)bearer[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic Bearer Token - bearer token assignment pattern",
    confidence=Confidence.MEDIUM,
)


# Hardcoded Password Patterns
HARDCODED_PASSWORD = Pattern(
    name="hardcoded_password",
    regex=r"(?i)(?:admin|root|user|db|database|mysql|postgres|redis)[_-]?(?:password|passwd|pwd|pass)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Hardcoded Password - password with common prefixes",
    confidence=Confidence.MEDIUM,
)

HARDCODED_PASSWORD_QUOTED = Pattern(
    name="hardcoded_password_quoted",
    regex=r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9!@#$%^&*()_+=\-]{8,64})['\"]",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Hardcoded Password Quoted - password in quotes",
    confidence=Confidence.LOW,
)

DEFAULT_PASSWORD = Pattern(
    name="default_password",
    regex=r"(?i)(?:default|initial|temp|temporary)[_-]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Default Password - temporary or default password assignment",
    confidence=Confidence.MEDIUM,
)


# Base64 Encoded Secrets
BASE64_ENCODED_SECRET = Pattern(
    name="base64_encoded_secret",
    regex=r"(?i)(?:secret|key|token|password|credential|auth)[_-]?(?:base64|encoded)?['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Base64 Encoded Secret - potentially encoded secret value",
    confidence=Confidence.LOW,
)

BASE64_LONG_STRING = Pattern(
    name="base64_long_string",
    regex=r"(?i)(?:data|content|payload)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{64,}={0,2})['\"]?",
    severity=Severity.MEDIUM,
    category=PatternCategory.GENERIC,
    description="Base64 Long String - long base64 encoded data that may contain secrets",
    confidence=Confidence.LOW,
)


# Hex Encoded Secrets (32+ characters = 128+ bits)
HEX_ENCODED_SECRET = Pattern(
    name="hex_encoded_secret",
    regex=r"(?i)(?:secret|key|token|hash)[_-]?(?:hex)?['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Hex Encoded Secret - hexadecimal encoded secret value",
    confidence=Confidence.LOW,
)

HEX_STRING_64 = Pattern(
    name="hex_string_64",
    regex=r"(?i)(?:private|signing|encryption)[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{64})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Hex String 64 - 64-character hex string (256-bit key)",
    confidence=Confidence.MEDIUM,
)


# UUID Patterns
UUID_V4 = Pattern(
    name="uuid_v4",
    regex=r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="UUID v4 - random UUID that may be used as identifier or token",
    confidence=Confidence.LOW,
)

UUID_GENERIC = Pattern(
    name="uuid_generic",
    regex=r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="UUID Generic - any UUID format that may be used as identifier",
    confidence=Confidence.LOW,
)

UUID_WITH_CONTEXT = Pattern(
    name="uuid_with_context",
    regex=r"(?i)(?:api[_-]?key|secret|token|id)['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
    severity=Severity.MEDIUM,
    category=PatternCategory.GENERIC,
    description="UUID with Context - UUID in secret-like context",
    confidence=Confidence.MEDIUM,
)


# Hash Patterns
MD5_HASH = Pattern(
    name="md5_hash",
    regex=r"\b[0-9a-f]{32}\b",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="MD5 Hash - 32-character hexadecimal string (MD5 format)",
    confidence=Confidence.LOW,
)

SHA1_HASH = Pattern(
    name="sha1_hash",
    regex=r"\b[0-9a-f]{40}\b",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="SHA1 Hash - 40-character hexadecimal string (SHA1 format)",
    confidence=Confidence.LOW,
)

SHA256_HASH = Pattern(
    name="sha256_hash",
    regex=r"\b[0-9a-f]{64}\b",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="SHA256 Hash - 64-character hexadecimal string (SHA256 format)",
    confidence=Confidence.LOW,
)

SHA512_HASH = Pattern(
    name="sha512_hash",
    regex=r"\b[0-9a-f]{128}\b",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="SHA512 Hash - 128-character hexadecimal string (SHA512 format)",
    confidence=Confidence.LOW,
)

BCRYPT_HASH = Pattern(
    name="bcrypt_hash",
    regex=r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}",
    severity=Severity.MEDIUM,
    category=PatternCategory.GENERIC,
    description="Bcrypt Hash - bcrypt password hash format",
    confidence=Confidence.HIGH,
)

ARGON2_HASH = Pattern(
    name="argon2_hash",
    regex=r"\$argon2(?:id?|d)\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+",
    severity=Severity.MEDIUM,
    category=PatternCategory.GENERIC,
    description="Argon2 Hash - Argon2 password hash format",
    confidence=Confidence.HIGH,
)


# Private Key Content Patterns (without PEM headers)
PRIVATE_KEY_INLINE = Pattern(
    name="private_key_inline",
    regex=r"(?i)(?:private[_-]?key|priv[_-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{64,}={0,2})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Private Key Inline - private key content in assignment",
    confidence=Confidence.MEDIUM,
)


# Encryption Key Patterns
ENCRYPTION_KEY = Pattern(
    name="encryption_key",
    regex=r"(?i)(?:encryption|encrypt|aes|symmetric)[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Encryption Key - symmetric encryption key assignment",
    confidence=Confidence.MEDIUM,
)

SIGNING_KEY = Pattern(
    name="signing_key",
    regex=r"(?i)(?:signing|sign|signature)[_-]?(?:key|secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Signing Key - cryptographic signing key assignment",
    confidence=Confidence.MEDIUM,
)


# Master/Root Key Patterns
MASTER_KEY = Pattern(
    name="master_key",
    regex=r"(?i)master[_-]?(?:key|secret|password)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Master Key - master key or secret assignment",
    confidence=Confidence.MEDIUM,
)

ROOT_KEY = Pattern(
    name="root_key",
    regex=r"(?i)root[_-]?(?:key|secret|password|token)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.GENERIC,
    description="Root Key - root-level key or secret assignment",
    confidence=Confidence.MEDIUM,
)


# SSH/Auth Patterns
SSH_KEY_PASSPHRASE = Pattern(
    name="ssh_key_passphrase",
    regex=r"(?i)(?:ssh|key)[_-]?(?:passphrase|password)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="SSH Key Passphrase - passphrase for SSH key",
    confidence=Confidence.MEDIUM,
)


# High Entropy Generic Secret (requires at least one letter and number, 20+ chars)
HIGH_ENTROPY_STRING = Pattern(
    name="high_entropy_string",
    regex=r"(?i)(?:secret|key|token|credential|auth)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
    severity=Severity.MEDIUM,
    category=PatternCategory.GENERIC,
    description="High Entropy String - long alphanumeric string in secret context",
    confidence=Confidence.LOW,
)


# Collect all patterns for easy import
GENERIC_PATTERNS: list[Pattern] = [
    # Contact information patterns
    EMAIL_ADDRESS,
    PHONE_NUMBER_US,
    PHONE_NUMBER_INTL,
    URL_HTTP,
    # API Key patterns
    GENERIC_API_KEY,
    GENERIC_API_KEY_INLINE,
    # Secret patterns
    GENERIC_SECRET_KEY,
    GENERIC_SECRET,
    # Token patterns
    GENERIC_TOKEN,
    GENERIC_TOKEN_BEARER,
    # Password patterns
    HARDCODED_PASSWORD,
    HARDCODED_PASSWORD_QUOTED,
    DEFAULT_PASSWORD,
    # Base64 patterns
    BASE64_ENCODED_SECRET,
    BASE64_LONG_STRING,
    # Hex patterns
    HEX_ENCODED_SECRET,
    HEX_STRING_64,
    # UUID patterns
    UUID_V4,
    UUID_GENERIC,
    UUID_WITH_CONTEXT,
    # Hash patterns
    MD5_HASH,
    SHA1_HASH,
    SHA256_HASH,
    SHA512_HASH,
    BCRYPT_HASH,
    ARGON2_HASH,
    # Key patterns
    PRIVATE_KEY_INLINE,
    ENCRYPTION_KEY,
    SIGNING_KEY,
    MASTER_KEY,
    ROOT_KEY,
    SSH_KEY_PASSPHRASE,
    # Entropy pattern
    HIGH_ENTROPY_STRING,
]

__all__ = [
    "GENERIC_PATTERNS",
    # Contact information patterns
    "EMAIL_ADDRESS",
    "PHONE_NUMBER_US",
    "PHONE_NUMBER_INTL",
    "URL_HTTP",
    # API Key patterns
    "GENERIC_API_KEY",
    "GENERIC_API_KEY_INLINE",
    # Secret patterns
    "GENERIC_SECRET_KEY",
    "GENERIC_SECRET",
    # Token patterns
    "GENERIC_TOKEN",
    "GENERIC_TOKEN_BEARER",
    # Password patterns
    "HARDCODED_PASSWORD",
    "HARDCODED_PASSWORD_QUOTED",
    "DEFAULT_PASSWORD",
    # Base64 patterns
    "BASE64_ENCODED_SECRET",
    "BASE64_LONG_STRING",
    # Hex patterns
    "HEX_ENCODED_SECRET",
    "HEX_STRING_64",
    # UUID patterns
    "UUID_V4",
    "UUID_GENERIC",
    "UUID_WITH_CONTEXT",
    # Hash patterns
    "MD5_HASH",
    "SHA1_HASH",
    "SHA256_HASH",
    "SHA512_HASH",
    "BCRYPT_HASH",
    "ARGON2_HASH",
    # Key patterns
    "PRIVATE_KEY_INLINE",
    "ENCRYPTION_KEY",
    "SIGNING_KEY",
    "MASTER_KEY",
    "ROOT_KEY",
    "SSH_KEY_PASSPHRASE",
    # Entropy pattern
    "HIGH_ENTROPY_STRING",
]
