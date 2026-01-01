"""Legacy regex patterns from original hamburglar.py.

This module provides backward compatibility by including ALL regex patterns
from the original hamburglar.py implementation. This ensures zero detection
regression when migrating from the legacy tool to the new implementation.

The patterns are organized into two groups:
1. LEGACY_ONLY_PATTERNS: Patterns unique to the original tool (not in new library)
2. LEGACY_REGEX_LIST: Complete original regexList dictionary for drop-in replacement

Usage:
    from hamburglar.compat.legacy_patterns import LEGACY_ONLY_PATTERNS
    from hamburglar.compat.legacy_patterns import LEGACY_REGEX_LIST

For migration purposes, you can also import individual patterns:
    from hamburglar.compat.legacy_patterns import EMAIL_PATTERN, PHONE_PATTERN
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# =============================================================================
# Legacy-only patterns (not present in new pattern library)
# These patterns existed in the original hamburglar.py but are not covered
# by the new modular pattern library, or use different matching styles.
# =============================================================================

# Email Pattern
EMAIL_PATTERN = Pattern(
    name="email",
    regex=r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="Email Address - matches email addresses in text",
    confidence=Confidence.MEDIUM,
)

# Phone Number Pattern (US format)
PHONE_PATTERN = Pattern(
    name="phone",
    regex=r"\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}",
    severity=Severity.LOW,
    category=PatternCategory.GENERIC,
    description="Phone Number - US format phone numbers",
    confidence=Confidence.MEDIUM,
)

# URL/Site Pattern
SITE_PATTERN = Pattern(
    name="site",
    regex=r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="URL/Site - HTTP/HTTPS URLs",
    confidence=Confidence.HIGH,
)

# Bitcoin URI Pattern
BITCOIN_URI_PATTERN = Pattern(
    name="bitcoin_uri",
    regex=r"bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin URI - bitcoin: protocol URI with address",
    confidence=Confidence.HIGH,
)

# Bitcoin Extended Public Key (xpub)
BITCOIN_XPUB_KEY_PATTERN = Pattern(
    name="bitcoin_xpub_key",
    regex=r"(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\?c=\d*&h=bip\d{2,3})?",
    severity=Severity.HIGH,
    category=PatternCategory.CRYPTO,
    description="Bitcoin xpub Key - Extended public key for HD wallets",
    confidence=Confidence.HIGH,
)

# Bitcoin Cash Address
BITCOIN_CASH_ADDRESS_PATTERN = Pattern(
    name="bitcoin_cash_address",
    regex=r"(?:^[13][a-km-zA-HJ-NP-Z1-9]{33})",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Bitcoin Cash Address - BCH legacy address format",
    confidence=Confidence.MEDIUM,
)

# Dash Cryptocurrency Address
DASH_ADDRESS_PATTERN = Pattern(
    name="dash_address",
    regex=r"(?:^X[1-9A-HJ-NP-Za-km-z]{33})",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="Dash Address - Dash cryptocurrency address starting with X",
    confidence=Confidence.HIGH,
)

# NEO Cryptocurrency Address
NEO_ADDRESS_PATTERN = Pattern(
    name="neo_address",
    regex=r"(?:^A[0-9a-zA-Z]{33})",
    severity=Severity.MEDIUM,
    category=PatternCategory.CRYPTO,
    description="NEO Address - NEO blockchain address starting with A",
    confidence=Confidence.MEDIUM,
)

# Facebook OAuth Token
FACEBOOK_OAUTH_PATTERN = Pattern(
    name="facebook_oauth",
    regex=r"[fF][aA][cC][eE][bB][oO][oO][kK].*['\"][0-9a-f]{32}['\"]",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Facebook OAuth - Facebook OAuth token or secret",
    confidence=Confidence.HIGH,
)

# Twitter OAuth Token
TWITTER_OAUTH_PATTERN = Pattern(
    name="twitter_oauth",
    regex=r"[tT][wW][iI][tT][tT][eE][rR].*['\"][0-9a-zA-Z]{35,44}['\"]",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Twitter OAuth - Twitter OAuth token or secret",
    confidence=Confidence.HIGH,
)

# Generic Secret (legacy style with case-insensitive character class)
GENERIC_SECRET_LEGACY_PATTERN = Pattern(
    name="generic_secret_legacy",
    regex=r"[sS][eE][cC][rR][eE][tT].*['\"][0-9a-zA-Z]{32,45}['\"]",
    severity=Severity.HIGH,
    category=PatternCategory.GENERIC,
    description="Generic Secret (Legacy) - Secret values in original format",
    confidence=Confidence.MEDIUM,
)

# GitHub Token (legacy style)
GITHUB_LEGACY_PATTERN = Pattern(
    name="github_legacy",
    regex=r"[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub Token (Legacy) - GitHub token in original format",
    confidence=Confidence.MEDIUM,
)

# Heroku API Key (legacy style with case-insensitive)
HEROKU_API_KEY_LEGACY_PATTERN = Pattern(
    name="heroku_api_key_legacy",
    regex=r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Heroku API Key (Legacy) - Heroku API key in original format",
    confidence=Confidence.HIGH,
)


# =============================================================================
# Collection of legacy-only patterns
# =============================================================================

LEGACY_ONLY_PATTERNS: list[Pattern] = [
    EMAIL_PATTERN,
    PHONE_PATTERN,
    SITE_PATTERN,
    BITCOIN_URI_PATTERN,
    BITCOIN_XPUB_KEY_PATTERN,
    BITCOIN_CASH_ADDRESS_PATTERN,
    DASH_ADDRESS_PATTERN,
    NEO_ADDRESS_PATTERN,
    FACEBOOK_OAUTH_PATTERN,
    TWITTER_OAUTH_PATTERN,
    GENERIC_SECRET_LEGACY_PATTERN,
    GITHUB_LEGACY_PATTERN,
    HEROKU_API_KEY_LEGACY_PATTERN,
]


# =============================================================================
# Original regexList dictionary (exact patterns from hamburglar.py)
# This can be used as a drop-in replacement for the original regexList
# =============================================================================

LEGACY_REGEX_LIST: dict[str, str] = {
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    # "bitcoin-address" : "[13][a-km-zA-HJ-NP-Z1-9]{25,34}" ,  # commented out in original
    "bitcoin-cash-address": r"(?:^[13][a-km-zA-HJ-NP-Z1-9]{33})",
    "bitcoin-uri": r"bitcoin:([13][a-km-zA-HJ-NP-Z1-9]{25,34})",
    "bitcoin-xpub-key": r"(xpub[a-km-zA-HJ-NP-Z1-9]{100,108})(\?c=\d*&h=bip\d{2,3})?",
    "dash-address": r"(?:^X[1-9A-HJ-NP-Za-km-z]{33})",
    "dogecoin-address": r"(?:^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32})",
    "email": r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+",
    "ethereum-address": r"(?:^0x[a-fA-F0-9]{40})",
    "Facebook Oauth": r"[fF][aA][cC][eE][bB][oO][oO][kK].*['\"][0-9a-f]{32}['\"]",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT].*['\"][0-9a-zA-Z]{32,45}['\"]",
    "GitHub": r"[gG][iI][tT][hH][uU][bB].*['\"][0-9a-zA-Z]{35,40}['\"]",
    "Google Oauth": r'("client_secret":"[a-zA-Z0-9-_]{24}")',
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "ipv4": r"[0-9]+(?:\.[0-9]+){3}",
    "litecoin-address": r"(?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})",
    "monero-address": r"(?:^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})",
    "neo-address": r"(?:^A[0-9a-zA-Z]{33})",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "phone": r"\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}",
    "ripple-address": r"(?:^r[0-9a-zA-Z]{33})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "site": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+",
    "Slack Token": r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH (OPENSSH) private key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Twitter Oauth": r"[tT][wW][iI][tT][tT][eE][rR].*['\"][0-9a-zA-Z]{35,44}['\"]",
}


def get_legacy_pattern_names() -> list[str]:
    """Get a list of all legacy pattern names.

    Returns:
        List of pattern names from the original regexList.
    """
    return list(LEGACY_REGEX_LIST.keys())


def get_legacy_pattern(name: str) -> str | None:
    """Get a legacy regex pattern by name.

    Args:
        name: The pattern name from the original regexList.

    Returns:
        The regex pattern string, or None if not found.
    """
    return LEGACY_REGEX_LIST.get(name)


def legacy_patterns_to_detector_format() -> dict[str, dict]:
    """Convert legacy patterns to the format expected by RegexDetector.

    Returns:
        Dictionary mapping pattern names to detector-compatible dictionaries.
    """
    result = {}
    for name, regex in LEGACY_REGEX_LIST.items():
        # Determine severity based on pattern type
        if "private key" in name.lower() or "oauth" in name.lower():
            severity = Severity.CRITICAL
        elif "key" in name.lower() or "token" in name.lower():
            severity = Severity.HIGH
        elif "address" in name.lower():
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        result[name] = {
            "pattern": regex,
            "severity": severity,
            "description": f"Legacy pattern: {name}",
        }
    return result


__all__ = [
    # Pattern collections
    "LEGACY_ONLY_PATTERNS",
    "LEGACY_REGEX_LIST",
    # Individual legacy-only patterns
    "EMAIL_PATTERN",
    "PHONE_PATTERN",
    "SITE_PATTERN",
    "BITCOIN_URI_PATTERN",
    "BITCOIN_XPUB_KEY_PATTERN",
    "BITCOIN_CASH_ADDRESS_PATTERN",
    "DASH_ADDRESS_PATTERN",
    "NEO_ADDRESS_PATTERN",
    "FACEBOOK_OAUTH_PATTERN",
    "TWITTER_OAUTH_PATTERN",
    "GENERIC_SECRET_LEGACY_PATTERN",
    "GITHUB_LEGACY_PATTERN",
    "HEROKU_API_KEY_LEGACY_PATTERN",
    # Utility functions
    "get_legacy_pattern_names",
    "get_legacy_pattern",
    "legacy_patterns_to_detector_format",
]
