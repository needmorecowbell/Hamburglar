# Backward compatibility utilities for Hamburglar
#
# This module provides utilities for maintaining backward compatibility
# with the original hamburglar.py implementation, including:
# - Legacy regex patterns
# - IOC extraction integration
# - Migration helpers

from hamburglar.compat.legacy_patterns import (
    LEGACY_ONLY_PATTERNS,
    LEGACY_REGEX_LIST,
    get_legacy_pattern,
    get_legacy_pattern_names,
    legacy_patterns_to_detector_format,
)

from hamburglar.compat.ioc_extract import (
    IOCExtractDetector,
    IOCExtractFallbackDetector,
    IOCExtractNotAvailable,
    extract_all_iocs,
    extract_emails,
    extract_hashes,
    extract_iocs_legacy,
    extract_ips,
    extract_urls,
    extract_yara_rules,
    get_detector,
    get_import_error,
    is_available,
)

__all__ = [
    # Legacy patterns
    "LEGACY_ONLY_PATTERNS",
    "LEGACY_REGEX_LIST",
    "get_legacy_pattern",
    "get_legacy_pattern_names",
    "legacy_patterns_to_detector_format",
    # IOC extraction
    "IOCExtractDetector",
    "IOCExtractFallbackDetector",
    "IOCExtractNotAvailable",
    "extract_all_iocs",
    "extract_emails",
    "extract_hashes",
    "extract_iocs_legacy",
    "extract_ips",
    "extract_urls",
    "extract_yara_rules",
    "get_detector",
    "get_import_error",
    "is_available",
]
