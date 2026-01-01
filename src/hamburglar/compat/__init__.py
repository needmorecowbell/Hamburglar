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

__all__ = [
    "LEGACY_ONLY_PATTERNS",
    "LEGACY_REGEX_LIST",
    "get_legacy_pattern",
    "get_legacy_pattern_names",
    "legacy_patterns_to_detector_format",
]
