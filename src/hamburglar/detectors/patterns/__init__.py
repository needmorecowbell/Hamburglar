"""Pattern definitions for the regex detector.

This module provides the core data structures for organizing and defining
detection patterns used to identify sensitive information such as API keys,
credentials, private keys, and other secrets.
"""

from dataclasses import dataclass, field
from enum import Enum

from hamburglar.core.models import Severity


class PatternCategory(str, Enum):
    """Categories for organizing detection patterns."""

    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    CRYPTO = "crypto"
    NETWORK = "network"
    PRIVATE_KEYS = "private_keys"
    CLOUD = "cloud"
    GENERIC = "generic"


class Confidence(str, Enum):
    """Confidence levels for pattern matches.

    Higher confidence patterns are more likely to be true positives,
    while lower confidence patterns may require manual review.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Pattern:
    """A detection pattern for identifying sensitive information.

    Attributes:
        name: Unique identifier for the pattern.
        regex: Regular expression pattern string.
        severity: Severity level for findings from this pattern.
        category: Category this pattern belongs to.
        description: Human-readable description of what the pattern detects.
        confidence: Confidence level of matches (high, medium, low).
    """

    name: str
    regex: str
    severity: Severity
    category: PatternCategory
    description: str = ""
    confidence: Confidence = Confidence.MEDIUM

    def to_dict(self) -> dict:
        """Convert the pattern to a dictionary format compatible with RegexDetector.

        Returns:
            Dictionary with 'pattern', 'severity', 'description', and metadata fields.
        """
        return {
            "pattern": self.regex,
            "severity": self.severity,
            "description": self.description,
            "category": self.category.value,
            "confidence": self.confidence.value,
        }


# Re-export Severity for convenience
__all__ = ["PatternCategory", "Confidence", "Pattern", "Severity"]
