"""Entropy-based detector for sensitive information.

This module provides a detector that uses Shannon entropy to identify
high-entropy strings that may be secrets, passwords, or encryption keys.
"""

from __future__ import annotations

import math
import re
import time
from typing import Any

from hamburglar.core.logging import get_logger
from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector

# Default entropy thresholds
DEFAULT_ENTROPY_THRESHOLD = 4.5  # Shannon entropy threshold for secrets
HIGH_ENTROPY_THRESHOLD = 5.0  # Threshold for high-confidence secrets
MIN_STRING_LENGTH = 16  # Minimum string length to consider
MAX_STRING_LENGTH = 256  # Maximum string length to consider
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Character classes for entropy calculation
HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
ALPHANUMERIC_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# Patterns to extract potential secrets from content
# These patterns match strings that might be secrets in various contexts
STRING_PATTERNS = [
    # Quoted strings (single or double quotes)
    re.compile(r"""["']([A-Za-z0-9+/=_\-]{16,256})["']"""),
    # Assignments with equals sign
    re.compile(r"""=\s*["']?([A-Za-z0-9+/=_\-]{16,256})["']?"""),
    # Hex strings (often encryption keys)
    re.compile(r"\b([0-9a-fA-F]{32,128})\b"),
    # Base64 strings (common secret encoding)
    re.compile(r"\b([A-Za-z0-9+/]{32,256}={0,2})\b"),
]

# Known false positive patterns to exclude
FALSE_POSITIVE_PATTERNS = [
    # UUID patterns (version 4 and generic)
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
    # Hashes in comments or documentation
    re.compile(r"^[0-9a-fA-F]{32}$"),  # MD5 is too common for false positives
    # Version strings that look like hex
    re.compile(r"^v?\d+\.\d+\.\d+"),
    # File paths with long names
    re.compile(r"^[/\\]"),
    # Import/require statements
    re.compile(r"^(import|require|from)\s"),
    # Common hash algorithm names
    re.compile(r"^(SHA256|SHA512|MD5|RIPEMD|BLAKE2)", re.IGNORECASE),
    # Lorem ipsum text
    re.compile(r"(lorem|ipsum|dolor|sit|amet)", re.IGNORECASE),
    # Git commit SHAs in comments
    re.compile(r"^commit\s+[0-9a-fA-F]{40}$", re.IGNORECASE),
    # Common test/example values
    re.compile(r"^(test|example|sample|placeholder|dummy)", re.IGNORECASE),
    # Padding strings
    re.compile(r"^([A-Za-z])\1{15,}$"),  # Repeated single character
    # Sequential patterns
    re.compile(r"^(0123456789|abcdefghij)", re.IGNORECASE),
]

# Context patterns that indicate a string might be a secret
SECRET_CONTEXT_PATTERNS = [
    re.compile(r"(password|passwd|pwd|secret|token|key|apikey|api_key)", re.IGNORECASE),
    re.compile(r"(credential|auth|bearer|private)", re.IGNORECASE),
    re.compile(r"(encrypt|decrypt|sign|hmac|hash)", re.IGNORECASE),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Shannon entropy measures the unpredictability of a string. Higher values
    indicate more randomness, which is characteristic of secrets.

    Args:
        data: The string to calculate entropy for.

    Returns:
        The Shannon entropy value (bits per character).
    """
    if not data:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def is_base64_encoded(data: str) -> bool:
    """Check if a string appears to be base64 encoded.

    Args:
        data: The string to check.

    Returns:
        True if the string appears to be base64 encoded.
    """
    if len(data) < 16:
        return False

    # Check if all characters are valid base64
    if not all(c in BASE64_CHARS for c in data):
        return False

    # Check for proper padding
    padding_count = data.count("=")
    if padding_count > 2:
        return False

    # Check length is appropriate for base64
    if len(data) % 4 != 0:
        return False

    return True


def is_hex_encoded(data: str) -> bool:
    """Check if a string appears to be hex encoded.

    Args:
        data: The string to check.

    Returns:
        True if the string appears to be hex encoded.
    """
    if len(data) < 16:
        return False

    # Check if all characters are valid hex
    if not all(c in HEX_CHARS for c in data):
        return False

    # Hex strings should be even length
    if len(data) % 2 != 0:
        return False

    return True


def is_known_false_positive(data: str, context: str = "") -> bool:
    """Check if a string matches known false positive patterns.

    Args:
        data: The string to check.
        context: Surrounding context for additional checks.

    Returns:
        True if the string is likely a false positive.
    """
    # Check against known false positive patterns
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.match(data):
            return True

    # Check for common word-based strings (low entropy despite appearance)
    if data.isalpha() and data.lower() in _COMMON_WORDS:
        return True

    return False


def has_secret_context(context: str) -> bool:
    """Check if the surrounding context suggests a secret.

    Args:
        context: The surrounding text to check.

    Returns:
        True if the context suggests this might be a secret.
    """
    for pattern in SECRET_CONTEXT_PATTERNS:
        if pattern.search(context):
            return True
    return False


# Common words to exclude (subset of most common)
_COMMON_WORDS = frozenset(
    [
        "function",
        "return",
        "import",
        "export",
        "const",
        "class",
        "interface",
        "namespace",
        "module",
        "package",
        "string",
        "number",
        "boolean",
        "undefined",
        "null",
        "true",
        "false",
        "public",
        "private",
        "protected",
        "static",
        "readonly",
        "abstract",
        "extends",
        "implements",
        "constructor",
        "abcdefghijklmnop",
        "qrstuvwxyzabcdef",  # Common test patterns
    ]
)


class EntropyDetector(BaseDetector):
    """Detector that uses Shannon entropy to identify high-entropy secrets.

    The EntropyDetector scans content for strings with high entropy (randomness),
    which is characteristic of secrets like API keys, passwords, and encryption keys.

    Features:
    - Configurable entropy thresholds
    - Base64 and hex encoding detection
    - False positive exclusion (UUIDs, hashes in comments)
    - Context-aware detection for increased confidence

    Example:
        detector = EntropyDetector()
        findings = detector.detect(file_content, "path/to/file.py")

        # With custom threshold:
        detector = EntropyDetector(entropy_threshold=5.0)

        # With context-aware detection:
        detector = EntropyDetector(require_context=True)
    """

    def __init__(
        self,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        high_entropy_threshold: float = HIGH_ENTROPY_THRESHOLD,
        min_string_length: int = MIN_STRING_LENGTH,
        max_string_length: int = MAX_STRING_LENGTH,
        require_context: bool = False,
        exclude_base64: bool = False,
        exclude_hex: bool = False,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ) -> None:
        """Initialize the EntropyDetector.

        Args:
            entropy_threshold: Minimum entropy to consider a string as potentially
                             secret (default 4.5).
            high_entropy_threshold: Entropy threshold for high-confidence findings
                                  (default 5.0).
            min_string_length: Minimum string length to analyze (default 16).
            max_string_length: Maximum string length to analyze (default 256).
            require_context: If True, only report findings that have secret-related
                           context (e.g., "password=", "api_key:").
            exclude_base64: If True, exclude strings that appear to be base64.
            exclude_hex: If True, exclude strings that appear to be hex.
            max_file_size: Maximum file size in bytes to process (default 10MB).
        """
        self._entropy_threshold = entropy_threshold
        self._high_entropy_threshold = high_entropy_threshold
        self._min_string_length = min_string_length
        self._max_string_length = max_string_length
        self._require_context = require_context
        self._exclude_base64 = exclude_base64
        self._exclude_hex = exclude_hex
        self._max_file_size = max_file_size
        self._logger = get_logger()

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "entropy"

    @property
    def entropy_threshold(self) -> float:
        """Return the entropy threshold."""
        return self._entropy_threshold

    @property
    def high_entropy_threshold(self) -> float:
        """Return the high entropy threshold."""
        return self._high_entropy_threshold

    @property
    def min_string_length(self) -> int:
        """Return the minimum string length."""
        return self._min_string_length

    @property
    def max_string_length(self) -> int:
        """Return the maximum string length."""
        return self._max_string_length

    @property
    def max_file_size(self) -> int:
        """Return the maximum file size in bytes."""
        return self._max_file_size

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect high-entropy strings in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected high-entropy string.
        """
        start_time = time.perf_counter()

        # Check file size before processing
        content_size = len(content.encode("utf-8", errors="replace"))
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return []

        findings: list[Finding] = []
        seen_matches: set[str] = set()

        # Extract and analyze potential secrets
        for pattern in STRING_PATTERNS:
            for match in pattern.finditer(content):
                candidate = match.group(1) if match.lastindex else match.group(0)

                # Skip if already seen
                if candidate in seen_matches:
                    continue
                seen_matches.add(candidate)

                # Skip if outside length bounds
                if not (self._min_string_length <= len(candidate) <= self._max_string_length):
                    continue

                # Skip known false positives
                context = self._get_context(content, match.start(), match.end())
                if is_known_false_positive(candidate, context):
                    continue

                # Check encoding types if exclusions are enabled
                is_base64 = is_base64_encoded(candidate)
                is_hex = is_hex_encoded(candidate)

                if self._exclude_base64 and is_base64:
                    continue
                if self._exclude_hex and is_hex:
                    continue

                # Calculate entropy
                entropy = calculate_shannon_entropy(candidate)

                # Skip if below threshold
                if entropy < self._entropy_threshold:
                    continue

                # Check context requirement
                has_context = has_secret_context(context)
                if self._require_context and not has_context:
                    continue

                # Determine severity based on entropy and context
                severity = self._determine_severity(entropy, has_context, is_base64, is_hex)

                # Create finding
                finding = Finding(
                    file_path=file_path,
                    detector_name=f"entropy:{self._get_finding_type(is_base64, is_hex)}",
                    matches=[candidate],
                    severity=severity,
                    metadata=self._build_metadata(
                        candidate, entropy, is_base64, is_hex, has_context, context
                    ),
                )
                findings.append(finding)

        # Log performance metrics
        elapsed = time.perf_counter() - start_time
        self._logger.debug(
            "EntropyDetector processed %s in %.3fs: %d findings",
            file_path,
            elapsed,
            len(findings),
        )

        return findings

    def _get_context(self, content: str, start: int, end: int, window: int = 50) -> str:
        """Get surrounding context for a match.

        Args:
            content: The full content.
            start: Start position of the match.
            end: End position of the match.
            window: Number of characters before and after to include.

        Returns:
            The surrounding context string.
        """
        context_start = max(0, start - window)
        context_end = min(len(content), end + window)
        return content[context_start:context_end]

    def _determine_severity(
        self, entropy: float, has_context: bool, is_base64: bool, is_hex: bool
    ) -> Severity:
        """Determine the severity level based on entropy and context.

        Args:
            entropy: The Shannon entropy value.
            has_context: Whether secret-related context was found.
            is_base64: Whether the string is base64 encoded.
            is_hex: Whether the string is hex encoded.

        Returns:
            The appropriate Severity level.
        """
        # High entropy with context is most suspicious
        if entropy >= self._high_entropy_threshold and has_context:
            return Severity.HIGH

        # High entropy encoding types are suspicious
        if entropy >= self._high_entropy_threshold and (is_base64 or is_hex):
            return Severity.HIGH

        # High entropy without context
        if entropy >= self._high_entropy_threshold:
            return Severity.MEDIUM

        # Medium entropy with context
        if has_context:
            return Severity.MEDIUM

        # Default for threshold-meeting strings
        return Severity.LOW

    def _get_finding_type(self, is_base64: bool, is_hex: bool) -> str:
        """Get the finding type based on encoding.

        Args:
            is_base64: Whether the string is base64 encoded.
            is_hex: Whether the string is hex encoded.

        Returns:
            String describing the finding type.
        """
        if is_base64:
            return "base64"
        if is_hex:
            return "hex"
        return "generic"

    def _build_metadata(
        self,
        candidate: str,
        entropy: float,
        is_base64: bool,
        is_hex: bool,
        has_context: bool,
        context: str,
    ) -> dict[str, Any]:
        """Build metadata for a finding.

        Args:
            candidate: The matched string.
            entropy: The Shannon entropy value.
            is_base64: Whether the string is base64 encoded.
            is_hex: Whether the string is hex encoded.
            has_context: Whether secret-related context was found.
            context: The surrounding context.

        Returns:
            Dictionary of metadata.
        """
        return {
            "entropy": round(entropy, 3),
            "length": len(candidate),
            "is_base64": is_base64,
            "is_hex": is_hex,
            "has_secret_context": has_context,
            "context_snippet": context[:100] if len(context) > 100 else context,
            "encoding_type": self._get_finding_type(is_base64, is_hex),
        }

    def analyze_string(self, data: str) -> dict[str, Any]:
        """Analyze a single string for entropy characteristics.

        This is a utility method for testing and debugging.

        Args:
            data: The string to analyze.

        Returns:
            Dictionary with analysis results.
        """
        entropy = calculate_shannon_entropy(data)
        return {
            "string": data,
            "length": len(data),
            "entropy": round(entropy, 3),
            "is_base64": is_base64_encoded(data),
            "is_hex": is_hex_encoded(data),
            "is_false_positive": is_known_false_positive(data),
            "exceeds_threshold": entropy >= self._entropy_threshold,
            "exceeds_high_threshold": entropy >= self._high_entropy_threshold,
        }
