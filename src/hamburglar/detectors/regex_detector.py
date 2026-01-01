"""Regex-based detector for sensitive information.

This module provides a detector that uses regular expressions to identify
sensitive data patterns such as API keys, credentials, and other secrets.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hamburglar.core.logging import get_logger
from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# Import all pattern modules
from hamburglar.detectors.patterns.api_keys import API_KEY_PATTERNS
from hamburglar.detectors.patterns.cloud import CLOUD_PATTERNS
from hamburglar.detectors.patterns.credentials import CREDENTIAL_PATTERNS
from hamburglar.detectors.patterns.crypto import CRYPTO_PATTERNS
from hamburglar.detectors.patterns.generic import GENERIC_PATTERNS
from hamburglar.detectors.patterns.network import NETWORK_PATTERNS
from hamburglar.detectors.patterns.private_keys import PRIVATE_KEY_PATTERNS

# Default maximum file size in bytes (10MB)
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024

# Default regex timeout in seconds
DEFAULT_REGEX_TIMEOUT = 5.0

# Bytes that indicate binary content - null bytes and control characters
# except common text control chars (tab, newline, carriage return)
BINARY_INDICATOR_BYTES = bytes(range(0, 9)) + bytes(range(14, 32))

# Threshold of binary bytes to consider file binary (as fraction of sample)
BINARY_THRESHOLD = 0.1

# All patterns organized by category
ALL_PATTERN_CATEGORIES: dict[PatternCategory, list[Pattern]] = {
    PatternCategory.API_KEYS: API_KEY_PATTERNS,
    PatternCategory.CLOUD: CLOUD_PATTERNS,
    PatternCategory.CREDENTIALS: CREDENTIAL_PATTERNS,
    PatternCategory.CRYPTO: CRYPTO_PATTERNS,
    PatternCategory.GENERIC: GENERIC_PATTERNS,
    PatternCategory.NETWORK: NETWORK_PATTERNS,
    PatternCategory.PRIVATE_KEYS: PRIVATE_KEY_PATTERNS,
}

# Convenience function to get all patterns
def get_all_patterns() -> list[Pattern]:
    """Get all patterns from all categories."""
    all_patterns: list[Pattern] = []
    for patterns in ALL_PATTERN_CATEGORIES.values():
        all_patterns.extend(patterns)
    return all_patterns


def get_patterns_by_category(category: PatternCategory) -> list[Pattern]:
    """Get patterns for a specific category."""
    return ALL_PATTERN_CATEGORIES.get(category, [])

# Default patterns with severity levels - Top 20 critical patterns
DEFAULT_PATTERNS: dict[str, dict[str, Any]] = {
    # AWS Credentials - CRITICAL
    "AWS API Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key ID",
    },
    "AWS Secret Key": {
        "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": Severity.CRITICAL,
        "description": "AWS Secret Access Key",
    },
    # GitHub Tokens - CRITICAL
    "GitHub Token": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}",
        "severity": Severity.CRITICAL,
        "description": "GitHub Personal Access Token or OAuth Token",
    },
    "GitHub Legacy Token": {
        "pattern": r"[g|G][i|I][t|T][h|H][u|U][b|B].*['\"][0-9a-zA-Z]{35,40}['\"]",
        "severity": Severity.HIGH,
        "description": "GitHub Legacy Token Pattern",
    },
    # Private Keys - CRITICAL
    "RSA Private Key": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "RSA Private Key Header",
    },
    "SSH (DSA) Private Key": {
        "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "DSA Private Key Header",
    },
    "SSH (EC) Private Key": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "EC Private Key Header",
    },
    "SSH (OPENSSH) Private Key": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "OpenSSH Private Key Header",
    },
    "PGP Private Key Block": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": Severity.CRITICAL,
        "description": "PGP Private Key Block Header",
    },
    # API Keys - HIGH
    "Generic API Key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,64}['\"]",
        "severity": Severity.HIGH,
        "description": "Generic API Key Pattern",
    },
    "Slack Token": {
        "pattern": r"xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
        "severity": Severity.CRITICAL,
        "description": "Slack OAuth Token",
    },
    "Slack Webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "severity": Severity.HIGH,
        "description": "Slack Webhook URL",
    },
    "Google OAuth": {
        "pattern": r'"client_secret":"[a-zA-Z0-9-_]{24}"',
        "severity": Severity.HIGH,
        "description": "Google OAuth Client Secret",
    },
    "Generic Secret": {
        "pattern": r"(?i)[s][e][c][r][e][t].*['\"][0-9a-zA-Z]{32,45}['\"]",
        "severity": Severity.HIGH,
        "description": "Generic Secret Pattern",
    },
    # Contact Info - MEDIUM
    "Email Address": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": Severity.MEDIUM,
        "description": "Email Address",
    },
    # Network - LOW/INFO
    "IPv4 Address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "severity": Severity.LOW,
        "description": "IPv4 Address",
    },
    "URL": {
        "pattern": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.?=&#%]*",
        "severity": Severity.INFO,
        "description": "HTTP/HTTPS URL",
    },
    # Cryptocurrency - HIGH
    "Bitcoin Address": {
        "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "severity": Severity.HIGH,
        "description": "Bitcoin Address",
    },
    "Ethereum Address": {
        "pattern": r"\b0x[a-fA-F0-9]{40}\b",
        "severity": Severity.HIGH,
        "description": "Ethereum Address",
    },
    # Other Services - HIGH
    "Heroku API Key": {
        "pattern": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "severity": Severity.HIGH,
        "description": "Heroku API Key",
    },
}


def load_patterns_from_file(file_path: str | Path) -> list[Pattern]:
    """Load patterns from a JSON or YAML file.

    Args:
        file_path: Path to the pattern file (JSON or YAML).

    Returns:
        List of Pattern objects loaded from the file.

    Raises:
        ValueError: If the file format is unsupported or pattern data is invalid.
        FileNotFoundError: If the file does not exist.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Pattern file not found: {file_path}")

    suffix = path.suffix.lower()

    if suffix == ".json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml

            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except ImportError as e:
            raise ValueError(
                "PyYAML is required to load YAML pattern files. "
                "Install it with: pip install pyyaml"
            ) from e
    else:
        raise ValueError(f"Unsupported pattern file format: {suffix}. Use .json or .yaml/.yml")

    if not isinstance(data, dict) or "patterns" not in data:
        raise ValueError("Pattern file must contain a 'patterns' key with a list of patterns")

    patterns: list[Pattern] = []
    for pattern_data in data["patterns"]:
        try:
            # Map string values to enums
            severity_str = pattern_data.get("severity", "MEDIUM").upper()
            severity = Severity[severity_str] if hasattr(Severity, severity_str) else Severity.MEDIUM

            category_str = pattern_data.get("category", "GENERIC").upper()
            category = (
                PatternCategory[category_str]
                if hasattr(PatternCategory, category_str)
                else PatternCategory.GENERIC
            )

            confidence_str = pattern_data.get("confidence", "MEDIUM").upper()
            confidence = (
                Confidence[confidence_str]
                if hasattr(Confidence, confidence_str)
                else Confidence.MEDIUM
            )

            pattern = Pattern(
                name=pattern_data["name"],
                regex=pattern_data["regex"],
                severity=severity,
                category=category,
                description=pattern_data.get("description", ""),
                confidence=confidence,
            )
            patterns.append(pattern)
        except KeyError as e:
            raise ValueError(f"Pattern missing required field: {e}") from e

    return patterns


class RegexDetector(BaseDetector):
    """Detector that uses regular expressions to find sensitive information.

    The RegexDetector can be initialized with a custom set of patterns or use
    the default set of common sensitive data patterns. Each pattern has an
    associated severity level, description, category, and confidence level.

    Example:
        detector = RegexDetector()
        findings = detector.detect(file_content, "path/to/file.py")

        # With expanded pattern library (all categories):
        detector = RegexDetector(use_expanded_patterns=True)

        # Enable only specific categories:
        detector = RegexDetector(
            use_expanded_patterns=True,
            enabled_categories=[PatternCategory.API_KEYS, PatternCategory.PRIVATE_KEYS]
        )

        # Filter by minimum confidence:
        detector = RegexDetector(
            use_expanded_patterns=True,
            min_confidence=Confidence.HIGH
        )

        # Load custom patterns from file:
        detector = RegexDetector(custom_pattern_files=["my_patterns.json"])

        # Or with custom patterns dictionary:
        custom_patterns = {
            "Custom Pattern": {
                "pattern": r"CUSTOM-[0-9]{8}",
                "severity": Severity.HIGH,
                "description": "Custom pattern description",
            }
        }
        detector = RegexDetector(patterns=custom_patterns)
    """

    def __init__(
        self,
        patterns: dict[str, dict[str, Any]] | None = None,
        use_defaults: bool = True,
        use_expanded_patterns: bool = False,
        enabled_categories: list[PatternCategory] | None = None,
        disabled_categories: list[PatternCategory] | None = None,
        min_confidence: Confidence | None = None,
        custom_pattern_files: list[str | Path] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        regex_timeout: float = DEFAULT_REGEX_TIMEOUT,
    ) -> None:
        """Initialize the RegexDetector.

        Args:
            patterns: Optional dictionary of custom patterns to use.
                     Each pattern should have 'pattern', 'severity', and 'description' keys.
            use_defaults: If True and patterns is provided, merge with default patterns.
                         If False and patterns is provided, use only custom patterns.
                         If patterns is None, always use default patterns.
            use_expanded_patterns: If True, use the expanded pattern library from all
                         pattern modules (api_keys, cloud, credentials, crypto, etc.).
                         This provides comprehensive secret detection.
            enabled_categories: If provided, only use patterns from these categories.
                         Ignored if use_expanded_patterns is False.
            disabled_categories: If provided, exclude patterns from these categories.
                         Ignored if use_expanded_patterns is False.
            min_confidence: If provided, only use patterns with this confidence level
                         or higher (HIGH > MEDIUM > LOW).
            custom_pattern_files: List of paths to custom pattern files (JSON or YAML).
                         Patterns from these files are added to the pattern set.
            max_file_size: Maximum file size in bytes to process (default 10MB).
                          Files larger than this will be skipped with a warning.
            regex_timeout: Timeout in seconds for regex operations (default 5.0s).
                          Used to prevent catastrophic backtracking on pathological input.
        """
        self._max_file_size = max_file_size
        self._regex_timeout = regex_timeout
        self._logger = get_logger()
        self._min_confidence = min_confidence
        self._enabled_categories = enabled_categories
        self._disabled_categories = disabled_categories

        # Build the pattern dictionary
        self._patterns: dict[str, dict[str, Any]] = {}

        if use_expanded_patterns:
            # Use the expanded pattern library
            expanded_patterns = self._build_expanded_patterns(
                enabled_categories, disabled_categories, min_confidence
            )
            self._patterns.update(expanded_patterns)
        elif patterns is None:
            self._patterns = DEFAULT_PATTERNS.copy()
        elif use_defaults:
            self._patterns = DEFAULT_PATTERNS.copy()
            self._patterns.update(patterns)
        else:
            self._patterns = patterns.copy()

        # If use_expanded_patterns and patterns provided, merge them
        if use_expanded_patterns and patterns:
            self._patterns.update(patterns)

        # Load patterns from custom files
        if custom_pattern_files:
            for file_path in custom_pattern_files:
                try:
                    file_patterns = load_patterns_from_file(file_path)
                    for pattern in file_patterns:
                        # Apply confidence filter if set
                        if self._should_include_pattern(pattern):
                            self._patterns[pattern.name] = pattern.to_dict()
                except Exception as e:
                    self._logger.warning(
                        "Failed to load pattern file %s: %s", file_path, str(e)
                    )

        # Pre-compile all regex patterns for performance
        self._compiled_patterns: dict[
            str, tuple[re.Pattern[str], Severity, str, str, str]
        ] = {}
        for name, config in self._patterns.items():
            try:
                compiled = re.compile(config["pattern"])
                self._compiled_patterns[name] = (
                    compiled,
                    config.get("severity", Severity.MEDIUM),
                    config.get("description", ""),
                    config.get("category", ""),
                    config.get("confidence", "medium"),
                )
            except re.error as e:
                # Skip invalid patterns but log the issue
                warnings.warn(f"Invalid regex pattern '{name}': {e}", stacklevel=2)

    def _build_expanded_patterns(
        self,
        enabled_categories: list[PatternCategory] | None,
        disabled_categories: list[PatternCategory] | None,
        min_confidence: Confidence | None,
    ) -> dict[str, dict[str, Any]]:
        """Build pattern dictionary from expanded pattern library.

        Args:
            enabled_categories: If provided, only include these categories.
            disabled_categories: If provided, exclude these categories.
            min_confidence: If provided, only include patterns at this level or higher.

        Returns:
            Dictionary of patterns suitable for the detector.
        """
        patterns: dict[str, dict[str, Any]] = {}

        for category, category_patterns in ALL_PATTERN_CATEGORIES.items():
            # Filter by enabled categories
            if enabled_categories and category not in enabled_categories:
                continue

            # Filter by disabled categories
            if disabled_categories and category in disabled_categories:
                continue

            for pattern in category_patterns:
                if self._should_include_pattern(pattern, min_confidence):
                    patterns[pattern.name] = pattern.to_dict()

        return patterns

    def _should_include_pattern(
        self,
        pattern: Pattern,
        min_confidence: Confidence | None = None,
    ) -> bool:
        """Check if a pattern should be included based on filters.

        Args:
            pattern: The pattern to check.
            min_confidence: Override minimum confidence level.

        Returns:
            True if the pattern should be included.
        """
        confidence_check = min_confidence or self._min_confidence
        if confidence_check:
            confidence_order = {
                Confidence.LOW: 0,
                Confidence.MEDIUM: 1,
                Confidence.HIGH: 2,
            }
            pattern_confidence = confidence_order.get(pattern.confidence, 1)
            min_confidence_level = confidence_order.get(confidence_check, 1)
            if pattern_confidence < min_confidence_level:
                return False

        return True

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "regex"

    @property
    def max_file_size(self) -> int:
        """Return the maximum file size in bytes."""
        return self._max_file_size

    @property
    def regex_timeout(self) -> float:
        """Return the regex timeout in seconds."""
        return self._regex_timeout

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect sensitive patterns in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected pattern.
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

        # Check for binary content
        if self._is_binary_content(content):
            self._logger.debug("Skipping binary file: %s", file_path)
            return []

        findings: list[Finding] = []
        patterns_matched = 0
        patterns_timed_out = 0

        for pattern_name, pattern_data in self._compiled_patterns.items():
            compiled, severity, description, category, confidence = pattern_data
            pattern_start = time.perf_counter()
            try:
                matches = self._find_matches_with_timeout(compiled, content, pattern_name)
                if matches:
                    patterns_matched += 1
                    # Deduplicate matches while preserving order
                    unique_matches = list(dict.fromkeys(matches))
                    findings.append(
                        Finding(
                            file_path=file_path,
                            detector_name=f"regex:{pattern_name}",
                            matches=unique_matches,
                            severity=severity,
                            metadata={
                                "pattern_name": pattern_name,
                                "description": description,
                                "match_count": len(unique_matches),
                                "category": category,
                                "confidence": confidence,
                            },
                        )
                    )
            except TimeoutError:
                patterns_timed_out += 1
                self._logger.warning(
                    "Pattern '%s' timed out on file %s (limit: %.1fs)",
                    pattern_name,
                    file_path,
                    self._regex_timeout,
                )
                continue
            except Exception as e:
                # Skip patterns that fail during matching (e.g., on binary content)
                self._logger.debug(
                    "Pattern '%s' failed on file %s: %s",
                    pattern_name,
                    file_path,
                    str(e),
                )
                continue
            finally:
                pattern_elapsed = time.perf_counter() - pattern_start
                if pattern_elapsed > 0.1:  # Log slow patterns (>100ms)
                    self._logger.debug(
                        "Pattern '%s' took %.3fs on file %s",
                        pattern_name,
                        pattern_elapsed,
                        file_path,
                    )

        # Log performance metrics in verbose mode
        elapsed = time.perf_counter() - start_time
        self._logger.debug(
            "RegexDetector processed %s in %.3fs: %d patterns matched, %d timed out, %d findings",
            file_path,
            elapsed,
            patterns_matched,
            patterns_timed_out,
            len(findings),
        )

        return findings

    def _is_binary_content(self, content: str) -> bool:
        """Check if content appears to be binary.

        Uses a heuristic based on the presence of null bytes and control
        characters in the first 8KB of content.

        Args:
            content: The content to check.

        Returns:
            True if the content appears to be binary, False otherwise.
        """
        # Check the first 8KB of content
        sample = content[:8192]
        if not sample:
            return False

        # Encode to bytes for binary check
        try:
            sample_bytes = sample.encode("utf-8", errors="replace")
        except Exception:
            # If encoding fails, assume binary
            return True

        # Count binary indicator bytes
        binary_count = sum(1 for b in sample_bytes if b in BINARY_INDICATOR_BYTES)
        binary_ratio = binary_count / len(sample_bytes)

        return binary_ratio > BINARY_THRESHOLD

    def _find_matches_with_timeout(
        self, pattern: re.Pattern[str], content: str, pattern_name: str
    ) -> list[str]:
        """Find all matches for a pattern with timeout protection.

        Python's re module doesn't support true timeout, so we use a time-based
        approach that checks elapsed time during matching. For very long content,
        we process in chunks.

        Args:
            pattern: The compiled regex pattern.
            content: The content to search.
            pattern_name: Name of the pattern (for logging).

        Returns:
            List of matched strings.

        Raises:
            TimeoutError: If the pattern takes too long to match.
        """
        start_time = time.perf_counter()

        # For large content, check timeout periodically
        # Process in chunks of 1MB to allow timeout checking
        chunk_size = 1024 * 1024
        all_matches: list[str] = []

        if len(content) <= chunk_size:
            # Small content - process directly
            matches = pattern.findall(content)
            elapsed = time.perf_counter() - start_time
            if elapsed > self._regex_timeout:
                raise TimeoutError(f"Pattern '{pattern_name}' exceeded timeout")
            return matches if matches else []

        # Large content - process in chunks with timeout checking
        for i in range(0, len(content), chunk_size):
            # Check timeout before processing each chunk
            elapsed = time.perf_counter() - start_time
            if elapsed > self._regex_timeout:
                raise TimeoutError(f"Pattern '{pattern_name}' exceeded timeout")

            chunk = content[i : i + chunk_size]
            # Add overlap to avoid missing matches at boundaries
            if i > 0:
                # Include some overlap from the previous chunk
                overlap_start = max(0, i - 1000)
                chunk = content[overlap_start : i + chunk_size]

            matches = pattern.findall(chunk)
            if matches:
                all_matches.extend(matches)

        return all_matches

    def get_patterns(self) -> dict[str, dict[str, Any]]:
        """Return the current pattern configuration.

        Returns:
            Dictionary of pattern names to their configurations.
        """
        return self._patterns.copy()

    def add_pattern(
        self,
        name: str,
        pattern: str,
        severity: Severity = Severity.MEDIUM,
        description: str = "",
        category: str = "",
        confidence: str = "medium",
    ) -> None:
        """Add a new pattern to the detector.

        Args:
            name: Unique name for the pattern.
            pattern: Regular expression pattern string.
            severity: Severity level for findings from this pattern.
            description: Human-readable description of what the pattern detects.
            category: Category for the pattern (e.g., "api_keys", "credentials").
            confidence: Confidence level ("high", "medium", "low").

        Raises:
            ValueError: If the pattern name already exists or the regex is invalid.
        """
        if name in self._patterns:
            raise ValueError(f"Pattern '{name}' already exists")

        try:
            compiled = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e

        self._patterns[name] = {
            "pattern": pattern,
            "severity": severity,
            "description": description,
            "category": category,
            "confidence": confidence,
        }
        self._compiled_patterns[name] = (compiled, severity, description, category, confidence)

    def remove_pattern(self, name: str) -> None:
        """Remove a pattern from the detector.

        Args:
            name: Name of the pattern to remove.

        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")

        del self._patterns[name]
        del self._compiled_patterns[name]

    def get_enabled_categories(self) -> list[PatternCategory] | None:
        """Return the list of enabled categories, or None if all are enabled.

        Returns:
            List of enabled PatternCategory values, or None if no filter is set.
        """
        return self._enabled_categories

    def get_disabled_categories(self) -> list[PatternCategory] | None:
        """Return the list of disabled categories, or None if none are disabled.

        Returns:
            List of disabled PatternCategory values, or None if no filter is set.
        """
        return self._disabled_categories

    def get_min_confidence(self) -> Confidence | None:
        """Return the minimum confidence level filter, or None if not set.

        Returns:
            Minimum Confidence level, or None if no filter is set.
        """
        return self._min_confidence

    def get_pattern_count(self) -> int:
        """Return the total number of patterns loaded.

        Returns:
            Number of patterns currently registered in the detector.
        """
        return len(self._patterns)

    def get_patterns_by_category(self, category: str) -> dict[str, dict[str, Any]]:
        """Return patterns filtered by category.

        Args:
            category: The category name to filter by (e.g., "api_keys").

        Returns:
            Dictionary of pattern names to their configurations for the category.
        """
        return {
            name: config
            for name, config in self._patterns.items()
            if config.get("category", "") == category
        }

    def get_patterns_by_confidence(self, confidence: str) -> dict[str, dict[str, Any]]:
        """Return patterns filtered by confidence level.

        Args:
            confidence: The confidence level to filter by ("high", "medium", "low").

        Returns:
            Dictionary of pattern names to their configurations for the confidence.
        """
        return {
            name: config
            for name, config in self._patterns.items()
            if config.get("confidence", "medium") == confidence
        }

    async def detect_async(self, content: str, file_path: str = "") -> list[Finding]:
        """Asynchronously detect sensitive patterns in the given content.

        This method runs the synchronous detect() method in a thread pool
        using asyncio.to_thread(), allowing it to be called from async code
        without blocking the event loop.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected pattern.
        """
        return await asyncio.to_thread(self.detect, content, file_path)

    def detect_batch(
        self,
        contents: list[tuple[str, str]],
        stop_on_first_match: bool = False,
    ) -> dict[str, list[Finding]]:
        """Detect sensitive patterns in multiple contents efficiently.

        This method processes multiple pieces of content in a batch,
        reusing compiled patterns and optimizing for throughput.

        Args:
            contents: List of (content, file_path) tuples to analyze.
            stop_on_first_match: If True, stop processing a file after first match.

        Returns:
            Dictionary mapping file paths to their findings.
        """
        results: dict[str, list[Finding]] = {}

        for content, file_path in contents:
            findings = self._detect_with_early_exit(content, file_path, stop_on_first_match)
            results[file_path] = findings

        return results

    def _detect_with_early_exit(
        self,
        content: str,
        file_path: str,
        stop_on_first_match: bool,
    ) -> list[Finding]:
        """Detect patterns with optional early exit on first match.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.
            stop_on_first_match: If True, return after first finding.

        Returns:
            A list of Finding objects for each detected pattern.
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

        # Check for binary content
        if self._is_binary_content(content):
            self._logger.debug("Skipping binary file: %s", file_path)
            return []

        findings: list[Finding] = []
        patterns_matched = 0
        patterns_timed_out = 0

        for pattern_name, pattern_data in self._compiled_patterns.items():
            compiled, severity, description, category, confidence = pattern_data
            pattern_start = time.perf_counter()
            try:
                matches = self._find_matches_with_timeout(compiled, content, pattern_name)
                if matches:
                    patterns_matched += 1
                    # Deduplicate matches while preserving order
                    unique_matches = list(dict.fromkeys(matches))
                    findings.append(
                        Finding(
                            file_path=file_path,
                            detector_name=f"regex:{pattern_name}",
                            matches=unique_matches,
                            severity=severity,
                            metadata={
                                "pattern_name": pattern_name,
                                "description": description,
                                "match_count": len(unique_matches),
                                "category": category,
                                "confidence": confidence,
                            },
                        )
                    )
                    if stop_on_first_match:
                        break
            except TimeoutError:
                patterns_timed_out += 1
                self._logger.warning(
                    "Pattern '%s' timed out on file %s (limit: %.1fs)",
                    pattern_name,
                    file_path,
                    self._regex_timeout,
                )
                continue
            except Exception as e:
                self._logger.debug(
                    "Pattern '%s' failed on file %s: %s",
                    pattern_name,
                    file_path,
                    str(e),
                )
                continue
            finally:
                pattern_elapsed = time.perf_counter() - pattern_start
                if pattern_elapsed > 0.1:
                    self._logger.debug(
                        "Pattern '%s' took %.3fs on file %s",
                        pattern_name,
                        pattern_elapsed,
                        file_path,
                    )

        elapsed = time.perf_counter() - start_time
        self._logger.debug(
            "RegexDetector processed %s in %.3fs: %d patterns matched, %d timed out, %d findings",
            file_path,
            elapsed,
            patterns_matched,
            patterns_timed_out,
            len(findings),
        )

        return findings

    async def detect_batch_async(
        self,
        contents: list[tuple[str, str]],
        stop_on_first_match: bool = False,
        concurrency_limit: int = 10,
    ) -> dict[str, list[Finding]]:
        """Asynchronously detect patterns in multiple contents with concurrency control.

        This method processes multiple pieces of content concurrently using a
        semaphore to limit the number of parallel operations.

        Args:
            contents: List of (content, file_path) tuples to analyze.
            stop_on_first_match: If True, stop processing a file after first match.
            concurrency_limit: Maximum number of concurrent detection operations.

        Returns:
            Dictionary mapping file paths to their findings.
        """
        semaphore = asyncio.Semaphore(concurrency_limit)
        results: dict[str, list[Finding]] = {}
        lock = asyncio.Lock()

        async def process_content(content: str, file_path: str) -> None:
            async with semaphore:
                findings = await asyncio.to_thread(
                    self._detect_with_early_exit, content, file_path, stop_on_first_match
                )
                async with lock:
                    results[file_path] = findings

        tasks = [process_content(content, file_path) for content, file_path in contents]
        await asyncio.gather(*tasks)

        return results

    def get_pattern_stats(self) -> dict[str, Any]:
        """Get statistics about the loaded patterns.

        Returns:
            Dictionary with pattern statistics including counts by category,
            severity, and confidence levels.
        """
        stats: dict[str, Any] = {
            "total_patterns": len(self._patterns),
            "by_category": {},
            "by_severity": {},
            "by_confidence": {},
        }

        for config in self._patterns.values():
            # Count by category
            category = config.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            # Count by severity
            severity = config.get("severity", Severity.MEDIUM)
            if isinstance(severity, Severity):
                severity_key = severity.value
            else:
                severity_key = str(severity)
            stats["by_severity"][severity_key] = stats["by_severity"].get(severity_key, 0) + 1

            # Count by confidence
            confidence = config.get("confidence", "medium")
            stats["by_confidence"][confidence] = stats["by_confidence"].get(confidence, 0) + 1

        return stats
