"""Regex-based detector for sensitive information.

This module provides a detector that uses regular expressions to identify
sensitive data patterns such as API keys, credentials, and other secrets.
"""

import re
import warnings
from typing import Any

from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector

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


class RegexDetector(BaseDetector):
    """Detector that uses regular expressions to find sensitive information.

    The RegexDetector can be initialized with a custom set of patterns or use
    the default set of common sensitive data patterns. Each pattern has an
    associated severity level and description.

    Example:
        detector = RegexDetector()
        findings = detector.detect(file_content, "path/to/file.py")

        # Or with custom patterns:
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
    ) -> None:
        """Initialize the RegexDetector.

        Args:
            patterns: Optional dictionary of custom patterns to use.
                     Each pattern should have 'pattern', 'severity', and 'description' keys.
            use_defaults: If True and patterns is provided, merge with default patterns.
                         If False and patterns is provided, use only custom patterns.
                         If patterns is None, always use default patterns.
        """
        if patterns is None:
            self._patterns = DEFAULT_PATTERNS.copy()
        elif use_defaults:
            self._patterns = DEFAULT_PATTERNS.copy()
            self._patterns.update(patterns)
        else:
            self._patterns = patterns.copy()

        # Pre-compile all regex patterns for performance
        self._compiled_patterns: dict[str, tuple[re.Pattern[str], Severity, str]] = {}
        for name, config in self._patterns.items():
            try:
                compiled = re.compile(config["pattern"])
                self._compiled_patterns[name] = (
                    compiled,
                    config.get("severity", Severity.MEDIUM),
                    config.get("description", ""),
                )
            except re.error as e:
                # Skip invalid patterns but log the issue
                warnings.warn(f"Invalid regex pattern '{name}': {e}", stacklevel=2)

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "regex"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect sensitive patterns in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected pattern.
        """
        findings: list[Finding] = []

        for pattern_name, (compiled, severity, description) in self._compiled_patterns.items():
            try:
                matches = compiled.findall(content)
                if matches:
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
                            },
                        )
                    )
            except Exception:
                # Skip patterns that fail during matching (e.g., on binary content)
                continue

        return findings

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
    ) -> None:
        """Add a new pattern to the detector.

        Args:
            name: Unique name for the pattern.
            pattern: Regular expression pattern string.
            severity: Severity level for findings from this pattern.
            description: Human-readable description of what the pattern detects.

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
        }
        self._compiled_patterns[name] = (compiled, severity, description)

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
