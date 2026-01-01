"""Example Custom Detector Plugin for Hamburglar.

This example demonstrates how to create a custom detector plugin that can be
loaded by Hamburglar without modifying the core codebase. The plugin detects
custom API key patterns that might be specific to your organization.

INSTALLATION METHODS
====================

Method 1: File Copy (Simplest)
------------------------------
Copy this file to a directory and configure Hamburglar to scan it:

    # In your .hamburglar.yml config file:
    plugins:
      directories:
        - /path/to/your/plugins

    # Or via environment variable:
    export HAMBURGLAR_PLUGIN_DIRS="/path/to/your/plugins"

Method 2: Entry Points (For Pip-Installable Packages)
------------------------------------------------------
Add an entry point to your package's pyproject.toml:

    [project.entry-points."hamburglar.plugins.detectors"]
    custom_api_keys = "your_package.detectors:CustomAPIKeyDetector"

Then install your package with pip:

    pip install your-package

CONFIGURATION
=============

Plugin configuration can be provided via the config file:

    # In your .hamburglar.yml config file:
    plugins:
      config:
        custom_api_keys:
          min_key_length: 20
          check_entropy: true
          key_prefixes:
            - "MYORG_"
            - "CUSTOM_"

USAGE
=====

Once installed, the detector will automatically be used during scans:

    hamburglar scan /path/to/code

To verify the plugin is loaded:

    hamburglar plugins list

Example output:
    Detector Plugins:
      custom_api_keys  v1.0.0  Detects custom organization API keys
"""

from __future__ import annotations

import math
import re
from typing import Any

from hamburglar.core.models import Finding, Severity
from hamburglar.plugins.detector_plugin import DetectorPlugin


class CustomAPIKeyDetector(DetectorPlugin):
    """Detects custom organization-specific API keys and tokens.

    This detector is designed to find API keys that follow patterns specific
    to your organization or commonly used third-party services.

    Configuration Options:
        min_key_length: Minimum length for detected keys (default: 16)
        check_entropy: Whether to validate key entropy (default: True)
        min_entropy: Minimum entropy threshold (default: 3.0)
        key_prefixes: List of prefixes to search for (default: see below)
        case_sensitive: Whether prefix matching is case-sensitive (default: False)

    Example:
        detector = CustomAPIKeyDetector(
            min_key_length=20,
            check_entropy=True,
            key_prefixes=["MYORG_", "CUSTOM_"]
        )
        findings = detector.detect(file_content, "config.py")
    """

    # Class-level metadata (used by the plugin system)
    __version__ = "1.0.0"
    __author__ = "Your Organization"

    # Default patterns to detect
    DEFAULT_PATTERNS = [
        # Generic API key assignments (key=value or key: value)
        r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
        # Bearer tokens in headers
        r'["\']?Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']?',
        # Authorization headers with tokens
        r'Authorization["\']?\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})',
        # Generic secret patterns
        r'(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']([A-Za-z0-9_\-]{12,})["\']',
    ]

    def __init__(self, **config: Any) -> None:
        """Initialize the custom API key detector.

        Args:
            **config: Configuration options including:
                - min_key_length: Minimum key length to detect
                - check_entropy: Whether to validate key randomness
                - min_entropy: Minimum Shannon entropy threshold
                - key_prefixes: Custom prefixes to search for
                - case_sensitive: Case sensitivity for prefix matching
        """
        super().__init__(**config)

        # Store configuration with defaults
        self._min_key_length = self.get_config("min_key_length", 16)
        self._check_entropy = self.get_config("check_entropy", True)
        self._min_entropy = self.get_config("min_entropy", 3.0)
        self._case_sensitive = self.get_config("case_sensitive", False)

        # Build prefix patterns from configuration
        self._key_prefixes = self.get_config(
            "key_prefixes",
            ["ACME_", "MYORG_", "INTERNAL_", "PROD_", "STAGING_"],
        )

    @property
    def name(self) -> str:
        """Return the unique name of this detector."""
        return "custom_api_keys"

    @property
    def description(self) -> str:
        """Return a human-readable description of this detector."""
        return "Detects custom organization API keys and tokens"

    @property
    def supported_extensions(self) -> list[str] | None:
        """Return file extensions this detector should scan.

        Returns None to scan all files, or a list of extensions to limit
        scanning to specific file types.
        """
        # Scan common configuration and source code files
        return [
            ".py",
            ".js",
            ".ts",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".env",
            ".cfg",
            ".ini",
            ".conf",
            ".sh",
            ".bash",
        ]

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect custom API keys in the given content.

        This method searches for:
        1. Keys matching configured prefix patterns
        2. Keys matching common API key formats
        3. Keys that meet entropy requirements (if enabled)

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected key.
        """
        # Skip files that don't match our supported extensions
        if not self.should_scan_file(file_path):
            return []

        findings: list[Finding] = []

        # Detect keys with configured prefixes
        findings.extend(self._detect_prefixed_keys(content, file_path))

        # Detect keys matching common patterns
        findings.extend(self._detect_pattern_matches(content, file_path))

        return findings

    def _detect_prefixed_keys(self, content: str, file_path: str) -> list[Finding]:
        """Detect keys that start with configured prefixes.

        Args:
            content: The content to search.
            file_path: The file path for findings.

        Returns:
            List of findings for prefixed keys.
        """
        findings: list[Finding] = []

        for prefix in self._key_prefixes:
            # Build pattern: PREFIX followed by alphanumeric chars
            # The pattern captures the full key including prefix
            flags = 0 if self._case_sensitive else re.IGNORECASE
            pattern = rf"({re.escape(prefix)}[A-Za-z0-9_\-]{{8,}})"

            for match in re.finditer(pattern, content, flags):
                key = match.group(1)

                # Validate key length
                if len(key) < self._min_key_length:
                    continue

                # Validate entropy if enabled
                if self._check_entropy and not self._has_sufficient_entropy(key):
                    continue

                # Determine severity based on key characteristics
                severity = self._assess_severity(key, prefix)

                findings.append(
                    self.create_finding(
                        file_path=file_path,
                        matches=[key],
                        severity=severity,
                        metadata={
                            "prefix": prefix,
                            "key_length": len(key),
                            "entropy": self._calculate_entropy(key),
                            "position": match.start(),
                            "detection_method": "prefix_match",
                        },
                    )
                )

        return findings

    def _detect_pattern_matches(self, content: str, file_path: str) -> list[Finding]:
        """Detect keys matching common API key patterns.

        Args:
            content: The content to search.
            file_path: The file path for findings.

        Returns:
            List of findings for pattern-matched keys.
        """
        findings: list[Finding] = []

        for pattern in self.DEFAULT_PATTERNS:
            # Use the utility method from the base class
            pattern_findings = self.match_pattern(
                content=content,
                file_path=file_path,
                pattern=pattern,
                severity=Severity.HIGH,
                flags=re.IGNORECASE,
            )

            # Filter by entropy if enabled
            for finding in pattern_findings:
                if finding.matches:
                    key = finding.matches[0]

                    # Skip if key is too short
                    if len(key) < self._min_key_length:
                        continue

                    # Skip if entropy is too low
                    if self._check_entropy and not self._has_sufficient_entropy(key):
                        continue

                    # Add entropy info to metadata
                    finding.metadata["entropy"] = self._calculate_entropy(key)
                    finding.metadata["detection_method"] = "pattern_match"
                    findings.append(finding)

        return findings

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness, which is typical
        of real API keys and secrets.

        Args:
            text: The string to analyze.

        Returns:
            Shannon entropy value (bits per character).
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _has_sufficient_entropy(self, text: str) -> bool:
        """Check if text has sufficient entropy to be a real key.

        This helps filter out false positives like variable names
        or placeholder values.

        Args:
            text: The string to check.

        Returns:
            True if entropy meets the threshold.
        """
        return self._calculate_entropy(text) >= self._min_entropy

    def _assess_severity(self, key: str, prefix: str) -> Severity:
        """Assess the severity of a detected key.

        Severity is determined based on:
        - Key length (longer keys are often more sensitive)
        - Prefix (production keys are more critical)
        - Key entropy (high entropy suggests real keys)

        Args:
            key: The detected key.
            prefix: The matched prefix.

        Returns:
            Severity level for this finding.
        """
        # Production keys are critical
        if any(p in prefix.upper() for p in ["PROD", "LIVE", "MASTER"]):
            return Severity.CRITICAL

        # Keys with high entropy are likely real
        entropy = self._calculate_entropy(key)
        if entropy > 4.0:
            return Severity.HIGH

        # Staging/dev keys are medium
        if any(p in prefix.upper() for p in ["STAGING", "DEV", "TEST"]):
            return Severity.MEDIUM

        # Default to high for other keys
        return Severity.HIGH


# Optionally use the decorator for automatic registration
# Uncomment this if you want the plugin to self-register when imported
#
# from hamburglar.plugins import detector_plugin
#
# @detector_plugin(
#     "custom_api_keys",
#     description="Detects custom organization API keys",
#     version="1.0.0",
#     author="Your Organization"
# )
# class CustomAPIKeyDetector(DetectorPlugin):
#     ...


if __name__ == "__main__":
    # Quick test of the detector
    print("Testing CustomAPIKeyDetector...")

    detector = CustomAPIKeyDetector(
        min_key_length=16,
        check_entropy=True,
        key_prefixes=["ACME_", "TEST_"],
    )

    test_content = '''
    # Configuration file
    API_KEY = "ACME_abc123xyz789secret"
    ACME_TOKEN = "ACME_1234567890abcdef"
    TEST_API_KEY = "TEST_randomTokenValue123456"

    # False positives (should be filtered)
    ACME_AAA = "ACME_AAAAAAAAAAAAAAAA"  # Low entropy
    SHORT_KEY = "TEST_abc"  # Too short

    # Generic patterns
    Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    api_key = "fake_test_key_1234567890abcdef123"
    '''

    findings = detector.detect(test_content, "test_config.py")

    print(f"\nFound {len(findings)} potential secrets:")
    for f in findings:
        print(f"  - {f.matches[0][:30]}... (severity: {f.severity.value})")
        print(f"    Entropy: {f.metadata.get('entropy', 'N/A'):.2f}")
        print(f"    Method: {f.metadata.get('detection_method', 'N/A')}")

    print("\nDetector test complete!")
