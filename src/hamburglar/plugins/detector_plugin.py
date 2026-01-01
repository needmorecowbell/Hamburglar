"""DetectorPlugin base class for custom detector plugins.

This module provides the `DetectorPlugin` base class that enables users to create
custom detectors without modifying the core Hamburglar codebase. Detector plugins
can be loaded from entry points, directories, or registered manually.

Example usage::

    from hamburglar.plugins.detector_plugin import DetectorPlugin
    from hamburglar.core.models import Finding, Severity
    import re

    class MySecretDetector(DetectorPlugin):
        '''Detects my custom secrets.'''

        @property
        def name(self) -> str:
            return "my_secrets"

        @property
        def description(self) -> str:
            return "Detects my custom secret format"

        def detect(self, content: str, file_path: str = "") -> list[Finding]:
            findings = []
            for match in re.finditer(r'MY_SECRET_[A-Z0-9]{16}', content):
                findings.append(self.create_finding(
                    file_path=file_path,
                    matches=[match.group()],
                    severity=Severity.HIGH,
                    metadata={"position": match.start()}
                ))
            return findings
"""

from __future__ import annotations

import re
from abc import abstractmethod
from typing import TYPE_CHECKING, Any

from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector, default_registry

if TYPE_CHECKING:
    from collections.abc import Pattern


class DetectorPlugin(BaseDetector):
    """Base class for detector plugins.

    This class extends BaseDetector with additional functionality useful for
    plugin development, including:

    - Configuration support via constructor arguments
    - Utility methods for pattern matching
    - Helper method for creating findings
    - Integration with the detector registry

    Subclasses must implement:
    - `name` property: Unique identifier for the detector
    - `detect` method: Detection logic

    Optional overrides:
    - `description` property: Human-readable description
    - `version` property: Plugin version string
    - `author` property: Plugin author name
    - `supported_extensions` property: File extensions this detector handles

    Example:
        class MyDetector(DetectorPlugin):
            @property
            def name(self) -> str:
                return "my_detector"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return self.match_patterns(
                    content,
                    file_path,
                    patterns=[r'SECRET_[A-Z0-9]+'],
                    severity=Severity.HIGH
                )
    """

    # Class-level attributes for plugin metadata
    __version__: str = "1.0.0"
    __author__: str = ""

    def __init__(self, **config: Any) -> None:
        """Initialize the detector plugin.

        Args:
            **config: Plugin-specific configuration options. These are stored
                in self._config and can be accessed via the `config` property.

        Example:
            detector = MyDetector(min_length=16, case_sensitive=True)
        """
        self._config: dict[str, Any] = config
        self._compiled_patterns: dict[str, Pattern[str]] = {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this detector.

        This name is used to identify the detector in configuration,
        findings, and the plugin registry.

        Returns:
            A string identifier (e.g., 'api_keys', 'custom_secrets').
        """
        ...

    @abstractmethod
    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect sensitive information in the given content.

        Implement this method with your detection logic. Use the utility
        methods provided by this class to simplify pattern matching.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each detected item.
        """
        ...

    @property
    def description(self) -> str:
        """Return a human-readable description of this detector.

        Override this to provide documentation for your detector.

        Returns:
            A description string.
        """
        return self.__doc__ or f"{self.name} detector plugin"

    @property
    def version(self) -> str:
        """Return the version of this detector plugin.

        Returns:
            A version string (e.g., '1.0.0').
        """
        return getattr(self.__class__, "__version__", "1.0.0")

    @property
    def author(self) -> str:
        """Return the author of this detector plugin.

        Returns:
            An author name string.
        """
        return getattr(self.__class__, "__author__", "")

    @property
    def config(self) -> dict[str, Any]:
        """Return the plugin configuration.

        Returns:
            A dictionary of configuration options.
        """
        return self._config.copy()

    @property
    def supported_extensions(self) -> list[str] | None:
        """Return file extensions this detector handles.

        Override this to limit the detector to specific file types.
        Return None to handle all file types.

        Returns:
            A list of extensions (e.g., ['.py', '.js']) or None for all.
        """
        return None

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: The configuration key to retrieve.
            default: Default value if key is not found.

        Returns:
            The configuration value or the default.
        """
        return self._config.get(key, default)

    def should_scan_file(self, file_path: str) -> bool:
        """Check if this detector should scan the given file.

        Uses the `supported_extensions` property to filter files.

        Args:
            file_path: The path to check.

        Returns:
            True if the file should be scanned, False otherwise.
        """
        extensions = self.supported_extensions
        if extensions is None:
            return True

        for ext in extensions:
            if file_path.endswith(ext):
                return True
        return False

    def create_finding(
        self,
        file_path: str,
        matches: list[str],
        severity: Severity = Severity.MEDIUM,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """Create a Finding object with this detector's name.

        This is a convenience method that automatically sets the
        detector_name field.

        Args:
            file_path: Path to the file where the match was found.
            matches: List of matched strings.
            severity: Severity level of the finding.
            metadata: Additional metadata for the finding.

        Returns:
            A Finding object.

        Example:
            finding = self.create_finding(
                file_path="config.py",
                matches=["API_KEY=abc123"],
                severity=Severity.HIGH,
                metadata={"line": 42}
            )
        """
        return Finding(
            file_path=file_path,
            detector_name=self.name,
            matches=matches,
            severity=severity,
            metadata=metadata or {},
        )

    def compile_pattern(
        self,
        pattern: str,
        flags: int = 0,
    ) -> Pattern[str]:
        """Compile and cache a regex pattern.

        Patterns are cached by their string representation for efficiency.

        Args:
            pattern: The regex pattern string.
            flags: Regex flags (e.g., re.IGNORECASE).

        Returns:
            A compiled Pattern object.
        """
        cache_key = f"{pattern}:{flags}"
        if cache_key not in self._compiled_patterns:
            self._compiled_patterns[cache_key] = re.compile(pattern, flags)
        return self._compiled_patterns[cache_key]

    def match_pattern(
        self,
        content: str,
        file_path: str,
        pattern: str | Pattern[str],
        severity: Severity = Severity.MEDIUM,
        metadata: dict[str, Any] | None = None,
        flags: int = 0,
    ) -> list[Finding]:
        """Match a single pattern against content and return findings.

        Args:
            content: The content to search.
            file_path: The path to the file being scanned.
            pattern: A regex pattern string or compiled Pattern.
            severity: Severity level for any findings.
            metadata: Base metadata to include in all findings.
            flags: Regex flags if pattern is a string.

        Returns:
            A list of Finding objects for each match.

        Example:
            findings = self.match_pattern(
                content=file_content,
                file_path="config.py",
                pattern=r'API_KEY\\s*=\\s*["\\'](\\w+)["\\']]',
                severity=Severity.HIGH
            )
        """
        if isinstance(pattern, str):
            compiled = self.compile_pattern(pattern, flags)
        else:
            compiled = pattern

        findings: list[Finding] = []
        for match in compiled.finditer(content):
            match_text = match.group()
            match_metadata = {
                "start": match.start(),
                "end": match.end(),
                **(metadata or {}),
            }

            # Include named groups in metadata
            if match.groupdict():
                match_metadata["groups"] = match.groupdict()

            findings.append(
                self.create_finding(
                    file_path=file_path,
                    matches=[match_text],
                    severity=severity,
                    metadata=match_metadata,
                )
            )

        return findings

    def match_patterns(
        self,
        content: str,
        file_path: str,
        patterns: list[str | Pattern[str]],
        severity: Severity = Severity.MEDIUM,
        metadata: dict[str, Any] | None = None,
        flags: int = 0,
    ) -> list[Finding]:
        """Match multiple patterns against content and return findings.

        Args:
            content: The content to search.
            file_path: The path to the file being scanned.
            patterns: List of regex pattern strings or compiled Patterns.
            severity: Severity level for any findings.
            metadata: Base metadata to include in all findings.
            flags: Regex flags if patterns are strings.

        Returns:
            A list of Finding objects for all matches across all patterns.

        Example:
            findings = self.match_patterns(
                content=file_content,
                file_path="config.py",
                patterns=[
                    r'API_KEY\\s*=\\s*["\\'](\\w+)["\\']]',
                    r'SECRET\\s*=\\s*["\\'](\\w+)["\\']]',
                ],
                severity=Severity.HIGH
            )
        """
        all_findings: list[Finding] = []
        for pattern in patterns:
            all_findings.extend(
                self.match_pattern(
                    content=content,
                    file_path=file_path,
                    pattern=pattern,
                    severity=severity,
                    metadata=metadata,
                    flags=flags,
                )
            )
        return all_findings

    def match_literal(
        self,
        content: str,
        file_path: str,
        literal: str,
        severity: Severity = Severity.MEDIUM,
        case_sensitive: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Match a literal string in content and return findings.

        Args:
            content: The content to search.
            file_path: The path to the file being scanned.
            literal: The literal string to search for.
            severity: Severity level for any findings.
            case_sensitive: Whether the match is case-sensitive.
            metadata: Base metadata to include in all findings.

        Returns:
            A list of Finding objects for each occurrence.
        """
        escaped = re.escape(literal)
        flags = 0 if case_sensitive else re.IGNORECASE
        return self.match_pattern(
            content=content,
            file_path=file_path,
            pattern=escaped,
            severity=severity,
            metadata=metadata,
            flags=flags,
        )

    def register(self) -> None:
        """Register this detector with the default registry.

        Call this method to make the detector available for scanning.
        Note that plugins discovered via entry points or directories
        are automatically registered.

        Raises:
            ValueError: If a detector with the same name is already registered.

        Example:
            detector = MyDetector()
            detector.register()
        """
        default_registry.register(self)

    def unregister(self) -> None:
        """Unregister this detector from the default registry.

        Raises:
            KeyError: If the detector is not registered.
        """
        default_registry.unregister(self.name)


__all__ = ["DetectorPlugin"]
