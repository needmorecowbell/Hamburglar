"""OutputPlugin base class for custom output plugins.

This module provides the `OutputPlugin` base class that enables users to create
custom output formatters without modifying the core Hamburglar codebase. Output
plugins can be loaded from entry points, directories, or registered manually.

Example usage::

    from hamburglar.plugins.output_plugin import OutputPlugin
    from hamburglar.core.models import ScanResult, Finding

    class MyCustomOutput(OutputPlugin):
        '''Formats results as custom text.'''

        @property
        def name(self) -> str:
            return "custom_text"

        @property
        def description(self) -> str:
            return "Custom text output format"

        def format(self, result: ScanResult) -> str:
            lines = []
            for finding in result.findings:
                lines.append(f"[{finding.severity.value}] {finding.file_path}")
                for match in finding.matches:
                    lines.append(f"  - {match}")
            return "\\n".join(lines)
"""

from __future__ import annotations

import json
from abc import abstractmethod
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput, default_registry


class OutputPlugin(BaseOutput):
    """Base class for output plugins.

    This class extends BaseOutput with additional functionality useful for
    plugin development, including:

    - Configuration support via constructor arguments
    - Utility methods for formatting findings
    - Helper methods for common output patterns
    - Integration with the output registry

    Subclasses must implement:
    - `name` property: Unique identifier for the output formatter
    - `format` method: Formatting logic

    Optional overrides:
    - `description` property: Human-readable description
    - `version` property: Plugin version string
    - `author` property: Plugin author name
    - `file_extension` property: Default file extension for output

    Example:
        class MyOutput(OutputPlugin):
            @property
            def name(self) -> str:
                return "my_output"

            def format(self, result: ScanResult) -> str:
                return self.format_as_lines(result)
    """

    # Class-level attributes for plugin metadata
    __version__: str = "1.0.0"
    __author__: str = ""

    def __init__(self, **config: Any) -> None:
        """Initialize the output plugin.

        Args:
            **config: Plugin-specific configuration options. These are stored
                in self._config and can be accessed via the `config` property.

        Example:
            output = MyOutput(include_metadata=True, max_matches=100)
        """
        self._config: dict[str, Any] = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this output formatter.

        This name is used to identify the formatter in configuration,
        CLI arguments, and the plugin registry.

        Returns:
            A string identifier (e.g., 'json', 'csv', 'custom_html').
        """
        ...

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Format a scan result for output.

        Implement this method with your formatting logic. Use the utility
        methods provided by this class to simplify common formatting tasks.

        Args:
            result: The ScanResult to format.

        Returns:
            A formatted string representation of the scan result.
        """
        ...

    @property
    def description(self) -> str:
        """Return a human-readable description of this output formatter.

        Override this to provide documentation for your formatter.

        Returns:
            A description string.
        """
        return self.__doc__ or f"{self.name} output plugin"

    @property
    def version(self) -> str:
        """Return the version of this output plugin.

        Returns:
            A version string (e.g., '1.0.0').
        """
        return getattr(self.__class__, "__version__", "1.0.0")

    @property
    def author(self) -> str:
        """Return the author of this output plugin.

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
    def file_extension(self) -> str:
        """Return the default file extension for this output format.

        Override this to specify the appropriate extension for your format.
        The extension should include the leading dot.

        Returns:
            A file extension (e.g., '.json', '.csv', '.html').
        """
        return ".txt"

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: The configuration key to retrieve.
            default: Default value if key is not found.

        Returns:
            The configuration value or the default.
        """
        return self._config.get(key, default)

    def format_finding(
        self,
        finding: Finding,
        include_metadata: bool = False,
    ) -> dict[str, Any]:
        """Convert a finding to a dictionary representation.

        This is a utility method for creating structured output from findings.

        Args:
            finding: The Finding to convert.
            include_metadata: Whether to include the metadata field.

        Returns:
            A dictionary representation of the finding.

        Example:
            finding_dict = self.format_finding(finding, include_metadata=True)
        """
        result: dict[str, Any] = {
            "file_path": finding.file_path,
            "detector_name": finding.detector_name,
            "matches": finding.matches,
            "severity": finding.severity.value,
        }

        if include_metadata and finding.metadata:
            result["metadata"] = finding.metadata

        return result

    def format_result(
        self,
        result: ScanResult,
        include_metadata: bool = False,
        include_summary: bool = True,
    ) -> dict[str, Any]:
        """Convert a scan result to a dictionary representation.

        This is a utility method for creating structured output from results.

        Args:
            result: The ScanResult to convert.
            include_metadata: Whether to include finding metadata.
            include_summary: Whether to include summary statistics.

        Returns:
            A dictionary representation of the scan result.

        Example:
            result_dict = self.format_result(result, include_summary=True)
        """
        output: dict[str, Any] = {
            "findings": [
                self.format_finding(f, include_metadata=include_metadata) for f in result.findings
            ],
        }

        if include_summary:
            output["summary"] = self.get_summary(result)

        return output

    def get_summary(self, result: ScanResult) -> dict[str, Any]:
        """Generate a summary of the scan result.

        Args:
            result: The ScanResult to summarize.

        Returns:
            A dictionary with summary statistics.
        """
        severity_counts: dict[str, int] = {}
        detector_counts: dict[str, int] = {}

        for finding in result.findings:
            # Count by severity
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # Count by detector
            det = finding.detector_name
            detector_counts[det] = detector_counts.get(det, 0) + 1

        # Get files_scanned from stats dict if available
        files_scanned = result.stats.get("files_scanned", 0)

        return {
            "total_findings": len(result.findings),
            "files_scanned": files_scanned,
            "target_path": result.target_path,
            "scan_duration": result.scan_duration,
            "by_severity": severity_counts,
            "by_detector": detector_counts,
        }

    def format_as_json(
        self,
        result: ScanResult,
        include_metadata: bool = True,
        indent: int | None = 2,
    ) -> str:
        """Format the scan result as JSON.

        This is a convenience method for JSON-based output formats.

        Args:
            result: The ScanResult to format.
            include_metadata: Whether to include finding metadata.
            indent: JSON indentation level (None for compact).

        Returns:
            A JSON string representation.
        """
        data = self.format_result(result, include_metadata=include_metadata)
        return json.dumps(data, indent=indent, default=str)

    def format_as_lines(
        self,
        result: ScanResult,
        separator: str = "\n",
        include_severity: bool = True,
    ) -> str:
        """Format the scan result as lines of text.

        This is a convenience method for simple text-based output formats.

        Args:
            result: The ScanResult to format.
            separator: The line separator to use.
            include_severity: Whether to include severity prefix.

        Returns:
            A text string with one finding per line.
        """
        lines: list[str] = []

        for finding in result.findings:
            prefix = f"[{finding.severity.value}] " if include_severity else ""
            line = f"{prefix}{finding.file_path}: {finding.detector_name}"

            if finding.matches:
                matches_str = ", ".join(finding.matches[:3])
                if len(finding.matches) > 3:
                    matches_str += f" (+{len(finding.matches) - 3} more)"
                line += f" - {matches_str}"

            lines.append(line)

        return separator.join(lines)

    def group_by_file(
        self,
        result: ScanResult,
    ) -> dict[str, list[Finding]]:
        """Group findings by file path.

        This is a utility method for creating file-grouped output.

        Args:
            result: The ScanResult to group.

        Returns:
            A dictionary mapping file paths to lists of findings.
        """
        grouped: dict[str, list[Finding]] = {}

        for finding in result.findings:
            if finding.file_path not in grouped:
                grouped[finding.file_path] = []
            grouped[finding.file_path].append(finding)

        return grouped

    def group_by_severity(
        self,
        result: ScanResult,
    ) -> dict[Severity, list[Finding]]:
        """Group findings by severity level.

        This is a utility method for creating severity-grouped output.

        Args:
            result: The ScanResult to group.

        Returns:
            A dictionary mapping severity levels to lists of findings.
        """
        grouped: dict[Severity, list[Finding]] = {}

        for finding in result.findings:
            if finding.severity not in grouped:
                grouped[finding.severity] = []
            grouped[finding.severity].append(finding)

        return grouped

    def group_by_detector(
        self,
        result: ScanResult,
    ) -> dict[str, list[Finding]]:
        """Group findings by detector name.

        This is a utility method for creating detector-grouped output.

        Args:
            result: The ScanResult to group.

        Returns:
            A dictionary mapping detector names to lists of findings.
        """
        grouped: dict[str, list[Finding]] = {}

        for finding in result.findings:
            if finding.detector_name not in grouped:
                grouped[finding.detector_name] = []
            grouped[finding.detector_name].append(finding)

        return grouped

    def register(self) -> None:
        """Register this output formatter with the default registry.

        Call this method to make the formatter available for use.
        Note that plugins discovered via entry points or directories
        are automatically registered.

        Raises:
            ValueError: If a formatter with the same name is already registered.

        Example:
            output = MyOutput()
            output.register()
        """
        default_registry.register(self)

    def unregister(self) -> None:
        """Unregister this output formatter from the default registry.

        Raises:
            KeyError: If the formatter is not registered.
        """
        default_registry.unregister(self.name)


__all__ = ["OutputPlugin"]
