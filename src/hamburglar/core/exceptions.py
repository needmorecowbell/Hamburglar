"""Custom exception hierarchy for Hamburglar.

This module defines the exception classes used throughout Hamburglar
for error handling and reporting. All exceptions inherit from the
base HamburglarError class, allowing callers to catch all Hamburglar
errors with a single except clause.
"""

from __future__ import annotations


class HamburglarError(Exception):
    """Base exception for all Hamburglar errors.

    All custom exceptions in Hamburglar inherit from this class,
    allowing callers to catch any Hamburglar-specific error with
    a single except clause.

    Attributes:
        message: Human-readable error message.
        context: Optional dictionary of additional context about the error.
    """

    def __init__(self, message: str, context: dict | None = None):
        """Initialize the exception.

        Args:
            message: Human-readable error message.
            context: Optional dictionary of additional context about the error.
        """
        self.message = message
        self.context = context or {}
        super().__init__(message)

    def __str__(self) -> str:
        """Return string representation including context if present."""
        if self.context:
            context_str = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} ({context_str})"
        return self.message


class ScanError(HamburglarError):
    """Exception raised when a scan operation fails.

    This exception is raised for fatal issues during scanning,
    such as the target path not existing or being inaccessible.

    Example:
        >>> raise ScanError("Target path does not exist", context={"path": "/nonexistent"})
    """

    def __init__(self, message: str, path: str | None = None, context: dict | None = None):
        """Initialize the scan error.

        Args:
            message: Human-readable error message.
            path: The path that caused the error, if applicable.
            context: Optional dictionary of additional context.
        """
        ctx = context or {}
        if path:
            ctx["path"] = path
        super().__init__(message, ctx)
        self.path = path


class DetectorError(HamburglarError):
    """Exception raised when a detector encounters an error.

    This exception is raised when a detector fails to process
    content, such as encountering a regex timeout or other
    processing failure.

    Example:
        >>> raise DetectorError("Regex timeout", detector_name="RegexDetector")
    """

    def __init__(self, message: str, detector_name: str | None = None, context: dict | None = None):
        """Initialize the detector error.

        Args:
            message: Human-readable error message.
            detector_name: Name of the detector that raised the error.
            context: Optional dictionary of additional context.
        """
        ctx = context or {}
        if detector_name:
            ctx["detector"] = detector_name
        super().__init__(message, ctx)
        self.detector_name = detector_name


class ConfigError(HamburglarError):
    """Exception raised for configuration errors.

    This exception is raised when the configuration is invalid
    or contains incompatible options.

    Example:
        >>> raise ConfigError("Invalid output format", context={"format": "xml"})
    """

    def __init__(self, message: str, config_key: str | None = None, context: dict | None = None):
        """Initialize the config error.

        Args:
            message: Human-readable error message.
            config_key: The configuration key that caused the error.
            context: Optional dictionary of additional context.
        """
        ctx = context or {}
        if config_key:
            ctx["config_key"] = config_key
        super().__init__(message, ctx)
        self.config_key = config_key


class OutputError(HamburglarError):
    """Exception raised when output generation fails.

    This exception is raised when the output formatter fails
    to generate output, such as when writing to a file fails.

    Example:
        >>> raise OutputError("Failed to write output file", context={"path": "/readonly/file"})
    """

    def __init__(self, message: str, output_path: str | None = None, context: dict | None = None):
        """Initialize the output error.

        Args:
            message: Human-readable error message.
            output_path: The output path that caused the error.
            context: Optional dictionary of additional context.
        """
        ctx = context or {}
        if output_path:
            ctx["output_path"] = output_path
        super().__init__(message, ctx)
        self.output_path = output_path


class YaraCompilationError(HamburglarError):
    """Exception raised when YARA rule compilation fails.

    This exception is raised when YARA rules fail to compile,
    providing helpful information about which rule file and
    what error occurred.

    Example:
        >>> raise YaraCompilationError(
        ...     "Syntax error in YARA rule",
        ...     rule_file="bad_rule.yar",
        ...     context={"line": 10, "column": 5}
        ... )
    """

    def __init__(self, message: str, rule_file: str | None = None, context: dict | None = None):
        """Initialize the YARA compilation error.

        Args:
            message: Human-readable error message.
            rule_file: Path to the rule file that failed to compile.
            context: Optional dictionary of additional context about the error.
        """
        ctx = context or {}
        if rule_file:
            ctx["rule_file"] = rule_file
        super().__init__(message, ctx)
        self.rule_file = rule_file
