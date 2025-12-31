"""YARA-based detector for file type and malware detection.

This module provides a detector that uses YARA rules to identify
file types, malware signatures, and other patterns in file content.

The yara-python library is an optional dependency. When not installed,
the detector will be unavailable but the rest of Hamburglar will work.
"""

from __future__ import annotations

import time
from pathlib import Path

from hamburglar.core.exceptions import YaraCompilationError
from hamburglar.core.logging import get_logger
from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector

# YARA is an optional dependency
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    YARA_AVAILABLE = False


# Default maximum file size for YARA matching (100MB)
# YARA can handle large files but performance degrades significantly
DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024

# Default timeout for YARA matching in seconds
DEFAULT_YARA_TIMEOUT = 60


def is_yara_available() -> bool:
    """Check if yara-python is installed and available.

    Returns:
        True if yara-python is available, False otherwise.
    """
    return YARA_AVAILABLE


class YaraDetector(BaseDetector):
    """Detector that uses YARA rules to find patterns in content.

    The YaraDetector compiles YARA rules from a directory and matches
    them against file content to detect file types, malware, and other
    patterns defined in the rules.

    Example:
        detector = YaraDetector("/path/to/yara/rules")
        findings = detector.detect(file_content, "path/to/file.bin")

    Note:
        This detector requires the optional yara-python dependency.
        Use `is_yara_available()` to check if YARA is available.
    """

    def __init__(
        self,
        rules_path: str | Path,
        severity_mapping: dict[str, Severity] | None = None,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        timeout: int = DEFAULT_YARA_TIMEOUT,
    ) -> None:
        """Initialize the YaraDetector.

        Args:
            rules_path: Path to a directory containing .yar/.yara files,
                       or path to a single YARA rule file.
            severity_mapping: Optional dictionary mapping rule names to severity
                             levels. Rules not in this mapping use MEDIUM severity.
            max_file_size: Maximum file size in bytes to scan (default 100MB).
                          Files larger than this will be skipped with a warning.
            timeout: Timeout in seconds for YARA matching (default 60s).

        Raises:
            ImportError: If yara-python is not installed.
            FileNotFoundError: If the rules_path doesn't exist.
            YaraCompilationError: If any YARA rule has syntax errors.
        """
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python is not installed. Install it with: pip install yara-python"
            )

        self._rules_path = Path(rules_path)
        self._severity_mapping = severity_mapping or {}
        self._rules: yara.Rules | None = None
        self._rule_count = 0
        self._max_file_size = max_file_size
        self._timeout = timeout
        self._logger = get_logger()

        if not self._rules_path.exists():
            raise FileNotFoundError(f"YARA rules path not found: {rules_path}")

        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile YARA rules from the configured path.

        This method discovers all .yar and .yara files in the rules path
        (recursively if it's a directory) and compiles them together.

        Raises:
            YaraCompilationError: If any YARA rule has syntax errors.
            ValueError: If no valid YARA rule files are found.
        """
        rules_path = self._rules_path

        try:
            if rules_path.is_file():
                # Single file - compile directly
                self._rules = yara.compile(filepath=str(rules_path))
                self._rule_count = 1
            else:
                # Directory - find all .yar and .yara files
                rule_files = list(rules_path.glob("**/*.yar")) + list(rules_path.glob("**/*.yara"))

                if not rule_files:
                    raise ValueError(f"No YARA rule files found in {rules_path}")

                # Compile all rule files together using filepaths dict
                filepaths = {f.stem: str(f) for f in rule_files}
                self._rules = yara.compile(filepaths=filepaths)
                self._rule_count = len(rule_files)
        except yara.SyntaxError as e:
            # Extract helpful information from the YARA syntax error
            error_msg = str(e)
            rule_file = str(rules_path) if rules_path.is_file() else None

            # Try to parse line/column info from the error message
            context: dict[str, str | int] = {}
            if "line " in error_msg.lower():
                # Try to extract line number
                import re

                line_match = re.search(r"line\s+(\d+)", error_msg, re.IGNORECASE)
                if line_match:
                    context["line"] = int(line_match.group(1))

            raise YaraCompilationError(
                f"Failed to compile YARA rules: {error_msg}",
                rule_file=rule_file,
                context=context if context else None,
            ) from e
        except yara.Error as e:
            # Handle other YARA errors (e.g., warnings treated as errors)
            raise YaraCompilationError(
                f"YARA compilation error: {e}",
                rule_file=str(rules_path) if rules_path.is_file() else None,
            ) from e

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "yara"

    @property
    def rule_count(self) -> int:
        """Return the number of rule files loaded."""
        return self._rule_count

    @property
    def max_file_size(self) -> int:
        """Return the maximum file size in bytes."""
        return self._max_file_size

    @property
    def timeout(self) -> int:
        """Return the timeout in seconds."""
        return self._timeout

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect YARA rule matches in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        # YARA expects bytes for matching
        content_bytes = content.encode("utf-8", errors="replace")

        # Check file size before processing
        content_size = len(content_bytes)
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds YARA max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return []

        return self._match_and_extract(content_bytes, file_path)

    def detect_bytes(self, content: bytes, file_path: str = "") -> list[Finding]:
        """Detect YARA rule matches in raw byte content.

        This is a convenience method for scanning binary content directly
        without encoding conversion.

        Args:
            content: The raw byte content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        # Check file size before processing
        content_size = len(content)
        if content_size > self._max_file_size:
            self._logger.warning(
                "Skipping file %s: size %d bytes exceeds YARA max %d bytes",
                file_path,
                content_size,
                self._max_file_size,
            )
            return []

        return self._match_and_extract(content, file_path)

    def _match_and_extract(self, content: bytes, file_path: str) -> list[Finding]:
        """Match YARA rules against content and extract findings.

        Args:
            content: The byte content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each matched YARA rule.
        """
        if self._rules is None:
            return []

        findings: list[Finding] = []
        start_time = time.perf_counter()

        try:
            # Use timeout parameter for YARA matching
            matches = self._rules.match(data=content, timeout=self._timeout)

            for match in matches:
                rule_name = match.rule
                severity = self._severity_mapping.get(rule_name, Severity.MEDIUM)

                # Extract match strings
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_data = instance.matched_data.decode("utf-8", errors="replace")
                        except AttributeError:
                            matched_data = str(instance.matched_data)
                        matched_strings.append(matched_data)

                # Extract metadata from the rule
                metadata = dict(match.meta) if match.meta else {}
                metadata["rule_name"] = rule_name
                metadata["namespace"] = match.namespace
                metadata["tags"] = list(match.tags) if match.tags else []

                findings.append(
                    Finding(
                        file_path=file_path,
                        detector_name=f"yara:{rule_name}",
                        matches=matched_strings if matched_strings else [rule_name],
                        severity=severity,
                        metadata=metadata,
                    )
                )

        except yara.TimeoutError:
            elapsed = time.perf_counter() - start_time
            self._logger.warning(
                "YARA matching timed out on file %s after %.1fs (limit: %ds)",
                file_path,
                elapsed,
                self._timeout,
            )
        except yara.Error as e:
            # Handle other YARA matching errors gracefully
            self._logger.debug(
                "YARA error on file %s: %s",
                file_path,
                str(e),
            )
        except Exception as e:
            # Handle other errors (e.g., encoding issues)
            self._logger.debug(
                "Unexpected error during YARA matching on file %s: %s",
                file_path,
                str(e),
            )

        # Log performance metrics in verbose mode
        elapsed = time.perf_counter() - start_time
        self._logger.debug(
            "YaraDetector processed %s in %.3fs: %d findings",
            file_path,
            elapsed,
            len(findings),
        )

        return findings

    def get_rules_path(self) -> Path:
        """Return the path to the YARA rules.

        Returns:
            The Path object for the rules directory or file.
        """
        return self._rules_path

    def reload_rules(self) -> None:
        """Reload and recompile YARA rules from the configured path.

        This can be used to pick up changes to rule files without
        recreating the detector instance.

        Raises:
            yara.SyntaxError: If any YARA rule has syntax errors.
        """
        self._compile_rules()
