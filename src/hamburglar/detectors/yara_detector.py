"""YARA-based detector for file type and malware detection.

This module provides a detector that uses YARA rules to identify
file types, malware signatures, and other patterns in file content.
"""

from pathlib import Path

import yara

from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector


class YaraDetector(BaseDetector):
    """Detector that uses YARA rules to find patterns in content.

    The YaraDetector compiles YARA rules from a directory and matches
    them against file content to detect file types, malware, and other
    patterns defined in the rules.

    Example:
        detector = YaraDetector("/path/to/yara/rules")
        findings = detector.detect(file_content, "path/to/file.bin")
    """

    def __init__(
        self,
        rules_path: str | Path,
        severity_mapping: dict[str, Severity] | None = None,
    ) -> None:
        """Initialize the YaraDetector.

        Args:
            rules_path: Path to a directory containing .yar/.yara files,
                       or path to a single YARA rule file.
            severity_mapping: Optional dictionary mapping rule names to severity
                             levels. Rules not in this mapping use MEDIUM severity.

        Raises:
            FileNotFoundError: If the rules_path doesn't exist.
            yara.SyntaxError: If any YARA rule has syntax errors.
        """
        self._rules_path = Path(rules_path)
        self._severity_mapping = severity_mapping or {}
        self._rules: yara.Rules | None = None
        self._rule_count = 0

        if not self._rules_path.exists():
            raise FileNotFoundError(f"YARA rules path not found: {rules_path}")

        self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile YARA rules from the configured path.

        This method discovers all .yar and .yara files in the rules path
        (recursively if it's a directory) and compiles them together.

        Raises:
            yara.SyntaxError: If any YARA rule has syntax errors.
            ValueError: If no valid YARA rule files are found.
        """
        rules_path = self._rules_path

        if rules_path.is_file():
            # Single file - compile directly
            self._rules = yara.compile(filepath=str(rules_path))
            self._rule_count = 1
        else:
            # Directory - find all .yar and .yara files
            rule_files = list(rules_path.glob("**/*.yar")) + list(
                rules_path.glob("**/*.yara")
            )

            if not rule_files:
                raise ValueError(f"No YARA rule files found in {rules_path}")

            # Compile all rule files together using filepaths dict
            filepaths = {f.stem: str(f) for f in rule_files}
            self._rules = yara.compile(filepaths=filepaths)
            self._rule_count = len(rule_files)

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "yara"

    @property
    def rule_count(self) -> int:
        """Return the number of rule files loaded."""
        return self._rule_count

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

        findings: list[Finding] = []

        try:
            # YARA expects bytes for matching
            content_bytes = content.encode("utf-8", errors="replace")
            matches = self._rules.match(data=content_bytes)

            for match in matches:
                rule_name = match.rule
                severity = self._severity_mapping.get(rule_name, Severity.MEDIUM)

                # Extract match strings
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        # Get the matched data as string or hex representation
                        try:
                            matched_data = instance.matched_data.decode(
                                "utf-8", errors="replace"
                            )
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

        except yara.Error:
            # Handle YARA matching errors gracefully (e.g., timeout, memory issues)
            pass
        except Exception:
            # Handle other errors (e.g., encoding issues)
            pass

        return findings

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

        findings: list[Finding] = []

        try:
            matches = self._rules.match(data=content)

            for match in matches:
                rule_name = match.rule
                severity = self._severity_mapping.get(rule_name, Severity.MEDIUM)

                # Extract match strings
                matched_strings = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        try:
                            matched_data = instance.matched_data.decode(
                                "utf-8", errors="replace"
                            )
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

        except yara.Error:
            pass
        except Exception:
            pass

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
