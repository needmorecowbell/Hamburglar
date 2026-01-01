"""SARIF output formatter for Hamburglar.

This module provides a SARIF (Static Analysis Results Interchange Format) 2.1.0
output formatter that enables integration with GitHub Advanced Security,
Azure DevOps, and other code scanning tools.

SARIF specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput


# SARIF 2.1.0 schema URI
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Hamburglar tool information
TOOL_NAME = "Hamburglar"
TOOL_VERSION = "2.0.0"
TOOL_INFORMATION_URI = "https://github.com/needmorecowbell/Hamburglar"

# Map Hamburglar severity to SARIF level
# SARIF levels: error, warning, note, none
SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Map Hamburglar severity to SARIF security-severity score (0.0 - 10.0)
SEVERITY_TO_SECURITY_SCORE: dict[Severity, float] = {
    Severity.CRITICAL: 9.0,
    Severity.HIGH: 7.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}


class SarifOutput(BaseOutput):
    """Output formatter that generates SARIF 2.1.0 compliant JSON.

    SARIF (Static Analysis Results Interchange Format) is a standardized format
    for the output of static analysis tools. This formatter enables Hamburglar's
    findings to be consumed by tools like GitHub Advanced Security, Azure DevOps,
    and other code scanning platforms.

    Example:
        formatter = SarifOutput()
        sarif_json = formatter.format(scan_result)
        print(sarif_json)
    """

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "sarif"

    def format(self, result: ScanResult) -> str:
        """Format a scan result as SARIF 2.1.0 JSON.

        Args:
            result: The ScanResult to format.

        Returns:
            A SARIF 2.1.0 compliant JSON string.
        """
        sarif = self._build_sarif(result)
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _build_sarif(self, result: ScanResult) -> dict[str, Any]:
        """Build the complete SARIF document structure.

        Args:
            result: The ScanResult to convert.

        Returns:
            A dictionary representing the SARIF document.
        """
        # Collect unique detector names to build rule definitions
        detector_names = self._get_unique_detectors(result.findings)
        rules = [self._build_rule(name) for name in sorted(detector_names)]

        # Build results from findings
        results = []
        for finding in result.findings:
            sarif_result = self._build_result(finding, detector_names)
            results.append(sarif_result)

        return {
            "$schema": SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": TOOL_VERSION,
                            "informationUri": TOOL_INFORMATION_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ],
                }
            ],
        }

    def _get_unique_detectors(self, findings: list[Finding]) -> list[str]:
        """Extract unique detector names from findings.

        Args:
            findings: List of findings to extract detector names from.

        Returns:
            Sorted list of unique detector names.
        """
        return sorted(set(f.detector_name for f in findings))

    def _build_rule(self, detector_name: str) -> dict[str, Any]:
        """Build a SARIF rule definition for a detector.

        Args:
            detector_name: The name of the detector.

        Returns:
            A SARIF rule definition dictionary.
        """
        # Create a rule ID from the detector name
        rule_id = f"hamburglar/{detector_name}"

        return {
            "id": rule_id,
            "name": detector_name,
            "shortDescription": {
                "text": f"Detected by {detector_name} detector",
            },
            "fullDescription": {
                "text": f"This rule detects potential sensitive information identified by the {detector_name} detector.",
            },
            "help": {
                "text": f"Review and remediate findings from the {detector_name} detector.",
                "markdown": f"Review and remediate findings from the **{detector_name}** detector.",
            },
            "properties": {
                "tags": ["security", "secrets", detector_name],
            },
        }

    def _build_result(
        self, finding: Finding, detector_names: list[str]
    ) -> dict[str, Any]:
        """Build a SARIF result object from a finding.

        Args:
            finding: The Finding to convert.
            detector_names: List of all detector names (for rule index).

        Returns:
            A SARIF result dictionary.
        """
        rule_id = f"hamburglar/{finding.detector_name}"
        rule_index = detector_names.index(finding.detector_name)
        level = SEVERITY_TO_SARIF_LEVEL[finding.severity]
        security_severity = SEVERITY_TO_SECURITY_SCORE[finding.severity]

        # Build the message with match information
        if finding.matches:
            match_count = len(finding.matches)
            if match_count == 1:
                message_text = f"Found 1 potential secret: {self._redact_match(finding.matches[0])}"
            else:
                message_text = f"Found {match_count} potential secrets"
        else:
            message_text = f"Potential sensitive information detected by {finding.detector_name}"

        # Build location information
        locations = self._build_locations(finding)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {
                "text": message_text,
            },
            "locations": locations,
            "properties": {
                "security-severity": str(security_severity),
                "detector": finding.detector_name,
                "severity": finding.severity.value,
            },
        }

        # Add fingerprint for deduplication
        result["fingerprints"] = {
            "hamburglar/v1": self._compute_fingerprint(finding),
        }

        return result

    def _build_locations(self, finding: Finding) -> list[dict[str, Any]]:
        """Build SARIF location objects from a finding.

        Args:
            finding: The Finding to extract location from.

        Returns:
            A list of SARIF location dictionaries.
        """
        # Build physical location
        physical_location: dict[str, Any] = {
            "artifactLocation": {
                "uri": finding.file_path,
                "uriBaseId": "%SRCROOT%",
            },
        }

        # Add region if line number is available in metadata
        line_number = finding.metadata.get("line") or finding.metadata.get(
            "line_number"
        )
        if line_number is not None:
            physical_location["region"] = {
                "startLine": int(line_number),
            }

            # Add column info if available
            column = finding.metadata.get("column")
            if column is not None:
                physical_location["region"]["startColumn"] = int(column)

            # Add end line if available
            end_line = finding.metadata.get("end_line")
            if end_line is not None:
                physical_location["region"]["endLine"] = int(end_line)

        return [{"physicalLocation": physical_location}]

    def _redact_match(self, match: str, visible_chars: int = 4) -> str:
        """Redact a match string for safe display.

        Args:
            match: The match string to redact.
            visible_chars: Number of characters to show at start and end.

        Returns:
            A redacted version of the match string.
        """
        if len(match) <= visible_chars * 2:
            return match

        return f"{match[:visible_chars]}...{match[-visible_chars:]}"

    def _compute_fingerprint(self, finding: Finding) -> str:
        """Compute a stable fingerprint for deduplication.

        Args:
            finding: The Finding to compute fingerprint for.

        Returns:
            A fingerprint string for the finding.
        """
        import hashlib

        # Combine key attributes for fingerprinting
        parts = [
            finding.file_path,
            finding.detector_name,
            str(finding.metadata.get("line", "")),
        ]

        # Include first match if available (for uniqueness)
        if finding.matches:
            parts.append(finding.matches[0])

        fingerprint_input = "|".join(parts)
        return hashlib.sha256(fingerprint_input.encode()).hexdigest()[:32]
