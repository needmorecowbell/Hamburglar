"""CSV output formatter for Hamburglar.

This module provides an RFC 4180 compliant CSV output formatter that enables
integration with spreadsheet tools and data analysis pipelines.

RFC 4180 specification: https://tools.ietf.org/html/rfc4180
"""

from __future__ import annotations

import csv
import io

from hamburglar.core.models import Finding, ScanResult
from hamburglar.outputs import BaseOutput

# Default CSV headers
DEFAULT_HEADERS = [
    "file",
    "detector",
    "match",
    "severity",
    "line_number",
    "context",
]


class CsvOutput(BaseOutput):
    """Output formatter that generates RFC 4180 compliant CSV.

    This formatter outputs scan results as a CSV file suitable for
    spreadsheet applications and data analysis tools.

    Attributes:
        delimiter: The character used to separate fields (default: comma).
        include_headers: Whether to include header row (default: True).

    Example:
        formatter = CsvOutput()
        csv_content = formatter.format(scan_result)
        print(csv_content)

        # Custom delimiter
        formatter = CsvOutput(delimiter=";")
        csv_content = formatter.format(scan_result)
    """

    def __init__(
        self,
        delimiter: str = ",",
        include_headers: bool = True,
    ) -> None:
        """Initialize the CSV output formatter.

        Args:
            delimiter: The character used to separate fields.
            include_headers: Whether to include the header row.
        """
        self._delimiter = delimiter
        self._include_headers = include_headers

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "csv"

    @property
    def delimiter(self) -> str:
        """Return the configured delimiter."""
        return self._delimiter

    @property
    def include_headers(self) -> bool:
        """Return whether headers are included."""
        return self._include_headers

    def format(self, result: ScanResult) -> str:
        """Format a scan result as RFC 4180 compliant CSV.

        Args:
            result: The ScanResult to format.

        Returns:
            An RFC 4180 compliant CSV string.
        """
        output = io.StringIO()
        writer = csv.writer(
            output,
            delimiter=self._delimiter,
            quoting=csv.QUOTE_MINIMAL,
            lineterminator="\r\n",  # RFC 4180 requires CRLF
        )

        # Write headers if enabled
        if self._include_headers:
            writer.writerow(DEFAULT_HEADERS)

        # Write findings
        for finding in result.findings:
            rows = self._finding_to_rows(finding)
            for row in rows:
                writer.writerow(row)

        return output.getvalue()

    def _finding_to_rows(self, finding: Finding) -> list[list[str]]:
        """Convert a finding to one or more CSV rows.

        Each match in a finding becomes a separate row.

        Args:
            finding: The Finding to convert.

        Returns:
            A list of row lists, each containing field values.
        """
        rows = []

        # Extract common fields
        file_path = finding.file_path
        detector_name = finding.detector_name
        severity = finding.severity.value
        line_number = self._get_line_number(finding)
        context = self._get_context(finding)

        # Create a row for each match, or one row if no matches
        matches = finding.matches if finding.matches else [""]
        for match in matches:
            row = [
                file_path,
                detector_name,
                match,
                severity,
                line_number,
                context,
            ]
            rows.append(row)

        return rows

    def _get_line_number(self, finding: Finding) -> str:
        """Extract line number from finding metadata.

        Args:
            finding: The Finding to extract line number from.

        Returns:
            Line number as string, or empty string if not available.
        """
        line = finding.metadata.get("line") or finding.metadata.get("line_number")
        return str(line) if line is not None else ""

    def _get_context(self, finding: Finding) -> str:
        """Extract context from finding metadata.

        Args:
            finding: The Finding to extract context from.

        Returns:
            Context string, or empty string if not available.
        """
        context = finding.metadata.get("context")
        return str(context) if context is not None else ""
