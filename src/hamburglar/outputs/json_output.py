"""JSON output formatter for Hamburglar.

This module provides a JSON output formatter that serializes scan results
to formatted JSON using Pydantic's model serialization.
"""

from hamburglar.core.models import ScanResult
from hamburglar.outputs import BaseOutput


class JsonOutput(BaseOutput):
    """Output formatter that serializes ScanResult to formatted JSON.

    Uses Pydantic's built-in JSON serialization to produce a human-readable
    JSON representation of scan results with proper indentation.

    Example:
        formatter = JsonOutput()
        json_str = formatter.format(scan_result)
        print(json_str)
    """

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "json"

    def format(self, result: ScanResult) -> str:
        """Format a scan result as JSON.

        Args:
            result: The ScanResult to format.

        Returns:
            A formatted JSON string representation of the scan result.
        """
        return result.model_dump_json(indent=2)
