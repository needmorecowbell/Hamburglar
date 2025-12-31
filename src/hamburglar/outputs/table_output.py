"""Table output formatter for Hamburglar.

This module provides a table output formatter that renders scan results
as a console-friendly table using Rich.
"""

from io import StringIO

from rich.console import Console
from rich.table import Table

from hamburglar.core.models import ScanResult, Severity
from hamburglar.outputs import BaseOutput

# Severity colors for visual distinction
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class TableOutput(BaseOutput):
    """Output formatter that renders ScanResult as a Rich table.

    Creates a console-friendly table showing file path, detector name,
    match count, and severity for each finding. Uses color coding to
    visually distinguish severity levels.

    Example:
        formatter = TableOutput()
        table_str = formatter.format(scan_result)
        print(table_str)
    """

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "table"

    def format(self, result: ScanResult) -> str:
        """Format a scan result as a Rich table.

        Args:
            result: The ScanResult to format.

        Returns:
            A formatted table string representation of the scan result.
        """
        # Create the main findings table
        table = Table(
            title=f"Scan Results: {result.target_path}",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("File Path", style="white", no_wrap=False)
        table.add_column("Detector", style="cyan")
        table.add_column("Matches", justify="right", style="magenta")
        table.add_column("Severity", justify="center")

        # Add rows for each finding
        for finding in result.findings:
            severity_style = SEVERITY_COLORS.get(finding.severity, "white")
            table.add_row(
                finding.file_path,
                finding.detector_name,
                str(len(finding.matches)),
                f"[{severity_style}]{finding.severity.value.upper()}[/{severity_style}]",
            )

        # Render table to string
        string_io = StringIO()
        console = Console(file=string_io, force_terminal=True, width=120)
        console.print(table)

        # Add summary statistics
        stats = result.stats
        summary_lines = [
            "",
            "[bold]Scan Summary[/bold]",
            f"  Duration: {result.scan_duration:.2f}s",
            f"  Total findings: {len(result.findings)}",
        ]

        if stats:
            if "files_scanned" in stats:
                summary_lines.append(f"  Files scanned: {stats['files_scanned']}")
            if "files_skipped" in stats:
                summary_lines.append(f"  Files skipped: {stats['files_skipped']}")
            if "errors" in stats:
                summary_lines.append(f"  Errors: {stats['errors']}")

        # Print severity breakdown if there are findings
        if result.findings:
            severity_counts: dict[str, int] = {}
            for finding in result.findings:
                sev = finding.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            summary_lines.append("  By severity:")
            for severity in Severity:
                count = severity_counts.get(severity.value, 0)
                if count > 0:
                    style = SEVERITY_COLORS.get(severity, "white")
                    summary_lines.append(
                        f"    [{style}]{severity.value.upper()}: {count}[/{style}]"
                    )

        for line in summary_lines:
            console.print(line)

        return string_io.getvalue()
