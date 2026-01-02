"""Table output formatter for Hamburglar.

This module provides a table output formatter that renders scan results
as a console-friendly table using Rich.
"""

import sys
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

        # Or print directly to console for proper terminal width handling:
        formatter.print_to_console(scan_result, console)
    """

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "table"

    def _format_evidence(self, matches: list[str], max_matches: int = 2, max_length: int = 60) -> str:
        """Format matches as evidence string for display.

        Args:
            matches: List of matched strings.
            max_matches: Maximum number of matches to show.
            max_length: Maximum length per match before truncation.

        Returns:
            Formatted evidence string.
        """
        if not matches:
            return "[dim]No matches[/dim]"

        # Show up to max_matches, truncate long ones
        evidence_parts = []
        for match in matches[:max_matches]:
            # Truncate long matches
            if len(match) > max_length:
                truncated = match[:max_length - 3] + "..."
            else:
                truncated = match
            evidence_parts.append(truncated)

        evidence = " | ".join(evidence_parts)

        # Indicate if there are more matches
        if len(matches) > max_matches:
            evidence += f" [dim](+{len(matches) - max_matches} more)[/dim]"

        return evidence

    def _build_table(self, result: ScanResult) -> Table:
        """Build the Rich Table object for the scan result.

        Args:
            result: The ScanResult to format.

        Returns:
            A Rich Table object ready for rendering.
        """
        table = Table(
            title=f"Scan Results: {result.target_path}",
            show_header=True,
            header_style="bold cyan",
            expand=False,
        )

        table.add_column("File Path", style="white", no_wrap=True, overflow="ellipsis", max_width=80)
        table.add_column("Detector", style="cyan", no_wrap=True, min_width=20)
        table.add_column("Matches", justify="right", style="magenta", no_wrap=True, min_width=7)
        table.add_column("Evidence", style="yellow", no_wrap=False, overflow="ellipsis", max_width=80)
        table.add_column("Severity", justify="center", no_wrap=True, min_width=10)

        for finding in result.findings:
            severity_style = SEVERITY_COLORS.get(finding.severity, "white")
            evidence = self._format_evidence(finding.matches)
            table.add_row(
                finding.file_path,
                finding.detector_name,
                str(len(finding.matches)),
                evidence,
                f"[{severity_style}]{finding.severity.value.upper()}[/{severity_style}]",
            )

        return table

    def _build_summary_lines(self, result: ScanResult) -> list[str]:
        """Build the summary lines for the scan result.

        Args:
            result: The ScanResult to summarize.

        Returns:
            A list of Rich-formatted summary lines.
        """
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

        return summary_lines

    def print_to_console(self, result: ScanResult, console: Console) -> None:
        """Print the scan result directly to a Rich Console.

        This method prints directly to the provided console, allowing Rich
        to properly handle terminal width and avoid line-wrapping issues.

        Args:
            result: The ScanResult to display.
            console: The Rich Console to print to.
        """
        table = self._build_table(result)
        console.print(table)

        for line in self._build_summary_lines(result):
            console.print(line)

    def format(self, result: ScanResult) -> str:
        """Format a scan result as a Rich table string.

        Note: For terminal output, prefer using print_to_console() to avoid
        width-related rendering issues.

        Args:
            result: The ScanResult to format.

        Returns:
            A formatted table string representation of the scan result.
        """
        table = self._build_table(result)

        # Render table to string with a wide width to avoid truncation
        # Check if stdout is a terminal to determine if we should output ANSI codes
        # Only output ANSI codes when stdout is actually a terminal, otherwise
        # they may be displayed literally
        string_io = StringIO()
        # Check if stdout is a TTY (terminal)
        is_terminal = sys.stdout.isatty() if hasattr(sys.stdout, 'isatty') else False
        # Only force terminal mode if stdout is actually a terminal
        # This ensures ANSI codes are only output when they'll be properly interpreted
        console = Console(file=string_io, force_terminal=is_terminal, width=200, legacy_windows=False)
        console.print(table)

        for line in self._build_summary_lines(result):
            console.print(line)

        return string_io.getvalue()
