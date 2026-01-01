"""Markdown output formatter for Hamburglar.

This module provides a GitHub-flavored Markdown report generator that displays
scan findings in a format suitable for PR comments, issue creation, or
documentation.

The generated Markdown uses collapsible details sections for organizing
findings by file and includes relative file path links.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput


# Severity order for sorting (most severe first)
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Severity emoji mapping for visual indicators
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":warning:",
    Severity.MEDIUM: ":large_orange_diamond:",
    Severity.LOW: ":small_blue_diamond:",
    Severity.INFO: ":information_source:",
}


class MarkdownOutput(BaseOutput):
    """Output formatter that generates GitHub-flavored Markdown reports.

    This formatter creates a Markdown report that includes:
    - Summary table with total findings, severity breakdown, and scan stats
    - Findings grouped by file with collapsible details sections
    - Relative file path links for easy navigation
    - Severity badges with emoji indicators

    The output is designed to be suitable for:
    - GitHub PR comments
    - GitHub issue creation
    - Wiki pages or documentation
    - Any Markdown-compatible display

    Example:
        formatter = MarkdownOutput()
        markdown_report = formatter.format(scan_result)
        with open("report.md", "w") as f:
            f.write(markdown_report)
    """

    def __init__(
        self, title: str | None = None, base_path: str | None = None
    ) -> None:
        """Initialize the Markdown output formatter.

        Args:
            title: Optional custom title for the report.
            base_path: Optional base path to strip from file paths for
                creating relative links. If not provided, full paths are used.
        """
        self._title = title
        self._base_path = base_path

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "markdown"

    @property
    def title(self) -> str | None:
        """Return the configured title."""
        return self._title

    @property
    def base_path(self) -> str | None:
        """Return the configured base path."""
        return self._base_path

    def format(self, result: ScanResult) -> str:
        """Format a scan result as GitHub-flavored Markdown.

        Args:
            result: The ScanResult to format.

        Returns:
            A complete Markdown document as a string.
        """
        title = self._title or f"Hamburglar Scan Report - {result.target_path}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Calculate statistics
        stats = self._calculate_stats(result)

        # Group findings by file
        findings_by_file = self._group_findings_by_file(result.findings)

        # Sort files by highest severity finding
        sorted_files = self._sort_files_by_severity(findings_by_file)

        # Build Markdown sections
        lines: list[str] = []

        # Title and timestamp
        lines.append(f"# {self._escape_markdown(title)}")
        lines.append("")
        lines.append(f"*Generated: {timestamp}*")
        lines.append("")

        # Summary section
        lines.extend(self._build_summary(stats, result))

        # Findings section
        lines.extend(self._build_findings_sections(sorted_files, findings_by_file))

        # Footer
        lines.extend(self._build_footer())

        return "\n".join(lines)

    def _calculate_stats(self, result: ScanResult) -> dict[str, Any]:
        """Calculate summary statistics from scan results.

        Args:
            result: The ScanResult to analyze.

        Returns:
            Dictionary containing various statistics.
        """
        severity_counts: dict[Severity, int] = defaultdict(int)
        files_with_findings: set[str] = set()
        total_matches = 0

        for finding in result.findings:
            severity_counts[finding.severity] += 1
            files_with_findings.add(finding.file_path)
            total_matches += len(finding.matches) if finding.matches else 1

        return {
            "total_findings": len(result.findings),
            "total_matches": total_matches,
            "files_with_findings": len(files_with_findings),
            "severity_counts": dict(severity_counts),
            "scan_duration": result.scan_duration,
            "files_scanned": result.stats.get("files_scanned", 0),
            "files_skipped": result.stats.get("files_skipped", 0),
            "errors": result.stats.get("errors", 0),
        }

    def _group_findings_by_file(
        self, findings: list[Finding]
    ) -> dict[str, list[Finding]]:
        """Group findings by their file path.

        Args:
            findings: List of findings to group.

        Returns:
            Dictionary mapping file paths to their findings.
        """
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            grouped[finding.file_path].append(finding)
        return dict(grouped)

    def _sort_files_by_severity(
        self, findings_by_file: dict[str, list[Finding]]
    ) -> list[str]:
        """Sort files by the highest severity finding they contain.

        Args:
            findings_by_file: Dictionary of file paths to findings.

        Returns:
            List of file paths sorted by severity (most severe first).
        """

        def get_highest_severity(file_path: str) -> tuple[int, str]:
            findings = findings_by_file[file_path]
            min_order = min(SEVERITY_ORDER[f.severity] for f in findings)
            return (min_order, file_path)

        return sorted(findings_by_file.keys(), key=get_highest_severity)

    def _build_summary(self, stats: dict[str, Any], result: ScanResult) -> list[str]:
        """Build the Markdown summary section.

        Args:
            stats: Statistics dictionary.
            result: Original scan result.

        Returns:
            List of Markdown lines for the summary section.
        """
        lines: list[str] = []

        lines.append("## Summary")
        lines.append("")

        # Summary table
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Findings | {stats['total_findings']} |")
        lines.append(f"| Total Matches | {stats['total_matches']} |")
        lines.append(f"| Files Affected | {stats['files_with_findings']} |")
        lines.append(f"| Files Scanned | {stats['files_scanned']} |")
        lines.append(f"| Duration | {stats['scan_duration']:.2f}s |")
        lines.append("")

        # Severity breakdown
        if stats["severity_counts"]:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")

            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                count = stats["severity_counts"].get(severity, 0)
                if count > 0:
                    emoji = SEVERITY_EMOJI[severity]
                    lines.append(f"| {emoji} {severity.value.upper()} | {count} |")

            lines.append("")

        # Target path info
        lines.append(f"**Target:** `{self._escape_markdown(result.target_path)}`")
        lines.append("")

        return lines

    def _build_findings_sections(
        self, sorted_files: list[str], findings_by_file: dict[str, list[Finding]]
    ) -> list[str]:
        """Build collapsible sections for each file's findings.

        Args:
            sorted_files: List of file paths sorted by severity.
            findings_by_file: Dictionary mapping files to their findings.

        Returns:
            List of Markdown lines containing all file sections.
        """
        lines: list[str] = []

        lines.append("## Findings")
        lines.append("")

        if not sorted_files:
            lines.append("> :white_check_mark: **No findings detected.**")
            lines.append(">")
            lines.append("> The scan completed without detecting any sensitive information.")
            lines.append("")
            return lines

        for file_path in sorted_files:
            findings = findings_by_file[file_path]
            lines.extend(self._build_file_section(file_path, findings))

        return lines

    def _build_file_section(
        self, file_path: str, findings: list[Finding]
    ) -> list[str]:
        """Build a collapsible section for a single file.

        Args:
            file_path: The path to the file.
            findings: List of findings for this file.

        Returns:
            List of Markdown lines for the file section.
        """
        lines: list[str] = []

        # Sort findings by severity
        sorted_findings = sorted(
            findings, key=lambda f: SEVERITY_ORDER[f.severity]
        )

        # Get highest severity for section badge
        highest_severity = sorted_findings[0].severity
        emoji = SEVERITY_EMOJI[highest_severity]

        finding_count = len(findings)
        finding_label = "finding" if finding_count == 1 else "findings"

        # Create relative path link
        display_path = self._get_relative_path(file_path)
        file_link = self._create_file_link(file_path)

        # Collapsible details section
        lines.append("<details>")
        lines.append(
            f"<summary>{emoji} <strong>{file_link}</strong> "
            f"({finding_count} {finding_label})</summary>"
        )
        lines.append("")

        for finding in sorted_findings:
            lines.extend(self._build_finding_entry(finding))

        lines.append("</details>")
        lines.append("")

        return lines

    def _build_finding_entry(self, finding: Finding) -> list[str]:
        """Build a Markdown entry for a single finding.

        Args:
            finding: The finding to render.

        Returns:
            List of Markdown lines for the finding entry.
        """
        lines: list[str] = []
        emoji = SEVERITY_EMOJI[finding.severity]
        line_info = self._get_line_info(finding)

        # Finding header
        header = f"#### {emoji} {finding.severity.value.upper()} - {self._escape_markdown(finding.detector_name)}"
        if line_info:
            header += f" (Line {line_info})"
        lines.append(header)
        lines.append("")

        # Matches
        if finding.matches:
            lines.append("**Matches:**")
            for match in finding.matches:
                escaped_match = self._escape_markdown(match)
                lines.append(f"- `{escaped_match}`")
            lines.append("")

        # Context
        context = finding.metadata.get("context")
        if context:
            lines.append("**Context:**")
            lines.append("```")
            lines.append(str(context))
            lines.append("```")
            lines.append("")

        return lines

    def _get_line_info(self, finding: Finding) -> str | None:
        """Extract line number information from finding metadata.

        Args:
            finding: The finding to extract line info from.

        Returns:
            Line number as string if available, None otherwise.
        """
        line = finding.metadata.get("line") or finding.metadata.get("line_number")
        if line is not None:
            return str(line)
        return None

    def _get_relative_path(self, file_path: str) -> str:
        """Get a relative path from the file path.

        Args:
            file_path: The absolute or full file path.

        Returns:
            Relative path if base_path is set, otherwise the original path.
        """
        if self._base_path and file_path.startswith(self._base_path):
            relative = file_path[len(self._base_path) :]
            # Remove leading slash if present
            if relative.startswith("/"):
                relative = relative[1:]
            return relative
        return file_path

    def _create_file_link(self, file_path: str) -> str:
        """Create a Markdown link to a file.

        Creates a relative path link suitable for GitHub navigation.

        Args:
            file_path: The path to the file.

        Returns:
            Markdown link string.
        """
        display_path = self._get_relative_path(file_path)
        escaped_path = self._escape_markdown(display_path)

        # Create a link-safe path (replace spaces with %20)
        link_path = display_path.replace(" ", "%20")

        return f"[`{escaped_path}`]({link_path})"

    def _build_footer(self) -> list[str]:
        """Build the Markdown footer.

        Returns:
            List of Markdown lines for the footer.
        """
        lines: list[str] = []
        lines.append("---")
        lines.append("")
        lines.append(
            "*Generated by [Hamburglar](https://github.com/needmorecowbell/Hamburglar)*"
        )
        lines.append("")
        return lines

    def _escape_markdown(self, text: str) -> str:
        """Escape special Markdown characters in text.

        Args:
            text: The text to escape.

        Returns:
            Text with special Markdown characters escaped.
        """
        # Characters that have special meaning in Markdown
        special_chars = ["\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", ".", "!", "|"]

        result = text
        for char in special_chars:
            result = result.replace(char, f"\\{char}")

        return result
