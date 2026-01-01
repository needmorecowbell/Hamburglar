"""HTML output formatter for Hamburglar.

This module provides a standalone HTML report generator that displays
scan findings with syntax highlighting, severity color coding, and
collapsible sections for easy navigation.

The generated HTML is completely self-contained with no external dependencies,
making it viewable in any modern web browser.
"""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput

# Severity color mapping (CSS colors)
SEVERITY_COLORS: dict[Severity, dict[str, str]] = {
    Severity.CRITICAL: {"bg": "#fee2e2", "border": "#ef4444", "text": "#991b1b"},
    Severity.HIGH: {"bg": "#ffedd5", "border": "#f97316", "text": "#9a3412"},
    Severity.MEDIUM: {"bg": "#fef3c7", "border": "#f59e0b", "text": "#92400e"},
    Severity.LOW: {"bg": "#dbeafe", "border": "#3b82f6", "text": "#1e40af"},
    Severity.INFO: {"bg": "#f3f4f6", "border": "#6b7280", "text": "#374151"},
}

# Severity order for sorting (most severe first)
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class HtmlOutput(BaseOutput):
    """Output formatter that generates standalone HTML reports.

    This formatter creates a self-contained HTML report that includes:
    - Summary statistics (total findings, severity breakdown, files affected)
    - Findings grouped by file with collapsible sections
    - Syntax highlighting for matched content
    - Severity color coding for easy triage
    - No external dependencies (all CSS/JS inline)

    Example:
        formatter = HtmlOutput()
        html_report = formatter.format(scan_result)
        with open("report.html", "w") as f:
            f.write(html_report)
    """

    def __init__(self, title: str | None = None) -> None:
        """Initialize the HTML output formatter.

        Args:
            title: Optional custom title for the report.
        """
        self._title = title

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "html"

    @property
    def title(self) -> str | None:
        """Return the configured title."""
        return self._title

    def format(self, result: ScanResult) -> str:
        """Format a scan result as a standalone HTML report.

        Args:
            result: The ScanResult to format.

        Returns:
            A complete HTML document as a string.
        """
        title = self._title or f"Hamburglar Scan Report - {result.target_path}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Calculate statistics
        stats = self._calculate_stats(result)

        # Group findings by file
        findings_by_file = self._group_findings_by_file(result.findings)

        # Sort files by highest severity finding
        sorted_files = self._sort_files_by_severity(findings_by_file)

        # Build HTML sections
        summary_html = self._build_summary(stats, result)
        findings_html = self._build_findings_sections(sorted_files, findings_by_file)

        return self._build_document(title, timestamp, summary_html, findings_html)

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

    def _group_findings_by_file(self, findings: list[Finding]) -> dict[str, list[Finding]]:
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

    def _sort_files_by_severity(self, findings_by_file: dict[str, list[Finding]]) -> list[str]:
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

    def _build_summary(self, stats: dict[str, Any], result: ScanResult) -> str:
        """Build the HTML summary section.

        Args:
            stats: Statistics dictionary.
            result: Original scan result.

        Returns:
            HTML string for the summary section.
        """
        severity_badges = ""
        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = stats["severity_counts"].get(severity, 0)
            if count > 0:
                colors = SEVERITY_COLORS[severity]
                severity_badges += f"""
                    <span class="severity-badge" style="background-color: {colors["bg"]};
                           border-color: {colors["border"]}; color: {colors["text"]};">
                        {severity.value.upper()}: {count}
                    </span>
                """

        return f"""
        <div class="summary">
            <h2>Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats["total_findings"]}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats["total_matches"]}</div>
                    <div class="stat-label">Total Matches</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats["files_with_findings"]}</div>
                    <div class="stat-label">Files Affected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats["files_scanned"]}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
            </div>
            <div class="severity-summary">
                {severity_badges}
            </div>
            <div class="scan-info">
                <p><strong>Target:</strong> {html.escape(result.target_path)}</p>
                <p><strong>Duration:</strong> {stats["scan_duration"]:.2f}s</p>
                <p><strong>Files Skipped:</strong> {stats["files_skipped"]} |
                   <strong>Errors:</strong> {stats["errors"]}</p>
            </div>
        </div>
        """

    def _build_findings_sections(
        self, sorted_files: list[str], findings_by_file: dict[str, list[Finding]]
    ) -> str:
        """Build collapsible sections for each file's findings.

        Args:
            sorted_files: List of file paths sorted by severity.
            findings_by_file: Dictionary mapping files to their findings.

        Returns:
            HTML string containing all file sections.
        """
        if not sorted_files:
            return """
            <div class="no-findings">
                <h2>No Findings</h2>
                <p>The scan completed without detecting any sensitive information.</p>
            </div>
            """

        sections = []
        for file_path in sorted_files:
            findings = findings_by_file[file_path]
            section = self._build_file_section(file_path, findings)
            sections.append(section)

        return "\n".join(sections)

    def _build_file_section(self, file_path: str, findings: list[Finding]) -> str:
        """Build a collapsible section for a single file.

        Args:
            file_path: The path to the file.
            findings: List of findings for this file.

        Returns:
            HTML string for the file section.
        """
        # Sort findings by severity
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])

        # Get highest severity for section coloring
        highest_severity = sorted_findings[0].severity
        colors = SEVERITY_COLORS[highest_severity]

        finding_count = len(findings)
        finding_label = "finding" if finding_count == 1 else "findings"

        findings_html = ""
        for finding in sorted_findings:
            findings_html += self._build_finding_card(finding)

        return f"""
        <details class="file-section" open>
            <summary class="file-header" style="border-left-color: {colors["border"]};">
                <span class="file-path">{html.escape(file_path)}</span>
                <span class="finding-count">{finding_count} {finding_label}</span>
            </summary>
            <div class="findings-container">
                {findings_html}
            </div>
        </details>
        """

    def _build_finding_card(self, finding: Finding) -> str:
        """Build an HTML card for a single finding.

        Args:
            finding: The finding to render.

        Returns:
            HTML string for the finding card.
        """
        colors = SEVERITY_COLORS[finding.severity]
        line_info = self._get_line_info(finding)
        matches_html = self._build_matches_html(finding)
        metadata_html = self._build_metadata_html(finding)

        return f"""
        <div class="finding-card" style="border-left-color: {colors["border"]};">
            <div class="finding-header">
                <span class="severity-badge" style="background-color: {colors["bg"]};
                       border-color: {colors["border"]}; color: {colors["text"]};">
                    {finding.severity.value.upper()}
                </span>
                <span class="detector-name">{html.escape(finding.detector_name)}</span>
                {line_info}
            </div>
            {matches_html}
            {metadata_html}
        </div>
        """

    def _get_line_info(self, finding: Finding) -> str:
        """Extract and format line number information.

        Args:
            finding: The finding to extract line info from.

        Returns:
            HTML string with line number if available.
        """
        line = finding.metadata.get("line") or finding.metadata.get("line_number")
        if line is not None:
            return f'<span class="line-info">Line {line}</span>'
        return ""

    def _build_matches_html(self, finding: Finding) -> str:
        """Build HTML for displaying matched content with highlighting.

        Args:
            finding: The finding containing matches.

        Returns:
            HTML string displaying the matches.
        """
        if not finding.matches:
            return ""

        matches_list = ""
        for match in finding.matches:
            highlighted = self._highlight_match(match)
            matches_list += f'<div class="match-item">{highlighted}</div>'

        return f"""
        <div class="matches-section">
            <div class="matches-label">Matches:</div>
            {matches_list}
        </div>
        """

    def _highlight_match(self, match: str) -> str:
        """Apply syntax highlighting to a match string.

        Args:
            match: The matched string to highlight.

        Returns:
            HTML string with syntax highlighting applied.
        """
        escaped = html.escape(match)
        # Wrap in a code block with highlighted styling
        return f'<code class="match-highlight">{escaped}</code>'

    def _build_metadata_html(self, finding: Finding) -> str:
        """Build HTML for displaying finding metadata.

        Args:
            finding: The finding containing metadata.

        Returns:
            HTML string displaying relevant metadata.
        """
        context = finding.metadata.get("context")
        if not context:
            return ""

        escaped_context = html.escape(str(context))
        return f"""
        <div class="context-section">
            <div class="context-label">Context:</div>
            <pre class="context-code">{escaped_context}</pre>
        </div>
        """

    def _build_document(
        self, title: str, timestamp: str, summary_html: str, findings_html: str
    ) -> str:
        """Build the complete HTML document.

        Args:
            title: The document title.
            timestamp: The generation timestamp.
            summary_html: The summary section HTML.
            findings_html: The findings sections HTML.

        Returns:
            Complete HTML document as a string.
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(title)}</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background-color: #f9fafb;
            margin: 0;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        header h1 {{
            margin: 0 0 10px 0;
            font-size: 1.75rem;
        }}

        header .timestamp {{
            opacity: 0.9;
            font-size: 0.9rem;
        }}

        .summary {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}

        .summary h2 {{
            margin-top: 0;
            color: #1e3a5f;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: #f3f4f6;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: #1e3a5f;
        }}

        .stat-label {{
            color: #6b7280;
            font-size: 0.875rem;
            margin-top: 5px;
        }}

        .severity-summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }}

        .severity-badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
            border: 2px solid;
        }}

        .scan-info {{
            background: #f9fafb;
            padding: 15px;
            border-radius: 8px;
            font-size: 0.9rem;
        }}

        .scan-info p {{
            margin: 5px 0;
        }}

        .no-findings {{
            background: #d1fae5;
            color: #065f46;
            padding: 40px;
            border-radius: 12px;
            text-align: center;
        }}

        .no-findings h2 {{
            margin-top: 0;
        }}

        .file-section {{
            background: white;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}

        .file-header {{
            padding: 15px 20px;
            background: #f9fafb;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 4px solid;
            font-weight: 500;
        }}

        .file-header:hover {{
            background: #f3f4f6;
        }}

        .file-path {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.9rem;
            word-break: break-all;
        }}

        .finding-count {{
            background: #e5e7eb;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            color: #4b5563;
            white-space: nowrap;
            margin-left: 10px;
        }}

        .findings-container {{
            padding: 15px 20px;
        }}

        .finding-card {{
            background: #f9fafb;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}

        .finding-card:last-child {{
            margin-bottom: 0;
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}

        .detector-name {{
            font-weight: 600;
            color: #374151;
        }}

        .line-info {{
            color: #6b7280;
            font-size: 0.875rem;
            margin-left: auto;
        }}

        .matches-section {{
            margin-top: 10px;
        }}

        .matches-label,
        .context-label {{
            font-weight: 600;
            font-size: 0.8rem;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 5px;
        }}

        .match-item {{
            margin-bottom: 5px;
        }}

        .match-highlight {{
            background: #fef3c7;
            color: #92400e;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.875rem;
            word-break: break-all;
            display: inline-block;
        }}

        .context-section {{
            margin-top: 10px;
        }}

        .context-code {{
            background: #1f2937;
            color: #f9fafb;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.875rem;
            margin: 5px 0 0 0;
        }}

        footer {{
            text-align: center;
            color: #6b7280;
            font-size: 0.875rem;
            margin-top: 40px;
            padding: 20px;
        }}

        footer a {{
            color: #2563eb;
            text-decoration: none;
        }}

        footer a:hover {{
            text-decoration: underline;
        }}

        @media (max-width: 640px) {{
            body {{
                padding: 10px;
            }}

            header {{
                padding: 20px;
            }}

            header h1 {{
                font-size: 1.25rem;
            }}

            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .stat-value {{
                font-size: 1.5rem;
            }}

            .file-header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }}

            .finding-count {{
                margin-left: 0;
            }}

            .line-info {{
                margin-left: 0;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{html.escape(title)}</h1>
            <div class="timestamp">Generated: {timestamp}</div>
        </header>

        {summary_html}

        <main>
            {findings_html}
        </main>

        <footer>
            <p>Generated by <a href="https://github.com/needmorecowbell/Hamburglar"
               target="_blank">Hamburglar</a> - Secret Scanner</p>
        </footer>
    </div>
</body>
</html>
"""
