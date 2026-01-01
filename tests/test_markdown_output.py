"""Comprehensive tests for Markdown output formatter.

This module tests the Markdown output formatter for proper GitHub-flavored
Markdown generation, summary table accuracy, collapsible details sections,
relative file path links, and suitability for PR comments or issue creation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput
from hamburglar.outputs.markdown_output import (
    SEVERITY_EMOJI,
    SEVERITY_ORDER,
    MarkdownOutput,
)

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def empty_scan_result() -> ScanResult:
    """Return a scan result with no findings."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[],
        scan_duration=1.5,
        stats={"files_scanned": 10, "files_skipped": 2, "errors": 0},
    )


@pytest.fixture
def single_finding_result() -> ScanResult:
    """Return a scan result with a single finding."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE"],
                severity=Severity.HIGH,
                metadata={"line": 5},
            )
        ],
        scan_duration=2.0,
        stats={"files_scanned": 5, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def multiple_findings_result() -> ScanResult:
    """Return a scan result with multiple findings across different severities."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE", "AKIABCDEFGHIJ1234567"],
                severity=Severity.CRITICAL,
                metadata={"line": 5, "context": "aws_access_key_id = AKIA..."},
            ),
            Finding(
                file_path="/tmp/test/config.py",
                detector_name="email",
                matches=["admin@example.com"],
                severity=Severity.LOW,
                metadata={"line_number": 10},
            ),
            Finding(
                file_path="/tmp/test/database.yml",
                detector_name="password",
                matches=["password123"],
                severity=Severity.HIGH,
                metadata={"line": 15, "context": "password: password123"},
            ),
            Finding(
                file_path="/tmp/test/notes.txt",
                detector_name="url",
                matches=["http://internal.server.local/api"],
                severity=Severity.INFO,
            ),
            Finding(
                file_path="/tmp/test/api.js",
                detector_name="api_key",
                matches=["sk_live_1234567890abcdef"],
                severity=Severity.MEDIUM,
                metadata={"line": 42},
            ),
        ],
        scan_duration=5.5,
        stats={"files_scanned": 100, "files_skipped": 5, "errors": 1},
    )


@pytest.fixture
def multi_findings_same_file_result() -> ScanResult:
    """Return a scan result with multiple findings in the same file."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE"],
                severity=Severity.CRITICAL,
                metadata={"line": 5},
            ),
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="password",
                matches=["mysecretpass"],
                severity=Severity.HIGH,
                metadata={"line": 10},
            ),
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="email",
                matches=["secret@company.com"],
                severity=Severity.LOW,
                metadata={"line": 15},
            ),
        ],
        scan_duration=1.0,
        stats={"files_scanned": 1, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def special_characters_result() -> ScanResult:
    """Return a scan result with special Markdown characters that need escaping."""
    return ScanResult(
        target_path="/tmp/test_*_project",
        findings=[
            Finding(
                file_path="/tmp/test/file_[1].txt",
                detector_name="test_detector",
                matches=["value*with_special*chars", "code`with`backticks"],
                severity=Severity.HIGH,
                metadata={
                    "line": 1,
                    "context": "# Comment with *bold* and _italic_",
                },
            ),
        ],
        scan_duration=0.5,
        stats={"files_scanned": 1, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def unicode_result() -> ScanResult:
    """Return a scan result with Unicode characters."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test.txt",
                detector_name="unicode_detector",
                matches=["secret123", "API_KEY=abc"],
                severity=Severity.MEDIUM,
                metadata={"line": 1, "context": "username and password"},
            ),
        ],
        scan_duration=0.5,
        stats={"files_scanned": 1, "files_skipped": 0, "errors": 0},
    )


# ============================================================================
# Markdown Output - GitHub-Flavored Markdown Tests
# ============================================================================


class TestMarkdownOutputGFM:
    """Test that Markdown output produces valid GitHub-flavored Markdown."""

    def test_starts_with_heading(self, single_finding_result: ScanResult) -> None:
        """Test that output starts with a level 1 heading."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert output.startswith("# ")

    def test_includes_summary_heading(self, single_finding_result: ScanResult) -> None:
        """Test that output includes a Summary heading."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "## Summary" in output

    def test_includes_findings_heading(self, single_finding_result: ScanResult) -> None:
        """Test that output includes a Findings heading."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "## Findings" in output

    def test_includes_timestamp(self, single_finding_result: ScanResult) -> None:
        """Test that output includes a generation timestamp."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "*Generated:" in output
        # Should have date format
        date_pattern = r"\d{4}-\d{2}-\d{2}"
        assert re.search(date_pattern, output) is not None

    def test_uses_gfm_tables(self, single_finding_result: ScanResult) -> None:
        """Test that output uses GFM-style tables."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # GFM tables have pipe separators
        assert "| Metric | Value |" in output
        assert "|--------|-------|" in output

    def test_uses_code_fences(self, multiple_findings_result: ScanResult) -> None:
        """Test that code blocks use fenced syntax."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # Should use triple backtick code fences
        assert "```" in output


# ============================================================================
# Markdown Output - Summary Table Tests
# ============================================================================


class TestMarkdownOutputSummary:
    """Test that Markdown output includes correct summary table."""

    def test_shows_total_findings_count(self, multiple_findings_result: ScanResult) -> None:
        """Test that total findings count is in the table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "| Total Findings | 5 |" in output

    def test_shows_total_matches(self, multiple_findings_result: ScanResult) -> None:
        """Test that total matches count is in the table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # Multiple findings have different match counts
        assert "Total Matches" in output

    def test_shows_files_affected(self, multiple_findings_result: ScanResult) -> None:
        """Test that files affected count is in the table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "Files Affected" in output

    def test_shows_files_scanned(self, multiple_findings_result: ScanResult) -> None:
        """Test that files scanned count is in the table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "| Files Scanned | 100 |" in output

    def test_shows_scan_duration(self, multiple_findings_result: ScanResult) -> None:
        """Test that scan duration is in the table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "| Duration | 5.50s |" in output

    def test_shows_target_path(self, single_finding_result: ScanResult) -> None:
        """Test that target path is displayed."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "**Target:**" in output
        assert "`/tmp/test`" in output

    def test_shows_severity_breakdown_table(self, multiple_findings_result: ScanResult) -> None:
        """Test that severity breakdown is shown as a table."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "### Severity Breakdown" in output
        assert "| Severity | Count |" in output
        assert "|----------|-------|" in output

    def test_severity_breakdown_includes_all_present_severities(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that all present severity levels are in the breakdown."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output
        assert "INFO" in output


# ============================================================================
# Markdown Output - Collapsible Details Tests
# ============================================================================


class TestMarkdownOutputCollapsible:
    """Test that findings use collapsible details sections."""

    def test_uses_details_element(self, single_finding_result: ScanResult) -> None:
        """Test that file sections use <details> element."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "<details>" in output
        assert "</details>" in output

    def test_uses_summary_element(self, single_finding_result: ScanResult) -> None:
        """Test that file sections use <summary> element."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "<summary>" in output
        assert "</summary>" in output

    def test_summary_shows_finding_count(self, multi_findings_same_file_result: ScanResult) -> None:
        """Test that summary shows the number of findings."""
        formatter = MarkdownOutput()
        output = formatter.format(multi_findings_same_file_result)

        assert "3 findings" in output

    def test_singular_finding_label(self, single_finding_result: ScanResult) -> None:
        """Test that a single finding uses singular 'finding'."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "1 finding)" in output

    def test_empty_result_shows_no_findings_message(self, empty_scan_result: ScanResult) -> None:
        """Test that empty results show appropriate message."""
        formatter = MarkdownOutput()
        output = formatter.format(empty_scan_result)

        assert "No findings detected" in output or "no findings" in output.lower()


# ============================================================================
# Markdown Output - File Grouping Tests
# ============================================================================


class TestMarkdownOutputGrouping:
    """Test that findings are grouped correctly by file."""

    def test_findings_grouped_by_file(self, multi_findings_same_file_result: ScanResult) -> None:
        """Test that multiple findings in same file are grouped together."""
        formatter = MarkdownOutput()
        output = formatter.format(multi_findings_same_file_result)

        # Count occurrences of details sections - should be one per file
        details_count = output.count("<details>")
        assert details_count == 1

        # All three detectors should appear (underscores are escaped)
        assert "aws\\_key" in output
        assert "password" in output
        assert "email" in output

    def test_multiple_files_have_separate_sections(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that different files get separate sections."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # Should have 5 separate detail sections
        details_count = output.count("<details>")
        assert details_count == 5


# ============================================================================
# Markdown Output - Severity Ordering Tests
# ============================================================================


class TestMarkdownOutputSeverityOrdering:
    """Test that findings are sorted by severity."""

    def test_files_sorted_by_highest_severity(self, multiple_findings_result: ScanResult) -> None:
        """Test that files with critical findings appear first."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # secrets.txt has CRITICAL, should appear before others
        secrets_pos = output.find("secrets.txt")
        config_pos = output.find("config.py")  # LOW
        notes_pos = output.find("notes.txt")  # INFO

        assert secrets_pos < config_pos
        assert secrets_pos < notes_pos

    def test_findings_in_file_sorted_by_severity(
        self, multi_findings_same_file_result: ScanResult
    ) -> None:
        """Test that findings within a file are sorted by severity."""
        formatter = MarkdownOutput()
        output = formatter.format(multi_findings_same_file_result)

        # CRITICAL should appear before HIGH which should appear before LOW
        critical_pos = output.find("CRITICAL")
        high_pos = output.find("HIGH")
        low_pos = output.find("LOW")

        assert critical_pos < high_pos < low_pos


# ============================================================================
# Markdown Output - Severity Emoji Tests
# ============================================================================


class TestMarkdownOutputSeverityEmoji:
    """Test that severity levels have emoji indicators."""

    def test_severity_emoji_defined(self) -> None:
        """Test that all severity levels have emoji definitions."""
        for severity in Severity:
            assert severity in SEVERITY_EMOJI
            assert len(SEVERITY_EMOJI[severity]) > 0

    def test_emojis_appear_in_output(self, multiple_findings_result: ScanResult) -> None:
        """Test that emoji indicators appear in output."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # Should contain GitHub emoji syntax
        assert ":rotating_light:" in output  # CRITICAL
        assert ":warning:" in output  # HIGH

    def test_finding_headers_include_emoji(self, single_finding_result: ScanResult) -> None:
        """Test that finding headers include severity emoji."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # HIGH severity finding should have warning emoji
        assert ":warning:" in output


# ============================================================================
# Markdown Output - File Path Links Tests
# ============================================================================


class TestMarkdownOutputFileLinks:
    """Test that file paths are formatted as links."""

    def test_file_path_is_link(self, single_finding_result: ScanResult) -> None:
        """Test that file path is rendered as a Markdown link."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # Should contain a link with the file path
        assert "](/tmp/test/secrets.txt)" in output or "](secrets.txt)" in output

    def test_relative_path_with_base_path(self) -> None:
        """Test that base_path creates relative links."""
        result = ScanResult(
            target_path="/home/user/project",
            findings=[
                Finding(
                    file_path="/home/user/project/src/config.py",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput(base_path="/home/user/project/")
        output = formatter.format(result)

        # Should have relative path
        assert "src/config.py" in output
        # Should not have the base path in the link
        assert "](/home/user/project/src" not in output

    def test_file_path_spaces_encoded(self) -> None:
        """Test that spaces in file paths are URL encoded."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/my file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Spaces should be encoded as %20 in the link
        assert "my%20file.txt)" in output


# ============================================================================
# Markdown Output - Match Display Tests
# ============================================================================


class TestMarkdownOutputMatches:
    """Test that matches are displayed correctly."""

    def test_matches_in_backtick_code(self, single_finding_result: ScanResult) -> None:
        """Test that matches are displayed in inline code."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # Matches should be in backticks
        assert "`AKIAIOSFODNN7EXAMPLE`" in output

    def test_multiple_matches_as_list(self, multiple_findings_result: ScanResult) -> None:
        """Test that multiple matches are displayed as a list."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        # Should have list items with matches
        assert "- `" in output

    def test_matches_header_present(self, single_finding_result: ScanResult) -> None:
        """Test that Matches: header is present."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "**Matches:**" in output


# ============================================================================
# Markdown Output - Context Display Tests
# ============================================================================


class TestMarkdownOutputContext:
    """Test that context is displayed in code blocks."""

    def test_context_in_code_fence(self, multiple_findings_result: ScanResult) -> None:
        """Test that context is displayed in fenced code blocks."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "**Context:**" in output
        assert "```" in output

    def test_context_header_present(self, multiple_findings_result: ScanResult) -> None:
        """Test that Context: header is present."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "**Context:**" in output


# ============================================================================
# Markdown Output - Line Number Tests
# ============================================================================


class TestMarkdownOutputLineNumbers:
    """Test that line numbers are displayed when available."""

    def test_line_number_displayed(self, single_finding_result: ScanResult) -> None:
        """Test that line number is displayed when in metadata."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "(Line 5)" in output

    def test_line_number_from_line_key(self, multiple_findings_result: ScanResult) -> None:
        """Test that line number works with 'line' metadata key."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "(Line 5)" in output

    def test_line_number_from_line_number_key(self, multiple_findings_result: ScanResult) -> None:
        """Test that line number works with 'line_number' metadata key."""
        formatter = MarkdownOutput()
        output = formatter.format(multiple_findings_result)

        assert "(Line 10)" in output


# ============================================================================
# Markdown Output - Special Characters Tests
# ============================================================================


class TestMarkdownOutputSpecialChars:
    """Test that special Markdown characters are properly escaped."""

    def test_asterisks_escaped(self, special_characters_result: ScanResult) -> None:
        """Test that asterisks are escaped."""
        formatter = MarkdownOutput()
        output = formatter.format(special_characters_result)

        # Should not have unescaped asterisks that could cause formatting
        # The title should have the asterisks escaped
        assert "test\\_\\*\\_project" in output

    def test_underscores_escaped(self, special_characters_result: ScanResult) -> None:
        """Test that underscores are escaped in paths."""
        formatter = MarkdownOutput()
        output = formatter.format(special_characters_result)

        # Should have escaped underscores
        assert "\\_" in output

    def test_backticks_escaped_in_matches(self, special_characters_result: ScanResult) -> None:
        """Test that backticks are escaped in match content."""
        formatter = MarkdownOutput()
        output = formatter.format(special_characters_result)

        # Matches with backticks should be escaped
        assert "\\`" in output

    def test_brackets_escaped(self, special_characters_result: ScanResult) -> None:
        """Test that brackets are escaped."""
        formatter = MarkdownOutput()
        output = formatter.format(special_characters_result)

        # Should have escaped brackets
        assert "\\[" in output or "\\]" in output


# ============================================================================
# Markdown Output - Unicode Handling Tests
# ============================================================================


class TestMarkdownOutputUnicode:
    """Test that Unicode content is handled correctly."""

    def test_unicode_in_matches_displayed(self, unicode_result: ScanResult) -> None:
        """Test that Unicode match content is displayed correctly."""
        formatter = MarkdownOutput()
        output = formatter.format(unicode_result)

        assert "secret123" in output

    def test_unicode_context_displayed(self, unicode_result: ScanResult) -> None:
        """Test that Unicode context is displayed correctly."""
        formatter = MarkdownOutput()
        output = formatter.format(unicode_result)

        assert "username and password" in output


# ============================================================================
# Markdown Output - Custom Title Tests
# ============================================================================


class TestMarkdownOutputCustomTitle:
    """Test custom title functionality."""

    def test_custom_title_in_markdown(self, single_finding_result: ScanResult) -> None:
        """Test that custom title appears in Markdown."""
        custom_title = "My Custom Security Report"
        formatter = MarkdownOutput(title=custom_title)
        output = formatter.format(single_finding_result)

        # Title should be escaped but recognizable
        assert "My Custom Security Report" in output

    def test_default_title_includes_target(self, single_finding_result: ScanResult) -> None:
        """Test that default title includes target path."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "Hamburglar Scan Report" in output

    def test_title_property_returns_value(self) -> None:
        """Test that title property returns configured value."""
        formatter = MarkdownOutput(title="Test Title")
        assert formatter.title == "Test Title"

    def test_title_property_none_by_default(self) -> None:
        """Test that title property is None by default."""
        formatter = MarkdownOutput()
        assert formatter.title is None


# ============================================================================
# Markdown Output - BaseOutput Interface Tests
# ============================================================================


class TestMarkdownOutputInterface:
    """Test that MarkdownOutput properly implements BaseOutput interface."""

    def test_is_base_output_subclass(self) -> None:
        """Test that MarkdownOutput is a subclass of BaseOutput."""
        assert issubclass(MarkdownOutput, BaseOutput)

    def test_has_name_property(self) -> None:
        """Test that MarkdownOutput has a name property."""
        formatter = MarkdownOutput()
        assert hasattr(formatter, "name")
        assert formatter.name == "markdown"

    def test_has_format_method(self) -> None:
        """Test that MarkdownOutput has a format method."""
        formatter = MarkdownOutput()
        assert hasattr(formatter, "format")
        assert callable(formatter.format)

    def test_format_returns_string(self, single_finding_result: ScanResult) -> None:
        """Test that format returns a string."""
        formatter = MarkdownOutput()
        result = formatter.format(single_finding_result)
        assert isinstance(result, str)


# ============================================================================
# Markdown Output - Registry Integration Tests
# ============================================================================


class TestMarkdownOutputRegistryIntegration:
    """Test that MarkdownOutput works with the output registry."""

    def test_can_be_registered(self) -> None:
        """Test that MarkdownOutput can be registered in OutputRegistry."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = MarkdownOutput()

        registry.register(formatter)
        assert "markdown" in registry
        assert registry.get("markdown") is formatter

    def test_registered_name_matches_property(self) -> None:
        """Test that registered name matches the name property."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = MarkdownOutput()

        registry.register(formatter)
        retrieved = registry.get(formatter.name)
        assert retrieved is formatter


# ============================================================================
# Markdown Output - Edge Cases Tests
# ============================================================================


class TestMarkdownOutputEdgeCases:
    """Test edge cases and error handling."""

    def test_finding_without_matches(self) -> None:
        """Test handling of finding with empty matches list."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test_detector",
                    matches=[],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should still render without errors
        assert "# " in output
        # Underscore in detector name is escaped
        assert "test\\_detector" in output

    def test_finding_without_line_number(self) -> None:
        """Test handling of finding without line number in metadata."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test_detector",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                    metadata={},
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should render without line info
        assert "(Line" not in output

    def test_finding_without_context(self) -> None:
        """Test handling of finding without context in metadata."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test_detector",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                    metadata={"line": 1},
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should render without context section
        assert "**Context:**" not in output

    def test_empty_stats_dictionary(self) -> None:
        """Test handling of empty stats dictionary."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should render with 0 values for missing stats
        assert "| Files Scanned | 0 |" in output

    def test_very_long_match_content(self) -> None:
        """Test handling of very long match content."""
        long_match = "A" * 10000
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test_detector",
                    matches=[long_match],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should handle long content without issues
        assert "# " in output

    def test_many_findings_performance(self) -> None:
        """Test that many findings can be formatted without issues."""
        findings = [
            Finding(
                file_path=f"/tmp/test/file{i}.txt",
                detector_name=f"detector_{i % 5}",
                matches=[f"match_{i}"],
                severity=list(Severity)[i % 5],
                metadata={"line": i},
            )
            for i in range(100)
        ]

        result = ScanResult(
            target_path="/tmp/test",
            findings=findings,
            scan_duration=10.0,
            stats={"files_scanned": 100},
        )

        formatter = MarkdownOutput()
        output = formatter.format(result)

        # Should complete and produce valid output
        assert "# " in output
        assert "## Findings" in output


# ============================================================================
# Markdown Output - Severity Constants Tests
# ============================================================================


class TestMarkdownOutputConstants:
    """Test module-level constants."""

    def test_severity_order_has_all_severities(self) -> None:
        """Test that SEVERITY_ORDER includes all severity levels."""
        for severity in Severity:
            assert severity in SEVERITY_ORDER

    def test_severity_order_values_unique(self) -> None:
        """Test that SEVERITY_ORDER values are unique."""
        values = list(SEVERITY_ORDER.values())
        assert len(values) == len(set(values))

    def test_severity_order_critical_is_lowest(self) -> None:
        """Test that CRITICAL has the lowest order value (sorted first)."""
        assert SEVERITY_ORDER[Severity.CRITICAL] == min(SEVERITY_ORDER.values())

    def test_severity_order_info_is_highest(self) -> None:
        """Test that INFO has the highest order value (sorted last)."""
        assert SEVERITY_ORDER[Severity.INFO] == max(SEVERITY_ORDER.values())


# ============================================================================
# Markdown Output - Footer Tests
# ============================================================================


class TestMarkdownOutputFooter:
    """Test that footer includes proper attribution."""

    def test_footer_contains_hamburglar_link(self, single_finding_result: ScanResult) -> None:
        """Test that footer links to Hamburglar repository."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "Hamburglar" in output
        assert "github.com/needmorecowbell/Hamburglar" in output

    def test_footer_has_horizontal_rule(self, single_finding_result: ScanResult) -> None:
        """Test that footer has horizontal rule separator."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        assert "---" in output


# ============================================================================
# Markdown Output - base_path Property Tests
# ============================================================================


class TestMarkdownOutputBasePath:
    """Test base_path property and functionality."""

    def test_base_path_property_returns_value(self) -> None:
        """Test that base_path property returns configured value."""
        formatter = MarkdownOutput(base_path="/home/user/project/")
        assert formatter.base_path == "/home/user/project/"

    def test_base_path_property_none_by_default(self) -> None:
        """Test that base_path property is None by default."""
        formatter = MarkdownOutput()
        assert formatter.base_path is None

    def test_relative_path_removes_base(self) -> None:
        """Test that relative path correctly removes base path."""
        result = ScanResult(
            target_path="/home/user/project",
            findings=[
                Finding(
                    file_path="/home/user/project/deep/nested/file.py",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = MarkdownOutput(base_path="/home/user/project/")
        output = formatter.format(result)

        assert "deep/nested/file.py" in output

    def test_relative_path_handles_trailing_slash(self) -> None:
        """Test that relative path works with/without trailing slash."""
        result = ScanResult(
            target_path="/home/user/project",
            findings=[
                Finding(
                    file_path="/home/user/project/file.py",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        # Test without trailing slash
        formatter = MarkdownOutput(base_path="/home/user/project")
        output = formatter.format(result)

        # Should still work and show relative path
        assert "file.py" in output


# ============================================================================
# Markdown Output - PR/Issue Suitability Tests
# ============================================================================


class TestMarkdownOutputPRSuitability:
    """Test that output is suitable for PR comments and issues."""

    def test_output_has_no_raw_html_except_details(self, single_finding_result: ScanResult) -> None:
        """Test that output uses minimal HTML (only details/summary)."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # Should only have details and summary HTML tags
        # Remove details/summary tags and check for other HTML
        cleaned = output.replace("<details>", "").replace("</details>", "")
        cleaned = cleaned.replace("<summary>", "").replace("</summary>", "")
        cleaned = cleaned.replace("<strong>", "").replace("</strong>", "")

        # Should not have other HTML block elements
        assert "<div>" not in cleaned
        assert "<span>" not in cleaned
        assert "<table>" not in cleaned

    def test_output_is_reasonable_length(self, single_finding_result: ScanResult) -> None:
        """Test that output for single finding is not excessively long."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # Single finding shouldn't produce thousands of characters
        assert len(output) < 5000

    def test_output_has_no_excessive_whitespace(self, single_finding_result: ScanResult) -> None:
        """Test that output doesn't have excessive blank lines."""
        formatter = MarkdownOutput()
        output = formatter.format(single_finding_result)

        # Should not have more than 2 consecutive blank lines
        assert "\n\n\n\n" not in output
