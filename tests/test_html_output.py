"""Comprehensive tests for HTML output formatter.

This module tests the HTML output formatter for proper HTML generation,
well-formed structure, summary statistics accuracy, finding grouping,
and no external dependencies requirement.
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
from hamburglar.outputs.html_output import (
    SEVERITY_COLORS,
    SEVERITY_ORDER,
    HtmlOutput,
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
    """Return a scan result with special HTML characters that need escaping."""
    return ScanResult(
        target_path="/tmp/<script>alert('xss')</script>",
        findings=[
            Finding(
                file_path="/tmp/test/<file>.txt",
                detector_name="test_detector",
                matches=["<script>alert('xss')</script>", 'value="quoted"'],
                severity=Severity.HIGH,
                metadata={
                    "line": 1,
                    "context": '<div class="test">content & more</div>',
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
        target_path="/tmp/测试目录",
        findings=[
            Finding(
                file_path="/tmp/测试.txt",
                detector_name="unicode_detector",
                matches=["密码: secret123", "🔑 API_KEY=abc"],
                severity=Severity.MEDIUM,
                metadata={"line": 1, "context": "用户名和密码"},
            ),
        ],
        scan_duration=0.5,
        stats={"files_scanned": 1, "files_skipped": 0, "errors": 0},
    )


# ============================================================================
# HTML Output - Valid Structure Tests
# ============================================================================


class TestHtmlOutputValidStructure:
    """Test that HTML output produces valid, well-formed HTML."""

    def test_empty_result_is_valid_html(self, empty_scan_result: ScanResult) -> None:
        """Test that an empty scan result produces valid HTML."""
        formatter = HtmlOutput()
        output = formatter.format(empty_scan_result)

        assert output.startswith("<!DOCTYPE html>")
        assert "<html" in output
        assert "</html>" in output
        assert "<head>" in output
        assert "</head>" in output
        assert "<body>" in output
        assert "</body>" in output

    def test_single_finding_is_valid_html(self, single_finding_result: ScanResult) -> None:
        """Test that a single finding produces valid HTML."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert output.startswith("<!DOCTYPE html>")
        assert "<html" in output
        assert "</html>" in output

    def test_multiple_findings_is_valid_html(self, multiple_findings_result: ScanResult) -> None:
        """Test that multiple findings produce valid HTML."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        assert output.startswith("<!DOCTYPE html>")
        assert "<html" in output
        assert "</html>" in output

    def test_html_has_meta_charset(self, single_finding_result: ScanResult) -> None:
        """Test that HTML includes charset meta tag."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert 'charset="UTF-8"' in output or "charset=UTF-8" in output

    def test_html_has_viewport_meta(self, single_finding_result: ScanResult) -> None:
        """Test that HTML includes viewport meta tag for responsive design."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "viewport" in output

    def test_html_has_title(self, single_finding_result: ScanResult) -> None:
        """Test that HTML includes a title element."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "<title>" in output
        assert "</title>" in output


# ============================================================================
# HTML Output - No External Dependencies Tests
# ============================================================================


class TestHtmlOutputNoExternalDeps:
    """Test that HTML output has no external dependencies."""

    def test_no_external_css_links(self, multiple_findings_result: ScanResult) -> None:
        """Test that there are no external CSS link tags."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should not contain external stylesheet links
        assert 'rel="stylesheet" href="http' not in output
        assert 'rel="stylesheet" href="https' not in output
        assert 'rel="stylesheet" href="//' not in output

    def test_no_external_scripts(self, multiple_findings_result: ScanResult) -> None:
        """Test that there are no external script tags."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should not contain external script sources
        assert 'src="http' not in output
        assert 'src="https' not in output
        assert "src='//" not in output

    def test_has_inline_styles(self, single_finding_result: ScanResult) -> None:
        """Test that CSS is included inline."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "<style>" in output
        assert "</style>" in output

    def test_no_font_imports(self, single_finding_result: ScanResult) -> None:
        """Test that there are no external font imports."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # Should not import external fonts
        assert "@import" not in output or "fonts.googleapis" not in output


# ============================================================================
# HTML Output - Summary Statistics Tests
# ============================================================================


class TestHtmlOutputSummary:
    """Test that HTML output includes correct summary statistics."""

    def test_shows_total_findings_count(self, multiple_findings_result: ScanResult) -> None:
        """Test that total findings count is displayed."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should show total findings (5 in this fixture)
        assert ">5<" in output or ">5 " in output or " 5<" in output

    def test_shows_files_scanned(self, multiple_findings_result: ScanResult) -> None:
        """Test that files scanned count is displayed."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should show files scanned (100 in this fixture)
        assert "100" in output

    def test_shows_scan_duration(self, multiple_findings_result: ScanResult) -> None:
        """Test that scan duration is displayed."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should show duration (5.5s in this fixture)
        assert "5.5" in output or "5.50" in output

    def test_shows_target_path(self, single_finding_result: ScanResult) -> None:
        """Test that target path is displayed."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "/tmp/test" in output

    def test_shows_severity_breakdown(self, multiple_findings_result: ScanResult) -> None:
        """Test that severity breakdown is shown."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Should show severity badges
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output
        assert "INFO" in output

    def test_empty_result_shows_no_findings_message(self, empty_scan_result: ScanResult) -> None:
        """Test that empty results show appropriate message."""
        formatter = HtmlOutput()
        output = formatter.format(empty_scan_result)

        # Should indicate no findings
        assert "No Findings" in output or "no findings" in output.lower()


# ============================================================================
# HTML Output - Finding Grouping Tests
# ============================================================================


class TestHtmlOutputGrouping:
    """Test that findings are grouped correctly by file."""

    def test_findings_grouped_by_file(self, multi_findings_same_file_result: ScanResult) -> None:
        """Test that multiple findings in same file are grouped together."""
        formatter = HtmlOutput()
        output = formatter.format(multi_findings_same_file_result)

        # The file path should appear only once as a section header
        # Count occurrences of the file path in section headers
        file_path = "/tmp/test/secrets.txt"
        assert file_path in output

        # All three detectors should appear under the same file
        assert "aws_key" in output
        assert "password" in output
        assert "email" in output

    def test_multiple_files_have_separate_sections(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that different files get separate sections."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # All files should have their own section
        assert "/tmp/test/secrets.txt" in output
        assert "/tmp/test/config.py" in output
        assert "/tmp/test/database.yml" in output
        assert "/tmp/test/notes.txt" in output
        assert "/tmp/test/api.js" in output

    def test_uses_collapsible_details_element(self, single_finding_result: ScanResult) -> None:
        """Test that file sections use collapsible details element."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "<details" in output
        assert "<summary" in output
        assert "</details>" in output
        assert "</summary>" in output


# ============================================================================
# HTML Output - Severity Ordering Tests
# ============================================================================


class TestHtmlOutputSeverityOrdering:
    """Test that findings are sorted by severity."""

    def test_files_sorted_by_highest_severity(self, multiple_findings_result: ScanResult) -> None:
        """Test that files with critical findings appear first."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # secrets.txt has CRITICAL, should appear before others
        secrets_pos = output.find("/tmp/test/secrets.txt")
        config_pos = output.find("/tmp/test/config.py")  # LOW
        notes_pos = output.find("/tmp/test/notes.txt")  # INFO

        assert secrets_pos < config_pos
        assert secrets_pos < notes_pos

    def test_findings_in_file_sorted_by_severity(
        self, multi_findings_same_file_result: ScanResult
    ) -> None:
        """Test that findings within a file are sorted by severity."""
        formatter = HtmlOutput()
        output = formatter.format(multi_findings_same_file_result)

        # CRITICAL should appear before HIGH which should appear before LOW
        critical_pos = output.find("CRITICAL")
        high_pos = output.find("HIGH")
        low_pos = output.find("LOW")

        assert critical_pos < high_pos < low_pos


# ============================================================================
# HTML Output - Severity Color Coding Tests
# ============================================================================


class TestHtmlOutputSeverityColors:
    """Test that severity levels have appropriate color coding."""

    def test_severity_colors_defined(self) -> None:
        """Test that all severity levels have color definitions."""
        for severity in Severity:
            assert severity in SEVERITY_COLORS
            colors = SEVERITY_COLORS[severity]
            assert "bg" in colors
            assert "border" in colors
            assert "text" in colors

    def test_severity_badges_have_colors(self, multiple_findings_result: ScanResult) -> None:
        """Test that severity badges include color styling."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Check that color styles are present
        assert "background-color:" in output
        assert "border-color:" in output
        assert "color:" in output

    def test_file_sections_colored_by_severity(self, single_finding_result: ScanResult) -> None:
        """Test that file sections are color-coded by severity."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # File section should have border styling
        assert "border-left-color:" in output


# ============================================================================
# HTML Output - Match Highlighting Tests
# ============================================================================


class TestHtmlOutputMatchHighlighting:
    """Test that matched content is syntax highlighted."""

    def test_matches_highlighted(self, single_finding_result: ScanResult) -> None:
        """Test that matches are displayed with highlighting."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # Matches should be in code elements
        assert "<code" in output
        assert "AKIAIOSFODNN7EXAMPLE" in output

    def test_context_displayed_in_pre_block(self, multiple_findings_result: ScanResult) -> None:
        """Test that context is displayed in pre-formatted block."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # Context should be in pre elements
        assert "<pre" in output
        # Check context content is present
        assert "aws_access_key_id" in output or "password:" in output


# ============================================================================
# HTML Output - Line Number Tests
# ============================================================================


class TestHtmlOutputLineNumbers:
    """Test that line numbers are displayed when available."""

    def test_line_number_displayed(self, single_finding_result: ScanResult) -> None:
        """Test that line number is displayed when in metadata."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # Should show line 5
        assert "Line 5" in output or "line 5" in output.lower()

    def test_line_number_from_line_key(self, multiple_findings_result: ScanResult) -> None:
        """Test that line number works with 'line' metadata key."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # One finding has line: 5
        assert "Line 5" in output

    def test_line_number_from_line_number_key(self, multiple_findings_result: ScanResult) -> None:
        """Test that line number works with 'line_number' metadata key."""
        formatter = HtmlOutput()
        output = formatter.format(multiple_findings_result)

        # One finding has line_number: 10
        assert "Line 10" in output


# ============================================================================
# HTML Output - Special Characters / XSS Prevention Tests
# ============================================================================


class TestHtmlOutputXssPrevention:
    """Test that special characters are properly escaped."""

    def test_html_entities_escaped_in_file_path(
        self, special_characters_result: ScanResult
    ) -> None:
        """Test that HTML entities are escaped in file paths."""
        formatter = HtmlOutput()
        output = formatter.format(special_characters_result)

        # Raw script tags should not appear unescaped
        assert "<script>alert" not in output
        # Should be escaped
        assert "&lt;script&gt;" in output or "&#x" in output

    def test_html_entities_escaped_in_matches(self, special_characters_result: ScanResult) -> None:
        """Test that HTML entities are escaped in match content."""
        formatter = HtmlOutput()
        output = formatter.format(special_characters_result)

        # Raw script tags should not appear
        # The actual script content should be escaped
        assert "<script>alert('xss')</script>" not in output

    def test_quotes_escaped_in_attributes(self, special_characters_result: ScanResult) -> None:
        """Test that quotes are properly escaped."""
        formatter = HtmlOutput()
        output = formatter.format(special_characters_result)

        # Should have proper HTML escaping for quotes
        assert 'value="quoted"' not in output or "&quot;" in output

    def test_ampersands_escaped(self, special_characters_result: ScanResult) -> None:
        """Test that ampersands are properly escaped."""
        formatter = HtmlOutput()
        output = formatter.format(special_characters_result)

        # Context contains "&" which should be escaped as &amp;
        # Check that context content is escaped
        assert "&amp;" in output


# ============================================================================
# HTML Output - Unicode Handling Tests
# ============================================================================


class TestHtmlOutputUnicode:
    """Test that Unicode content is handled correctly."""

    def test_unicode_file_path_displayed(self, unicode_result: ScanResult) -> None:
        """Test that Unicode file paths are displayed correctly."""
        formatter = HtmlOutput()
        output = formatter.format(unicode_result)

        assert "测试" in output

    def test_unicode_matches_displayed(self, unicode_result: ScanResult) -> None:
        """Test that Unicode match content is displayed correctly."""
        formatter = HtmlOutput()
        output = formatter.format(unicode_result)

        assert "密码" in output

    def test_emoji_in_matches_displayed(self, unicode_result: ScanResult) -> None:
        """Test that emoji characters are displayed correctly."""
        formatter = HtmlOutput()
        output = formatter.format(unicode_result)

        assert "🔑" in output

    def test_unicode_context_displayed(self, unicode_result: ScanResult) -> None:
        """Test that Unicode context is displayed correctly."""
        formatter = HtmlOutput()
        output = formatter.format(unicode_result)

        assert "用户名和密码" in output


# ============================================================================
# HTML Output - Custom Title Tests
# ============================================================================


class TestHtmlOutputCustomTitle:
    """Test custom title functionality."""

    def test_custom_title_in_html(self, single_finding_result: ScanResult) -> None:
        """Test that custom title appears in HTML."""
        custom_title = "My Custom Security Report"
        formatter = HtmlOutput(title=custom_title)
        output = formatter.format(single_finding_result)

        assert custom_title in output
        assert f"<title>{custom_title}</title>" in output

    def test_default_title_includes_target(self, single_finding_result: ScanResult) -> None:
        """Test that default title includes target path."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "/tmp/test" in output
        assert "Hamburglar" in output

    def test_title_property_returns_value(self) -> None:
        """Test that title property returns configured value."""
        formatter = HtmlOutput(title="Test Title")
        assert formatter.title == "Test Title"

    def test_title_property_none_by_default(self) -> None:
        """Test that title property is None by default."""
        formatter = HtmlOutput()
        assert formatter.title is None


# ============================================================================
# HTML Output - BaseOutput Interface Tests
# ============================================================================


class TestHtmlOutputInterface:
    """Test that HtmlOutput properly implements BaseOutput interface."""

    def test_is_base_output_subclass(self) -> None:
        """Test that HtmlOutput is a subclass of BaseOutput."""
        assert issubclass(HtmlOutput, BaseOutput)

    def test_has_name_property(self) -> None:
        """Test that HtmlOutput has a name property."""
        formatter = HtmlOutput()
        assert hasattr(formatter, "name")
        assert formatter.name == "html"

    def test_has_format_method(self) -> None:
        """Test that HtmlOutput has a format method."""
        formatter = HtmlOutput()
        assert hasattr(formatter, "format")
        assert callable(formatter.format)

    def test_format_returns_string(self, single_finding_result: ScanResult) -> None:
        """Test that format returns a string."""
        formatter = HtmlOutput()
        result = formatter.format(single_finding_result)
        assert isinstance(result, str)


# ============================================================================
# HTML Output - Registry Integration Tests
# ============================================================================


class TestHtmlOutputRegistryIntegration:
    """Test that HtmlOutput works with the output registry."""

    def test_can_be_registered(self) -> None:
        """Test that HtmlOutput can be registered in OutputRegistry."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = HtmlOutput()

        registry.register(formatter)
        assert "html" in registry
        assert registry.get("html") is formatter

    def test_registered_name_matches_property(self) -> None:
        """Test that registered name matches the name property."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = HtmlOutput()

        registry.register(formatter)
        retrieved = registry.get(formatter.name)
        assert retrieved is formatter


# ============================================================================
# HTML Output - Edge Cases Tests
# ============================================================================


class TestHtmlOutputEdgeCases:
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

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should still render without errors
        assert "<!DOCTYPE html>" in output
        assert "test_detector" in output

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

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should render without line info
        assert "<!DOCTYPE html>" in output
        assert "Line" not in output or "Line " not in output

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

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should render without context section
        assert "<!DOCTYPE html>" in output
        # No context-section class or context label
        assert "context-section" not in output.lower() or "Context:" not in output

    def test_empty_stats_dictionary(self) -> None:
        """Test handling of empty stats dictionary."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=0.5,
            stats={},
        )

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should render with 0 values for missing stats
        assert "<!DOCTYPE html>" in output

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

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should handle long content without issues
        assert "<!DOCTYPE html>" in output
        assert long_match in output

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

        formatter = HtmlOutput()
        output = formatter.format(result)

        # Should complete and produce valid output
        assert "<!DOCTYPE html>" in output
        assert "</html>" in output

    def test_special_file_path_characters(self) -> None:
        """Test handling of special characters in file paths."""
        result = ScanResult(
            target_path="/tmp/test path/with spaces",
            findings=[
                Finding(
                    file_path="/tmp/test path/file (1).txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=0.5,
            stats={},
        )

        formatter = HtmlOutput()
        output = formatter.format(result)

        assert "file (1).txt" in output


# ============================================================================
# HTML Output - Severity Constants Tests
# ============================================================================


class TestHtmlOutputConstants:
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

    def test_severity_colors_are_valid_css(self) -> None:
        """Test that severity colors are valid CSS color values."""
        for severity, colors in SEVERITY_COLORS.items():
            # All should be hex colors
            assert colors["bg"].startswith("#")
            assert colors["border"].startswith("#")
            assert colors["text"].startswith("#")

            # Check length (should be 7 for full hex)
            assert len(colors["bg"]) == 7
            assert len(colors["border"]) == 7
            assert len(colors["text"]) == 7


# ============================================================================
# HTML Output - Timestamp Tests
# ============================================================================


class TestHtmlOutputTimestamp:
    """Test that timestamp is included in output."""

    def test_timestamp_present(self, single_finding_result: ScanResult) -> None:
        """Test that a timestamp is included in the output."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # Should contain "Generated:" with a timestamp
        assert "Generated:" in output

    def test_timestamp_format(self, single_finding_result: ScanResult) -> None:
        """Test that timestamp appears in expected format."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        # Should contain date in YYYY-MM-DD format somewhere

        date_pattern = r"\d{4}-\d{2}-\d{2}"
        assert re.search(date_pattern, output) is not None


# ============================================================================
# HTML Output - Footer Tests
# ============================================================================


class TestHtmlOutputFooter:
    """Test that footer includes proper attribution."""

    def test_footer_contains_hamburglar_link(self, single_finding_result: ScanResult) -> None:
        """Test that footer links to Hamburglar repository."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "Hamburglar" in output
        assert "github.com" in output.lower() or "needmorecowbell" in output.lower()

    def test_footer_element_present(self, single_finding_result: ScanResult) -> None:
        """Test that footer element is present."""
        formatter = HtmlOutput()
        output = formatter.format(single_finding_result)

        assert "<footer>" in output
        assert "</footer>" in output
