"""Comprehensive tests for output formatters.

This module tests the JSON and Table output formatters for proper
formatting, content validation, and edge case handling.
"""

from __future__ import annotations

import json
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
from hamburglar.outputs import BaseOutput, OutputRegistry
from hamburglar.outputs.json_output import JsonOutput
from hamburglar.outputs.table_output import SEVERITY_COLORS, TableOutput

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
            ),
            Finding(
                file_path="/tmp/test/config.py",
                detector_name="email",
                matches=["admin@example.com"],
                severity=Severity.LOW,
            ),
            Finding(
                file_path="/tmp/test/database.yml",
                detector_name="password",
                matches=["password123"],
                severity=Severity.HIGH,
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
            ),
        ],
        scan_duration=5.5,
        stats={"files_scanned": 100, "files_skipped": 5, "errors": 1},
    )


# ============================================================================
# JSON Output - Valid JSON Tests
# ============================================================================


class TestJsonOutputValidJson:
    """Test that JSON output produces valid JSON."""

    def test_empty_result_is_valid_json(self, empty_scan_result: ScanResult) -> None:
        """Test that an empty scan result produces valid JSON."""
        formatter = JsonOutput()
        output = formatter.format(empty_scan_result)

        # Should not raise
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_single_finding_is_valid_json(self, single_finding_result: ScanResult) -> None:
        """Test that a single finding produces valid JSON."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_multiple_findings_is_valid_json(self, multiple_findings_result: ScanResult) -> None:
        """Test that multiple findings produce valid JSON."""
        formatter = JsonOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_is_indented(self, single_finding_result: ScanResult) -> None:
        """Test that JSON output is properly indented for readability."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        # Should have newlines and indentation
        assert "\n" in output
        assert "  " in output  # 2-space indent from indent=2

    def test_json_with_special_characters_in_matches(self) -> None:
        """Test that special characters in matches are properly escaped."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=['quote: "value"', "newline:\nhere", "tab:\there"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        # Should not raise - special chars properly escaped
        parsed = json.loads(output)
        matches = parsed["findings"][0]["matches"]
        assert 'quote: "value"' in matches
        assert "newline:\nhere" in matches
        assert "tab:\there" in matches

    def test_json_with_unicode_characters(self) -> None:
        """Test that unicode characters are handled correctly."""
        result = ScanResult(
            target_path="/tmp/test/日本語",
            findings=[
                Finding(
                    file_path="/tmp/test/文件.txt",
                    detector_name="test",
                    matches=["密码: пароль", "emoji: 🔑"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert "日本語" in parsed["target_path"]
        assert "文件.txt" in parsed["findings"][0]["file_path"]


# ============================================================================
# JSON Output - Content Validation Tests
# ============================================================================


class TestJsonOutputContainsAllFindings:
    """Test that JSON output contains all findings data."""

    def test_json_contains_target_path(self, single_finding_result: ScanResult) -> None:
        """Test that JSON contains the target path."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert parsed["target_path"] == "/tmp/test"

    def test_json_contains_scan_duration(self, single_finding_result: ScanResult) -> None:
        """Test that JSON contains the scan duration."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert parsed["scan_duration"] == 2.0

    def test_json_contains_stats(self, single_finding_result: ScanResult) -> None:
        """Test that JSON contains scan statistics."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert parsed["stats"]["files_scanned"] == 5
        assert parsed["stats"]["files_skipped"] == 0
        assert parsed["stats"]["errors"] == 0

    def test_json_contains_all_findings(self, multiple_findings_result: ScanResult) -> None:
        """Test that JSON contains all findings."""
        formatter = JsonOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        assert len(parsed["findings"]) == 5

    def test_json_finding_has_all_fields(self, single_finding_result: ScanResult) -> None:
        """Test that each finding has all required fields."""
        formatter = JsonOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        finding = parsed["findings"][0]

        assert finding["file_path"] == "/tmp/test/secrets.txt"
        assert finding["detector_name"] == "aws_key"
        assert finding["matches"] == ["AKIAIOSFODNN7EXAMPLE"]
        assert finding["severity"] == "high"
        assert finding["metadata"] == {"line": 5}

    def test_json_contains_all_matches(self, multiple_findings_result: ScanResult) -> None:
        """Test that all matches are included for each finding."""
        formatter = JsonOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)

        # First finding should have 2 matches
        first_finding = parsed["findings"][0]
        assert len(first_finding["matches"]) == 2
        assert "AKIAIOSFODNN7EXAMPLE" in first_finding["matches"]
        assert "AKIABCDEFGHIJ1234567" in first_finding["matches"]

    def test_json_preserves_severity_values(self, multiple_findings_result: ScanResult) -> None:
        """Test that all severity values are preserved correctly."""
        formatter = JsonOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        severities = [f["severity"] for f in parsed["findings"]]

        assert "critical" in severities
        assert "high" in severities
        assert "medium" in severities
        assert "low" in severities
        assert "info" in severities


# ============================================================================
# JSON Output - Edge Cases
# ============================================================================


class TestJsonOutputEdgeCases:
    """Test JSON output edge cases."""

    def test_empty_matches_list(self) -> None:
        """Test handling of finding with empty matches list."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=[],
                    severity=Severity.LOW,
                )
            ],
            scan_duration=1.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["findings"][0]["matches"] == []

    def test_empty_stats(self) -> None:
        """Test handling of empty stats dictionary."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=1.0,
            stats={},
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["stats"] == {}

    def test_zero_duration(self) -> None:
        """Test handling of zero scan duration."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=0.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["scan_duration"] == 0.0

    def test_very_long_file_path(self) -> None:
        """Test handling of very long file paths."""
        long_path = "/tmp/" + "a" * 500 + "/file.txt"
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path=long_path,
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["findings"][0]["file_path"] == long_path

    def test_many_findings(self) -> None:
        """Test handling of many findings (100+)."""
        findings = [
            Finding(
                file_path=f"/tmp/test/file_{i}.txt",
                detector_name=f"detector_{i % 5}",
                matches=[f"match_{i}"],
                severity=list(Severity)[i % 5],
            )
            for i in range(150)
        ]

        result = ScanResult(
            target_path="/tmp/test",
            findings=findings,
            scan_duration=10.0,
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert len(parsed["findings"]) == 150


# ============================================================================
# Table Output - Rendering Tests
# ============================================================================


class TestTableOutputRendering:
    """Test that table output renders without errors."""

    def test_empty_result_renders(self, empty_scan_result: ScanResult) -> None:
        """Test that an empty scan result renders without errors."""
        formatter = TableOutput()
        output = formatter.format(empty_scan_result)

        assert isinstance(output, str)
        assert len(output) > 0

    def test_single_finding_renders(self, single_finding_result: ScanResult) -> None:
        """Test that a single finding renders without errors."""
        formatter = TableOutput()
        output = formatter.format(single_finding_result)

        assert isinstance(output, str)
        assert "secrets.txt" in output
        assert "aws_key" in output

    def test_multiple_findings_render(self, multiple_findings_result: ScanResult) -> None:
        """Test that multiple findings render without errors."""
        formatter = TableOutput()
        output = formatter.format(multiple_findings_result)

        assert isinstance(output, str)
        # Should contain all detector names
        assert "aws_key" in output
        assert "email" in output
        assert "password" in output

    def test_table_contains_headers(self, single_finding_result: ScanResult) -> None:
        """Test that the table contains expected headers."""
        formatter = TableOutput()
        output = formatter.format(single_finding_result)

        assert "File Path" in output
        assert "Detector" in output
        assert "Matches" in output
        assert "Severity" in output

    def test_table_contains_title(self, single_finding_result: ScanResult) -> None:
        """Test that the table contains the scan target as title."""
        formatter = TableOutput()
        output = formatter.format(single_finding_result)

        assert "Scan Results" in output
        assert "/tmp/test" in output

    def test_table_contains_summary(self, single_finding_result: ScanResult) -> None:
        """Test that the table contains a summary section."""
        formatter = TableOutput()
        output = formatter.format(single_finding_result)

        assert "Scan Summary" in output
        assert "Duration" in output
        assert "Total findings" in output

    def test_table_contains_stats(self, single_finding_result: ScanResult) -> None:
        """Test that the table contains scan statistics."""
        formatter = TableOutput()
        output = formatter.format(single_finding_result)

        assert "Files scanned" in output

    def test_table_contains_severity_breakdown(self, multiple_findings_result: ScanResult) -> None:
        """Test that the table contains severity breakdown for results with findings."""
        formatter = TableOutput()
        output = formatter.format(multiple_findings_result)

        assert "By severity" in output
        assert "CRITICAL" in output
        assert "HIGH" in output


# ============================================================================
# Table Output - Long File Paths
# ============================================================================


class TestTableOutputLongFilePaths:
    """Test that table output handles long file paths correctly."""

    def test_long_file_path_truncated(self) -> None:
        """Test that long file paths are truncated in output."""
        long_path = "/home/user/projects/very/deeply/nested/directory/structure/that/goes/on/for/a/while/secrets.txt"
        result = ScanResult(
            target_path="/home/user/projects",
            findings=[
                Finding(
                    file_path=long_path,
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # The path should be truncated with ellipsis
        assert "…" in output or "..." in output
        # Start of the path should still be visible
        assert "/home/user/projects" in output
        # The table should render without errors
        assert "test" in output

    def test_very_long_file_path_renders(self) -> None:
        """Test that very long file paths don't break rendering."""
        # Create a 300+ character path
        long_path = "/tmp/" + "/".join(["directory"] * 50) + "/file.txt"
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path=long_path,
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without exception
        assert isinstance(output, str)
        assert len(output) > 0
        # Start of path should be visible, but truncated with ellipsis
        assert "/tmp/directory" in output
        assert "…" in output or "..." in output
        # The other fields should still be rendered
        assert "test" in output
        assert "HIGH" in output

    def test_mixed_path_lengths(self) -> None:
        """Test rendering with mixed short and long paths."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/short.txt",
                    detector_name="test1",
                    matches=["secret1"],
                    severity=Severity.HIGH,
                ),
                Finding(
                    file_path="/tmp/" + "a" * 200 + "/medium.txt",
                    detector_name="test2",
                    matches=["secret2"],
                    severity=Severity.MEDIUM,
                ),
                Finding(
                    file_path="/tmp/" + "/".join(["d"] * 100) + "/long.txt",
                    detector_name="test3",
                    matches=["secret3"],
                    severity=Severity.LOW,
                ),
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        assert isinstance(output, str)
        # All detector names should be present
        assert "test1" in output
        assert "test2" in output
        assert "test3" in output

    def test_path_with_spaces(self) -> None:
        """Test rendering paths with spaces."""
        result = ScanResult(
            target_path="/home/user",
            findings=[
                Finding(
                    file_path="/home/user/My Documents/Project Files/config.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        assert "config.txt" in output


# ============================================================================
# Table Output - Special Characters
# ============================================================================


class TestTableOutputSpecialCharacters:
    """Test that table output handles special characters in findings."""

    def test_quotes_in_matches(self) -> None:
        """Test handling of quotes in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=['password="secret123"', "api_key='abc123'"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)
        assert "test" in output

    def test_newlines_in_matches(self) -> None:
        """Test handling of newlines in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["line1\nline2\nline3"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)

    def test_tabs_in_matches(self) -> None:
        """Test handling of tabs in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["key\t=\tvalue"],
                    severity=Severity.LOW,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        assert isinstance(output, str)

    def test_unicode_in_findings(self) -> None:
        """Test handling of unicode characters in findings."""
        result = ScanResult(
            target_path="/tmp/日本語",
            findings=[
                Finding(
                    file_path="/tmp/日本語/文件.txt",
                    detector_name="пароль_детектор",
                    matches=["密码: secretpassword", "🔑 api_key=abc123"],
                    severity=Severity.CRITICAL,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)
        # Detector name should be present
        assert "пароль_детектор" in output or "CRITICAL" in output

    def test_ansi_escape_sequences_in_matches(self) -> None:
        """Test handling of ANSI escape sequences in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["\x1b[31mred text\x1b[0m"],
                    severity=Severity.INFO,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)

    def test_null_bytes_in_matches(self) -> None:
        """Test handling of null bytes in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["secret\x00hidden"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)

    def test_rich_markup_in_matches(self) -> None:
        """Test that Rich markup in match content is escaped."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["[bold red]not actually bold[/bold red]"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors or interpreting the markup
        assert isinstance(output, str)

    def test_backslashes_in_matches(self) -> None:
        """Test handling of backslashes in match content."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=["C:\\Users\\Admin\\secret.txt", "path\\to\\file"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should render without errors
        assert isinstance(output, str)


# ============================================================================
# Table Output - Severity Display
# ============================================================================


class TestTableOutputSeverityDisplay:
    """Test that table output displays severity correctly."""

    def test_all_severity_levels_displayed(self, multiple_findings_result: ScanResult) -> None:
        """Test that all severity levels are displayed."""
        formatter = TableOutput()
        output = formatter.format(multiple_findings_result)

        # All severity levels should appear
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output
        assert "INFO" in output

    def test_severity_colors_defined(self) -> None:
        """Test that all severity levels have colors defined."""
        for severity in Severity:
            assert severity in SEVERITY_COLORS
            assert isinstance(SEVERITY_COLORS[severity], str)


# ============================================================================
# Table Output - Match Count Display
# ============================================================================


class TestTableOutputMatchCount:
    """Test that table output displays match counts correctly."""

    def test_match_count_displayed(self, multiple_findings_result: ScanResult) -> None:
        """Test that match counts are displayed in the table."""
        formatter = TableOutput()
        output = formatter.format(multiple_findings_result)

        # The first finding has 2 matches
        assert "2" in output
        # Other findings have 1 match each
        assert "1" in output

    def test_zero_matches_displayed(self) -> None:
        """Test display of findings with zero matches."""
        result = ScanResult(
            target_path="/tmp",
            findings=[
                Finding(
                    file_path="/tmp/file.txt",
                    detector_name="test",
                    matches=[],
                    severity=Severity.LOW,
                )
            ],
            scan_duration=1.0,
        )

        formatter = TableOutput()
        output = formatter.format(result)

        # Should show 0 in matches column
        assert "0" in output


# ============================================================================
# Formatter Properties
# ============================================================================


class TestFormatterProperties:
    """Test formatter name properties and interface."""

    def test_json_formatter_name(self) -> None:
        """Test that JSON formatter has correct name."""
        formatter = JsonOutput()
        assert formatter.name == "json"

    def test_table_formatter_name(self) -> None:
        """Test that table formatter has correct name."""
        formatter = TableOutput()
        assert formatter.name == "table"

    def test_formatters_extend_base_output(self) -> None:
        """Test that formatters extend BaseOutput."""
        assert issubclass(JsonOutput, BaseOutput)
        assert issubclass(TableOutput, BaseOutput)


# ============================================================================
# Integration with Registry
# ============================================================================


class TestOutputRegistryIntegration:
    """Test output formatters with the registry."""

    def test_json_formatter_can_be_registered(self) -> None:
        """Test that JSON formatter can be registered."""
        registry = OutputRegistry()
        formatter = JsonOutput()
        registry.register(formatter)

        assert "json" in registry
        assert registry.get("json") is formatter

    def test_table_formatter_can_be_registered(self) -> None:
        """Test that table formatter can be registered."""
        registry = OutputRegistry()
        formatter = TableOutput()
        registry.register(formatter)

        assert "table" in registry
        assert registry.get("table") is formatter

    def test_both_formatters_registered_together(self) -> None:
        """Test that both formatters can be registered together."""
        registry = OutputRegistry()
        json_formatter = JsonOutput()
        table_formatter = TableOutput()

        registry.register(json_formatter)
        registry.register(table_formatter)

        assert len(registry) == 2
        assert "json" in registry
        assert "table" in registry


# ============================================================================
# Edge Case: Empty and Minimal Results
# ============================================================================


class TestMinimalResults:
    """Test handling of minimal and edge-case results."""

    def test_json_with_minimal_finding(self) -> None:
        """Test JSON output with minimal finding (only required fields)."""
        result = ScanResult(
            target_path="/",
            findings=[
                Finding(
                    file_path="/file.txt",
                    detector_name="d",
                )
            ],
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["findings"][0]["matches"] == []
        assert parsed["findings"][0]["severity"] == "medium"  # default
        assert parsed["findings"][0]["metadata"] == {}

    def test_table_with_minimal_finding(self) -> None:
        """Test table output with minimal finding."""
        result = ScanResult(
            target_path="/",
            findings=[
                Finding(
                    file_path="/file.txt",
                    detector_name="d",
                )
            ],
        )

        formatter = TableOutput()
        output = formatter.format(result)

        assert "d" in output
        assert "0" in output  # 0 matches

    def test_json_empty_target_path(self) -> None:
        """Test JSON output with empty string target path."""
        result = ScanResult(
            target_path="",
            findings=[],
        )

        formatter = JsonOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        assert parsed["target_path"] == ""

    def test_table_empty_target_path(self) -> None:
        """Test table output with empty string target path."""
        result = ScanResult(
            target_path="",
            findings=[],
        )

        formatter = TableOutput()
        output = formatter.format(result)

        assert isinstance(output, str)
