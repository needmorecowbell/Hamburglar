"""Comprehensive tests for CSV output formatter.

This module tests the CSV output formatter for RFC 4180 compliance,
correct header generation, proper character escaping, Unicode handling,
and delimiter configurability.
"""

from __future__ import annotations

import csv
import io
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
from hamburglar.outputs.csv_output import DEFAULT_HEADERS, CsvOutput


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
                metadata={"line": 5, "context": "aws_access_key_id = ..."},
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
        ],
        scan_duration=5.5,
        stats={"files_scanned": 100, "files_skipped": 5, "errors": 1},
    )


# ============================================================================
# RFC 4180 Compliance Tests
# ============================================================================


class TestRfc4180Compliance:
    """Test that CSV output follows RFC 4180 specification."""

    def test_uses_crlf_line_endings(self, single_finding_result: ScanResult) -> None:
        """Test that CSV uses CRLF line endings per RFC 4180."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        # Should have CRLF line endings
        assert "\r\n" in output
        # Should not have lone LF (except within CRLF)
        lines = output.split("\r\n")
        for line in lines[:-1]:  # Last split will be empty
            assert "\n" not in line

    def test_fields_are_comma_separated(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that fields are comma separated by default."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        lines = output.strip().split("\r\n")
        # Header line should have commas
        assert "," in lines[0]

    def test_quoted_fields_with_commas(self) -> None:
        """Test that fields containing commas are quoted."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["value,with,commas"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        # The match with commas should be quoted
        assert '"value,with,commas"' in output

    def test_quoted_fields_with_newlines(self) -> None:
        """Test that fields containing newlines are quoted."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["value\nwith\nnewlines"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        # The match with newlines should be quoted
        assert '"value\nwith\nnewlines"' in output

    def test_quoted_fields_with_double_quotes(self) -> None:
        """Test that fields containing quotes have them escaped."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=['value"with"quotes'],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        # Quotes inside fields should be doubled per RFC 4180
        assert '"value""with""quotes"' in output

    def test_csv_is_parseable(self, multiple_findings_result: ScanResult) -> None:
        """Test that output can be parsed by Python's csv module."""
        formatter = CsvOutput()
        output = formatter.format(multiple_findings_result)

        # Should parse without errors
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # Should have header + data rows
        assert len(rows) >= 1


# ============================================================================
# Header Tests
# ============================================================================


class TestCsvHeaders:
    """Test that CSV headers are correct."""

    def test_headers_are_included_by_default(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that headers are included by default."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        lines = output.strip().split("\r\n")
        header = lines[0]

        assert "file" in header
        assert "detector" in header
        assert "match" in header
        assert "severity" in header
        assert "line_number" in header
        assert "context" in header

    def test_header_order(self, single_finding_result: ScanResult) -> None:
        """Test that headers are in the expected order."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        headers = next(reader)

        assert headers == DEFAULT_HEADERS

    def test_headers_can_be_disabled(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that headers can be disabled."""
        formatter = CsvOutput(include_headers=False)
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        first_row = next(reader)

        # First row should be data, not headers
        assert first_row[0] == "/tmp/test/secrets.txt"
        assert first_row[1] == "aws_key"

    def test_empty_result_still_has_headers(
        self, empty_scan_result: ScanResult
    ) -> None:
        """Test that empty result still includes headers."""
        formatter = CsvOutput()
        output = formatter.format(empty_scan_result)

        lines = output.strip().split("\r\n")
        assert len(lines) == 1  # Just the header
        assert "file" in lines[0]


# ============================================================================
# Special Character Escaping Tests
# ============================================================================


class TestSpecialCharacterEscaping:
    """Test that special characters are properly escaped."""

    def test_comma_in_file_path(self) -> None:
        """Test handling of commas in file paths."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/file,with,commas.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        # Path should be quoted
        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[0] == "/tmp/file,with,commas.txt"

    def test_newline_in_context(self) -> None:
        """Test handling of newlines in context field."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                    metadata={"context": "line1\nline2\nline3"},
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[5] == "line1\nline2\nline3"

    def test_quote_in_detector_name(self) -> None:
        """Test handling of quotes in detector names."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name='test"detector',
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[1] == 'test"detector'

    def test_mixed_special_characters(self) -> None:
        """Test handling of mixed special characters."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=['value,"with"\nspecial\rchars'],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[2] == 'value,"with"\nspecial\rchars'


# ============================================================================
# Unicode Content Tests
# ============================================================================


class TestUnicodeHandling:
    """Test that Unicode content is handled correctly."""

    def test_unicode_in_file_path(self) -> None:
        """Test handling of Unicode in file paths."""
        result = ScanResult(
            target_path="/tmp/日本語",
            findings=[
                Finding(
                    file_path="/tmp/日本語/文件.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert "日本語" in row[0]
        assert "文件.txt" in row[0]

    def test_unicode_in_matches(self) -> None:
        """Test handling of Unicode in match values."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["密码: пароль = كلمة السر"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert "密码" in row[2]
        assert "пароль" in row[2]
        assert "كلمة السر" in row[2]

    def test_unicode_in_detector_name(self) -> None:
        """Test handling of Unicode in detector names."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="检测器",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[1] == "检测器"

    def test_emoji_in_content(self) -> None:
        """Test handling of emojis in content."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["🔐 secret 🔑"],
                    severity=Severity.HIGH,
                    metadata={"context": "🚨 Alert! 🚨"},
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert "🔐" in row[2]
        assert "🔑" in row[2]
        assert "🚨" in row[5]


# ============================================================================
# Delimiter Configuration Tests
# ============================================================================


class TestDelimiterConfiguration:
    """Test that delimiter is configurable."""

    def test_default_delimiter_is_comma(self) -> None:
        """Test that default delimiter is comma."""
        formatter = CsvOutput()
        assert formatter.delimiter == ","

    def test_semicolon_delimiter(self, single_finding_result: ScanResult) -> None:
        """Test using semicolon as delimiter."""
        formatter = CsvOutput(delimiter=";")
        output = formatter.format(single_finding_result)

        # Should use semicolons
        lines = output.strip().split("\r\n")
        assert ";" in lines[0]
        # Commas should not be delimiters (may appear in content)

    def test_tab_delimiter(self, single_finding_result: ScanResult) -> None:
        """Test using tab as delimiter."""
        formatter = CsvOutput(delimiter="\t")
        output = formatter.format(single_finding_result)

        # Should use tabs
        lines = output.strip().split("\r\n")
        assert "\t" in lines[0]

    def test_pipe_delimiter(self, single_finding_result: ScanResult) -> None:
        """Test using pipe as delimiter."""
        formatter = CsvOutput(delimiter="|")
        output = formatter.format(single_finding_result)

        # Should use pipes
        lines = output.strip().split("\r\n")
        assert "|" in lines[0]

    def test_custom_delimiter_parsing(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that custom delimiter output can be parsed."""
        formatter = CsvOutput(delimiter=";")
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output), delimiter=";")
        rows = list(reader)

        assert len(rows) == 2  # Header + 1 finding
        assert rows[0] == DEFAULT_HEADERS


# ============================================================================
# Field Value Tests
# ============================================================================


class TestFieldValues:
    """Test that field values are correctly extracted."""

    def test_file_path_is_correct(self, single_finding_result: ScanResult) -> None:
        """Test that file path is correctly included."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[0] == "/tmp/test/secrets.txt"

    def test_detector_name_is_correct(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that detector name is correctly included."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[1] == "aws_key"

    def test_match_value_is_correct(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that match value is correctly included."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[2] == "AKIAIOSFODNN7EXAMPLE"

    def test_severity_is_correct(self, single_finding_result: ScanResult) -> None:
        """Test that severity is correctly included."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[3] == "high"

    def test_line_number_from_line_key(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that line number is extracted from 'line' key."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[4] == "5"

    def test_line_number_from_line_number_key(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that line number is extracted from 'line_number' key."""
        formatter = CsvOutput()
        output = formatter.format(multiple_findings_result)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # Find the email finding which uses 'line_number' key
        email_row = [r for r in rows if r[1] == "email"][0]
        assert email_row[4] == "10"

    def test_missing_line_number_is_empty(self) -> None:
        """Test that missing line number results in empty string."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[4] == ""

    def test_context_is_included(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that context is correctly included."""
        formatter = CsvOutput()
        output = formatter.format(multiple_findings_result)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # Find the aws_key finding which has context
        aws_rows = [r for r in rows if r[1] == "aws_key"]
        # All aws_key rows should have the same context
        assert aws_rows[0][5] == "aws_access_key_id = ..."

    def test_missing_context_is_empty(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that missing context results in empty string."""
        formatter = CsvOutput()
        output = formatter.format(single_finding_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[5] == ""


# ============================================================================
# Multiple Matches Tests
# ============================================================================


class TestMultipleMatches:
    """Test handling of findings with multiple matches."""

    def test_multiple_matches_create_multiple_rows(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that multiple matches create multiple rows."""
        formatter = CsvOutput()
        output = formatter.format(multiple_findings_result)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        # aws_key has 2 matches, email has 1, password has 1 = 4 total + header
        assert len(rows) == 5

    def test_multiple_match_rows_share_common_fields(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that rows from same finding share common fields."""
        formatter = CsvOutput()
        output = formatter.format(multiple_findings_result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        rows = list(reader)

        # Find aws_key rows
        aws_rows = [r for r in rows if r[1] == "aws_key"]
        assert len(aws_rows) == 2

        # Should share file path, detector, severity, line, context
        assert aws_rows[0][0] == aws_rows[1][0]  # file
        assert aws_rows[0][1] == aws_rows[1][1]  # detector
        assert aws_rows[0][3] == aws_rows[1][3]  # severity
        assert aws_rows[0][4] == aws_rows[1][4]  # line
        assert aws_rows[0][5] == aws_rows[1][5]  # context

        # Matches should be different
        assert aws_rows[0][2] != aws_rows[1][2]

    def test_empty_matches_creates_single_row(self) -> None:
        """Test that empty matches list creates single row with empty match."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=[],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[2] == ""


# ============================================================================
# Empty Results Tests
# ============================================================================


class TestEmptyResults:
    """Test handling of empty scan results."""

    def test_empty_findings_produces_headers_only(
        self, empty_scan_result: ScanResult
    ) -> None:
        """Test that empty findings still produces valid CSV with headers."""
        formatter = CsvOutput()
        output = formatter.format(empty_scan_result)

        reader = csv.reader(io.StringIO(output))
        rows = list(reader)

        assert len(rows) == 1  # Just header
        assert rows[0] == DEFAULT_HEADERS

    def test_empty_findings_no_headers(
        self, empty_scan_result: ScanResult
    ) -> None:
        """Test that empty findings with no headers produces empty output."""
        formatter = CsvOutput(include_headers=False)
        output = formatter.format(empty_scan_result)

        # Should be empty (no headers, no data)
        assert output == ""


# ============================================================================
# Formatter Properties Tests
# ============================================================================


class TestFormatterProperties:
    """Test CSV formatter properties and interface."""

    def test_csv_formatter_name(self) -> None:
        """Test that CSV formatter has correct name."""
        formatter = CsvOutput()
        assert formatter.name == "csv"

    def test_csv_extends_base_output(self) -> None:
        """Test that CSV formatter extends BaseOutput."""
        assert issubclass(CsvOutput, BaseOutput)

    def test_delimiter_property(self) -> None:
        """Test delimiter property access."""
        formatter = CsvOutput(delimiter=";")
        assert formatter.delimiter == ";"

    def test_include_headers_property(self) -> None:
        """Test include_headers property access."""
        formatter = CsvOutput(include_headers=False)
        assert formatter.include_headers is False


# ============================================================================
# Registry Integration Tests
# ============================================================================


class TestCsvRegistryIntegration:
    """Test CSV formatter with the registry."""

    def test_csv_formatter_can_be_registered(self) -> None:
        """Test that CSV formatter can be registered."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = CsvOutput()
        registry.register(formatter)

        assert "csv" in registry
        assert registry.get("csv") is formatter

    def test_csv_formatter_format_works_after_registry(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that formatting works after registry registration."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = CsvOutput()
        registry.register(formatter)

        retrieved = registry.get("csv")
        output = retrieved.format(single_finding_result)

        assert "file,detector,match,severity,line_number,context" in output
        assert "aws_key" in output


# ============================================================================
# Severity Value Tests
# ============================================================================


class TestSeverityValues:
    """Test that all severity levels are handled correctly."""

    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.CRITICAL, "critical"),
            (Severity.HIGH, "high"),
            (Severity.MEDIUM, "medium"),
            (Severity.LOW, "low"),
            (Severity.INFO, "info"),
        ],
    )
    def test_severity_value(self, severity: Severity, expected: str) -> None:
        """Test that each severity level produces correct value."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=severity,
                )
            ],
            scan_duration=1.0,
        )

        formatter = CsvOutput()
        output = formatter.format(result)

        reader = csv.reader(io.StringIO(output))
        next(reader)  # Skip header
        row = next(reader)
        assert row[3] == expected
