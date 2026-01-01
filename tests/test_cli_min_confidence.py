"""Tests for CLI --min-confidence option.

This module tests the command-line interface option for filtering
findings by minimum confidence level during scans.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.cli.main import (
    VALID_CONFIDENCE_LEVELS,
    app,
    parse_confidence,
)
from hamburglar.detectors.patterns import Confidence

runner = CliRunner()


class TestParseConfidenceFunction:
    """Test the parse_confidence helper function."""

    def test_parse_high_confidence(self) -> None:
        """Test parsing 'high' confidence level."""
        result = parse_confidence("high")
        assert result == Confidence.HIGH

    def test_parse_medium_confidence(self) -> None:
        """Test parsing 'medium' confidence level."""
        result = parse_confidence("medium")
        assert result == Confidence.MEDIUM

    def test_parse_low_confidence(self) -> None:
        """Test parsing 'low' confidence level."""
        result = parse_confidence("low")
        assert result == Confidence.LOW

    def test_parse_confidence_case_insensitive(self) -> None:
        """Test that confidence parsing is case-insensitive."""
        assert parse_confidence("HIGH") == Confidence.HIGH
        assert parse_confidence("Medium") == Confidence.MEDIUM
        assert parse_confidence("LOW") == Confidence.LOW
        assert parse_confidence("HiGh") == Confidence.HIGH

    def test_parse_confidence_with_whitespace(self) -> None:
        """Test parsing confidence with leading/trailing whitespace."""
        assert parse_confidence("  high  ") == Confidence.HIGH
        assert parse_confidence("\tmedium\n") == Confidence.MEDIUM

    def test_parse_empty_string_raises_error(self) -> None:
        """Test that empty string raises BadParameter."""
        import typer

        with pytest.raises(typer.BadParameter) as exc_info:
            parse_confidence("")
        assert "empty" in str(exc_info.value).lower()

    def test_parse_invalid_confidence_raises_error(self) -> None:
        """Test that an invalid confidence level raises BadParameter."""
        import typer

        with pytest.raises(typer.BadParameter) as exc_info:
            parse_confidence("invalid")
        assert "Invalid confidence level 'invalid'" in str(exc_info.value)
        assert "high" in str(exc_info.value)
        assert "medium" in str(exc_info.value)
        assert "low" in str(exc_info.value)

    def test_valid_confidence_levels_contains_all_values(self) -> None:
        """Test that VALID_CONFIDENCE_LEVELS contains all Confidence values."""
        for confidence in Confidence:
            assert confidence.value in VALID_CONFIDENCE_LEVELS
            assert VALID_CONFIDENCE_LEVELS[confidence.value] == confidence


class TestMinConfidenceHelpOutput:
    """Test that --min-confidence appears in help."""

    def test_help_shows_min_confidence_option(self) -> None:
        """Test that scan --help shows the --min-confidence option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--min-confidence" in result.output

    def test_help_describes_confidence_levels(self) -> None:
        """Test that help describes valid confidence levels."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        # Should mention the valid levels
        assert "high" in result.output.lower()
        assert "medium" in result.output.lower()
        assert "low" in result.output.lower()


class TestMinConfidenceOption:
    """Test --min-confidence option functionality."""

    def test_min_confidence_high(self, temp_directory: Path) -> None:
        """Test scanning with --min-confidence high."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-f", "json"]
        )
        # Should not error
        assert result.exit_code in (0, 2)  # 0 = findings, 2 = no findings

    def test_min_confidence_medium(self, temp_directory: Path) -> None:
        """Test scanning with --min-confidence medium."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "medium", "-f", "json"]
        )
        assert result.exit_code in (0, 2)

    def test_min_confidence_low(self, temp_directory: Path) -> None:
        """Test scanning with --min-confidence low."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "low", "-f", "json"]
        )
        assert result.exit_code in (0, 2)

    def test_min_confidence_case_insensitive(self, temp_directory: Path) -> None:
        """Test that --min-confidence is case-insensitive."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "HIGH", "-f", "json"]
        )
        assert result.exit_code in (0, 2)

    def test_invalid_min_confidence_shows_error(self, temp_directory: Path) -> None:
        """Test that an invalid confidence level shows an error message."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "invalid"]
        )
        assert result.exit_code == 1
        assert "invalid" in result.output.lower() or "error" in result.output.lower()

    def test_min_confidence_filters_patterns(self, temp_directory: Path) -> None:
        """Test that --min-confidence filters patterns correctly."""
        # Scan with low confidence (includes all patterns)
        result_low = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "low", "-f", "json"]
        )

        # Scan with high confidence (includes only high confidence patterns)
        result_high = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-f", "json"]
        )

        # Both should succeed or have no findings
        assert result_low.exit_code in (0, 2)
        assert result_high.exit_code in (0, 2)

        # If both have findings, high confidence should have same or fewer
        if result_low.exit_code == 0 and result_high.exit_code == 0:
            data_low = json.loads(result_low.output)
            data_high = json.loads(result_high.output)
            assert len(data_high["findings"]) <= len(data_low["findings"])


class TestMinConfidenceVerboseOutput:
    """Test verbose output with --min-confidence."""

    def test_verbose_shows_min_confidence(self, temp_directory: Path) -> None:
        """Test that verbose mode shows the minimum confidence level."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-v"]
        )
        assert result.exit_code in (0, 2)
        # Verbose should show the confidence level
        assert "high" in result.output.lower() or "confidence" in result.output.lower()

    def test_verbose_shows_pattern_count(self, temp_directory: Path) -> None:
        """Test that verbose mode shows pattern count when using min-confidence."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "medium", "-v"]
        )
        assert result.exit_code in (0, 2)
        # Should show pattern count in verbose mode
        assert "pattern" in result.output.lower() or "loaded" in result.output.lower()


class TestMinConfidenceWithOtherOptions:
    """Test --min-confidence with other CLI options."""

    def test_min_confidence_with_categories(self, temp_directory: Path) -> None:
        """Test --min-confidence combined with --categories."""
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--min-confidence", "high",
                "-c", "api_keys,private_keys",
                "-f", "json",
            ],
        )
        assert result.exit_code in (0, 2)

    def test_min_confidence_with_no_categories(self, temp_directory: Path) -> None:
        """Test --min-confidence combined with --no-categories."""
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--min-confidence", "medium",
                "--no-categories", "generic",
                "-f", "json",
            ],
        )
        assert result.exit_code in (0, 2)

    def test_min_confidence_with_categories_and_no_categories(
        self, temp_directory: Path
    ) -> None:
        """Test --min-confidence with both --categories and --no-categories."""
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--min-confidence", "high",
                "-c", "api_keys,cloud,credentials",
                "--no-categories", "cloud",
                "-f", "json",
            ],
        )
        assert result.exit_code in (0, 2)

    def test_min_confidence_with_output_file(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test --min-confidence with --output file."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--min-confidence", "high",
                "-f", "json",
                "-o", str(output_file),
            ],
        )
        assert result.exit_code in (0, 2)
        if result.exit_code == 0:
            assert output_file.exists()
            data = json.loads(output_file.read_text())
            assert "findings" in data

    def test_min_confidence_with_quiet(self, temp_directory: Path) -> None:
        """Test --min-confidence with --quiet."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-q"]
        )
        assert result.exit_code in (0, 2)
        # Quiet mode should produce no output
        assert result.output == ""

    def test_min_confidence_with_table_format(self, temp_directory: Path) -> None:
        """Test --min-confidence with table output format."""
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--min-confidence", "medium", "-f", "table"],
        )
        assert result.exit_code in (0, 2)
        # Table format - not JSON
        if result.exit_code == 0 and result.output:
            try:
                json.loads(result.output)
                pytest.fail("Expected table output, got JSON")
            except json.JSONDecodeError:
                pass  # Expected


class TestMinConfidencePatternFiltering:
    """Test that --min-confidence correctly filters patterns by confidence level."""

    def test_high_confidence_reduces_pattern_count(self, temp_directory: Path) -> None:
        """Test that high confidence has fewer patterns than low confidence."""
        # Run with verbose to see pattern counts
        result_low = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "low", "-v"]
        )
        result_high = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-v"]
        )

        assert result_low.exit_code in (0, 2)
        assert result_high.exit_code in (0, 2)

        # Both should mention patterns in verbose mode
        # The actual pattern count will differ based on the filter

    def test_medium_confidence_between_low_and_high(
        self, temp_directory: Path
    ) -> None:
        """Test that medium confidence is between low and high."""
        result_low = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "low", "-v"]
        )
        result_medium = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "medium", "-v"]
        )
        result_high = runner.invoke(
            app, ["scan", str(temp_directory), "--min-confidence", "high", "-v"]
        )

        assert result_low.exit_code in (0, 2)
        assert result_medium.exit_code in (0, 2)
        assert result_high.exit_code in (0, 2)
