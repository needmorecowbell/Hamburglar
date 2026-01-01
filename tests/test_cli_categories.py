"""Tests for CLI --categories and --no-categories options.

This module tests the command-line interface options for filtering
detector categories during scans.
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

from hamburglar.cli.main import VALID_CATEGORIES, app, parse_categories
from hamburglar.detectors.patterns import PatternCategory

runner = CliRunner()


class TestParseCategoriesFunction:
    """Test the parse_categories helper function."""

    def test_parse_single_category(self) -> None:
        """Test parsing a single category."""
        result = parse_categories("api_keys")
        assert result == [PatternCategory.API_KEYS]

    def test_parse_multiple_categories(self) -> None:
        """Test parsing multiple comma-separated categories."""
        result = parse_categories("api_keys,cloud,credentials")
        assert PatternCategory.API_KEYS in result
        assert PatternCategory.CLOUD in result
        assert PatternCategory.CREDENTIALS in result
        assert len(result) == 3

    def test_parse_categories_with_spaces(self) -> None:
        """Test parsing categories with spaces around commas."""
        result = parse_categories("api_keys, cloud , credentials")
        assert PatternCategory.API_KEYS in result
        assert PatternCategory.CLOUD in result
        assert PatternCategory.CREDENTIALS in result

    def test_parse_categories_case_insensitive(self) -> None:
        """Test that category parsing is case-insensitive."""
        result = parse_categories("API_KEYS,Cloud,CREDENTIALS")
        assert PatternCategory.API_KEYS in result
        assert PatternCategory.CLOUD in result
        assert PatternCategory.CREDENTIALS in result

    def test_parse_empty_string(self) -> None:
        """Test parsing an empty string returns empty list."""
        result = parse_categories("")
        assert result == []

    def test_parse_invalid_category_raises_error(self) -> None:
        """Test that an invalid category raises BadParameter."""
        import typer

        with pytest.raises(typer.BadParameter) as exc_info:
            parse_categories("invalid_category")
        assert "Invalid category 'invalid_category'" in str(exc_info.value)

    def test_parse_mixed_valid_invalid_categories_raises_error(self) -> None:
        """Test that mixing valid and invalid categories raises error."""
        import typer

        with pytest.raises(typer.BadParameter) as exc_info:
            parse_categories("api_keys,invalid,cloud")
        assert "Invalid category 'invalid'" in str(exc_info.value)

    def test_valid_categories_contains_all_pattern_categories(self) -> None:
        """Test that VALID_CATEGORIES contains all PatternCategory values."""
        for category in PatternCategory:
            assert category.value in VALID_CATEGORIES
            assert VALID_CATEGORIES[category.value] == category


class TestCategoriesHelpOutput:
    """Test that --categories and --no-categories appear in help."""

    def test_help_shows_categories_option(self) -> None:
        """Test that scan --help shows the --categories option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--categories" in result.output or "-c" in result.output

    def test_help_shows_no_categories_option(self) -> None:
        """Test that scan --help shows the --no-categories option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--no-categories" in result.output

    def test_help_lists_valid_categories(self) -> None:
        """Test that help lists valid category names."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        # At least some categories should be mentioned
        assert "api_keys" in result.output or "API_KEYS" in result.output


class TestCategoriesOption:
    """Test --categories/-c option functionality."""

    def test_categories_short_flag(self, temp_directory: Path) -> None:
        """Test that -c works as shorthand for --categories."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", "api_keys", "-f", "json"])
        # Should not error
        assert result.exit_code in (0, 2)  # 0 = findings, 2 = no findings

    def test_categories_long_flag(self, temp_directory: Path) -> None:
        """Test that --categories works."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--categories", "api_keys", "-f", "json"]
        )
        assert result.exit_code in (0, 2)

    def test_multiple_categories(self, temp_directory: Path) -> None:
        """Test enabling multiple categories."""
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "-c", "api_keys,cloud,credentials", "-f", "json"],
        )
        assert result.exit_code in (0, 2)

    def test_invalid_category_shows_error(self, temp_directory: Path) -> None:
        """Test that an invalid category shows an error message."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", "invalid_category"])
        assert result.exit_code == 1
        assert "invalid_category" in result.output.lower() or "error" in result.output.lower()

    def test_categories_with_verbose_shows_info(self, temp_directory: Path) -> None:
        """Test that verbose mode shows category information."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", "api_keys", "-v"])
        assert result.exit_code in (0, 2)
        # Verbose should show the categories being used
        assert "api_keys" in result.output or "Categories" in result.output

    def test_categories_filters_findings(self, temp_directory: Path) -> None:
        """Test that --categories filters findings to specified categories."""
        # First, scan with all patterns to establish baseline
        result_all = runner.invoke(app, ["scan", str(temp_directory), "-f", "json"])
        assert result_all.exit_code == 0

        # Now scan with only network category (should have fewer findings)
        result_network = runner.invoke(
            app, ["scan", str(temp_directory), "-c", "network", "-f", "json"]
        )
        # Either exit code 0 (findings) or 2 (no findings) is valid
        assert result_network.exit_code in (0, 2)

        # Parse results if both have findings
        if result_all.exit_code == 0 and result_network.exit_code == 0:
            data_all = json.loads(result_all.output)
            data_network = json.loads(result_network.output)
            # Network-only should have same or fewer findings
            assert len(data_network["findings"]) <= len(data_all["findings"])


class TestNoCategoriesOption:
    """Test --no-categories option functionality."""

    def test_no_categories_option(self, temp_directory: Path) -> None:
        """Test that --no-categories excludes specified categories."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--no-categories", "generic", "-f", "json"]
        )
        assert result.exit_code in (0, 2)

    def test_no_categories_with_verbose(self, temp_directory: Path) -> None:
        """Test verbose mode shows excluded categories."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "--no-categories", "generic", "-v"]
        )
        assert result.exit_code in (0, 2)
        # Verbose should show excluded categories
        assert "generic" in result.output or "Excluded" in result.output

    def test_no_categories_multiple(self, temp_directory: Path) -> None:
        """Test excluding multiple categories."""
        result = runner.invoke(
            app,
            ["scan", str(temp_directory), "--no-categories", "generic,network", "-f", "json"],
        )
        assert result.exit_code in (0, 2)

    def test_invalid_no_category_shows_error(self, temp_directory: Path) -> None:
        """Test that an invalid category in --no-categories shows error."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--no-categories", "not_real"])
        assert result.exit_code == 1
        assert "not_real" in result.output.lower() or "error" in result.output.lower()


class TestCategoriesCombinations:
    """Test combinations of --categories and --no-categories."""

    def test_categories_and_no_categories_together(self, temp_directory: Path) -> None:
        """Test using both --categories and --no-categories."""
        # Enable api_keys and credentials, but exclude nothing
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "-c",
                "api_keys,credentials,cloud",
                "--no-categories",
                "cloud",
                "-f",
                "json",
            ],
        )
        # This should work - enable 3, exclude 1
        assert result.exit_code in (0, 2)

    def test_all_categories(self, temp_directory: Path) -> None:
        """Test enabling all categories explicitly."""
        all_cats = ",".join(c.value for c in PatternCategory)
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", all_cats, "-f", "json"])
        assert result.exit_code in (0, 2)


class TestCategoriesVerboseOutput:
    """Test verbose output with category options."""

    def test_verbose_shows_pattern_count(self, temp_directory: Path) -> None:
        """Test that verbose mode shows pattern count when using categories."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", "api_keys", "-v"])
        assert result.exit_code in (0, 2)
        # Should show pattern count in verbose mode
        assert (
            "pattern" in result.output.lower()
            or "loaded" in result.output.lower()
            or "categories" in result.output.lower()
        )


class TestCategoriesWithOtherOptions:
    """Test --categories with other CLI options."""

    def test_categories_with_output_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test --categories with --output file."""
        output_file = tmp_path / "output.json"
        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "-c",
                "api_keys",
                "-f",
                "json",
                "-o",
                str(output_file),
            ],
        )
        assert result.exit_code in (0, 2)
        if result.exit_code == 0:
            assert output_file.exists()
            data = json.loads(output_file.read_text())
            assert "findings" in data

    def test_categories_with_quiet(self, temp_directory: Path) -> None:
        """Test --categories with --quiet."""
        result = runner.invoke(app, ["scan", str(temp_directory), "-c", "api_keys", "-q"])
        assert result.exit_code in (0, 2)
        # Quiet mode should produce no output
        assert result.output == ""

    def test_categories_with_table_format(self, temp_directory: Path) -> None:
        """Test --categories with table output format."""
        result = runner.invoke(
            app, ["scan", str(temp_directory), "-c", "api_keys,private_keys", "-f", "table"]
        )
        assert result.exit_code in (0, 2)
        # Table format - not JSON
        if result.exit_code == 0 and result.output:
            try:
                json.loads(result.output)
                pytest.fail("Expected table output, got JSON")
            except json.JSONDecodeError:
                pass  # Expected
