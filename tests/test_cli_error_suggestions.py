"""Tests for CLI error suggestions and helpful messages.

This module tests the command suggestion feature for typos,
context-aware help messages, and documentation links in errors.
"""

from __future__ import annotations

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

from hamburglar.cli.main import app
from hamburglar.cli.errors import (
    get_command_suggestion,
    get_subcommand_suggestion,
    get_option_suggestion,
    get_context_hint,
    DOC_LINKS,
    COMMAND_ALIASES,
    MAIN_COMMANDS,
)

runner = CliRunner()


class TestCommandSuggestions:
    """Test command suggestion for typos."""

    def test_suggest_scan_for_scna(self) -> None:
        """Test that 'scna' suggests 'scan'."""
        suggestion = get_command_suggestion("scna")
        assert suggestion == "scan"

    def test_suggest_scan_for_sacn(self) -> None:
        """Test that 'sacn' suggests 'scan'."""
        suggestion = get_command_suggestion("sacn")
        assert suggestion == "scan"

    def test_suggest_scan_git_for_scan_gti(self) -> None:
        """Test that 'scan-gti' suggests 'scan-git'."""
        suggestion = get_command_suggestion("scan-gti")
        assert suggestion == "scan-git"

    def test_suggest_history_for_histroy(self) -> None:
        """Test that 'histroy' suggests 'history'."""
        suggestion = get_command_suggestion("histroy")
        assert suggestion == "history"

    def test_suggest_doctor_for_docotr(self) -> None:
        """Test that 'docotr' suggests 'doctor'."""
        suggestion = get_command_suggestion("docotr")
        assert suggestion == "doctor"

    def test_suggest_plugins_for_plugns(self) -> None:
        """Test that 'plugns' suggests 'plugins'."""
        suggestion = get_command_suggestion("plugns")
        assert suggestion == "plugins"

    def test_suggest_config_for_confg(self) -> None:
        """Test that 'confg' suggests 'config'."""
        suggestion = get_command_suggestion("confg")
        assert suggestion == "config"

    def test_suggest_report_for_reprot(self) -> None:
        """Test that 'reprot' suggests 'report'."""
        suggestion = get_command_suggestion("reprot")
        assert suggestion == "report"

    def test_no_suggestion_for_completely_wrong_command(self) -> None:
        """Test that very different commands return None."""
        suggestion = get_command_suggestion("xyz123")
        assert suggestion is None

    def test_suggestion_is_case_insensitive(self) -> None:
        """Test that suggestions work regardless of case."""
        suggestion = get_command_suggestion("SCAN")
        assert suggestion == "scan"

        suggestion = get_command_suggestion("Scna")
        assert suggestion == "scan"


class TestCommandAliases:
    """Test that command aliases work correctly."""

    def test_check_alias_for_scan(self) -> None:
        """Test that 'check' suggests 'scan'."""
        suggestion = get_command_suggestion("check")
        assert suggestion == "scan"

    def test_find_alias_for_scan(self) -> None:
        """Test that 'find' suggests 'scan'."""
        suggestion = get_command_suggestion("find")
        assert suggestion == "scan"

    def test_git_alias_for_scan_git(self) -> None:
        """Test that 'git' suggests 'scan-git'."""
        suggestion = get_command_suggestion("git")
        assert suggestion == "scan-git"

    def test_url_alias_for_scan_web(self) -> None:
        """Test that 'url' suggests 'scan-web'."""
        suggestion = get_command_suggestion("url")
        assert suggestion == "scan-web"

    def test_hist_alias_for_history(self) -> None:
        """Test that 'hist' suggests 'history'."""
        suggestion = get_command_suggestion("hist")
        assert suggestion == "history"

    def test_health_alias_for_doctor(self) -> None:
        """Test that 'health' suggests 'doctor'."""
        suggestion = get_command_suggestion("health")
        assert suggestion == "doctor"

    def test_plugin_alias_for_plugins(self) -> None:
        """Test that 'plugin' suggests 'plugins'."""
        suggestion = get_command_suggestion("plugin")
        assert suggestion == "plugins"

    def test_settings_alias_for_config(self) -> None:
        """Test that 'settings' suggests 'config'."""
        suggestion = get_command_suggestion("settings")
        assert suggestion == "config"

    def test_stats_alias_for_report(self) -> None:
        """Test that 'stats' suggests 'report'."""
        suggestion = get_command_suggestion("stats")
        assert suggestion == "report"


class TestSubcommandSuggestions:
    """Test subcommand suggestion for typos."""

    def test_suggest_plugins_list_for_lis(self) -> None:
        """Test that 'lis' suggests 'list' for plugins."""
        suggestion = get_subcommand_suggestion("plugins", "lis")
        assert suggestion == "list"

    def test_suggest_plugins_info_for_inf(self) -> None:
        """Test that 'inf' suggests 'info' for plugins."""
        suggestion = get_subcommand_suggestion("plugins", "inf")
        assert suggestion == "info"

    def test_suggest_config_show_for_shwo(self) -> None:
        """Test that 'shwo' suggests 'show' for config."""
        suggestion = get_subcommand_suggestion("config", "shwo")
        assert suggestion == "show"

    def test_suggest_config_init_for_int(self) -> None:
        """Test that 'int' suggests 'init' for config."""
        suggestion = get_subcommand_suggestion("config", "int")
        assert suggestion == "init"

    def test_suggest_config_validate_for_validte(self) -> None:
        """Test that 'validte' suggests 'validate' for config."""
        suggestion = get_subcommand_suggestion("config", "validte")
        assert suggestion == "validate"

    def test_no_suggestion_for_unknown_parent(self) -> None:
        """Test that unknown parent returns None."""
        suggestion = get_subcommand_suggestion("unknown", "list")
        assert suggestion is None


class TestOptionSuggestions:
    """Test option suggestion for typos."""

    def test_suggest_format_for_fromat(self) -> None:
        """Test that '--fromat' suggests '--format'."""
        valid_options = ["--format", "--output", "--verbose", "--quiet"]
        suggestion = get_option_suggestion("--fromat", valid_options)
        assert suggestion == "--format"

    def test_suggest_verbose_for_verbos(self) -> None:
        """Test that '--verbos' suggests '--verbose'."""
        valid_options = ["--format", "--output", "--verbose", "--quiet"]
        suggestion = get_option_suggestion("--verbos", valid_options)
        assert suggestion == "--verbose"

    def test_suggest_recursive_for_recursiv(self) -> None:
        """Test that '--recursiv' suggests '--recursive'."""
        valid_options = ["--recursive", "--format", "--output"]
        suggestion = get_option_suggestion("--recursiv", valid_options)
        assert suggestion == "--recursive"

    def test_no_suggestion_for_very_different_option(self) -> None:
        """Test that very different options return None."""
        valid_options = ["--format", "--output", "--verbose"]
        suggestion = get_option_suggestion("--xyz123", valid_options)
        assert suggestion is None


class TestContextHints:
    """Test context-aware hints."""

    def test_invalid_format_hint(self) -> None:
        """Test hint for invalid format errors."""
        hint = get_context_hint("invalid_format")
        assert hint is not None
        assert "json" in hint.lower()
        assert "table" in hint.lower()

    def test_invalid_category_hint(self) -> None:
        """Test hint for invalid category errors."""
        hint = get_context_hint("invalid_category")
        assert hint is not None
        assert "api_keys" in hint.lower()
        assert "credentials" in hint.lower()

    def test_invalid_confidence_hint(self) -> None:
        """Test hint for invalid confidence errors."""
        hint = get_context_hint("invalid_confidence")
        assert hint is not None
        assert "high" in hint.lower()
        assert "low" in hint.lower()

    def test_yara_compile_error_hint(self) -> None:
        """Test hint for YARA compilation errors."""
        hint = get_context_hint("yara_compile_error")
        assert hint is not None
        assert "condition" in hint.lower()

    def test_permission_denied_hint(self) -> None:
        """Test hint for permission denied errors."""
        hint = get_context_hint("permission_denied")
        assert hint is not None
        assert "permission" in hint.lower() or "access" in hint.lower()

    def test_path_not_found_hint(self) -> None:
        """Test hint for path not found errors."""
        hint = get_context_hint("path_not_found")
        assert hint is not None
        assert "exist" in hint.lower() or "path" in hint.lower()

    def test_config_not_found_hint(self) -> None:
        """Test hint for config not found errors."""
        hint = get_context_hint("config_not_found")
        assert hint is not None
        assert "config init" in hint.lower()

    def test_unknown_context_returns_none(self) -> None:
        """Test that unknown context returns None."""
        hint = get_context_hint("unknown_context_xyz")
        assert hint is None


class TestDocLinks:
    """Test documentation links."""

    def test_installation_doc_link(self) -> None:
        """Test installation documentation link."""
        assert "installation" in DOC_LINKS
        assert "installation" in DOC_LINKS["installation"]

    def test_cli_doc_link(self) -> None:
        """Test CLI documentation link."""
        assert "cli" in DOC_LINKS
        assert "cli-reference" in DOC_LINKS["cli"]

    def test_configuration_doc_link(self) -> None:
        """Test configuration documentation link."""
        assert "configuration" in DOC_LINKS
        assert "configuration" in DOC_LINKS["configuration"]

    def test_yara_doc_link(self) -> None:
        """Test YARA documentation link."""
        assert "yara" in DOC_LINKS
        assert "yara" in DOC_LINKS["yara"].lower()

    def test_plugins_doc_link(self) -> None:
        """Test plugins documentation link."""
        assert "plugins" in DOC_LINKS
        assert "plugins" in DOC_LINKS["plugins"]

    def test_outputs_doc_link(self) -> None:
        """Test outputs documentation link."""
        assert "outputs" in DOC_LINKS
        assert "outputs" in DOC_LINKS["outputs"]


class TestCLIErrorMessagesIntegration:
    """Integration tests for CLI error messages."""

    def test_invalid_format_shows_hint(self, temp_directory: Path) -> None:
        """Test that invalid format shows a helpful hint."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "xml"])
        assert result.exit_code == 1
        # Should show format hint or valid formats
        output_lower = result.output.lower()
        assert "json" in output_lower or "table" in output_lower or "format" in output_lower

    def test_invalid_category_shows_hint(self, temp_directory: Path) -> None:
        """Test that invalid category shows a helpful hint."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--categories", "invalid_cat"])
        assert result.exit_code == 1
        # Should show category hint
        output_lower = result.output.lower()
        assert "api_keys" in output_lower or "category" in output_lower

    def test_invalid_confidence_shows_hint(self, temp_directory: Path) -> None:
        """Test that invalid confidence shows a helpful hint."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--min-confidence", "very_high"])
        assert result.exit_code == 1
        # Should show confidence hint
        output_lower = result.output.lower()
        assert "high" in output_lower or "medium" in output_lower or "low" in output_lower or "confidence" in output_lower

    def test_error_includes_documentation_link(self, temp_directory: Path) -> None:
        """Test that errors include documentation links."""
        result = runner.invoke(app, ["scan", str(temp_directory), "--format", "invalid"])
        # Should include a documentation URL or reference
        assert "documentation" in result.output.lower() or "docs" in result.output.lower() or "hamburglar" in result.output.lower()


class TestMainCommandConstants:
    """Test that command constants are correct."""

    def test_all_main_commands_defined(self) -> None:
        """Test that all main commands are in the list."""
        expected = ["scan", "scan-git", "scan-web", "history", "report", "doctor", "plugins", "config"]
        for cmd in expected:
            assert cmd in MAIN_COMMANDS

    def test_all_aliases_map_to_valid_commands(self) -> None:
        """Test that all aliases map to valid main commands."""
        for alias, target in COMMAND_ALIASES.items():
            assert target in MAIN_COMMANDS, f"Alias '{alias}' maps to unknown command '{target}'"


class TestAliasPartialMatch:
    """Test partial matching against aliases."""

    def test_partial_alias_match_returns_correct_command(self) -> None:
        """Test that a partial match against an alias returns the right command."""
        # Testing when the fuzzy match hits an alias (e.g., "chek" matches "check" alias)
        suggestion = get_command_suggestion("chek")  # Similar to "check" which is an alias for "scan"
        assert suggestion == "scan"

    def test_fuzzy_alias_diagnostics(self) -> None:
        """Test fuzzy matching against alias 'diagnose' (for doctor)."""
        suggestion = get_command_suggestion("diagno")
        assert suggestion == "doctor"

    def test_fuzzy_alias_extensions(self) -> None:
        """Test fuzzy matching against alias 'extensions' (for plugins)."""
        suggestion = get_command_suggestion("extension")
        assert suggestion == "plugins"


class TestFormatCommandSuggestion:
    """Test format_command_suggestion function."""

    def test_format_command_suggestion_output(self) -> None:
        """Test that format_command_suggestion returns a formatted message."""
        from hamburglar.cli.errors import format_command_suggestion

        result = format_command_suggestion("scna", "scan")
        assert "scna" in result
        assert "scan" in result
        assert "Did you mean" in result

    def test_format_command_suggestion_with_hyphen(self) -> None:
        """Test with hyphenated command."""
        from hamburglar.cli.errors import format_command_suggestion

        result = format_command_suggestion("scan-gti", "scan-git")
        assert "scan-gti" in result
        assert "scan-git" in result


class TestFormatAvailableCommands:
    """Test format_available_commands function."""

    def test_format_available_commands_output(self) -> None:
        """Test that format_available_commands returns a formatted list."""
        from hamburglar.cli.errors import format_available_commands

        result = format_available_commands()
        assert "Available commands" in result
        assert "scan" in result
        assert "scan-git" in result
        assert "doctor" in result
        assert "plugins" in result


class TestGetDocLink:
    """Test get_doc_link function."""

    def test_get_doc_link_returns_url(self) -> None:
        """Test that get_doc_link returns URL for known topics."""
        from hamburglar.cli.errors import get_doc_link

        link = get_doc_link("cli")
        assert link is not None
        assert "cli-reference" in link

    def test_get_doc_link_case_insensitive(self) -> None:
        """Test that get_doc_link is case-insensitive."""
        from hamburglar.cli.errors import get_doc_link

        link = get_doc_link("CLI")
        assert link is not None
        assert "cli-reference" in link

    def test_get_doc_link_unknown_topic(self) -> None:
        """Test that get_doc_link returns None for unknown topics."""
        from hamburglar.cli.errors import get_doc_link

        link = get_doc_link("unknown_topic_xyz")
        assert link is None


class TestFormatDocReference:
    """Test format_doc_reference function."""

    def test_format_doc_reference_known_topic(self) -> None:
        """Test that format_doc_reference returns formatted string for known topics."""
        from hamburglar.cli.errors import format_doc_reference

        result = format_doc_reference("cli")
        assert "See:" in result
        assert "cli-reference" in result

    def test_format_doc_reference_unknown_topic(self) -> None:
        """Test that format_doc_reference returns empty string for unknown topics."""
        from hamburglar.cli.errors import format_doc_reference

        result = format_doc_reference("unknown_xyz")
        assert result == ""


class TestFormatErrorWithContext:
    """Test format_error_with_context function."""

    def test_format_error_with_no_context(self) -> None:
        """Test that format_error_with_context works with no context."""
        from hamburglar.cli.errors import format_error_with_context

        result = format_error_with_context("Test error message")
        assert result == "Test error message"

    def test_format_error_with_suggestion(self) -> None:
        """Test that format_error_with_context includes suggestion."""
        from hamburglar.cli.errors import format_error_with_context, ErrorContext

        context = ErrorContext(suggestion="Use 'scan' instead")
        result = format_error_with_context("Test error", context)
        assert "Test error" in result
        assert "Suggestion:" in result
        assert "Use 'scan' instead" in result

    def test_format_error_with_hint(self) -> None:
        """Test that format_error_with_context includes hint."""
        from hamburglar.cli.errors import format_error_with_context, ErrorContext

        context = ErrorContext(hint="Check your configuration")
        result = format_error_with_context("Test error", context)
        assert "Test error" in result
        assert "Hint:" in result
        assert "Check your configuration" in result

    def test_format_error_with_doc_link(self) -> None:
        """Test that format_error_with_context includes doc link."""
        from hamburglar.cli.errors import format_error_with_context, ErrorContext

        context = ErrorContext(doc_link="https://example.com/docs")
        result = format_error_with_context("Test error", context)
        assert "Test error" in result
        assert "Docs:" in result
        assert "https://example.com/docs" in result

    def test_format_error_with_all_context(self) -> None:
        """Test that format_error_with_context includes all fields."""
        from hamburglar.cli.errors import format_error_with_context, ErrorContext

        context = ErrorContext(
            suggestion="Try X",
            hint="Remember Y",
            doc_link="https://docs.example.com"
        )
        result = format_error_with_context("Main error", context)
        assert "Main error" in result
        assert "Try X" in result
        assert "Remember Y" in result
        assert "https://docs.example.com" in result


class TestFormatHelpFooter:
    """Test format_help_footer function."""

    def test_format_help_footer_with_command(self) -> None:
        """Test that format_help_footer works with a command."""
        from hamburglar.cli.errors import format_help_footer

        result = format_help_footer("scan")
        assert "hamburglar scan --help" in result
        assert "Docs:" in result

    def test_format_help_footer_without_command(self) -> None:
        """Test that format_help_footer works without a command."""
        from hamburglar.cli.errors import format_help_footer

        result = format_help_footer()
        assert "hamburglar --help" in result
        assert "Docs:" in result

    def test_format_help_footer_none_command(self) -> None:
        """Test that format_help_footer works with None command."""
        from hamburglar.cli.errors import format_help_footer

        result = format_help_footer(None)
        assert "hamburglar --help" in result
