"""Error handling utilities for the Hamburglar CLI.

This module provides helpful error messages, command suggestions for typos,
context-aware help, and documentation links.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

# Documentation base URL
DOCS_BASE_URL = "https://hamburglar.readthedocs.io/en/latest"

# All available commands and subcommands
MAIN_COMMANDS = ["scan", "scan-git", "scan-web", "history", "report", "doctor", "plugins", "config"]
PLUGIN_SUBCOMMANDS = ["list", "info"]
CONFIG_SUBCOMMANDS = ["show", "init", "validate"]

# Command aliases (common alternatives users might try)
COMMAND_ALIASES: dict[str, str] = {
    # scan aliases
    "check": "scan",
    "find": "scan",
    "search": "scan",
    "detect": "scan",
    "analyze": "scan",
    "analyse": "scan",
    "inspect": "scan",
    "examine": "scan",
    "look": "scan",
    # scan-git aliases
    "git": "scan-git",
    "git-scan": "scan-git",
    "scangit": "scan-git",
    "repo": "scan-git",
    "repository": "scan-git",
    # scan-web aliases
    "web": "scan-web",
    "url": "scan-web",
    "scanweb": "scan-web",
    "scanurl": "scan-web",
    "fetch": "scan-web",
    "http": "scan-web",
    "https": "scan-web",
    # history aliases
    "hist": "history",
    "log": "history",
    "logs": "history",
    "findings": "history",
    "results": "history",
    "past": "history",
    # report aliases
    "summary": "report",
    "stats": "report",
    "statistics": "report",
    "export": "report",
    # doctor aliases
    "check-health": "doctor",
    "health": "doctor",
    "diagnose": "doctor",
    "diag": "doctor",
    "status": "doctor",
    "test": "doctor",
    "verify": "doctor",
    # plugins aliases
    "plugin": "plugins",
    "extensions": "plugins",
    "ext": "plugins",
    "addons": "plugins",
    # config aliases
    "configure": "config",
    "conf": "config",
    "cfg": "config",
    "settings": "config",
    "setup": "config",
    "options": "config",
}

# Documentation links for common issues
DOC_LINKS: dict[str, str] = {
    "installation": f"{DOCS_BASE_URL}/installation.html",
    "quickstart": f"{DOCS_BASE_URL}/quickstart.html",
    "cli": f"{DOCS_BASE_URL}/cli-reference.html",
    "configuration": f"{DOCS_BASE_URL}/configuration.html",
    "detectors": f"{DOCS_BASE_URL}/detectors.html",
    "outputs": f"{DOCS_BASE_URL}/outputs.html",
    "plugins": f"{DOCS_BASE_URL}/plugins.html",
    "yara": f"{DOCS_BASE_URL}/detectors.html#yara-rules",
    "formats": f"{DOCS_BASE_URL}/outputs.html#output-formats",
    "database": f"{DOCS_BASE_URL}/outputs.html#database-storage",
    "git": f"{DOCS_BASE_URL}/cli-reference.html#scan-git",
    "web": f"{DOCS_BASE_URL}/cli-reference.html#scan-web",
    "history": f"{DOCS_BASE_URL}/cli-reference.html#history",
    "report": f"{DOCS_BASE_URL}/cli-reference.html#report",
}


@dataclass
class ErrorContext:
    """Context for error messages."""

    command: str | None = None
    option: str | None = None
    value: str | None = None
    suggestion: str | None = None
    doc_link: str | None = None
    hint: str | None = None


def get_command_suggestion(invalid_command: str, cutoff: float = 0.6) -> str | None:
    """Get a suggested command for a typo.

    Args:
        invalid_command: The command the user typed.
        cutoff: Minimum similarity ratio (0-1) for a match.

    Returns:
        A suggested command string, or None if no good match found.
    """
    # First check if it's a known alias
    lower_cmd = invalid_command.lower()
    if lower_cmd in COMMAND_ALIASES:
        return COMMAND_ALIASES[lower_cmd]

    # Try fuzzy matching against main commands
    matches = difflib.get_close_matches(
        lower_cmd,
        MAIN_COMMANDS,
        n=1,
        cutoff=cutoff
    )

    if matches:
        return matches[0]

    # Try matching against aliases as well (for partial matches)
    alias_matches = difflib.get_close_matches(
        lower_cmd,
        list(COMMAND_ALIASES.keys()),
        n=1,
        cutoff=cutoff
    )

    if alias_matches:
        return COMMAND_ALIASES[alias_matches[0]]

    return None


def get_subcommand_suggestion(
    parent: str,
    invalid_subcommand: str,
    cutoff: float = 0.6
) -> str | None:
    """Get a suggested subcommand for a typo.

    Args:
        parent: The parent command (e.g., "plugins", "config").
        invalid_subcommand: The subcommand the user typed.
        cutoff: Minimum similarity ratio (0-1) for a match.

    Returns:
        A suggested subcommand string, or None if no good match found.
    """
    subcommands: Sequence[str] = []

    if parent == "plugins":
        subcommands = PLUGIN_SUBCOMMANDS
    elif parent == "config":
        subcommands = CONFIG_SUBCOMMANDS
    else:
        return None

    matches = difflib.get_close_matches(
        invalid_subcommand.lower(),
        subcommands,
        n=1,
        cutoff=cutoff
    )

    return matches[0] if matches else None


def format_command_suggestion(invalid_cmd: str, suggested_cmd: str) -> str:
    """Format a helpful message for command suggestions.

    Args:
        invalid_cmd: The invalid command entered.
        suggested_cmd: The suggested correct command.

    Returns:
        A formatted suggestion message.
    """
    return (
        f"Unknown command '{invalid_cmd}'. "
        f"Did you mean '[bold cyan]{suggested_cmd}[/bold cyan]'?"
    )


def format_available_commands() -> str:
    """Format a list of available commands.

    Returns:
        A formatted string listing all available commands.
    """
    return (
        "\n[dim]Available commands:[/dim] " +
        ", ".join(f"[cyan]{cmd}[/cyan]" for cmd in MAIN_COMMANDS)
    )


def get_doc_link(topic: str) -> str | None:
    """Get the documentation link for a topic.

    Args:
        topic: The topic to get docs for (e.g., "yara", "formats").

    Returns:
        The documentation URL or None if topic not found.
    """
    return DOC_LINKS.get(topic.lower())


def format_doc_reference(topic: str) -> str:
    """Format a documentation reference for display.

    Args:
        topic: The topic to reference.

    Returns:
        A formatted documentation reference string.
    """
    link = get_doc_link(topic)
    if link:
        return f"\n[dim]See:[/dim] {link}"
    return ""


# Context-aware hints for common error scenarios
CONTEXT_HINTS: dict[str, str] = {
    # Format errors
    "invalid_format": (
        "Valid formats: json, table, csv, html, markdown, sarif, ndjson"
    ),
    # Category errors
    "invalid_category": (
        "Valid categories: api_keys, cloud, credentials, crypto, generic, network, private_keys"
    ),
    # Confidence errors
    "invalid_confidence": (
        "Valid confidence levels: high, medium, low"
    ),
    # YARA errors
    "yara_not_found": (
        "Ensure YARA rules path exists. Use --no-yara to disable YARA scanning."
    ),
    "yara_compile_error": (
        "Check YARA rule syntax. Common issues: missing 'condition' section, "
        "invalid regex patterns, undefined identifiers."
    ),
    "yara_not_installed": (
        "Install yara-python with: pip install yara-python"
    ),
    # Path errors
    "path_not_found": (
        "Check that the file or directory exists and the path is correct."
    ),
    "permission_denied": (
        "Check file permissions. You may need read access to scan files."
    ),
    # Output errors
    "output_permission": (
        "Check write permissions for the output directory."
    ),
    "output_dir_missing": (
        "The output directory does not exist. Use --output-dir to auto-create."
    ),
    # Database errors
    "db_permission": (
        "Check write permissions for ~/.hamburglar/ or specify --db-path."
    ),
    # Config errors
    "config_not_found": (
        "Create a config file with: hamburglar config init"
    ),
    "config_invalid": (
        "Validate config with: hamburglar config validate"
    ),
    # Git scan errors
    "git_clone_failed": (
        "Check that the repository URL is correct and accessible."
    ),
    "git_not_installed": (
        "Git must be installed for git repository scanning."
    ),
    # Web scan errors
    "url_invalid": (
        "Ensure the URL starts with http:// or https://"
    ),
    "url_unreachable": (
        "Check network connectivity and that the URL is correct."
    ),
    # Plugin errors
    "plugin_not_found": (
        "List available plugins with: hamburglar plugins list"
    ),
    "plugin_load_error": (
        "Check plugin dependencies and compatibility."
    ),
}


def get_context_hint(context: str) -> str | None:
    """Get a context-aware hint for an error.

    Args:
        context: The error context key.

    Returns:
        A helpful hint string or None if no hint available.
    """
    return CONTEXT_HINTS.get(context)


def format_error_with_context(
    message: str,
    context: ErrorContext | None = None,
) -> str:
    """Format an error message with additional context and help.

    Args:
        message: The base error message.
        context: Optional error context with suggestions/hints.

    Returns:
        A formatted error message with all available help.
    """
    parts = [message]

    if context:
        if context.suggestion:
            parts.append(f"\n[cyan]Suggestion:[/cyan] {context.suggestion}")
        if context.hint:
            parts.append(f"\n[dim]Hint:[/dim] {context.hint}")
        if context.doc_link:
            parts.append(f"\n[dim]Docs:[/dim] {context.doc_link}")

    return "".join(parts)


def get_option_suggestion(
    invalid_option: str,
    valid_options: Sequence[str],
    cutoff: float = 0.6
) -> str | None:
    """Get a suggested option name for a typo.

    Args:
        invalid_option: The option the user typed.
        valid_options: List of valid option names.
        cutoff: Minimum similarity ratio for a match.

    Returns:
        A suggested option string, or None if no good match found.
    """
    # Strip leading dashes for comparison
    clean_option = invalid_option.lstrip("-")
    clean_valid = [opt.lstrip("-") for opt in valid_options]

    matches = difflib.get_close_matches(
        clean_option,
        clean_valid,
        n=1,
        cutoff=cutoff
    )

    if matches:
        # Find the original option with dashes
        idx = clean_valid.index(matches[0])
        return valid_options[idx]

    return None


# Error messages for specific scenarios
ERROR_MESSAGES: dict[str, str] = {
    "no_command": (
        "No command specified. Use 'hamburglar --help' to see available commands."
    ),
    "unknown_command": (
        "Unknown command. Use 'hamburglar --help' to see available commands."
    ),
    "missing_argument": (
        "Missing required argument. Use 'hamburglar {command} --help' for usage."
    ),
    "invalid_option": (
        "Invalid option. Use 'hamburglar {command} --help' for available options."
    ),
}


def format_help_footer(command: str | None = None) -> str:
    """Format a help footer with common actions.

    Args:
        command: Optional command name for command-specific help.

    Returns:
        A formatted help footer string.
    """
    if command:
        return (
            f"\n[dim]Run 'hamburglar {command} --help' for usage information.[/dim]"
            f"\n[dim]Docs: {DOC_LINKS.get('cli', DOCS_BASE_URL)}[/dim]"
        )
    return (
        "\n[dim]Run 'hamburglar --help' for usage information.[/dim]"
        f"\n[dim]Docs: {DOC_LINKS.get('cli', DOCS_BASE_URL)}[/dim]"
    )
