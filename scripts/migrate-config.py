#!/usr/bin/env python3
"""Migrate old ham.conf configuration to the new TOML format.

This script converts the legacy INI-style ham.conf configuration file
to the new Hamburglar v2 TOML configuration format.

Usage:
    python scripts/migrate-config.py [OPTIONS] [HAM_CONF_PATH]

Examples:
    # Interactive migration (searches for ham.conf in current directory)
    python scripts/migrate-config.py

    # Migrate specific file
    python scripts/migrate-config.py /path/to/ham.conf

    # Non-interactive with output to specific file
    python scripts/migrate-config.py --output ~/.hamburglar.toml --no-interactive

    # Preview without writing
    python scripts/migrate-config.py --dry-run
"""

from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path
from typing import Any


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


def color(text: str, *codes: str) -> str:
    """Apply color codes to text if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + Colors.END


def print_header(text: str) -> None:
    """Print a styled header."""
    print()
    print(color(f"=== {text} ===", Colors.BOLD, Colors.CYAN))
    print()


def print_success(text: str) -> None:
    """Print a success message."""
    print(color(f"[OK] {text}", Colors.GREEN))


def print_warning(text: str) -> None:
    """Print a warning message."""
    print(color(f"[WARNING] {text}", Colors.YELLOW))


def print_error(text: str) -> None:
    """Print an error message."""
    print(color(f"[ERROR] {text}", Colors.RED))


def print_info(text: str) -> None:
    """Print an info message."""
    print(color(f"[INFO] {text}", Colors.BLUE))


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """Prompt the user for a yes/no answer.

    Args:
        question: The question to ask.
        default: The default value if user just presses Enter.

    Returns:
        True for yes, False for no.
    """
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        answer = input(question + suffix).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Please answer 'yes' or 'no' (or just press Enter for default)")


def prompt_choice(
    question: str, choices: list[str], default: int = 0
) -> str:
    """Prompt the user to select from a list of choices.

    Args:
        question: The question to ask.
        choices: List of choices.
        default: Index of the default choice.

    Returns:
        The selected choice.
    """
    print(question)
    for i, choice in enumerate(choices):
        marker = "*" if i == default else " "
        print(f"  {marker} {i + 1}. {choice}")
    print()

    while True:
        answer = input(f"Enter choice [1-{len(choices)}] (default: {default + 1}): ").strip()
        if not answer:
            return choices[default]
        try:
            idx = int(answer) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        print(f"Please enter a number between 1 and {len(choices)}")


def prompt_string(question: str, default: str = "") -> str:
    """Prompt the user for a string value.

    Args:
        question: The question to ask.
        default: The default value.

    Returns:
        The user's input or the default.
    """
    if default:
        answer = input(f"{question} [{default}]: ").strip()
        return answer if answer else default
    return input(f"{question}: ").strip()


def find_ham_conf() -> Path | None:
    """Search for ham.conf in common locations.

    Returns:
        Path to ham.conf if found, None otherwise.
    """
    search_paths = [
        Path.cwd() / "ham.conf",
        Path.cwd() / ".ham.conf",
        Path.home() / "ham.conf",
        Path.home() / ".ham.conf",
        Path("/etc/hamburglar/ham.conf"),
    ]

    for path in search_paths:
        if path.exists() and path.is_file():
            return path

    return None


def parse_ham_conf(path: Path) -> dict[str, Any]:
    """Parse the legacy ham.conf INI file.

    Args:
        path: Path to the ham.conf file.

    Returns:
        Dictionary with parsed configuration.

    Raises:
        ValueError: If the file cannot be parsed.
    """
    config = configparser.ConfigParser()

    try:
        config.read(path)
    except configparser.Error as e:
        raise ValueError(f"Failed to parse {path}: {e}") from e

    result: dict[str, Any] = {}

    # Extract MySQL section if present
    if "mySql" in config or "mysql" in config:
        section = "mySql" if "mySql" in config else "mysql"
        mysql_config: dict[str, str] = {}

        if config.has_option(section, "user"):
            mysql_config["user"] = config.get(section, "user")
        if config.has_option(section, "password"):
            mysql_config["password"] = config.get(section, "password")
        if config.has_option(section, "host"):
            mysql_config["host"] = config.get(section, "host")
        if config.has_option(section, "database"):
            mysql_config["database"] = config.get(section, "database")
        if config.has_option(section, "port"):
            mysql_config["port"] = config.get(section, "port")

        if mysql_config:
            result["mysql"] = mysql_config

    # Extract any other sections
    for section in config.sections():
        if section.lower() not in ("mysql",):
            result[section] = dict(config.items(section))

    return result


def generate_toml_config(
    legacy_config: dict[str, Any],
    options: dict[str, Any],
) -> str:
    """Generate the new TOML configuration file content.

    Args:
        legacy_config: Parsed legacy configuration.
        options: Additional options from interactive prompts.

    Returns:
        TOML configuration file content as a string.
    """
    lines = [
        "# Hamburglar v2 Configuration",
        "# Migrated from ham.conf",
        "# See https://github.com/needmorecowbell/Hamburglar for documentation",
        "",
        "# Logging level (debug, info, warning, error, critical)",
        f'log_level = "{options.get("log_level", "info")}"',
        "",
    ]

    # Scan section
    lines.append("[scan]")
    lines.append("# Scan directories recursively")
    lines.append(f"recursive = {str(options.get('recursive', True)).lower()}")
    lines.append("")
    lines.append("# Maximum file size to scan (supports K, M, G suffixes)")
    lines.append(f'max_file_size = "{options.get("max_file_size", "10MB")}"')
    lines.append("")
    lines.append("# Number of concurrent file operations")
    lines.append(f"concurrency = {options.get('concurrency', 50)}")
    lines.append("")
    lines.append("# Timeout for individual file scans (seconds)")
    lines.append(f"timeout = {options.get('timeout', 30)}")
    lines.append("")
    lines.append("# Patterns to exclude from scanning")
    blacklist = options.get(
        "blacklist",
        [".git", "__pycache__", "node_modules", ".venv", "venv", "*.pyc"],
    )
    lines.append("blacklist = [")
    for item in blacklist:
        lines.append(f'    "{item}",')
    lines.append("]")
    lines.append("")
    lines.append("# If non-empty, only scan files matching these patterns")
    whitelist = options.get("whitelist", [])
    if whitelist:
        lines.append("whitelist = [")
        for item in whitelist:
            lines.append(f'    "{item}",')
        lines.append("]")
    else:
        lines.append("whitelist = []")
    lines.append("")

    # Detector section
    lines.append("[detector]")
    lines.append("# Categories to enable (empty = all)")
    lines.append(
        "# Available: api_keys, credentials, crypto, network, private_keys, cloud, generic"
    )
    categories = options.get("enabled_categories", [])
    if categories:
        lines.append("enabled_categories = [")
        for cat in categories:
            lines.append(f'    "{cat}",')
        lines.append("]")
    else:
        lines.append("enabled_categories = []")
    lines.append("")
    lines.append("# Specific pattern names to disable")
    lines.append("disabled_patterns = []")
    lines.append("")
    lines.append("# Minimum confidence level (low, medium, high)")
    lines.append(f'min_confidence = "{options.get("min_confidence", "low")}"')
    lines.append("")

    # Output section
    lines.append("[output]")
    lines.append("# Output format (json, table, sarif, csv, html, markdown)")
    lines.append(f'format = "{options.get("format", "table")}"')
    lines.append("")
    lines.append("# Save findings to SQLite database")
    lines.append(f"save_to_db = {str(options.get('save_to_db', False)).lower()}")
    lines.append("")
    lines.append("# Path to SQLite database")
    lines.append('# db_path = "~/.hamburglar/findings.db"')
    lines.append("")
    lines.append("# Suppress non-essential output")
    lines.append(f"quiet = {str(options.get('quiet', False)).lower()}")
    lines.append("")
    lines.append("# Enable verbose output")
    lines.append(f"verbose = {str(options.get('verbose', False)).lower()}")
    lines.append("")

    # YARA section
    lines.append("[yara]")
    lines.append("# Enable YARA rule scanning")
    lines.append(f"enabled = {str(options.get('yara_enabled', False)).lower()}")
    lines.append("")
    lines.append("# Path to YARA rules directory")
    if options.get("yara_rules_path"):
        lines.append(f'rules_path = "{options["yara_rules_path"]}"')
    else:
        lines.append('# rules_path = "./rules"')
    lines.append("")
    lines.append("# Timeout for YARA matching (seconds)")
    lines.append(f"timeout = {options.get('yara_timeout', 30)}")
    lines.append("")

    # Add migration notes about MySQL credentials
    if "mysql" in legacy_config:
        lines.append("# ============================================================")
        lines.append("# MIGRATION NOTE: MySQL Configuration")
        lines.append("# ============================================================")
        lines.append("# Your old ham.conf contained MySQL credentials for the")
        lines.append("# magic signature detection feature. This feature has been")
        lines.append("# removed in Hamburglar v2 in favor of YARA rules.")
        lines.append("#")
        lines.append("# The MySQL credentials from your old configuration were:")
        if "user" in legacy_config["mysql"]:
            lines.append(f"#   user: {legacy_config['mysql']['user']}")
        if "password" in legacy_config["mysql"]:
            lines.append("#   password: ********** (hidden for security)")
        if "host" in legacy_config["mysql"]:
            lines.append(f"#   host: {legacy_config['mysql']['host']}")
        if "database" in legacy_config["mysql"]:
            lines.append(f"#   database: {legacy_config['mysql']['database']}")
        lines.append("#")
        lines.append("# ALTERNATIVE: Use YARA rules for file type identification.")
        lines.append("# The rules/ directory contains pre-built rules for common")
        lines.append("# file formats (PNG, JPEG, PDF, executables, etc.)")
        lines.append("#")
        lines.append("# To enable YARA scanning:")
        lines.append("#   [yara]")
        lines.append("#   enabled = true")
        lines.append('#   rules_path = "./rules"')
        lines.append("# ============================================================")
        lines.append("")

    return "\n".join(lines)


def run_interactive_migration(legacy_config: dict[str, Any]) -> dict[str, Any]:
    """Run interactive prompts to gather new configuration options.

    Args:
        legacy_config: Parsed legacy configuration.

    Returns:
        Dictionary of configuration options.
    """
    options: dict[str, Any] = {}

    print_header("Hamburglar Configuration Migration")

    # Check for MySQL configuration
    if "mysql" in legacy_config:
        print_warning(
            "Your old ham.conf contains MySQL credentials for magic signature detection."
        )
        print_info(
            "This feature has been REMOVED in v2. YARA rules are used instead."
        )
        print()
        if prompt_yes_no("Would you like to enable YARA scanning as a replacement?"):
            options["yara_enabled"] = True
            options["yara_rules_path"] = prompt_string(
                "Path to YARA rules directory", "./rules"
            )
        print()

    # Scan settings
    print_header("Scan Settings")

    options["recursive"] = prompt_yes_no("Scan directories recursively?")

    max_size = prompt_choice(
        "Maximum file size to scan:",
        ["1MB", "5MB", "10MB", "50MB", "100MB", "unlimited"],
        default=2,  # 10MB
    )
    options["max_file_size"] = max_size if max_size != "unlimited" else "0"

    concurrency = prompt_string("Maximum concurrent operations", "50")
    try:
        options["concurrency"] = int(concurrency)
    except ValueError:
        options["concurrency"] = 50

    # Blacklist configuration
    print()
    print_info("Default blacklist patterns: .git, __pycache__, node_modules, .venv, venv, *.pyc")
    if prompt_yes_no("Use default blacklist patterns?"):
        options["blacklist"] = [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            "*.pyc",
        ]
    else:
        custom = prompt_string(
            "Enter blacklist patterns (comma-separated)", ""
        )
        options["blacklist"] = [p.strip() for p in custom.split(",") if p.strip()]

    # Detector settings
    print_header("Detection Settings")

    if prompt_yes_no("Enable all pattern categories?"):
        options["enabled_categories"] = []
    else:
        print("Available categories: api_keys, credentials, crypto, network, private_keys, cloud, generic")
        cats = prompt_string(
            "Enter categories to enable (comma-separated)", ""
        )
        options["enabled_categories"] = [c.strip() for c in cats.split(",") if c.strip()]

    confidence = prompt_choice(
        "Minimum confidence level for findings:",
        ["low (catch everything)", "medium (balanced)", "high (fewer false positives)"],
        default=0,
    )
    options["min_confidence"] = confidence.split()[0]

    # Output settings
    print_header("Output Settings")

    fmt = prompt_choice(
        "Default output format:",
        ["table (console)", "json", "csv", "html", "markdown", "sarif (CI/CD)"],
        default=0,
    )
    options["format"] = fmt.split()[0]

    options["save_to_db"] = prompt_yes_no("Save findings to SQLite database?", default=False)
    options["verbose"] = prompt_yes_no("Enable verbose output by default?", default=False)

    # Log level
    print_header("Logging")

    log_level = prompt_choice(
        "Default log level:",
        ["debug", "info", "warning", "error"],
        default=1,  # info
    )
    options["log_level"] = log_level

    return options


def run_non_interactive_migration(legacy_config: dict[str, Any]) -> dict[str, Any]:
    """Generate default configuration options without prompts.

    Args:
        legacy_config: Parsed legacy configuration.

    Returns:
        Dictionary of configuration options with sensible defaults.
    """
    options: dict[str, Any] = {
        "recursive": True,
        "max_file_size": "10MB",
        "concurrency": 50,
        "timeout": 30,
        "blacklist": [".git", "__pycache__", "node_modules", ".venv", "venv", "*.pyc"],
        "whitelist": [],
        "enabled_categories": [],
        "min_confidence": "low",
        "format": "table",
        "save_to_db": False,
        "quiet": False,
        "verbose": False,
        "yara_enabled": False,
        "yara_rules_path": None,
        "yara_timeout": 30,
        "log_level": "info",
    }

    # If MySQL was configured, suggest YARA as replacement
    if "mysql" in legacy_config:
        options["yara_enabled"] = True
        options["yara_rules_path"] = "./rules"

    return options


def main() -> int:
    """Main entry point for the migration script.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    parser = argparse.ArgumentParser(
        description="Migrate ham.conf to Hamburglar v2 TOML configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "ham_conf",
        nargs="?",
        type=Path,
        help="Path to ham.conf file (auto-detected if not specified)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output path for new config (default: .hamburglar.toml in current directory)",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Run without interactive prompts (use defaults)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the generated config without writing",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite output file if it exists",
    )
    parser.add_argument(
        "--format",
        choices=["toml", "yaml", "json"],
        default="toml",
        help="Output format (default: toml)",
    )

    args = parser.parse_args()

    # Find ham.conf
    ham_conf_path = args.ham_conf
    if not ham_conf_path:
        ham_conf_path = find_ham_conf()

    if ham_conf_path and ham_conf_path.exists():
        print_info(f"Found legacy configuration: {ham_conf_path}")
        try:
            legacy_config = parse_ham_conf(ham_conf_path)
            print_success(f"Parsed {len(legacy_config)} section(s) from ham.conf")
        except ValueError as e:
            print_error(str(e))
            return 1
    else:
        if args.ham_conf:
            print_error(f"Configuration file not found: {args.ham_conf}")
            return 1
        print_info("No ham.conf found. Creating new configuration from defaults.")
        legacy_config = {}

    # Gather options
    if args.no_interactive:
        options = run_non_interactive_migration(legacy_config)
    else:
        try:
            options = run_interactive_migration(legacy_config)
        except (KeyboardInterrupt, EOFError):
            print()
            print_warning("Migration cancelled by user.")
            return 1

    # Generate config content
    if args.format == "toml":
        config_content = generate_toml_config(legacy_config, options)
        default_filename = ".hamburglar.toml"
    elif args.format == "yaml":
        # For YAML, we'll generate TOML and inform user about conversion
        print_warning(
            "YAML output not yet implemented. Generating TOML format instead."
        )
        config_content = generate_toml_config(legacy_config, options)
        default_filename = ".hamburglar.toml"
    else:  # json
        print_warning(
            "JSON output not yet implemented. Generating TOML format instead."
        )
        config_content = generate_toml_config(legacy_config, options)
        default_filename = ".hamburglar.toml"

    # Dry run - just print
    if args.dry_run:
        print_header("Generated Configuration (dry-run)")
        print(config_content)
        print()
        print_info("Dry run complete. No files were written.")
        return 0

    # Determine output path
    output_path = args.output or Path.cwd() / default_filename

    # Check if output exists
    if output_path.exists() and not args.force:
        if args.no_interactive:
            print_error(
                f"Output file already exists: {output_path}\n"
                "Use --force to overwrite or specify a different --output path."
            )
            return 1
        if not prompt_yes_no(f"Output file {output_path} exists. Overwrite?", default=False):
            print_warning("Migration cancelled.")
            return 1

    # Write output
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(config_content, encoding="utf-8")
        print_success(f"Configuration written to: {output_path}")
    except OSError as e:
        print_error(f"Failed to write configuration: {e}")
        return 1

    # Print next steps
    print()
    print_header("Migration Complete!")
    print("Next steps:")
    print(f"  1. Review the generated config: {output_path}")
    print("  2. Run 'hamburglar doctor' to verify your setup")
    print("  3. Run 'hamburglar scan --help' to see available options")
    print()

    if "mysql" in legacy_config:
        print_warning(
            "IMPORTANT: Your MySQL credentials were NOT migrated to the new config.\n"
            "The MySQL-based magic signature feature has been replaced with YARA rules.\n"
            "Please delete your old ham.conf file after verifying the migration."
        )
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
