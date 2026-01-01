"""Command-line interface for Hamburglar.

This module provides the Typer-based CLI for running Hamburglar scans
with various options for output format, YARA rules, and verbosity.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Optional
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from hamburglar import __version__
from hamburglar.cli.errors import (
    DOC_LINKS,
    format_available_commands,
    get_command_suggestion,
    get_context_hint,
)
from hamburglar.config import (
    ConfigLoader,
    HamburglarConfig,
    load_config,
    reset_config,
)
from hamburglar.core.async_scanner import AsyncScanner
from hamburglar.core.exceptions import (
    ConfigError,
    DetectorError,
    HamburglarError,
    OutputError,
    ScanError,
    YaraCompilationError,
)
from hamburglar.core.logging import setup_logging
from hamburglar.core.models import OutputFormat, ScanConfig, ScanResult, Severity
from hamburglar.core.progress import ScanProgress
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.detectors.yara_detector import YaraDetector
from hamburglar.outputs import BaseOutput
from hamburglar.outputs.csv_output import CsvOutput
from hamburglar.outputs.html_output import HtmlOutput
from hamburglar.outputs.json_output import JsonOutput
from hamburglar.outputs.markdown_output import MarkdownOutput
from hamburglar.outputs.sarif import SarifOutput
from hamburglar.outputs.streaming import StreamingOutput
from hamburglar.outputs.table_output import TableOutput
from hamburglar.scanners import GitScanner, WebScanner
from hamburglar.storage import ScanStatistics, StorageError
from hamburglar.storage.sqlite import SqliteStorage

# Valid category names for CLI parsing
VALID_CATEGORIES = {cat.value: cat for cat in PatternCategory}

# Valid confidence levels for CLI parsing
VALID_CONFIDENCE_LEVELS = {conf.value: conf for conf in Confidence}

# Valid output formats for CLI parsing
VALID_FORMATS = {fmt.value: fmt for fmt in OutputFormat}

# Mapping of output formats to their formatter classes
FORMAT_FORMATTERS: dict[OutputFormat, type[BaseOutput]] = {
    OutputFormat.JSON: JsonOutput,
    OutputFormat.TABLE: TableOutput,
    OutputFormat.SARIF: SarifOutput,
    OutputFormat.CSV: CsvOutput,
    OutputFormat.HTML: HtmlOutput,
    OutputFormat.MARKDOWN: MarkdownOutput,
}

# Mapping of output formats to file extensions
FORMAT_EXTENSIONS: dict[OutputFormat, str] = {
    OutputFormat.JSON: ".json",
    OutputFormat.TABLE: ".txt",
    OutputFormat.SARIF: ".sarif.json",
    OutputFormat.CSV: ".csv",
    OutputFormat.HTML: ".html",
    OutputFormat.MARKDOWN: ".md",
}


def get_formatter(output_format: OutputFormat) -> BaseOutput:
    """Get the appropriate output formatter for the given format.

    Args:
        output_format: The output format enum value.

    Returns:
        An instance of the corresponding formatter class.
    """
    formatter_class = FORMAT_FORMATTERS.get(output_format)
    if formatter_class is None:
        raise ValueError(f"Unsupported output format: {output_format}")
    return formatter_class()


def generate_output_filename(
    target: str,
    output_format: OutputFormat,
    scan_type: str = "scan",
) -> str:
    """Generate an auto-named output filename based on target and timestamp.

    The filename format is: hamburglar_{scan_type}_{target_name}_{timestamp}{extension}

    Args:
        target: The scan target (file path, URL, or git repository).
        output_format: The output format enum value.
        scan_type: Type of scan ('scan', 'git', or 'web').

    Returns:
        A filename string with appropriate extension.
    """
    # Get timestamp in a filesystem-safe format
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Extract a clean target name
    if scan_type == "web":
        # For URLs, use the domain name
        parsed = urlparse(target)
        target_name = parsed.netloc or "url"
        # Remove port if present
        if ":" in target_name:
            target_name = target_name.split(":")[0]
    elif scan_type == "git":
        # For git repos, extract repo name from URL or path
        if target.startswith(("http://", "https://", "git@")):
            # Remote URL
            target_name = target.rstrip("/").split("/")[-1]
            # Remove .git suffix if present
            if target_name.endswith(".git"):
                target_name = target_name[:-4]
        else:
            # Local path
            target_name = Path(target).resolve().name
    else:
        # For file/directory paths, use the basename
        target_name = Path(target).resolve().name

    # Sanitize the target name for filesystem use
    # Replace any non-alphanumeric characters with underscore
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_name)
    # Remove consecutive underscores and strip trailing underscores
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")
    safe_name = safe_name.strip("_")

    # Ensure the name isn't empty
    if not safe_name:
        safe_name = "target"

    # Get file extension
    extension = FORMAT_EXTENSIONS.get(output_format, ".txt")

    return f"hamburglar_{scan_type}_{safe_name}_{timestamp}{extension}"


# Default concurrency limit for async scanning
DEFAULT_CONCURRENCY = 50

# Default database path for storing findings
DEFAULT_DB_PATH = Path.home() / ".hamburglar" / "findings.db"


def get_db_path(custom_path: Path | None = None) -> Path:
    """Get the database path, using custom path or default.

    Args:
        custom_path: Optional custom database path. If None, uses default.

    Returns:
        The resolved database path.
    """
    if custom_path is not None:
        return custom_path.resolve()
    return DEFAULT_DB_PATH


def get_effective_config(
    config_file: Path | None = None,
    cli_args: dict | None = None,
    quiet: bool = False,
    verbose: bool = False,
) -> HamburglarConfig:
    """Load configuration with CLI argument overrides.

    This function loads configuration from all sources (defaults, config file,
    environment variables) and applies CLI argument overrides on top.

    Args:
        config_file: Optional explicit path to a config file.
        cli_args: Dictionary of CLI argument overrides.
        quiet: Whether to suppress output.
        verbose: Whether to show verbose output.

    Returns:
        Merged HamburglarConfig with all settings resolved.
    """
    try:
        config = load_config(config_path=config_file, cli_args=cli_args)
        if verbose and not quiet:
            # Check if a config file was found
            loader = ConfigLoader()
            found_path = config_file or loader.find_config_file()
            if found_path:
                console.print(f"[dim]Using config:[/dim] {found_path}")
        return config
    except Exception as e:
        if not quiet:
            _display_error(ConfigError(f"Failed to load configuration: {e}"))
        # Fall back to defaults
        return HamburglarConfig()


def save_to_database(
    result: "ScanResult",
    db_path: Path,
    quiet: bool = False,
    verbose: bool = False,
) -> str | None:
    """Save scan results to SQLite database.

    Args:
        result: The scan result to save.
        db_path: Path to the SQLite database file.
        quiet: If True, suppress output messages.
        verbose: If True, show detailed output.

    Returns:
        The scan ID if successful, None otherwise.

    Raises:
        typer.Exit: If saving fails.
    """
    try:
        # Create the database directory if it doesn't exist
        db_dir = db_path.parent
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
            if verbose and not quiet:
                console.print(f"[dim]Created database directory:[/dim] {db_dir}")

        # Save to database
        with SqliteStorage(db_path) as storage:
            scan_id = storage.save_scan(result)

        if not quiet:
            console.print(f"[green]Saved to database:[/green] {db_path}")
            if verbose:
                console.print(f"[dim]Scan ID:[/dim] {scan_id}")

        return scan_id

    except StorageError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except OSError as e:
        _display_error(OutputError(f"Failed to save to database: {e}", output_path=str(db_path)))
        raise typer.Exit(code=EXIT_ERROR) from None


def parse_categories(value: str) -> list[PatternCategory]:
    """Parse a comma-separated list of category names into PatternCategory enums.

    Args:
        value: Comma-separated category names (e.g., "api_keys,cloud,credentials")

    Returns:
        List of PatternCategory enums.

    Raises:
        typer.BadParameter: If any category name is invalid.
    """
    if not value:
        return []

    categories = []
    for name in value.split(","):
        name = name.strip().lower()
        if not name:
            continue
        if name not in VALID_CATEGORIES:
            valid_names = ", ".join(sorted(VALID_CATEGORIES.keys()))
            raise typer.BadParameter(f"Invalid category '{name}'. Valid categories: {valid_names}")
        categories.append(VALID_CATEGORIES[name])

    return categories


def parse_confidence(value: str) -> Confidence:
    """Parse a confidence level string into a Confidence enum.

    Args:
        value: Confidence level name (e.g., "high", "medium", "low")

    Returns:
        Confidence enum value.

    Raises:
        typer.BadParameter: If the confidence level is invalid.
    """
    if not value:
        raise typer.BadParameter("Confidence level cannot be empty")

    level = value.strip().lower()
    if level not in VALID_CONFIDENCE_LEVELS:
        valid_names = ", ".join(sorted(VALID_CONFIDENCE_LEVELS.keys()))
        raise typer.BadParameter(f"Invalid confidence level '{level}'. Valid levels: {valid_names}")

    return VALID_CONFIDENCE_LEVELS[level]


if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector
    from hamburglar.plugins.discovery import PluginListEntry

# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_NO_FINDINGS = 2

# Initialize Typer app and Rich consoles
app = typer.Typer(
    name="hamburglar",
    help="Hamburglar - A static analysis tool for extracting sensitive information.",
    add_completion=True,
)
console = Console()
error_console = Console(stderr=True)


def _display_error(
    error: Exception,
    title: str = "Error",
    hint: str | None = None,
    doc_topic: str | None = None,
    suggestion: str | None = None,
) -> None:
    """Display an error with rich formatting, hints, and documentation links.

    Args:
        error: The exception to display.
        title: The title for the error panel.
        hint: Optional hint text to help the user fix the issue.
        doc_topic: Optional documentation topic key for a reference link.
        suggestion: Optional suggested command or fix.
    """
    # Build help section if any context is provided
    help_section = ""
    if suggestion:
        help_section += f"\n\n[cyan]Did you mean:[/cyan] {suggestion}"
    if hint:
        help_section += f"\n\n[yellow]Hint:[/yellow] {hint}"
    if doc_topic:
        doc_link = DOC_LINKS.get(doc_topic)
        if doc_link:
            help_section += f"\n\n[dim]Documentation:[/dim] {doc_link}"

    if isinstance(error, YaraCompilationError):
        message = f"[bold red]YARA Compilation Error[/bold red]\n\n{error.message}"
        if error.rule_file:
            message += f"\n\n[dim]Rule file:[/dim] {error.rule_file}"
        if error.context:
            for key, value in error.context.items():
                if key != "rule_file":
                    message += f"\n[dim]{key}:[/dim] {value}"
        # Add YARA-specific hint
        yara_hint = hint or get_context_hint("yara_compile_error")
        message += f"\n\n[yellow]Hint:[/yellow] {yara_hint}"
        message += f"\n\n[dim]Documentation:[/dim] {DOC_LINKS.get('yara', '')}"
        error_console.print(Panel(message, title="[red]YARA Error[/red]", border_style="red"))
    elif isinstance(error, ScanError):
        message = f"[bold red]Scan Error[/bold red]\n\n{error.message}"
        if error.path:
            message += f"\n\n[dim]Path:[/dim] {error.path}"
        message += help_section or f"\n\n[dim]Documentation:[/dim] {DOC_LINKS.get('cli', '')}"
        error_console.print(Panel(message, title="[red]Scan Error[/red]", border_style="red"))
    elif isinstance(error, ConfigError):
        message = f"[bold red]Configuration Error[/bold red]\n\n{error.message}"
        if error.config_key:
            message += f"\n\n[dim]Config key:[/dim] {error.config_key}"
            # Provide specific hints for known config keys
            if error.config_key == "format":
                message += f"\n\n[yellow]Hint:[/yellow] {get_context_hint('invalid_format')}"
            elif error.config_key == "categories":
                message += f"\n\n[yellow]Hint:[/yellow] {get_context_hint('invalid_category')}"
            elif error.config_key == "min_confidence":
                message += f"\n\n[yellow]Hint:[/yellow] {get_context_hint('invalid_confidence')}"
        message += (
            help_section or f"\n\n[dim]Documentation:[/dim] {DOC_LINKS.get('configuration', '')}"
        )
        error_console.print(Panel(message, title="[red]Config Error[/red]", border_style="red"))
    elif isinstance(error, OutputError):
        message = f"[bold red]Output Error[/bold red]\n\n{error.message}"
        if error.output_path:
            message += f"\n\n[dim]Output path:[/dim] {error.output_path}"
        out_hint = hint or get_context_hint("output_permission")
        message += f"\n\n[yellow]Hint:[/yellow] {out_hint}"
        message += f"\n\n[dim]Documentation:[/dim] {DOC_LINKS.get('outputs', '')}"
        error_console.print(Panel(message, title="[red]Output Error[/red]", border_style="red"))
    elif isinstance(error, DetectorError):
        message = f"[bold red]Detector Error[/bold red]\n\n{error.message}"
        if error.detector_name:
            message += f"\n\n[dim]Detector:[/dim] {error.detector_name}"
        message += help_section or f"\n\n[dim]Documentation:[/dim] {DOC_LINKS.get('detectors', '')}"
        error_console.print(Panel(message, title="[red]Detector Error[/red]", border_style="red"))
    elif isinstance(error, HamburglarError):
        message = f"[bold red]Error[/bold red]\n\n{error.message}"
        message += help_section
        error_console.print(Panel(message, title=f"[red]{title}[/red]", border_style="red"))
    elif isinstance(error, PermissionError):
        perm_hint = hint or get_context_hint("permission_denied")
        message = f"[bold red]Permission Denied[/bold red]\n\n{error}"
        message += f"\n\n[yellow]Hint:[/yellow] {perm_hint}"
        error_console.print(
            Panel(
                message,
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
    elif isinstance(error, FileNotFoundError):
        path_hint = hint or get_context_hint("path_not_found")
        message = f"[bold red]Path Not Found[/bold red]\n\n{error}"
        message += f"\n\n[yellow]Hint:[/yellow] {path_hint}"
        error_console.print(
            Panel(
                message,
                title="[red]File Not Found[/red]",
                border_style="red",
            )
        )
    else:
        message = f"[bold red]{title}[/bold red]\n\n{error}"
        message += help_section
        error_console.print(
            Panel(
                message,
                title="[red]Error[/red]",
                border_style="red",
            )
        )


def ensure_output_dir(output_dir: Path, quiet: bool = False) -> None:
    """Ensure the output directory exists, creating it if necessary.

    Args:
        output_dir: The directory path to ensure exists.
        quiet: If True, suppress the creation message.

    Raises:
        typer.Exit: If the directory cannot be created.
    """
    if not output_dir.exists():
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            if not quiet:
                console.print(f"[dim]Created output directory:[/dim] {output_dir}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(
                OutputError(
                    f"Failed to create output directory: {e}",
                    output_path=str(output_dir),
                )
            )
            raise typer.Exit(code=EXIT_ERROR) from None


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold cyan]Hamburglar[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to file or directory to scan",
            exists=True,
            resolve_path=True,
        ),
    ],
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-C",
            help="Path to configuration file. If not specified, searches for "
            ".hamburglar.yml, .hamburglar.yaml, .hamburglar.toml, or hamburglar.config.json "
            "in the current directory and ~/.config/hamburglar/",
            exists=True,
            resolve_path=True,
        ),
    ] = None,
    recursive: Annotated[
        Optional[bool],
        typer.Option(
            "--recursive/--no-recursive",
            "-r/-R",
            help="Scan directories recursively (default: from config or True)",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--output-dir",
            help="Save output to directory with auto-generated filename based on target and timestamp. "
            "Creates directory if it doesn't exist. Cannot be used with --output.",
            resolve_path=True,
        ),
    ] = None,
    format: Annotated[
        Optional[str],
        typer.Option(
            "--format",
            "-f",
            help="Output format (json, table, sarif, csv, html, markdown). Default: from config or table",
            case_sensitive=False,
        ),
    ] = None,
    yara: Annotated[
        Optional[Path],
        typer.Option(
            "--yara",
            "-y",
            help="Path to YARA rules directory or file",
            exists=True,
            resolve_path=True,
        ),
    ] = None,
    no_yara: Annotated[
        bool,
        typer.Option(
            "--no-yara",
            help="Disable YARA scanning even if enabled in config",
        ),
    ] = False,
    verbose: Annotated[
        Optional[bool],
        typer.Option(
            "--verbose/--no-verbose",
            "-v/-V",
            help="Enable verbose output (default: from config or False)",
        ),
    ] = None,
    quiet: Annotated[
        Optional[bool],
        typer.Option(
            "--quiet/--no-quiet",
            "-q/-Q",
            help="Suppress non-error output (default: from config or False)",
        ),
    ] = None,
    categories: Annotated[
        Optional[str],
        typer.Option(
            "--categories",
            "-c",
            help="Enable only specific detector categories (comma-separated). "
            "Valid categories: api_keys, cloud, credentials, crypto, generic, network, private_keys. "
            "Example: --categories api_keys,cloud",
        ),
    ] = None,
    no_categories: Annotated[
        Optional[str],
        typer.Option(
            "--no-categories",
            help="Disable specific detector categories (comma-separated). "
            "Example: --no-categories generic,network",
        ),
    ] = None,
    min_confidence: Annotated[
        Optional[str],
        typer.Option(
            "--min-confidence",
            help="Minimum confidence level for findings (high, medium, low). "
            "Only patterns with this confidence level or higher will be used. "
            "Example: --min-confidence high",
        ),
    ] = None,
    concurrency: Annotated[
        Optional[int],
        typer.Option(
            "--concurrency",
            "-j",
            help="Maximum number of files to scan concurrently. Default: from config or 50",
            min=1,
            max=1000,
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help="Stream findings as NDJSON (newline-delimited JSON) in real-time. "
            "Findings are output immediately as they're discovered.",
        ),
    ] = False,
    benchmark: Annotated[
        bool,
        typer.Option(
            "--benchmark",
            help="Run a quick performance test and report throughput (files/second). "
            "Scans without generating normal output.",
        ),
    ] = False,
    save_to_db: Annotated[
        Optional[bool],
        typer.Option(
            "--save-to-db/--no-save-to-db",
            help="Save findings to SQLite database (default: from config or False). "
            "Default location: ~/.hamburglar/findings.db. "
            "Use --db-path to specify a custom database path.",
        ),
    ] = None,
    db_path: Annotated[
        Optional[Path],
        typer.Option(
            "--db-path",
            help="Custom path for SQLite database file. Creates the file and directory if they don't exist. "
            "Only used when --save-to-db is enabled.",
            resolve_path=True,
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what would be scanned without performing the scan. "
            "Displays configuration, detectors, and file list.",
        ),
    ] = False,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
) -> None:
    """Scan a file or directory for sensitive information.

    Hamburglar scans files for patterns that may indicate sensitive data
    such as API keys, credentials, private keys, and other secrets.

    Configuration is loaded from (in priority order, highest first):
    1. CLI arguments (--format, --recursive, etc.)
    2. Environment variables (HAMBURGLAR_*)
    3. Config file (.hamburglar.yml, etc.)
    4. Built-in defaults

    Exit codes:
        0: Success (findings found)
        1: Error occurred during scan
        2: No findings found
    """
    # Build CLI arguments dictionary for config override (only non-None values)
    cli_args: dict = {}
    if recursive is not None:
        cli_args["recursive"] = recursive
    if format is not None:
        cli_args["format"] = format
    if concurrency is not None:
        cli_args["concurrency"] = concurrency
    if verbose is not None:
        cli_args["verbose"] = verbose
    if quiet is not None:
        cli_args["quiet"] = quiet
    if save_to_db is not None:
        cli_args["save_to_db"] = save_to_db
    if db_path is not None:
        cli_args["db_path"] = db_path
    if output is not None:
        cli_args["output"] = output
    if categories is not None:
        cli_args["categories"] = categories
    if min_confidence is not None:
        cli_args["min_confidence"] = min_confidence
    # Handle YARA settings
    if yara is not None:
        cli_args["yara"] = True
        cli_args["yara_rules"] = yara
    if no_yara:
        cli_args["yara"] = False

    # Load configuration with CLI overrides
    # Use temporary quiet/verbose values for config loading message
    temp_quiet = quiet if quiet is not None else False
    temp_verbose = verbose if verbose is not None else False
    cfg = get_effective_config(
        config_file=config_file,
        cli_args=cli_args if cli_args else None,
        quiet=temp_quiet,
        verbose=temp_verbose,
    )

    # Resolve effective values (CLI > config)
    eff_recursive = recursive if recursive is not None else cfg.scan.recursive
    eff_format = format if format is not None else cfg.output.format.value
    eff_concurrency = concurrency if concurrency is not None else cfg.scan.concurrency
    eff_verbose = verbose if verbose is not None else cfg.output.verbose
    eff_quiet = quiet if quiet is not None else cfg.output.quiet
    eff_save_to_db = save_to_db if save_to_db is not None else cfg.output.save_to_db
    eff_db_path = db_path if db_path is not None else cfg.output.db_path
    eff_output = output if output is not None else cfg.output.output_path
    eff_min_confidence = (
        min_confidence if min_confidence is not None else cfg.detector.min_confidence
    )

    # Handle YARA: CLI --yara path takes precedence, then --no-yara, then config
    if yara is not None:
        eff_use_yara = True
        eff_yara_path = yara
    elif no_yara:
        eff_use_yara = False
        eff_yara_path = None
    else:
        eff_use_yara = cfg.yara.enabled
        eff_yara_path = cfg.yara.rules_path

    # Handle categories: CLI overrides config
    if categories is not None:
        eff_categories = categories
    elif cfg.detector.enabled_categories:
        eff_categories = ",".join(cfg.detector.enabled_categories)
    else:
        eff_categories = None

    # Set up logging based on verbosity (quiet mode suppresses all non-error output)
    if not eff_quiet:
        setup_logging(verbose=eff_verbose)

    # Validate format option
    format_lower = eff_format.lower()
    if format_lower not in VALID_FORMATS:
        valid_names = ", ".join(sorted(VALID_FORMATS.keys()))
        _display_error(
            ConfigError(
                f"Invalid format '{eff_format}'. Valid formats: {valid_names}",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = VALID_FORMATS[format_lower]

    # Validate that --output and --output-dir are not used together
    if eff_output and output_dir:
        _display_error(
            ConfigError(
                "Cannot use both --output and --output-dir. Use one or the other.",
                config_key="output",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    # Handle --output-dir: create directory and generate filename
    if output_dir:
        ensure_output_dir(output_dir, quiet=eff_quiet)
        filename = generate_output_filename(str(path), output_format, scan_type="scan")
        eff_output = output_dir / filename
        if eff_verbose and not eff_quiet:
            console.print(f"[dim]Output file:[/dim] {eff_output}")

    # Parse category filters
    enabled_categories: list[PatternCategory] | None = None
    disabled_categories: list[PatternCategory] | None = None
    use_expanded_patterns = False

    if eff_categories:
        try:
            enabled_categories = parse_categories(eff_categories)
            use_expanded_patterns = True  # Use expanded patterns when filtering by category
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if no_categories:
        try:
            disabled_categories = parse_categories(no_categories)
            use_expanded_patterns = True  # Use expanded patterns when filtering by category
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="no_categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Parse minimum confidence level
    confidence_filter: Confidence | None = None
    if eff_min_confidence:
        try:
            confidence_filter = parse_confidence(eff_min_confidence)
            use_expanded_patterns = True  # Use expanded patterns when filtering by confidence
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="min_confidence"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if eff_verbose and not eff_quiet:
        console.print(f"[dim]Scanning:[/dim] {path}")
        console.print(f"[dim]Recursive:[/dim] {eff_recursive}")
        console.print(f"[dim]Format:[/dim] {output_format.value}")
        console.print(f"[dim]Concurrency:[/dim] {eff_concurrency}")
        if stream:
            console.print("[dim]Mode:[/dim] Streaming (NDJSON)")
        if enabled_categories:
            console.print(
                f"[dim]Categories:[/dim] {', '.join(c.value for c in enabled_categories)}"
            )
        if disabled_categories:
            console.print(
                f"[dim]Excluded categories:[/dim] {', '.join(c.value for c in disabled_categories)}"
            )
        if confidence_filter:
            console.print(f"[dim]Min confidence:[/dim] {confidence_filter.value}")
        if eff_use_yara and eff_yara_path:
            console.print(f"[dim]YARA rules:[/dim] {eff_yara_path}")

    # Build scan configuration
    scan_config = ScanConfig(
        target_path=path,
        recursive=eff_recursive,
        use_yara=eff_use_yara and eff_yara_path is not None,
        yara_rules_path=eff_yara_path,
        output_format=output_format,
    )

    # Initialize detectors
    regex_detector = RegexDetector(
        use_expanded_patterns=use_expanded_patterns,
        enabled_categories=enabled_categories,
        disabled_categories=disabled_categories,
        min_confidence=confidence_filter,
    )
    detectors: list[BaseDetector] = [regex_detector]

    if eff_verbose and not eff_quiet and use_expanded_patterns:
        console.print(f"[dim]Loaded {regex_detector.get_pattern_count()} patterns[/dim]")

    if eff_use_yara and eff_yara_path:
        try:
            yara_detector = YaraDetector(eff_yara_path)
            detectors.append(yara_detector)
            if eff_verbose and not eff_quiet:
                console.print(f"[dim]Loaded {yara_detector.rule_count} YARA rule file(s)[/dim]")
        except YaraCompilationError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except FileNotFoundError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except HamburglarError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except Exception as e:
            _display_error(e, title="Failed to load YARA rules")
            raise typer.Exit(code=EXIT_ERROR) from None

    # Handle dry-run mode
    if dry_run:
        asyncio.run(
            _run_dry_run(
                scan_config,
                detectors,
                eff_concurrency,
                eff_quiet,
                eff_verbose,
                enabled_categories,
                disabled_categories,
                confidence_filter,
            )
        )
        return

    # Handle streaming mode
    if stream:
        asyncio.run(
            _run_streaming_scan(
                scan_config, detectors, eff_concurrency, eff_output, eff_quiet, eff_verbose
            )
        )
        return

    # Handle benchmark mode
    if benchmark:
        asyncio.run(_run_benchmark_scan(scan_config, detectors, eff_concurrency, eff_quiet))
        return

    # Run the scan with progress bar (non-streaming mode)
    try:
        result = asyncio.run(
            _run_scan_with_progress(scan_config, detectors, eff_concurrency, eff_quiet, eff_verbose)
        )
    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except KeyboardInterrupt:
        if not eff_quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error during scan")
        raise typer.Exit(code=EXIT_ERROR) from None

    # Format output
    formatter = get_formatter(output_format)

    try:
        formatted_output = formatter.format(result)
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(OutputError(f"Failed to format output: {e}"))
        raise typer.Exit(code=EXIT_ERROR) from None

    # Write to file or stdout (unless quiet mode and no findings)
    if eff_output:
        try:
            eff_output.write_text(formatted_output)
            if not eff_quiet:
                console.print(f"[green]Output written to:[/green] {eff_output}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(
                OutputError(f"Failed to write output file: {e}", output_path=str(eff_output))
            )
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not eff_quiet:
        # For structured formats (JSON, SARIF, CSV), use print() directly to avoid
        # Rich's text wrapping which can break parsing. For table format, print
        # directly to console to handle terminal width correctly. For HTML and
        # markdown, use the pre-rendered string.
        if output_format in (OutputFormat.JSON, OutputFormat.SARIF, OutputFormat.CSV):
            print(formatted_output)
        elif output_format == OutputFormat.TABLE:
            # Use print_to_console for proper terminal width handling
            from hamburglar.outputs.table_output import TableOutput

            table_formatter = TableOutput()
            table_formatter.print_to_console(result, console)
        else:
            console.print(formatted_output)

    # Save to database if requested
    if eff_save_to_db:
        resolved_db_path = get_db_path(eff_db_path)
        save_to_database(result, resolved_db_path, quiet=eff_quiet, verbose=eff_verbose)

    # Determine exit code based on findings
    if len(result.findings) == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    # Show warning for high severity findings in verbose mode
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and eff_verbose and not eff_quiet:
        console.print(
            f"[yellow]Warning:[/yellow] Found {high_severity_count} high/critical severity finding(s)"
        )

    raise typer.Exit(code=EXIT_SUCCESS)


async def _run_scan_with_progress(
    config: ScanConfig,
    detectors: list["BaseDetector"],
    concurrency: int,
    quiet: bool,
    verbose: bool,
) -> "ScanResult":
    """Run a scan with rich progress bar display.

    Args:
        config: Scan configuration.
        detectors: List of detectors to use.
        concurrency: Maximum concurrent file operations.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.

    Returns:
        ScanResult with all findings.
    """

    # Progress tracking state
    progress_state: dict[str, Any] = {
        "task_id": None,
        "last_progress": None,
    }

    def progress_callback(progress: ScanProgress) -> None:
        """Update the rich progress bar."""
        progress_state["last_progress"] = progress

    scanner = AsyncScanner(
        config,
        detectors,
        progress_callback=progress_callback,
        concurrency_limit=concurrency,
    )

    if quiet:
        # Run without progress display
        return await scanner.scan()

    # Create rich progress bar with real-time stats
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[stats]}[/dim]"),
        console=console,
        transient=not verbose,  # Keep progress visible in verbose mode
    ) as progress:
        # Start with discovering task
        discover_task = progress.add_task("[cyan]Discovering files...", total=None, stats="")

        # Start the scan
        scan_task = asyncio.create_task(scanner.scan())

        # Update progress while scanning
        scan_started = False
        while not scan_task.done():
            await asyncio.sleep(0.1)

            last_progress = progress_state["last_progress"]
            if last_progress is not None:
                if not scan_started and last_progress.total_files > 0:
                    # File discovery complete, switch to scanning progress
                    progress.remove_task(discover_task)
                    progress_state["task_id"] = progress.add_task(
                        "[cyan]Scanning files",
                        total=last_progress.total_files,
                        stats="",
                    )
                    scan_started = True

                if scan_started and progress_state["task_id"] is not None:
                    # Build stats string
                    fps = last_progress.files_per_second
                    stats_parts = []
                    if fps > 0:
                        stats_parts.append(f"{fps:.1f} files/s")
                    if last_progress.findings_count > 0:
                        stats_parts.append(
                            f"[yellow]{last_progress.findings_count} findings[/yellow]"
                        )
                    stats_str = " | ".join(stats_parts) if stats_parts else ""

                    progress.update(
                        progress_state["task_id"],
                        completed=last_progress.scanned_files,
                        stats=stats_str,
                    )

        result = await scan_task

        # Final update
        if progress_state["task_id"] is not None:
            progress.update(
                progress_state["task_id"],
                completed=result.stats.get("files_scanned", 0),
            )

    # Show summary
    if verbose:
        console.print(
            f"[dim]Scanned {result.stats.get('files_scanned', 0)} files "
            f"in {result.scan_duration:.2f}s "
            f"({result.stats.get('files_scanned', 0) / max(result.scan_duration, 0.001):.1f} files/s)[/dim]"
        )

    return result


async def _run_streaming_scan(
    config: ScanConfig,
    detectors: list["BaseDetector"],
    concurrency: int,
    output_path: Optional[Path],
    quiet: bool,
    verbose: bool,
) -> None:
    """Run a scan in streaming mode, outputting NDJSON as findings are discovered.

    Args:
        config: Scan configuration.
        detectors: List of detectors to use.
        concurrency: Maximum concurrent file operations.
        output_path: Optional path to write output to.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.
    """
    scanner = AsyncScanner(
        config,
        detectors,
        concurrency_limit=concurrency,
    )

    formatter = StreamingOutput()
    findings_count = 0

    try:
        if output_path:
            # Write to file
            with open(output_path, "w") as f:
                async for finding in scanner.scan_stream():
                    f.write(formatter.format_finding(finding) + "\n")
                    f.flush()
                    findings_count += 1

            if not quiet:
                console.print(
                    f"[green]Streamed {findings_count} findings to:[/green] {output_path}"
                )
        else:
            # Write to stdout
            async for finding in scanner.scan_stream():
                print(formatter.format_finding(finding), flush=True)
                findings_count += 1

        # Show summary in verbose mode (to stderr so it doesn't mix with NDJSON)
        if verbose and not quiet:
            stats = scanner.get_stats()
            error_console.print(
                f"[dim]Streamed {findings_count} findings from "
                f"{stats.get('files_scanned', 0)} files[/dim]"
            )

    except KeyboardInterrupt:
        if not quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR)

    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)

    except Exception as e:
        _display_error(e, title="Error during streaming scan")
        raise typer.Exit(code=EXIT_ERROR)

    # Determine exit code
    if findings_count == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    raise typer.Exit(code=EXIT_SUCCESS)


async def _run_dry_run(
    config: ScanConfig,
    detectors: list["BaseDetector"],
    concurrency: int,
    quiet: bool,
    verbose: bool,
    enabled_categories: list["PatternCategory"] | None,
    disabled_categories: list["PatternCategory"] | None,
    confidence_filter: "Confidence | None",
) -> None:
    """Run a dry-run scan that shows what would be scanned without scanning.

    This discovers files, shows configuration, and lists what would be scanned,
    but does not actually perform pattern matching or output findings.

    Args:
        config: Scan configuration.
        detectors: List of detectors to use.
        concurrency: Maximum concurrent file operations.
        quiet: If True, suppress non-essential output.
        verbose: If True, show detailed information.
        enabled_categories: Categories to enable, if specified.
        disabled_categories: Categories to disable, if specified.
        confidence_filter: Minimum confidence level, if specified.
    """
    from rich.table import Table

    if not quiet:
        console.print()
        console.print(
            Panel(
                "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
                "This shows what would be scanned without performing the actual scan.\n"
                "No files will be read for pattern matching, and no findings will be generated.",
                title="[bold]Dry Run[/bold]",
                border_style="yellow",
            )
        )
        console.print()

    # Build configuration table
    config_table = Table(title="Scan Configuration", show_header=True, header_style="bold cyan")
    config_table.add_column("Setting", style="dim")
    config_table.add_column("Value")

    config_table.add_row("Target", str(config.target_path))
    config_table.add_row("Recursive", "Yes" if config.recursive else "No")
    config_table.add_row("Output Format", config.output_format.value)
    config_table.add_row("Concurrency", str(concurrency))
    config_table.add_row("YARA Enabled", "Yes" if config.use_yara else "No")
    if config.use_yara and config.yara_rules_path:
        config_table.add_row("YARA Rules Path", str(config.yara_rules_path))

    if enabled_categories:
        config_table.add_row("Enabled Categories", ", ".join(c.value for c in enabled_categories))
    if disabled_categories:
        config_table.add_row("Disabled Categories", ", ".join(c.value for c in disabled_categories))
    if confidence_filter:
        config_table.add_row("Min Confidence", confidence_filter.value)

    if not quiet:
        console.print(config_table)
        console.print()

    # Build detectors table
    detector_table = Table(title="Detectors", show_header=True, header_style="bold cyan")
    detector_table.add_column("Detector", style="dim")
    detector_table.add_column("Patterns/Rules")

    for detector in detectors:
        detector_name = detector.__class__.__name__
        if hasattr(detector, "get_pattern_count"):
            count = detector.get_pattern_count()
            detector_table.add_row(detector_name, f"{count} patterns")
        elif hasattr(detector, "rule_count"):
            count = detector.rule_count
            detector_table.add_row(detector_name, f"{count} rule file(s)")
        else:
            detector_table.add_row(detector_name, "N/A")

    if not quiet:
        console.print(detector_table)
        console.print()

    # Discover files
    if not quiet:
        console.print("[cyan]Discovering files...[/cyan]")

    scanner = AsyncScanner(
        config,
        detectors=[],  # Empty detectors for discovery only
        concurrency_limit=concurrency,
    )

    try:
        files = await scanner._discover_files()
    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)

    # Calculate total size
    total_size = 0
    file_sizes: list[tuple[Path, int]] = []
    for f in files:
        try:
            size = f.stat().st_size
            file_sizes.append((f, size))
            total_size += size
        except (OSError, PermissionError):
            file_sizes.append((f, 0))

    # Format size helper
    def format_bytes(num_bytes: int) -> str:
        """Format bytes into human-readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if num_bytes < 1024:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024  # type: ignore[assignment]
        return f"{num_bytes:.1f} TB"

    # Display summary
    summary_table = Table(
        title="File Discovery Summary", show_header=True, header_style="bold cyan"
    )
    summary_table.add_column("Metric", style="dim")
    summary_table.add_column("Value")

    summary_table.add_row("Files to Scan", f"{len(files):,}")
    summary_table.add_row("Total Size", format_bytes(total_size))
    if len(files) > 0:
        avg_size = total_size // len(files)
        summary_table.add_row("Average File Size", format_bytes(avg_size))

    if not quiet:
        console.print()
        console.print(summary_table)

    # Show file list in verbose mode or for small number of files
    if verbose or len(files) <= 20:
        if not quiet and files:
            console.print()
            file_table = Table(
                title=f"Files to Scan ({len(files)} file{'s' if len(files) != 1 else ''})",
                show_header=True,
                header_style="bold cyan",
            )
            file_table.add_column("File", style="dim", no_wrap=True)
            file_table.add_column("Size", justify="right")

            # Sort by path for consistent output
            file_sizes.sort(key=lambda x: str(x[0]))

            for file_path, size in file_sizes:
                # Make path relative to target for cleaner display
                try:
                    rel_path = file_path.relative_to(config.target_path)
                except ValueError:
                    rel_path = file_path
                file_table.add_row(str(rel_path), format_bytes(size))

            console.print(file_table)
    elif not quiet and len(files) > 20:
        console.print()
        console.print(f"[dim]Use --verbose to see the full list of {len(files)} files[/dim]")

    if not quiet:
        console.print()
        console.print("[green]✓ Dry run complete. No files were scanned.[/green]")


def _run_git_dry_run(
    target: str,
    detectors: list["BaseDetector"],
    output_format: OutputFormat,
    depth: Optional[int],
    branch: Optional[str],
    include_history: bool,
    clone_dir: Optional[Path],
    quiet: bool,
    verbose: bool,
    enabled_categories: list["PatternCategory"] | None,
    disabled_categories: list["PatternCategory"] | None,
    confidence_filter: "Confidence | None",
) -> None:
    """Run a dry-run for git scan that shows what would be scanned without scanning.

    Args:
        target: Git repository URL or local path.
        detectors: List of detectors to use.
        output_format: Output format to use.
        depth: Number of commits to scan.
        branch: Specific branch to scan.
        include_history: Whether to scan commit history.
        clone_dir: Directory to clone into.
        quiet: If True, suppress non-essential output.
        verbose: If True, show detailed information.
        enabled_categories: Categories to enable, if specified.
        disabled_categories: Categories to disable, if specified.
        confidence_filter: Minimum confidence level, if specified.
    """
    from rich.table import Table

    if not quiet:
        console.print()
        console.print(
            Panel(
                "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
                "This shows what would be scanned without performing the actual scan.\n"
                "No files will be read for pattern matching, and no findings will be generated.",
                title="[bold]Dry Run[/bold]",
                border_style="yellow",
            )
        )
        console.print()

    # Determine if target is a URL or local path
    is_remote = target.startswith(("http://", "https://", "git@", "ssh://"))

    # Build configuration table
    config_table = Table(title="Git Scan Configuration", show_header=True, header_style="bold cyan")
    config_table.add_column("Setting", style="dim")
    config_table.add_column("Value")

    config_table.add_row("Target", target)
    config_table.add_row("Type", "Remote Repository" if is_remote else "Local Repository")
    config_table.add_row("Include History", "Yes" if include_history else "No")
    if depth:
        config_table.add_row("Commit Depth", str(depth))
    else:
        config_table.add_row("Commit Depth", "All commits")
    if branch:
        config_table.add_row("Branch", branch)
    else:
        config_table.add_row("Branch", "Default branch")
    if clone_dir:
        config_table.add_row("Clone Directory", str(clone_dir))
    elif is_remote:
        config_table.add_row("Clone Directory", "Temporary directory")
    config_table.add_row("Output Format", output_format.value)

    if enabled_categories:
        config_table.add_row("Enabled Categories", ", ".join(c.value for c in enabled_categories))
    if disabled_categories:
        config_table.add_row("Disabled Categories", ", ".join(c.value for c in disabled_categories))
    if confidence_filter:
        config_table.add_row("Min Confidence", confidence_filter.value)

    if not quiet:
        console.print(config_table)
        console.print()

    # Build detectors table
    detector_table = Table(title="Detectors", show_header=True, header_style="bold cyan")
    detector_table.add_column("Detector", style="dim")
    detector_table.add_column("Patterns/Rules")

    for detector in detectors:
        detector_name = detector.__class__.__name__
        if hasattr(detector, "get_pattern_count"):
            count = detector.get_pattern_count()
            detector_table.add_row(detector_name, f"{count} patterns")
        elif hasattr(detector, "rule_count"):
            count = detector.rule_count
            detector_table.add_row(detector_name, f"{count} rule file(s)")
        else:
            detector_table.add_row(detector_name, "N/A")

    if not quiet:
        console.print(detector_table)
        console.print()

    # For local repos, we can show more info
    if not is_remote:
        try:
            from pathlib import Path as PathLib

            target_path = PathLib(target).resolve()
            if target_path.exists() and (target_path / ".git").exists():
                if not quiet:
                    console.print(
                        "[dim]Local repository detected. Run without --dry-run to scan.[/dim]"
                    )
            elif target_path.exists():
                if not quiet:
                    console.print(
                        f"[yellow]Warning: {target} exists but is not a git repository[/yellow]"
                    )
            else:
                if not quiet:
                    console.print(f"[yellow]Warning: {target} does not exist[/yellow]")
        except Exception:
            pass

    if not quiet:
        console.print()
        if is_remote:
            console.print(
                "[green]✓ Dry run complete. Repository would be cloned and scanned.[/green]"
            )
        else:
            console.print("[green]✓ Dry run complete. Repository would be scanned.[/green]")


def _run_web_dry_run(
    url: str,
    detectors: list["BaseDetector"],
    output_format: OutputFormat,
    depth: int,
    include_scripts: bool,
    user_agent: Optional[str],
    timeout: float,
    respect_robots: bool,
    auth_tuple: tuple[str, str] | None,
    quiet: bool,
    verbose: bool,
    enabled_categories: list["PatternCategory"] | None,
    disabled_categories: list["PatternCategory"] | None,
    confidence_filter: "Confidence | None",
) -> None:
    """Run a dry-run for web scan that shows what would be scanned without scanning.

    Args:
        url: URL to scan.
        detectors: List of detectors to use.
        output_format: Output format to use.
        depth: Maximum depth for following links.
        include_scripts: Whether to extract and scan JavaScript files.
        user_agent: Custom user agent string.
        timeout: Timeout for HTTP requests in seconds.
        respect_robots: Whether to respect robots.txt rules.
        auth_tuple: Basic auth credentials as (username, password) tuple.
        quiet: If True, suppress non-essential output.
        verbose: If True, show detailed information.
        enabled_categories: Categories to enable, if specified.
        disabled_categories: Categories to disable, if specified.
        confidence_filter: Minimum confidence level, if specified.
    """
    from urllib.parse import urlparse

    from rich.table import Table

    if not quiet:
        console.print()
        console.print(
            Panel(
                "[bold yellow]DRY RUN MODE[/bold yellow]\n\n"
                "This shows what would be scanned without performing the actual scan.\n"
                "No HTTP requests will be made, and no findings will be generated.",
                title="[bold]Dry Run[/bold]",
                border_style="yellow",
            )
        )
        console.print()

    # Parse URL for display
    parsed_url = urlparse(url)

    # Build configuration table
    config_table = Table(title="Web Scan Configuration", show_header=True, header_style="bold cyan")
    config_table.add_column("Setting", style="dim")
    config_table.add_column("Value")

    config_table.add_row("URL", url)
    config_table.add_row("Domain", parsed_url.netloc or "N/A")
    config_table.add_row("Protocol", parsed_url.scheme.upper() if parsed_url.scheme else "N/A")
    config_table.add_row("Link Depth", str(depth) if depth > 0 else "0 (starting URL only)")
    config_table.add_row("Include Scripts", "Yes" if include_scripts else "No")
    config_table.add_row("Timeout", f"{timeout}s")
    config_table.add_row("Respect robots.txt", "Yes" if respect_robots else "No")
    if user_agent:
        config_table.add_row("User Agent", user_agent)
    else:
        config_table.add_row("User Agent", "Default")
    if auth_tuple:
        config_table.add_row("Authentication", f"{auth_tuple[0]}:***")
    else:
        config_table.add_row("Authentication", "None")
    config_table.add_row("Output Format", output_format.value)

    if enabled_categories:
        config_table.add_row("Enabled Categories", ", ".join(c.value for c in enabled_categories))
    if disabled_categories:
        config_table.add_row("Disabled Categories", ", ".join(c.value for c in disabled_categories))
    if confidence_filter:
        config_table.add_row("Min Confidence", confidence_filter.value)

    if not quiet:
        console.print(config_table)
        console.print()

    # Build detectors table
    detector_table = Table(title="Detectors", show_header=True, header_style="bold cyan")
    detector_table.add_column("Detector", style="dim")
    detector_table.add_column("Patterns/Rules")

    for detector in detectors:
        detector_name = detector.__class__.__name__
        if hasattr(detector, "get_pattern_count"):
            count = detector.get_pattern_count()
            detector_table.add_row(detector_name, f"{count} patterns")
        elif hasattr(detector, "rule_count"):
            count = detector.rule_count
            detector_table.add_row(detector_name, f"{count} rule file(s)")
        else:
            detector_table.add_row(detector_name, "N/A")

    if not quiet:
        console.print(detector_table)
        console.print()

    # Show what would be scanned
    if not quiet:
        console.print("[dim]Scan behavior:[/dim]")
        if depth == 0:
            console.print("  • Only the starting URL would be scanned")
        else:
            console.print(f"  • Starting URL and linked pages up to depth {depth} would be scanned")
        if include_scripts:
            console.print("  • JavaScript files would be extracted and scanned")
        if respect_robots:
            console.print("  • robots.txt rules would be respected")
        console.print()
        console.print("[green]✓ Dry run complete. No HTTP requests were made.[/green]")


async def _run_benchmark_scan(
    config: ScanConfig,
    detectors: list["BaseDetector"],
    concurrency: int,
    quiet: bool,
) -> None:
    """Run a benchmark scan and report performance metrics.

    Args:
        config: Scan configuration.
        detectors: List of detectors to use.
        concurrency: Maximum concurrent file operations.
        quiet: If True, suppress progress output.
    """
    import time

    scanner = AsyncScanner(
        config,
        detectors,
        concurrency_limit=concurrency,
    )

    try:
        if not quiet:
            console.print("[cyan]Running performance benchmark...[/cyan]")

        start_time = time.time()
        result = await scanner.scan()
        elapsed_time = time.time() - start_time

        files_scanned = result.stats.get("files_scanned", 0)
        bytes_processed = result.stats.get("bytes_processed", 0)
        findings_count = len(result.findings)

        # Calculate throughput metrics
        files_per_second = files_scanned / elapsed_time if elapsed_time > 0 else 0
        bytes_per_second = bytes_processed / elapsed_time if elapsed_time > 0 else 0

        # Format bytes for human readability
        def format_bytes(num_bytes: float) -> str:
            """Format bytes into human-readable string."""
            for unit in ["B", "KB", "MB", "GB"]:
                if num_bytes < 1024:
                    return f"{num_bytes:.2f} {unit}"
                num_bytes /= 1024
            return f"{num_bytes:.2f} TB"

        # Display benchmark results
        console.print()
        console.print(
            Panel(
                f"[bold]Files Scanned:[/bold] {files_scanned:,}\n"
                f"[bold]Bytes Processed:[/bold] {format_bytes(bytes_processed)}\n"
                f"[bold]Findings:[/bold] {findings_count:,}\n"
                f"[bold]Duration:[/bold] {elapsed_time:.3f}s\n"
                f"[bold]Concurrency:[/bold] {concurrency}\n"
                f"\n"
                f"[bold green]Throughput:[/bold green]\n"
                f"  [green]{files_per_second:.2f} files/second[/green]\n"
                f"  [green]{format_bytes(bytes_per_second)}/second[/green]",
                title="[bold cyan]Benchmark Results[/bold cyan]",
                border_style="cyan",
            )
        )

    except KeyboardInterrupt:
        if not quiet:
            error_console.print("\n[yellow]Benchmark interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR)

    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)

    except Exception as e:
        _display_error(e, title="Error during benchmark scan")
        raise typer.Exit(code=EXIT_ERROR)

    raise typer.Exit(code=EXIT_SUCCESS)


@app.command("scan-git")
def scan_git(
    target: Annotated[
        str,
        typer.Argument(
            help="Git repository URL (HTTP/SSH) or local path to git directory",
        ),
    ],
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-C",
            help="Path to configuration file",
            exists=True,
            resolve_path=True,
        ),
    ] = None,
    depth: Annotated[
        Optional[int],
        typer.Option(
            "--depth",
            "-d",
            help="Number of commits to scan from history. Default: all commits",
            min=1,
        ),
    ] = None,
    branch: Annotated[
        Optional[str],
        typer.Option(
            "--branch",
            "-b",
            help="Specific branch to scan. Default: current/default branch",
        ),
    ] = None,
    include_history: Annotated[
        bool,
        typer.Option(
            "--include-history/--no-history",
            help="Scan commit history for removed secrets. Default: enabled",
        ),
    ] = True,
    clone_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--clone-dir",
            help="Directory to clone repository into. Default: temporary directory",
            resolve_path=True,
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--output-dir",
            help="Save output to directory with auto-generated filename based on target and timestamp. "
            "Creates directory if it doesn't exist. Cannot be used with --output.",
            resolve_path=True,
        ),
    ] = None,
    format: Annotated[
        Optional[str],
        typer.Option(
            "--format",
            "-f",
            help="Output format (json, table, sarif, csv, html, markdown). Default: from config or table",
            case_sensitive=False,
        ),
    ] = None,
    verbose: Annotated[
        Optional[bool],
        typer.Option(
            "--verbose/--no-verbose",
            "-v/-V",
            help="Enable verbose output (default: from config or False)",
        ),
    ] = None,
    quiet: Annotated[
        Optional[bool],
        typer.Option(
            "--quiet/--no-quiet",
            "-q/-Q",
            help="Suppress non-error output (default: from config or False)",
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help="Stream findings as NDJSON (newline-delimited JSON) in real-time",
        ),
    ] = False,
    categories: Annotated[
        Optional[str],
        typer.Option(
            "--categories",
            "-c",
            help="Enable only specific detector categories (comma-separated)",
        ),
    ] = None,
    no_categories: Annotated[
        Optional[str],
        typer.Option(
            "--no-categories",
            help="Disable specific detector categories (comma-separated)",
        ),
    ] = None,
    min_confidence: Annotated[
        Optional[str],
        typer.Option(
            "--min-confidence",
            help="Minimum confidence level for findings (high, medium, low)",
        ),
    ] = None,
    save_to_db: Annotated[
        Optional[bool],
        typer.Option(
            "--save-to-db/--no-save-to-db",
            help="Save findings to SQLite database (default: from config or False)",
        ),
    ] = None,
    db_path: Annotated[
        Optional[Path],
        typer.Option(
            "--db-path",
            help="Custom path for SQLite database file. Creates the file and directory if they don't exist. "
            "Only used when --save-to-db is enabled.",
            resolve_path=True,
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what would be scanned without performing the scan. "
            "Displays configuration, detectors, and repository information.",
        ),
    ] = False,
) -> None:
    """Scan a git repository for sensitive information.

    Scans both current files and commit history for secrets that may have been
    added and later removed. Supports both remote repositories (HTTP/SSH URLs)
    and local git directories.

    Examples:
        hamburglar scan-git https://github.com/user/repo
        hamburglar scan-git /path/to/local/repo
        hamburglar scan-git git@github.com:user/repo.git --depth 100
        hamburglar scan-git ./my-repo --no-history --format json

    Exit codes:
        0: Success (findings found)
        1: Error occurred during scan
        2: No findings found
    """
    # Build CLI arguments dictionary for config override (only non-None values)
    cli_args: dict = {}
    if format is not None:
        cli_args["format"] = format
    if verbose is not None:
        cli_args["verbose"] = verbose
    if quiet is not None:
        cli_args["quiet"] = quiet
    if save_to_db is not None:
        cli_args["save_to_db"] = save_to_db
    if db_path is not None:
        cli_args["db_path"] = db_path
    if output is not None:
        cli_args["output"] = output
    if categories is not None:
        cli_args["categories"] = categories
    if min_confidence is not None:
        cli_args["min_confidence"] = min_confidence

    # Load configuration with CLI overrides
    temp_quiet = quiet if quiet is not None else False
    temp_verbose = verbose if verbose is not None else False
    cfg = get_effective_config(
        config_file=config_file,
        cli_args=cli_args if cli_args else None,
        quiet=temp_quiet,
        verbose=temp_verbose,
    )

    # Resolve effective values (CLI > config)
    eff_format = format if format is not None else cfg.output.format.value
    eff_verbose = verbose if verbose is not None else cfg.output.verbose
    eff_quiet = quiet if quiet is not None else cfg.output.quiet
    eff_save_to_db = save_to_db if save_to_db is not None else cfg.output.save_to_db
    eff_db_path = db_path if db_path is not None else cfg.output.db_path
    eff_output = output if output is not None else cfg.output.output_path
    eff_min_confidence = (
        min_confidence if min_confidence is not None else cfg.detector.min_confidence
    )

    # Handle categories: CLI overrides config
    if categories is not None:
        eff_categories = categories
    elif cfg.detector.enabled_categories:
        eff_categories = ",".join(cfg.detector.enabled_categories)
    else:
        eff_categories = None

    # Set up logging based on verbosity
    if not eff_quiet:
        setup_logging(verbose=eff_verbose)

    # Validate format option
    format_lower = eff_format.lower()
    if format_lower not in VALID_FORMATS:
        valid_names = ", ".join(sorted(VALID_FORMATS.keys()))
        _display_error(
            ConfigError(
                f"Invalid format '{eff_format}'. Valid formats: {valid_names}",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = VALID_FORMATS[format_lower]

    # Validate that --output and --output-dir are not used together
    if eff_output and output_dir:
        _display_error(
            ConfigError(
                "Cannot use both --output and --output-dir. Use one or the other.",
                config_key="output",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    # Handle --output-dir: create directory and generate filename
    if output_dir:
        ensure_output_dir(output_dir, quiet=eff_quiet)
        filename = generate_output_filename(target, output_format, scan_type="git")
        eff_output = output_dir / filename
        if eff_verbose and not eff_quiet:
            console.print(f"[dim]Output file:[/dim] {eff_output}")

    # Parse category filters
    enabled_categories: list[PatternCategory] | None = None
    disabled_categories: list[PatternCategory] | None = None
    use_expanded_patterns = False

    if eff_categories:
        try:
            enabled_categories = parse_categories(eff_categories)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if no_categories:
        try:
            disabled_categories = parse_categories(no_categories)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="no_categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Parse minimum confidence level
    confidence_filter: Confidence | None = None
    if eff_min_confidence:
        try:
            confidence_filter = parse_confidence(eff_min_confidence)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="min_confidence"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if eff_verbose and not eff_quiet:
        console.print(f"[dim]Target:[/dim] {target}")
        console.print(f"[dim]Include History:[/dim] {include_history}")
        if depth:
            console.print(f"[dim]Commit Depth:[/dim] {depth}")
        if branch:
            console.print(f"[dim]Branch:[/dim] {branch}")
        if clone_dir:
            console.print(f"[dim]Clone Directory:[/dim] {clone_dir}")
        console.print(f"[dim]Format:[/dim] {output_format.value}")
        if stream:
            console.print("[dim]Mode:[/dim] Streaming (NDJSON)")
        if enabled_categories:
            console.print(
                f"[dim]Categories:[/dim] {', '.join(c.value for c in enabled_categories)}"
            )
        if disabled_categories:
            console.print(
                f"[dim]Excluded categories:[/dim] {', '.join(c.value for c in disabled_categories)}"
            )
        if confidence_filter:
            console.print(f"[dim]Min confidence:[/dim] {confidence_filter.value}")

    # Initialize detector
    regex_detector = RegexDetector(
        use_expanded_patterns=use_expanded_patterns,
        enabled_categories=enabled_categories,
        disabled_categories=disabled_categories,
        min_confidence=confidence_filter,
    )
    detectors: list[BaseDetector] = [regex_detector]

    if eff_verbose and not eff_quiet and use_expanded_patterns:
        console.print(f"[dim]Loaded {regex_detector.get_pattern_count()} patterns[/dim]")

    # Handle dry-run mode
    if dry_run:
        _run_git_dry_run(
            target,
            detectors,
            output_format,
            depth,
            branch,
            include_history,
            clone_dir,
            eff_quiet,
            eff_verbose,
            enabled_categories,
            disabled_categories,
            confidence_filter,
        )
        return

    # Handle streaming mode
    if stream:
        asyncio.run(
            _run_git_streaming_scan(
                target,
                detectors,
                depth,
                branch,
                include_history,
                clone_dir,
                eff_output,
                eff_quiet,
                eff_verbose,
            )
        )
        return

    # Run the scan with progress bar (non-streaming mode)
    try:
        result = asyncio.run(
            _run_git_scan_with_progress(
                target, detectors, depth, branch, include_history, clone_dir, eff_quiet, eff_verbose
            )
        )
    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except KeyboardInterrupt:
        if not eff_quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error during git scan")
        raise typer.Exit(code=EXIT_ERROR) from None

    # Format output
    formatter = get_formatter(output_format)

    try:
        formatted_output = formatter.format(result)
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(OutputError(f"Failed to format output: {e}"))
        raise typer.Exit(code=EXIT_ERROR) from None

    # Write to file or stdout
    if eff_output:
        try:
            eff_output.write_text(formatted_output)
            if not eff_quiet:
                console.print(f"[green]Output written to:[/green] {eff_output}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(
                OutputError(f"Failed to write output file: {e}", output_path=str(eff_output))
            )
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not eff_quiet:
        # For structured formats (JSON, SARIF, CSV), use print() directly to avoid
        # Rich's text wrapping which can break parsing. For table format, print
        # directly to console to handle terminal width correctly. For HTML and
        # markdown, use the pre-rendered string.
        if output_format in (OutputFormat.JSON, OutputFormat.SARIF, OutputFormat.CSV):
            print(formatted_output)
        elif output_format == OutputFormat.TABLE:
            # Use print_to_console for proper terminal width handling
            from hamburglar.outputs.table_output import TableOutput

            table_formatter = TableOutput()
            table_formatter.print_to_console(result, console)
        else:
            console.print(formatted_output)

    # Save to database if requested
    if eff_save_to_db:
        resolved_db_path = get_db_path(eff_db_path)
        save_to_database(result, resolved_db_path, quiet=eff_quiet, verbose=eff_verbose)

    # Determine exit code based on findings
    if len(result.findings) == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    # Show warning for high severity findings in verbose mode
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and eff_verbose and not eff_quiet:
        console.print(
            f"[yellow]Warning:[/yellow] Found {high_severity_count} high/critical severity finding(s)"
        )

    raise typer.Exit(code=EXIT_SUCCESS)


async def _run_git_scan_with_progress(
    target: str,
    detectors: list["BaseDetector"],
    depth: Optional[int],
    branch: Optional[str],
    include_history: bool,
    clone_dir: Optional[Path],
    quiet: bool,
    verbose: bool,
) -> "ScanResult":
    """Run a git scan with rich progress bar display.

    Args:
        target: Git repository URL or local path.
        detectors: List of detectors to use.
        depth: Number of commits to scan.
        branch: Specific branch to scan.
        include_history: Whether to scan commit history.
        clone_dir: Directory to clone into.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.

    Returns:
        ScanResult with all findings.
    """

    # Progress tracking state
    progress_state: dict[str, Any] = {
        "task_id": None,
        "last_progress": None,
    }

    def progress_callback(progress: ScanProgress) -> None:
        """Update the rich progress bar."""
        progress_state["last_progress"] = progress

    scanner = GitScanner(
        target=target,
        detectors=detectors,
        progress_callback=progress_callback,
        clone_dir=clone_dir,
        include_history=include_history,
        depth=depth,
        branch=branch,
    )

    if quiet:
        return await scanner.scan()

    # Create rich progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[stats]}[/dim]"),
        console=console,
        transient=not verbose,
    ) as progress:
        # Start with cloning/loading task
        main_task = progress.add_task("[cyan]Scanning git repository...", total=None, stats="")

        # Start the scan
        scan_task = asyncio.create_task(scanner.scan())

        # Update progress while scanning
        while not scan_task.done():
            await asyncio.sleep(0.1)

            last_progress = progress_state["last_progress"]
            if last_progress is not None:
                stats_parts = []
                if last_progress.scanned_files > 0:
                    stats_parts.append(f"{last_progress.scanned_files} files")
                if last_progress.findings_count > 0:
                    stats_parts.append(f"[yellow]{last_progress.findings_count} findings[/yellow]")
                if last_progress.current_file:
                    # Truncate long file names
                    current = last_progress.current_file
                    if len(current) > 40:
                        current = "..." + current[-37:]
                    stats_parts.append(f"[dim]{current}[/dim]")

                stats_str = " | ".join(stats_parts) if stats_parts else ""
                progress.update(main_task, stats=stats_str)

        result = await scan_task

    # Show summary
    if verbose:
        stats = result.stats
        console.print(
            f"[dim]Scanned {stats.get('files_scanned', 0)} files, "
            f"{stats.get('commits_scanned', 0)} commits "
            f"in {result.scan_duration:.2f}s[/dim]"
        )

    return result


async def _run_git_streaming_scan(
    target: str,
    detectors: list["BaseDetector"],
    depth: Optional[int],
    branch: Optional[str],
    include_history: bool,
    clone_dir: Optional[Path],
    output_path: Optional[Path],
    quiet: bool,
    verbose: bool,
) -> None:
    """Run a git scan in streaming mode, outputting NDJSON as findings are discovered.

    Args:
        target: Git repository URL or local path.
        detectors: List of detectors to use.
        depth: Number of commits to scan.
        branch: Specific branch to scan.
        include_history: Whether to scan commit history.
        clone_dir: Directory to clone into.
        output_path: Optional path to write output to.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.
    """
    scanner = GitScanner(
        target=target,
        detectors=detectors,
        clone_dir=clone_dir,
        include_history=include_history,
        depth=depth,
        branch=branch,
    )

    formatter = StreamingOutput()
    findings_count = 0

    try:
        if output_path:
            with open(output_path, "w") as f:
                async for finding in scanner.scan_stream():
                    f.write(formatter.format_finding(finding) + "\n")
                    f.flush()
                    findings_count += 1

            if not quiet:
                console.print(
                    f"[green]Streamed {findings_count} findings to:[/green] {output_path}"
                )
        else:
            async for finding in scanner.scan_stream():
                print(formatter.format_finding(finding), flush=True)
                findings_count += 1

        if verbose and not quiet:
            stats = scanner.get_stats()
            error_console.print(
                f"[dim]Streamed {findings_count} findings from "
                f"{stats.get('files_scanned', 0)} files, "
                f"{stats.get('commits_scanned', 0)} commits[/dim]"
            )

    except KeyboardInterrupt:
        if not quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR)

    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)

    except Exception as e:
        _display_error(e, title="Error during git streaming scan")
        raise typer.Exit(code=EXIT_ERROR)

    if findings_count == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    raise typer.Exit(code=EXIT_SUCCESS)


@app.command("scan-web")
def scan_web(
    url: Annotated[
        str,
        typer.Argument(
            help="URL to scan for secrets",
        ),
    ],
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-C",
            help="Path to configuration file",
            exists=True,
            resolve_path=True,
        ),
    ] = None,
    depth: Annotated[
        int,
        typer.Option(
            "--depth",
            "-d",
            help="Maximum depth for following links (0 = only scan the starting URL)",
            min=0,
        ),
    ] = 1,
    include_scripts: Annotated[
        bool,
        typer.Option(
            "--include-scripts/--no-scripts",
            help="Extract and scan JavaScript files. Default: enabled",
        ),
    ] = True,
    user_agent: Annotated[
        Optional[str],
        typer.Option(
            "--user-agent",
            "-u",
            help="Custom user agent string for HTTP requests",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Timeout for HTTP requests in seconds",
            min=1.0,
            max=300.0,
        ),
    ] = 30.0,
    auth: Annotated[
        Optional[str],
        typer.Option(
            "--auth",
            "-a",
            help="Basic auth credentials in format 'username:password'",
        ),
    ] = None,
    respect_robots: Annotated[
        bool,
        typer.Option(
            "--respect-robots/--ignore-robots",
            help="Respect robots.txt rules. Default: enabled",
        ),
    ] = True,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout",
        ),
    ] = None,
    output_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--output-dir",
            help="Save output to directory with auto-generated filename based on target and timestamp. "
            "Creates directory if it doesn't exist. Cannot be used with --output.",
            resolve_path=True,
        ),
    ] = None,
    format: Annotated[
        Optional[str],
        typer.Option(
            "--format",
            "-f",
            help="Output format (json, table, sarif, csv, html, markdown). Default: from config or table",
            case_sensitive=False,
        ),
    ] = None,
    verbose: Annotated[
        Optional[bool],
        typer.Option(
            "--verbose/--no-verbose",
            "-v/-V",
            help="Enable verbose output (default: from config or False)",
        ),
    ] = None,
    quiet: Annotated[
        Optional[bool],
        typer.Option(
            "--quiet/--no-quiet",
            "-q/-Q",
            help="Suppress non-error output (default: from config or False)",
        ),
    ] = None,
    stream: Annotated[
        bool,
        typer.Option(
            "--stream",
            help="Stream findings as NDJSON (newline-delimited JSON) in real-time",
        ),
    ] = False,
    categories: Annotated[
        Optional[str],
        typer.Option(
            "--categories",
            "-c",
            help="Enable only specific detector categories (comma-separated)",
        ),
    ] = None,
    no_categories: Annotated[
        Optional[str],
        typer.Option(
            "--no-categories",
            help="Disable specific detector categories (comma-separated)",
        ),
    ] = None,
    min_confidence: Annotated[
        Optional[str],
        typer.Option(
            "--min-confidence",
            help="Minimum confidence level for findings (high, medium, low)",
        ),
    ] = None,
    save_to_db: Annotated[
        Optional[bool],
        typer.Option(
            "--save-to-db/--no-save-to-db",
            help="Save findings to SQLite database (default: from config or False)",
        ),
    ] = None,
    db_path: Annotated[
        Optional[Path],
        typer.Option(
            "--db-path",
            help="Custom path for SQLite database file. Creates the file and directory if they don't exist. "
            "Only used when --save-to-db is enabled.",
            resolve_path=True,
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what would be scanned without performing the scan. "
            "Displays configuration, detectors, and URL information.",
        ),
    ] = False,
) -> None:
    """Scan a web URL for sensitive information.

    Fetches content from the URL, extracts text from HTML, follows links
    to a configurable depth, and scans for secrets in both page content
    and JavaScript files.

    Examples:
        hamburglar scan-web https://example.com
        hamburglar scan-web https://example.com --depth 2
        hamburglar scan-web https://example.com --no-scripts
        hamburglar scan-web https://example.com --auth user:pass

    Exit codes:
        0: Success (findings found)
        1: Error occurred during scan
        2: No findings found
    """
    # Build CLI arguments dictionary for config override (only non-None values)
    cli_args: dict = {}
    if format is not None:
        cli_args["format"] = format
    if verbose is not None:
        cli_args["verbose"] = verbose
    if quiet is not None:
        cli_args["quiet"] = quiet
    if save_to_db is not None:
        cli_args["save_to_db"] = save_to_db
    if db_path is not None:
        cli_args["db_path"] = db_path
    if output is not None:
        cli_args["output"] = output
    if categories is not None:
        cli_args["categories"] = categories
    if min_confidence is not None:
        cli_args["min_confidence"] = min_confidence

    # Load configuration with CLI overrides
    temp_quiet = quiet if quiet is not None else False
    temp_verbose = verbose if verbose is not None else False
    cfg = get_effective_config(
        config_file=config_file,
        cli_args=cli_args if cli_args else None,
        quiet=temp_quiet,
        verbose=temp_verbose,
    )

    # Resolve effective values (CLI > config)
    eff_format = format if format is not None else cfg.output.format.value
    eff_verbose = verbose if verbose is not None else cfg.output.verbose
    eff_quiet = quiet if quiet is not None else cfg.output.quiet
    eff_save_to_db = save_to_db if save_to_db is not None else cfg.output.save_to_db
    eff_db_path = db_path if db_path is not None else cfg.output.db_path
    eff_output = output if output is not None else cfg.output.output_path
    eff_min_confidence = (
        min_confidence if min_confidence is not None else cfg.detector.min_confidence
    )

    # Handle categories: CLI overrides config
    if categories is not None:
        eff_categories = categories
    elif cfg.detector.enabled_categories:
        eff_categories = ",".join(cfg.detector.enabled_categories)
    else:
        eff_categories = None

    # Set up logging based on verbosity
    if not eff_quiet:
        setup_logging(verbose=eff_verbose)

    # Validate format option
    format_lower = eff_format.lower()
    if format_lower not in VALID_FORMATS:
        valid_names = ", ".join(sorted(VALID_FORMATS.keys()))
        _display_error(
            ConfigError(
                f"Invalid format '{eff_format}'. Valid formats: {valid_names}",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = VALID_FORMATS[format_lower]

    # Validate that --output and --output-dir are not used together
    if eff_output and output_dir:
        _display_error(
            ConfigError(
                "Cannot use both --output and --output-dir. Use one or the other.",
                config_key="output",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    # Handle --output-dir: create directory and generate filename
    if output_dir:
        ensure_output_dir(output_dir, quiet=eff_quiet)
        filename = generate_output_filename(url, output_format, scan_type="web")
        eff_output = output_dir / filename
        if eff_verbose and not eff_quiet:
            console.print(f"[dim]Output file:[/dim] {eff_output}")

    # Parse category filters
    enabled_categories: list[PatternCategory] | None = None
    disabled_categories: list[PatternCategory] | None = None
    use_expanded_patterns = False

    if eff_categories:
        try:
            enabled_categories = parse_categories(eff_categories)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if no_categories:
        try:
            disabled_categories = parse_categories(no_categories)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="no_categories"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Parse minimum confidence level
    confidence_filter: Confidence | None = None
    if eff_min_confidence:
        try:
            confidence_filter = parse_confidence(eff_min_confidence)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="min_confidence"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Parse auth credentials if provided
    auth_tuple: tuple[str, str] | None = None
    if auth:
        if ":" not in auth:
            _display_error(
                ConfigError(
                    "Invalid auth format. Use 'username:password'.",
                    config_key="auth",
                )
            )
            raise typer.Exit(code=EXIT_ERROR)
        parts = auth.split(":", 1)
        auth_tuple = (parts[0], parts[1])

    if eff_verbose and not eff_quiet:
        console.print(f"[dim]URL:[/dim] {url}")
        console.print(f"[dim]Depth:[/dim] {depth}")
        console.print(f"[dim]Include Scripts:[/dim] {include_scripts}")
        console.print(f"[dim]Timeout:[/dim] {timeout}s")
        console.print(f"[dim]Respect Robots.txt:[/dim] {respect_robots}")
        if user_agent:
            console.print(f"[dim]User Agent:[/dim] {user_agent}")
        if auth_tuple:
            console.print(f"[dim]Auth:[/dim] {auth_tuple[0]}:***")
        console.print(f"[dim]Format:[/dim] {output_format.value}")
        if stream:
            console.print("[dim]Mode:[/dim] Streaming (NDJSON)")
        if enabled_categories:
            console.print(
                f"[dim]Categories:[/dim] {', '.join(c.value for c in enabled_categories)}"
            )
        if disabled_categories:
            console.print(
                f"[dim]Excluded categories:[/dim] {', '.join(c.value for c in disabled_categories)}"
            )
        if confidence_filter:
            console.print(f"[dim]Min confidence:[/dim] {confidence_filter.value}")

    # Initialize detector
    regex_detector = RegexDetector(
        use_expanded_patterns=use_expanded_patterns,
        enabled_categories=enabled_categories,
        disabled_categories=disabled_categories,
        min_confidence=confidence_filter,
    )
    detectors: list[BaseDetector] = [regex_detector]

    if eff_verbose and not eff_quiet and use_expanded_patterns:
        console.print(f"[dim]Loaded {regex_detector.get_pattern_count()} patterns[/dim]")

    # Handle dry-run mode
    if dry_run:
        _run_web_dry_run(
            url,
            detectors,
            output_format,
            depth,
            include_scripts,
            user_agent,
            timeout,
            respect_robots,
            auth_tuple,
            eff_quiet,
            eff_verbose,
            enabled_categories,
            disabled_categories,
            confidence_filter,
        )
        return

    # Handle streaming mode
    if stream:
        asyncio.run(
            _run_web_streaming_scan(
                url,
                detectors,
                depth,
                include_scripts,
                user_agent,
                timeout,
                respect_robots,
                auth_tuple,
                eff_output,
                eff_quiet,
                eff_verbose,
            )
        )
        return

    # Run the scan with progress bar (non-streaming mode)
    try:
        result = asyncio.run(
            _run_web_scan_with_progress(
                url,
                detectors,
                depth,
                include_scripts,
                user_agent,
                timeout,
                respect_robots,
                auth_tuple,
                eff_quiet,
                eff_verbose,
            )
        )
    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except KeyboardInterrupt:
        if not eff_quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error during web scan")
        raise typer.Exit(code=EXIT_ERROR) from None

    # Format output
    formatter = get_formatter(output_format)

    try:
        formatted_output = formatter.format(result)
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(OutputError(f"Failed to format output: {e}"))
        raise typer.Exit(code=EXIT_ERROR) from None

    # Write to file or stdout
    if eff_output:
        try:
            eff_output.write_text(formatted_output)
            if not eff_quiet:
                console.print(f"[green]Output written to:[/green] {eff_output}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(
                OutputError(f"Failed to write output file: {e}", output_path=str(eff_output))
            )
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not eff_quiet:
        # For structured formats (JSON, SARIF, CSV), use print() directly to avoid
        # Rich's text wrapping which can break parsing. For table format, print
        # directly to console to handle terminal width correctly. For HTML and
        # markdown, use the pre-rendered string.
        if output_format in (OutputFormat.JSON, OutputFormat.SARIF, OutputFormat.CSV):
            print(formatted_output)
        elif output_format == OutputFormat.TABLE:
            # Use print_to_console for proper terminal width handling
            from hamburglar.outputs.table_output import TableOutput

            table_formatter = TableOutput()
            table_formatter.print_to_console(result, console)
        else:
            console.print(formatted_output)

    # Save to database if requested
    if eff_save_to_db:
        resolved_db_path = get_db_path(eff_db_path)
        save_to_database(result, resolved_db_path, quiet=eff_quiet, verbose=eff_verbose)

    # Determine exit code based on findings
    if len(result.findings) == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    # Show warning for high severity findings in verbose mode
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and eff_verbose and not eff_quiet:
        console.print(
            f"[yellow]Warning:[/yellow] Found {high_severity_count} high/critical severity finding(s)"
        )

    raise typer.Exit(code=EXIT_SUCCESS)


async def _run_web_scan_with_progress(
    url: str,
    detectors: list["BaseDetector"],
    depth: int,
    include_scripts: bool,
    user_agent: Optional[str],
    timeout: float,
    respect_robots: bool,
    auth_tuple: tuple[str, str] | None,
    quiet: bool,
    verbose: bool,
) -> "ScanResult":
    """Run a web scan with rich progress bar display.

    Args:
        url: URL to scan.
        detectors: List of detectors to use.
        depth: Maximum depth for link following.
        include_scripts: Whether to scan JavaScript files.
        user_agent: Custom user agent string.
        timeout: HTTP request timeout in seconds.
        respect_robots: Whether to respect robots.txt.
        auth_tuple: Optional (username, password) tuple for basic auth.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.

    Returns:
        ScanResult with all findings.
    """

    # Progress tracking state
    progress_state: dict[str, Any] = {
        "task_id": None,
        "last_progress": None,
    }

    def progress_callback(progress: ScanProgress) -> None:
        """Update the rich progress bar."""
        progress_state["last_progress"] = progress

    # Build scanner kwargs
    scanner_kwargs = {
        "url": url,
        "detectors": detectors,
        "progress_callback": progress_callback,
        "depth": depth,
        "include_scripts": include_scripts,
        "timeout": timeout,
        "respect_robots_txt": respect_robots,
    }

    if user_agent:
        scanner_kwargs["user_agent"] = user_agent

    # Note: WebScanner doesn't support auth directly, but we can add it via httpx
    # For now, auth would need to be added to WebScanner if needed
    # This is a placeholder for future auth support
    if auth_tuple and verbose and not quiet:
        console.print(
            "[dim]Note: Auth credentials provided (requires WebScanner auth support)[/dim]"
        )

    scanner = WebScanner(**scanner_kwargs)  # type: ignore[arg-type]

    if quiet:
        return await scanner.scan()

    # Create rich progress bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[stats]}[/dim]"),
        console=console,
        transient=not verbose,
    ) as progress:
        # Start with scanning task
        main_task = progress.add_task("[cyan]Scanning web URL...", total=None, stats="")

        # Start the scan
        scan_task = asyncio.create_task(scanner.scan())

        # Update progress while scanning
        while not scan_task.done():
            await asyncio.sleep(0.1)

            last_progress = progress_state["last_progress"]
            if last_progress is not None:
                stats_parts = []
                if last_progress.scanned_files > 0:
                    stats_parts.append(f"{last_progress.scanned_files} URLs/scripts")
                if last_progress.findings_count > 0:
                    stats_parts.append(f"[yellow]{last_progress.findings_count} findings[/yellow]")
                if last_progress.current_file:
                    # Truncate long URLs
                    current = last_progress.current_file
                    if len(current) > 50:
                        current = current[:25] + "..." + current[-22:]
                    stats_parts.append(f"[dim]{current}[/dim]")

                stats_str = " | ".join(stats_parts) if stats_parts else ""
                progress.update(main_task, stats=stats_str)

        result = await scan_task

    # Show summary
    if verbose:
        stats = result.stats
        console.print(
            f"[dim]Scanned {stats.get('urls_scanned', 0)} URLs, "
            f"{stats.get('scripts_scanned', 0)} scripts "
            f"in {result.scan_duration:.2f}s[/dim]"
        )

    return result


async def _run_web_streaming_scan(
    url: str,
    detectors: list["BaseDetector"],
    depth: int,
    include_scripts: bool,
    user_agent: Optional[str],
    timeout: float,
    respect_robots: bool,
    auth_tuple: tuple[str, str] | None,
    output_path: Optional[Path],
    quiet: bool,
    verbose: bool,
) -> None:
    """Run a web scan in streaming mode, outputting NDJSON as findings are discovered.

    Args:
        url: URL to scan.
        detectors: List of detectors to use.
        depth: Maximum depth for link following.
        include_scripts: Whether to scan JavaScript files.
        user_agent: Custom user agent string.
        timeout: HTTP request timeout in seconds.
        respect_robots: Whether to respect robots.txt.
        auth_tuple: Optional (username, password) tuple for basic auth.
        output_path: Optional path to write output to.
        quiet: If True, suppress progress output.
        verbose: If True, show detailed progress.
    """
    # Build scanner kwargs
    scanner_kwargs = {
        "url": url,
        "detectors": detectors,
        "depth": depth,
        "include_scripts": include_scripts,
        "timeout": timeout,
        "respect_robots_txt": respect_robots,
    }

    if user_agent:
        scanner_kwargs["user_agent"] = user_agent

    scanner = WebScanner(**scanner_kwargs)  # type: ignore[arg-type]

    formatter = StreamingOutput()
    findings_count = 0

    try:
        if output_path:
            with open(output_path, "w") as f:
                async for finding in scanner.scan_stream():
                    f.write(formatter.format_finding(finding) + "\n")
                    f.flush()
                    findings_count += 1

            if not quiet:
                console.print(
                    f"[green]Streamed {findings_count} findings to:[/green] {output_path}"
                )
        else:
            async for finding in scanner.scan_stream():
                print(formatter.format_finding(finding), flush=True)
                findings_count += 1

        if verbose and not quiet:
            stats = scanner.get_stats()
            error_console.print(
                f"[dim]Streamed {findings_count} findings from "
                f"{stats.get('urls_scanned', 0)} URLs, "
                f"{stats.get('scripts_scanned', 0)} scripts[/dim]"
            )

    except KeyboardInterrupt:
        if not quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR)

    except ScanError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR)

    except Exception as e:
        _display_error(e, title="Error during web streaming scan")
        raise typer.Exit(code=EXIT_ERROR)

    if findings_count == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    raise typer.Exit(code=EXIT_SUCCESS)


def parse_severities(value: str) -> list[Severity]:
    """Parse a comma-separated list of severity levels.

    Args:
        value: Comma-separated severity names (e.g., "high,critical")

    Returns:
        List of Severity enums.

    Raises:
        typer.BadParameter: If any severity name is invalid.
    """
    if not value:
        return []

    valid_severities = {s.value: s for s in Severity}
    severities = []

    for name in value.split(","):
        name = name.strip().lower()
        if not name:
            continue
        if name not in valid_severities:
            valid_names = ", ".join(sorted(valid_severities.keys()))
            raise typer.BadParameter(f"Invalid severity '{name}'. Valid severities: {valid_names}")
        severities.append(valid_severities[name])

    return severities


def parse_date(value: str) -> datetime:
    """Parse a date string in various formats.

    Args:
        value: Date string (e.g., "2024-01-01", "2024-01-01T12:00:00", "1d", "7d", "24h")

    Returns:
        datetime object.

    Raises:
        typer.BadParameter: If the date format is invalid.
    """
    import re
    from datetime import timedelta

    value = value.strip()

    # Handle relative time formats: 1d, 7d, 24h, etc.
    relative_match = re.match(r"^(\d+)([dhwm])$", value.lower())
    if relative_match:
        amount = int(relative_match.group(1))
        unit = relative_match.group(2)

        now = datetime.now()
        if unit == "h":
            return now - timedelta(hours=amount)
        elif unit == "d":
            return now - timedelta(days=amount)
        elif unit == "w":
            return now - timedelta(weeks=amount)
        elif unit == "m":
            return now - timedelta(days=amount * 30)

    # Try ISO format (with optional time component)
    try:
        # Try with time component first
        return datetime.fromisoformat(value)
    except ValueError:
        pass

    # Try date-only format
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        pass

    raise typer.BadParameter(
        f"Invalid date format '{value}'. Use ISO format (YYYY-MM-DD), "
        "or relative format (e.g., 1d, 7d, 24h, 2w, 1m)"
    )


@app.command("history")
def history(
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (json, table, sarif, csv, html, markdown)",
            case_sensitive=False,
        ),
    ] = "table",
    since: Annotated[
        Optional[str],
        typer.Option(
            "--since",
            "-s",
            help="Show findings since date/time. Accepts ISO format (YYYY-MM-DD) "
            "or relative format (1d=1 day, 7d=7 days, 24h=24 hours, 2w=2 weeks, 1m=1 month)",
        ),
    ] = None,
    until: Annotated[
        Optional[str],
        typer.Option(
            "--until",
            help="Show findings until date/time. Same format as --since",
        ),
    ] = None,
    severity: Annotated[
        Optional[str],
        typer.Option(
            "--severity",
            help="Filter by severity level(s), comma-separated (critical, high, medium, low, info)",
        ),
    ] = None,
    detector: Annotated[
        Optional[str],
        typer.Option(
            "--detector",
            "-d",
            help="Filter by detector name (exact match)",
        ),
    ] = None,
    path: Annotated[
        Optional[str],
        typer.Option(
            "--path",
            "-p",
            help="Filter by file path (prefix match)",
        ),
    ] = None,
    target: Annotated[
        Optional[str],
        typer.Option(
            "--target",
            "-t",
            help="Filter by scan target path (prefix match)",
        ),
    ] = None,
    limit: Annotated[
        Optional[int],
        typer.Option(
            "--limit",
            "-n",
            help="Maximum number of findings to show",
            min=1,
        ),
    ] = None,
    stats: Annotated[
        bool,
        typer.Option(
            "--stats",
            help="Show statistics summary instead of findings",
        ),
    ] = False,
    db_path: Annotated[
        Optional[Path],
        typer.Option(
            "--db-path",
            help="Path to SQLite database file. Default: ~/.hamburglar/findings.db",
            resolve_path=True,
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress non-error output (only show errors)",
        ),
    ] = False,
) -> None:
    """Query stored findings from the database.

    View and filter historical scan findings stored in the database.
    Use --stats to see aggregate statistics instead of individual findings.

    Examples:
        hamburglar history                     # Show all findings
        hamburglar history --since 7d          # Findings from last 7 days
        hamburglar history --severity high,critical  # High/critical only
        hamburglar history --detector aws_key  # Filter by detector
        hamburglar history --stats             # Show statistics summary
        hamburglar history --format json -o out.json  # Export as JSON

    Exit codes:
        0: Success (findings found)
        1: Error occurred
        2: No findings found
    """
    from hamburglar.storage import FindingFilter

    # Set up logging based on verbosity
    if not quiet:
        setup_logging(verbose=verbose)

    # Validate format option
    format_lower = format.lower()
    if format_lower not in VALID_FORMATS:
        valid_names = ", ".join(sorted(VALID_FORMATS.keys()))
        _display_error(
            ConfigError(
                f"Invalid format '{format}'. Valid formats: {valid_names}",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = VALID_FORMATS[format_lower]

    # Parse date filters
    since_dt: datetime | None = None
    until_dt: datetime | None = None

    if since:
        try:
            since_dt = parse_date(since)
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="since"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if until:
        try:
            until_dt = parse_date(until)
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="until"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Parse severity filter
    severity_filter: list[Severity] | None = None
    if severity:
        try:
            severity_filter = parse_severities(severity)
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="severity"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Get database path
    resolved_db_path = get_db_path(db_path)

    # Check if database exists
    if not resolved_db_path.exists():
        if not quiet:
            console.print(
                f"[yellow]No database found at:[/yellow] {resolved_db_path}\n"
                "[dim]Run a scan with --save-to-db to create the database.[/dim]"
            )
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    if verbose and not quiet:
        console.print(f"[dim]Database:[/dim] {resolved_db_path}")
        if since_dt:
            console.print(f"[dim]Since:[/dim] {since_dt.isoformat()}")
        if until_dt:
            console.print(f"[dim]Until:[/dim] {until_dt.isoformat()}")
        if severity_filter:
            console.print(f"[dim]Severities:[/dim] {', '.join(s.value for s in severity_filter)}")
        if detector:
            console.print(f"[dim]Detector:[/dim] {detector}")
        if path:
            console.print(f"[dim]Path filter:[/dim] {path}")
        if target:
            console.print(f"[dim]Target filter:[/dim] {target}")
        if limit:
            console.print(f"[dim]Limit:[/dim] {limit}")

    try:
        with SqliteStorage(resolved_db_path) as storage:
            if stats:
                # Show statistics summary
                statistics = storage.get_statistics()
                _display_statistics(statistics, quiet, verbose, output, output_format)
            else:
                # Query findings
                finding_filter = FindingFilter(
                    since=since_dt,
                    until=until_dt,
                    file_path=path,
                    detector_name=detector,
                    severity=severity_filter if severity_filter else None,
                    target_path=target,
                    limit=limit,
                )

                findings = storage.get_findings(finding_filter)

                if not findings:
                    if not quiet:
                        console.print("[yellow]No findings match the specified filters.[/yellow]")
                    raise typer.Exit(code=EXIT_NO_FINDINGS)

                # Create a ScanResult for formatting
                # Note: We need to convert findings to dicts and back to ensure
                # they use the same Finding class as ScanResult (avoids issues
                # with module reimports during testing)
                from hamburglar.core.models import Finding as CurrentFinding
                from hamburglar.core.models import ScanResult

                converted_findings = [
                    CurrentFinding.model_validate(f.model_dump()) for f in findings
                ]

                result = ScanResult(
                    target_path="history",
                    findings=converted_findings,
                    scan_duration=0.0,
                    stats={
                        "findings_count": len(findings),
                        "source": "database",
                        "database_path": str(resolved_db_path),
                    },
                )

                # Format output
                formatter = get_formatter(output_format)
                formatted_output = formatter.format(result)

                # Write to file or stdout
                if output:
                    try:
                        output.write_text(formatted_output)
                        if not quiet:
                            console.print(f"[green]Output written to:[/green] {output}")
                    except PermissionError as e:
                        _display_error(e)
                        raise typer.Exit(code=EXIT_ERROR) from None
                    except OSError as e:
                        _display_error(
                            OutputError(
                                f"Failed to write output file: {e}", output_path=str(output)
                            )
                        )
                        raise typer.Exit(code=EXIT_ERROR) from None
                elif not quiet:
                    if output_format in (OutputFormat.JSON, OutputFormat.SARIF, OutputFormat.CSV):
                        print(formatted_output)
                    else:
                        console.print(formatted_output)

                if verbose and not quiet:
                    console.print(f"[dim]Found {len(findings)} matching findings[/dim]")

    except typer.Exit:
        # Re-raise typer.Exit (exit codes from within the try block)
        raise
    except StorageError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error querying database")
        raise typer.Exit(code=EXIT_ERROR) from None

    raise typer.Exit(code=EXIT_SUCCESS)


def _display_statistics(
    statistics: "ScanStatistics",
    quiet: bool,
    verbose: bool,
    output: Optional[Path],
    output_format: OutputFormat,
) -> None:
    """Display scan statistics in the requested format.

    Args:
        statistics: The ScanStatistics to display.
        quiet: If True, suppress output.
        verbose: If True, show detailed output.
        output: Optional path to write output to.
        output_format: The output format to use.
    """
    import json

    # Build a structured representation of the statistics
    stats_dict = {
        "total_scans": statistics.total_scans,
        "total_findings": statistics.total_findings,
        "total_files_scanned": statistics.total_files_scanned,
        "findings_by_severity": statistics.findings_by_severity,
        "findings_by_detector": statistics.findings_by_detector,
        "scans_by_date": statistics.scans_by_date,
        "first_scan_date": statistics.first_scan_date.isoformat()
        if statistics.first_scan_date
        else None,
        "last_scan_date": statistics.last_scan_date.isoformat()
        if statistics.last_scan_date
        else None,
        "average_findings_per_scan": round(statistics.average_findings_per_scan, 2),
        "average_scan_duration": round(statistics.average_scan_duration, 2),
    }

    if output_format == OutputFormat.JSON:
        formatted_output = json.dumps(stats_dict, indent=2)
    elif output_format == OutputFormat.CSV:
        # Create a simple CSV representation
        lines = ["metric,value"]
        lines.append(f"total_scans,{statistics.total_scans}")
        lines.append(f"total_findings,{statistics.total_findings}")
        lines.append(f"total_files_scanned,{statistics.total_files_scanned}")
        lines.append(f"average_findings_per_scan,{statistics.average_findings_per_scan:.2f}")
        lines.append(f"average_scan_duration,{statistics.average_scan_duration:.2f}")
        if statistics.first_scan_date:
            lines.append(f"first_scan_date,{statistics.first_scan_date.isoformat()}")
        if statistics.last_scan_date:
            lines.append(f"last_scan_date,{statistics.last_scan_date.isoformat()}")
        formatted_output = "\r\n".join(lines) + "\r\n"
    else:
        # Build a rich text table for table/html/markdown/sarif formats
        from rich.table import Table

        # Summary table
        summary = Table(title="Scan Statistics Summary", show_header=True, header_style="bold cyan")
        summary.add_column("Metric", style="dim")
        summary.add_column("Value", justify="right")

        summary.add_row("Total Scans", str(statistics.total_scans))
        summary.add_row("Total Findings", str(statistics.total_findings))
        summary.add_row("Total Files Scanned", str(statistics.total_files_scanned))
        summary.add_row("Avg Findings/Scan", f"{statistics.average_findings_per_scan:.2f}")
        summary.add_row("Avg Scan Duration", f"{statistics.average_scan_duration:.2f}s")
        if statistics.first_scan_date:
            summary.add_row("First Scan", statistics.first_scan_date.strftime("%Y-%m-%d %H:%M"))
        if statistics.last_scan_date:
            summary.add_row("Last Scan", statistics.last_scan_date.strftime("%Y-%m-%d %H:%M"))

        # Severity breakdown table
        severity_table = Table(
            title="Findings by Severity", show_header=True, header_style="bold cyan"
        )
        severity_table.add_column("Severity", style="dim")
        severity_table.add_column("Count", justify="right")

        # Order severities by criticality
        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            count = statistics.findings_by_severity.get(sev, 0)
            if count > 0:
                severity_table.add_row(sev.upper(), str(count))

        # Detector breakdown table (show top 10)
        detector_table = Table(
            title="Findings by Detector (Top 10)", show_header=True, header_style="bold cyan"
        )
        detector_table.add_column("Detector", style="dim")
        detector_table.add_column("Count", justify="right")

        sorted_detectors = sorted(
            statistics.findings_by_detector.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]
        for det_name, count in sorted_detectors:
            detector_table.add_row(det_name, str(count))

        # Scan activity table (show last 7 dates)
        activity_table = Table(
            title="Recent Scan Activity", show_header=True, header_style="bold cyan"
        )
        activity_table.add_column("Date", style="dim")
        activity_table.add_column("Scans", justify="right")

        sorted_dates = sorted(statistics.scans_by_date.items(), reverse=True)[:7]
        for date, count in sorted_dates:
            activity_table.add_row(date, str(count))

        # For non-JSON/CSV formats, use the console to render
        if output:
            # Capture console output to string
            from io import StringIO

            from rich.console import Console

            string_io = StringIO()
            temp_console = Console(file=string_io, force_terminal=False)
            temp_console.print(summary)
            temp_console.print()
            if statistics.findings_by_severity:
                temp_console.print(severity_table)
                temp_console.print()
            if statistics.findings_by_detector:
                temp_console.print(detector_table)
                temp_console.print()
            if statistics.scans_by_date:
                temp_console.print(activity_table)
            formatted_output = string_io.getvalue()
        else:
            if not quiet:
                console.print(summary)
                console.print()
                if statistics.findings_by_severity:
                    console.print(severity_table)
                    console.print()
                if statistics.findings_by_detector:
                    console.print(detector_table)
                    console.print()
                if statistics.scans_by_date:
                    console.print(activity_table)
            return

    # Write to file or stdout
    if output:
        try:
            output.write_text(formatted_output)
            if not quiet:
                console.print(f"[green]Statistics written to:[/green] {output}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(
                OutputError(f"Failed to write output file: {e}", output_path=str(output))
            )
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not quiet:
        if output_format in (OutputFormat.JSON, OutputFormat.CSV):
            print(formatted_output)


def _generate_report_html(
    statistics: "ScanStatistics",
    top_detectors: list[tuple[str, int]],
    top_files: list[tuple[str, int]],
    title: str = "Hamburglar Security Report",
) -> str:
    """Generate an HTML report from statistics and aggregated data.

    Args:
        statistics: The ScanStatistics object with aggregate data.
        top_detectors: List of (detector_name, count) tuples for most common finding types.
        top_files: List of (file_path, count) tuples for files with most findings.
        title: The report title.

    Returns:
        A self-contained HTML report string.
    """
    import html
    from datetime import datetime

    # Escape helper
    def esc(s: str) -> str:
        return html.escape(str(s))

    # Format date/time for display
    def fmt_datetime(dt: datetime | None) -> str:
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M")

    # Build severity breakdown rows
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_colors = {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#3498db",
        "info": "#95a5a6",
    }
    severity_rows = []
    for sev in severity_order:
        count = statistics.findings_by_severity.get(sev, 0)
        if count > 0:
            color = severity_colors.get(sev, "#95a5a6")
            severity_rows.append(
                f'<tr><td><span style="color:{color};font-weight:bold;">'
                f"{esc(sev.upper())}</span></td><td>{count}</td></tr>"
            )

    # Build detector breakdown rows
    detector_rows = []
    for det_name, count in top_detectors[:15]:
        detector_rows.append(f"<tr><td>{esc(det_name)}</td><td>{count}</td></tr>")

    # Build top files rows
    file_rows = []
    for file_path, count in top_files[:15]:
        # Truncate long paths for display
        display_path = file_path if len(file_path) <= 80 else "..." + file_path[-77:]
        file_rows.append(
            f'<tr><td title="{esc(file_path)}"><code>{esc(display_path)}</code></td>'
            f"<td>{count}</td></tr>"
        )

    # Build trend data (scans by date, sorted chronologically)
    sorted_dates = sorted(statistics.scans_by_date.items())
    trend_rows = []
    for date, count in sorted_dates[-30:]:  # Last 30 days
        trend_rows.append(f"<tr><td>{esc(date)}</td><td>{count}</td></tr>")

    # Generate report timestamp
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{
            color: #2c3e50;
            margin-bottom: 0.5rem;
            padding-bottom: 1rem;
            border-bottom: 3px solid #3498db;
        }}
        .report-meta {{
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 2rem;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #2c3e50;
        }}
        .stat-card .label {{
            color: #666;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #2c3e50;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #eee;
            font-size: 1.25rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }}
        td:last-child {{
            text-align: right;
            font-weight: 500;
        }}
        tr:hover {{ background: #f8f9fa; }}
        code {{
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 0.85rem;
            color: #e74c3c;
        }}
        .two-columns {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }}
        @media (max-width: 768px) {{
            .two-columns {{ grid-template-columns: 1fr; }}
            body {{ padding: 1rem; }}
        }}
        .footer {{
            text-align: center;
            color: #666;
            font-size: 0.85rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #eee;
        }}
        .footer a {{ color: #3498db; text-decoration: none; }}
        .empty-state {{
            text-align: center;
            color: #666;
            padding: 2rem;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{esc(title)}</h1>
        <p class="report-meta">
            Generated: {esc(report_time)} |
            Period: {fmt_datetime(statistics.first_scan_date)} to {fmt_datetime(statistics.last_scan_date)}
        </p>

        <div class="summary-grid">
            <div class="stat-card">
                <div class="value">{statistics.total_scans}</div>
                <div class="label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="value">{statistics.total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value">{statistics.total_files_scanned}</div>
                <div class="label">Files Scanned</div>
            </div>
            <div class="stat-card">
                <div class="value">{statistics.average_findings_per_scan:.1f}</div>
                <div class="label">Avg Findings/Scan</div>
            </div>
        </div>

        <div class="two-columns">
            <div class="section">
                <h2>Findings by Severity</h2>
                {"<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>" + "".join(severity_rows) + "</tbody></table>" if severity_rows else '<p class="empty-state">No findings recorded</p>'}
            </div>
            <div class="section">
                <h2>Most Common Finding Types</h2>
                {"<table><thead><tr><th>Detector</th><th>Count</th></tr></thead><tbody>" + "".join(detector_rows) + "</tbody></table>" if detector_rows else '<p class="empty-state">No findings recorded</p>'}
            </div>
        </div>

        <div class="section">
            <h2>Files with Most Findings</h2>
            {"<table><thead><tr><th>File Path</th><th>Findings</th></tr></thead><tbody>" + "".join(file_rows) + "</tbody></table>" if file_rows else '<p class="empty-state">No findings recorded</p>'}
        </div>

        <div class="section">
            <h2>Scan Activity Over Time</h2>
            {"<table><thead><tr><th>Date</th><th>Scans</th></tr></thead><tbody>" + "".join(trend_rows) + "</tbody></table>" if trend_rows else '<p class="empty-state">No scan activity recorded</p>'}
        </div>

        <div class="footer">
            Generated by <a href="https://github.com/needmorecowbell/Hamburglar">Hamburglar</a>
        </div>
    </div>
</body>
</html>"""
    return html_content


def _generate_report_markdown(
    statistics: "ScanStatistics",
    top_detectors: list[tuple[str, int]],
    top_files: list[tuple[str, int]],
    title: str = "Hamburglar Security Report",
) -> str:
    """Generate a Markdown report from statistics and aggregated data.

    Args:
        statistics: The ScanStatistics object with aggregate data.
        top_detectors: List of (detector_name, count) tuples for most common finding types.
        top_files: List of (file_path, count) tuples for files with most findings.
        title: The report title.

    Returns:
        A GitHub-flavored Markdown report string.
    """
    from datetime import datetime

    # Format date/time for display
    def fmt_datetime(dt: datetime | None) -> str:
        if dt is None:
            return "N/A"
        return dt.strftime("%Y-%m-%d %H:%M")

    # Escape markdown special characters in table cells
    def esc_md(s: str) -> str:
        return str(s).replace("|", "\\|").replace("\n", " ")

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"# {title}",
        "",
        f"**Generated:** {report_time}",
        f"**Period:** {fmt_datetime(statistics.first_scan_date)} to {fmt_datetime(statistics.last_scan_date)}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| Total Scans | {statistics.total_scans} |",
        f"| Total Findings | {statistics.total_findings} |",
        f"| Files Scanned | {statistics.total_files_scanned} |",
        f"| Avg Findings/Scan | {statistics.average_findings_per_scan:.1f} |",
        f"| Avg Scan Duration | {statistics.average_scan_duration:.2f}s |",
        "",
    ]

    # Severity breakdown
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_emojis = {
        "critical": "\U0001f6a8",  # 🚨
        "high": "\U0001f534",  # 🔴
        "medium": "\U0001f7e0",  # 🟠
        "low": "\U0001f535",  # 🔵
        "info": "\U00002139\ufe0f",  # ℹ️
    }

    lines.append("## Findings by Severity")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in severity_order:
        count = statistics.findings_by_severity.get(sev, 0)
        if count > 0:
            emoji = severity_emojis.get(sev, "")
            lines.append(f"| {emoji} {sev.upper()} | {count} |")
    lines.append("")

    # Most common finding types
    lines.append("## Most Common Finding Types")
    lines.append("")
    if top_detectors:
        lines.append("| Detector | Count |")
        lines.append("|----------|------:|")
        for det_name, count in top_detectors[:15]:
            lines.append(f"| `{esc_md(det_name)}` | {count} |")
    else:
        lines.append("*No findings recorded*")
    lines.append("")

    # Files with most findings
    lines.append("## Files with Most Findings")
    lines.append("")
    if top_files:
        lines.append("| File Path | Findings |")
        lines.append("|-----------|--------:|")
        for file_path, count in top_files[:15]:
            # Truncate long paths
            display_path = file_path if len(file_path) <= 60 else "..." + file_path[-57:]
            lines.append(f"| `{esc_md(display_path)}` | {count} |")
    else:
        lines.append("*No findings recorded*")
    lines.append("")

    # Trend over time
    lines.append("## Scan Activity Over Time")
    lines.append("")
    sorted_dates = sorted(statistics.scans_by_date.items())
    if sorted_dates:
        lines.append("| Date | Scans |")
        lines.append("|------|------:|")
        for date, count in sorted_dates[-30:]:  # Last 30 days
            lines.append(f"| {esc_md(date)} | {count} |")
    else:
        lines.append("*No scan activity recorded*")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Generated by [Hamburglar](https://github.com/needmorecowbell/Hamburglar)*")
    lines.append("")

    return "\n".join(lines)


@app.command("report")
def report(
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write report to file instead of stdout",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (html, markdown)",
            case_sensitive=False,
        ),
    ] = "html",
    since: Annotated[
        Optional[str],
        typer.Option(
            "--since",
            "-s",
            help="Include findings since date/time. Accepts ISO format (YYYY-MM-DD) "
            "or relative format (1d=1 day, 7d=7 days, 24h=24 hours, 2w=2 weeks, 1m=1 month)",
        ),
    ] = None,
    until: Annotated[
        Optional[str],
        typer.Option(
            "--until",
            help="Include findings until date/time. Same format as --since",
        ),
    ] = None,
    title: Annotated[
        str,
        typer.Option(
            "--title",
            "-t",
            help="Custom report title",
        ),
    ] = "Hamburglar Security Report",
    top_n: Annotated[
        int,
        typer.Option(
            "--top",
            "-n",
            help="Number of items to show in 'top' lists (detectors, files)",
            min=1,
            max=100,
        ),
    ] = 15,
    db_path: Annotated[
        Optional[Path],
        typer.Option(
            "--db-path",
            help="Path to SQLite database file. Default: ~/.hamburglar/findings.db",
            resolve_path=True,
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress non-error output (only show errors)",
        ),
    ] = False,
) -> None:
    """Generate a summary report from the database.

    Creates comprehensive HTML or Markdown reports showing:
    - Summary statistics (total scans, findings, files scanned)
    - Findings breakdown by severity
    - Most common finding types (detectors with most findings)
    - Files with the most findings
    - Scan activity trends over time

    Examples:
        hamburglar report                      # HTML report to stdout
        hamburglar report -o report.html       # Save HTML report to file
        hamburglar report -f markdown -o r.md  # Save Markdown report
        hamburglar report --since 7d           # Report for last 7 days
        hamburglar report --top 20             # Show top 20 items in lists

    Exit codes:
        0: Success
        1: Error occurred
        2: No data in database
    """
    from hamburglar.storage import FindingFilter

    # Set up logging based on verbosity
    if not quiet:
        setup_logging(verbose=verbose)

    # Validate format option
    format_lower = format.lower()
    valid_report_formats = {"html", "markdown", "md"}
    if format_lower not in valid_report_formats:
        _display_error(
            ConfigError(
                f"Invalid format '{format}'. Valid formats for report: html, markdown",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    # Normalize markdown format name
    if format_lower == "md":
        format_lower = "markdown"

    # Parse date filters
    since_dt: datetime | None = None
    until_dt: datetime | None = None

    if since:
        try:
            since_dt = parse_date(since)
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="since"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if until:
        try:
            until_dt = parse_date(until)
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="until"))
            raise typer.Exit(code=EXIT_ERROR) from None

    # Get database path
    resolved_db_path = get_db_path(db_path)

    # Check if database exists
    if not resolved_db_path.exists():
        if not quiet:
            console.print(
                f"[yellow]No database found at:[/yellow] {resolved_db_path}\n"
                "[dim]Run a scan with --save-to-db to create the database.[/dim]"
            )
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    if verbose and not quiet:
        console.print(f"[dim]Database:[/dim] {resolved_db_path}")
        console.print(f"[dim]Format:[/dim] {format_lower}")
        if since_dt:
            console.print(f"[dim]Since:[/dim] {since_dt.isoformat()}")
        if until_dt:
            console.print(f"[dim]Until:[/dim] {until_dt.isoformat()}")
        console.print(f"[dim]Top N:[/dim] {top_n}")

    try:
        with SqliteStorage(resolved_db_path) as storage:
            # Get statistics
            statistics = storage.get_statistics()

            # Check if there's any data
            if statistics.total_scans == 0:
                if not quiet:
                    console.print("[yellow]No scan data in database.[/yellow]")
                raise typer.Exit(code=EXIT_NO_FINDINGS)

            # Get findings for aggregation (with date filter if specified)
            finding_filter = FindingFilter(
                since=since_dt,
                until=until_dt,
            )
            findings = storage.get_findings(finding_filter)

            # Aggregate: files with most findings
            files_count: dict[str, int] = {}
            for finding in findings:
                files_count[finding.file_path] = files_count.get(finding.file_path, 0) + 1
            top_files = sorted(files_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

            # Get top detectors (already in statistics, but recompute for filtered data if needed)
            if since_dt or until_dt:
                # Recompute detector counts from filtered findings
                detector_count: dict[str, int] = {}
                for finding in findings:
                    detector_count[finding.detector_name] = (
                        detector_count.get(finding.detector_name, 0) + 1
                    )
                top_detectors = sorted(detector_count.items(), key=lambda x: x[1], reverse=True)[
                    :top_n
                ]
            else:
                # Use statistics data
                top_detectors = sorted(
                    statistics.findings_by_detector.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:top_n]

            # Generate report
            if format_lower == "html":
                report_content = _generate_report_html(
                    statistics=statistics,
                    top_detectors=top_detectors,
                    top_files=top_files,
                    title=title,
                )
            else:  # markdown
                report_content = _generate_report_markdown(
                    statistics=statistics,
                    top_detectors=top_detectors,
                    top_files=top_files,
                    title=title,
                )

            # Write to file or stdout
            if output:
                try:
                    output.write_text(report_content)
                    if not quiet:
                        console.print(f"[green]Report written to:[/green] {output}")
                except PermissionError as e:
                    _display_error(e)
                    raise typer.Exit(code=EXIT_ERROR) from None
                except OSError as e:
                    _display_error(
                        OutputError(f"Failed to write report file: {e}", output_path=str(output))
                    )
                    raise typer.Exit(code=EXIT_ERROR) from None
            elif not quiet:
                print(report_content)

    except typer.Exit:
        raise
    except StorageError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error generating report")
        raise typer.Exit(code=EXIT_ERROR) from None

    raise typer.Exit(code=EXIT_SUCCESS)


# ============================================================================
# Doctor command - System health checks
# ============================================================================


@app.command("doctor")
def doctor(
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed diagnostic information",
        ),
    ] = False,
    fix: Annotated[
        bool,
        typer.Option(
            "--fix",
            help="Attempt to fix any issues found (e.g., create missing directories)",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Only show errors and warnings, suppress success messages",
        ),
    ] = False,
) -> None:
    """Check Hamburglar's environment and configuration for issues.

    Performs diagnostic checks on:
    - Python version compatibility
    - Required dependencies installation
    - YARA library installation and functionality
    - Default configuration validity
    - Plugin system status
    - Default directories and paths

    Use this command to troubleshoot issues or verify your installation
    is working correctly.
    """
    import importlib.metadata
    import platform
    from dataclasses import dataclass
    from enum import Enum

    from rich.table import Table

    class CheckStatus(str, Enum):
        """Status for each diagnostic check."""

        OK = "ok"
        WARNING = "warning"
        ERROR = "error"
        FIXED = "fixed"

    @dataclass
    class CheckResult:
        """Result of a diagnostic check."""

        name: str
        status: CheckStatus
        message: str
        details: str | None = None
        suggestion: str | None = None

    results: list[CheckResult] = []
    has_errors = False
    has_warnings = False

    # -------------------------------------------------------------------------
    # Check 1: Python version
    # -------------------------------------------------------------------------
    python_version = platform.python_version()
    version_parts = tuple(map(int, python_version.split(".")[:2]))

    if version_parts < (3, 9):
        results.append(
            CheckResult(
                name="Python Version",
                status=CheckStatus.ERROR,
                message=f"Python {python_version} is not supported",
                details=f"Hamburglar requires Python 3.9 or higher. You have Python {python_version}.",
                suggestion="Upgrade to Python 3.9 or higher: https://www.python.org/downloads/",
            )
        )
        has_errors = True
    else:
        results.append(
            CheckResult(
                name="Python Version",
                status=CheckStatus.OK,
                message=f"Python {python_version}",
                details=f"Python {python_version} meets the minimum requirement (3.9+)."
                if verbose
                else None,
            )
        )

    # -------------------------------------------------------------------------
    # Check 2: Required dependencies
    # -------------------------------------------------------------------------
    required_packages = [
        ("typer", "0.9.0"),
        ("rich", "13.0.0"),
        ("pydantic", "2.0.0"),
        ("pydantic-settings", "2.0.0"),
        ("charset-normalizer", "3.0.0"),
        ("pyyaml", "6.0.0"),
    ]

    missing_packages = []
    outdated_packages = []

    for package_name, min_version in required_packages:
        try:
            installed_version = importlib.metadata.version(package_name)
            # Simple version comparison (handles most semver cases)
            installed_parts = installed_version.split(".")[:3]
            min_parts = min_version.split(".")[:3]

            def parse_version_part(part: str) -> int:
                """Parse version part, handling suffixes like '0rc1'."""
                import re

                match = re.match(r"(\d+)", part)
                return int(match.group(1)) if match else 0

            installed_tuple = tuple(parse_version_part(p) for p in installed_parts)
            min_tuple = tuple(parse_version_part(p) for p in min_parts)

            if installed_tuple < min_tuple:
                outdated_packages.append((package_name, installed_version, min_version))
        except importlib.metadata.PackageNotFoundError:
            missing_packages.append(package_name)

    if missing_packages:
        results.append(
            CheckResult(
                name="Dependencies",
                status=CheckStatus.ERROR,
                message=f"Missing packages: {', '.join(missing_packages)}",
                details=f"The following required packages are not installed: {', '.join(missing_packages)}",
                suggestion=f"Install with: pip install {' '.join(missing_packages)}",
            )
        )
        has_errors = True
    elif outdated_packages:
        pkg_info = ", ".join(f"{p[0]} ({p[1]} < {p[2]})" for p in outdated_packages)
        results.append(
            CheckResult(
                name="Dependencies",
                status=CheckStatus.WARNING,
                message=f"Outdated packages: {pkg_info}",
                details="Some packages are below the minimum required version.",
                suggestion=f"Upgrade with: pip install --upgrade {' '.join(p[0] for p in outdated_packages)}",
            )
        )
        has_warnings = True
    else:
        results.append(
            CheckResult(
                name="Dependencies",
                status=CheckStatus.OK,
                message="All required packages installed",
                details=f"Checked {len(required_packages)} packages." if verbose else None,
            )
        )

    # -------------------------------------------------------------------------
    # Check 3: YARA installation
    # -------------------------------------------------------------------------
    try:
        import yara  # type: ignore

        yara_version = yara.YARA_VERSION if hasattr(yara, "YARA_VERSION") else "unknown"

        # Test basic YARA functionality
        try:
            yara.compile(source="rule test { condition: true }")
            results.append(
                CheckResult(
                    name="YARA",
                    status=CheckStatus.OK,
                    message=f"yara-python installed (YARA {yara_version})",
                    details="YARA can compile and match rules successfully." if verbose else None,
                )
            )
        except Exception as e:
            results.append(
                CheckResult(
                    name="YARA",
                    status=CheckStatus.WARNING,
                    message="YARA installed but compilation failed",
                    details=str(e),
                    suggestion="Try reinstalling yara-python: pip install --force-reinstall yara-python",
                )
            )
            has_warnings = True
    except ImportError:
        results.append(
            CheckResult(
                name="YARA",
                status=CheckStatus.WARNING,
                message="yara-python not installed",
                details="YARA rule matching will not be available.",
                suggestion="Install with: pip install yara-python",
            )
        )
        has_warnings = True

    # -------------------------------------------------------------------------
    # Check 4: Configuration validation
    # -------------------------------------------------------------------------
    try:
        from hamburglar.config import load_config, reset_config
        from hamburglar.config.loader import ConfigLoader

        reset_config()
        loader = ConfigLoader()
        config_file = loader.find_config_file()

        if config_file:
            errors = loader.validate_config_file(config_file)
            if errors:
                results.append(
                    CheckResult(
                        name="Configuration",
                        status=CheckStatus.ERROR,
                        message=f"Invalid config file: {config_file}",
                        details="\n".join(f"  • {e}" for e in errors),
                        suggestion="Run 'hamburglar config validate' for details, or fix the errors in your config file.",
                    )
                )
                has_errors = True
            else:
                results.append(
                    CheckResult(
                        name="Configuration",
                        status=CheckStatus.OK,
                        message=f"Config file valid: {config_file.name}",
                        details=f"Located at: {config_file}" if verbose else None,
                    )
                )
        else:
            # No config file - try loading defaults
            load_config(use_file=False)
            results.append(
                CheckResult(
                    name="Configuration",
                    status=CheckStatus.OK,
                    message="Using default configuration",
                    details="No config file found; defaults are valid." if verbose else None,
                )
            )
    except Exception as e:
        results.append(
            CheckResult(
                name="Configuration",
                status=CheckStatus.ERROR,
                message="Failed to load configuration",
                details=str(e),
                suggestion="Check your config file syntax or run 'hamburglar config init' to create a new one.",
            )
        )
        has_errors = True

    # -------------------------------------------------------------------------
    # Check 5: Plugin system
    # -------------------------------------------------------------------------
    try:
        from hamburglar.plugins import get_plugin_manager, reset_plugin_manager
        from hamburglar.plugins.discovery import list_plugins

        reset_plugin_manager()
        manager = get_plugin_manager()
        manager.discover()

        plugins = list(list_plugins(manager=manager))
        detector_count = len([p for p in plugins if p.plugin_type == "detector"])
        output_count = len([p for p in plugins if p.plugin_type == "output"])

        results.append(
            CheckResult(
                name="Plugin System",
                status=CheckStatus.OK,
                message=f"Loaded {detector_count} detector(s), {output_count} output(s)",
                details="Plugin discovery working correctly." if verbose else None,
            )
        )
    except Exception as e:
        results.append(
            CheckResult(
                name="Plugin System",
                status=CheckStatus.WARNING,
                message="Plugin discovery failed",
                details=str(e),
                suggestion="Check that plugin directories exist and are accessible.",
            )
        )
        has_warnings = True

    # -------------------------------------------------------------------------
    # Check 6: Default database directory
    # -------------------------------------------------------------------------
    db_dir = Path.home() / ".hamburglar"

    if db_dir.exists():
        if db_dir.is_dir():
            results.append(
                CheckResult(
                    name="Data Directory",
                    status=CheckStatus.OK,
                    message="Directory exists: ~/.hamburglar",
                    details=f"Full path: {db_dir}" if verbose else None,
                )
            )
        else:
            results.append(
                CheckResult(
                    name="Data Directory",
                    status=CheckStatus.ERROR,
                    message="~/.hamburglar exists but is not a directory",
                    details=f"{db_dir} should be a directory, not a file.",
                    suggestion=f"Remove the file and let Hamburglar create the directory: rm {db_dir}",
                )
            )
            has_errors = True
    else:
        if fix:
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
                results.append(
                    CheckResult(
                        name="Data Directory",
                        status=CheckStatus.FIXED,
                        message="Created directory: ~/.hamburglar",
                        details=f"Created: {db_dir}" if verbose else None,
                    )
                )
            except PermissionError:
                results.append(
                    CheckResult(
                        name="Data Directory",
                        status=CheckStatus.ERROR,
                        message="Cannot create ~/.hamburglar directory",
                        details="Permission denied when trying to create the directory.",
                        suggestion="Create the directory manually or check permissions.",
                    )
                )
                has_errors = True
        else:
            results.append(
                CheckResult(
                    name="Data Directory",
                    status=CheckStatus.OK,
                    message="Directory will be created when needed",
                    details="~/.hamburglar does not exist yet (this is normal for new installations)."
                    if verbose
                    else None,
                )
            )

    # -------------------------------------------------------------------------
    # Check 7: Built-in YARA rules
    # -------------------------------------------------------------------------
    try:
        from hamburglar.detectors.yara_detector import YaraDetector  # noqa: F401

        # Get the default rules path
        rules_path = Path(__file__).parent.parent / "rules"

        if rules_path.exists():
            yara_files = list(rules_path.glob("*.yar"))
            if yara_files:
                results.append(
                    CheckResult(
                        name="YARA Rules",
                        status=CheckStatus.OK,
                        message=f"Found {len(yara_files)} built-in rule file(s)",
                        details=f"Rules directory: {rules_path}" if verbose else None,
                    )
                )
            else:
                results.append(
                    CheckResult(
                        name="YARA Rules",
                        status=CheckStatus.WARNING,
                        message="No .yar files in rules directory",
                        details=f"Rules directory exists but is empty: {rules_path}",
                        suggestion="Check that YARA rules were properly installed.",
                    )
                )
                has_warnings = True
        else:
            results.append(
                CheckResult(
                    name="YARA Rules",
                    status=CheckStatus.WARNING,
                    message="Built-in rules directory not found",
                    details=f"Expected at: {rules_path}",
                    suggestion="This may indicate an incomplete installation. Try reinstalling Hamburglar.",
                )
            )
            has_warnings = True
    except ImportError:
        # YARA not installed, already handled above
        pass

    # -------------------------------------------------------------------------
    # Display results
    # -------------------------------------------------------------------------
    if not quiet:
        console.print()
        console.print(Panel("[bold]Hamburglar Doctor[/bold] - System Health Check", expand=False))
        console.print()

    # Create results table
    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Check", style="bold")
    table.add_column("Status", width=8)
    table.add_column("Result")

    status_icons = {
        CheckStatus.OK: "[green]✓[/green]",
        CheckStatus.WARNING: "[yellow]![/yellow]",
        CheckStatus.ERROR: "[red]✗[/red]",
        CheckStatus.FIXED: "[cyan]↻[/cyan]",
    }

    for result in results:
        if quiet and result.status == CheckStatus.OK:
            continue

        icon = status_icons[result.status]
        table.add_row(result.name, icon, result.message)

    if not quiet or has_errors or has_warnings:
        console.print(table)
        console.print()

    # Show details and suggestions for problems
    for result in results:
        if result.status in (CheckStatus.WARNING, CheckStatus.ERROR):
            color = "yellow" if result.status == CheckStatus.WARNING else "red"
            console.print(f"[{color}]{result.name}:[/{color}]")
            if result.details:
                console.print(f"  [dim]{result.details}[/dim]")
            if result.suggestion:
                console.print(f"  [cyan]Suggestion:[/cyan] {result.suggestion}")
            console.print()

    # Summary
    if not quiet:
        if has_errors:
            console.print("[red]✗ Some checks failed.[/red] Please address the errors above.")
        elif has_warnings:
            console.print("[yellow]! All checks passed with warnings.[/yellow]")
        else:
            console.print("[green]✓ All checks passed![/green] Hamburglar is ready to use.")

    # Exit code based on results
    if has_errors:
        raise typer.Exit(code=EXIT_ERROR)
    raise typer.Exit(code=EXIT_SUCCESS)


# ============================================================================
# Plugins command group
# ============================================================================

plugins_app = typer.Typer(
    name="plugins",
    help="Plugin management commands.",
    no_args_is_help=True,
)
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list(
    plugin_type: Annotated[
        Optional[str],
        typer.Option(
            "--type",
            "-t",
            help="Filter by plugin type (detector or output)",
            case_sensitive=False,
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed information including author and source",
        ),
    ] = False,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, plain)",
            case_sensitive=False,
        ),
    ] = "table",
    discover: Annotated[
        bool,
        typer.Option(
            "--discover",
            "-d",
            help="Force plugin discovery before listing",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress informational messages",
        ),
    ] = False,
) -> None:
    """List all installed plugins.

    Shows detector and output plugins that are currently registered with
    Hamburglar, including both built-in plugins and external ones loaded
    from entry points or plugin directories.
    """
    from hamburglar.plugins import get_plugin_manager, reset_plugin_manager
    from hamburglar.plugins.discovery import (
        format_plugin_list,
        list_plugins,
    )

    # Validate plugin type if specified
    if plugin_type is not None:
        plugin_type_lower = plugin_type.lower()
        if plugin_type_lower not in ("detector", "output"):
            error_console.print(
                f"[red]Error:[/red] Invalid plugin type '{plugin_type}'. "
                "Use 'detector' or 'output'."
            )
            raise typer.Exit(code=EXIT_ERROR)
        plugin_type = plugin_type_lower

    # Get or reset the plugin manager
    if discover:
        reset_plugin_manager()

    manager = get_plugin_manager()

    # Ensure plugins are discovered
    if not manager._discovered or discover:
        manager.discover(force=discover)

    # Collect plugins
    plugins = list(list_plugins(plugin_type=plugin_type, manager=manager))

    # Handle no plugins found
    if not plugins:
        if plugin_type:
            msg = f"No {plugin_type} plugins found."
        else:
            msg = "No plugins found."
        if not quiet:
            console.print(f"[yellow]{msg}[/yellow]")
        raise typer.Exit(code=EXIT_SUCCESS)

    # Output based on format
    format_lower = format.lower()
    if format_lower == "json":
        import json

        plugin_dicts = [
            {
                "name": p.name,
                "type": p.plugin_type,
                "version": p.version,
                "author": p.author,
                "description": p.description,
                "source": p.source,
                "enabled": p.enabled,
            }
            for p in plugins
        ]
        console.print(json.dumps(plugin_dicts, indent=2))
    elif format_lower == "plain":
        # Use the format_plugin_list function
        output = format_plugin_list(plugins, verbose=verbose)
        console.print(output)
    else:
        # Default to table format
        _display_plugins_table(plugins, verbose=verbose)

    raise typer.Exit(code=EXIT_SUCCESS)


def _display_plugins_table(plugins: list["PluginListEntry"], verbose: bool = False) -> None:
    """Display plugins in a rich table format.

    Args:
        plugins: List of plugins to display.
        verbose: If True, show additional columns.
    """
    from rich.table import Table

    # Separate by type
    detectors = [p for p in plugins if p.plugin_type == "detector"]
    outputs = [p for p in plugins if p.plugin_type == "output"]

    if detectors:
        table = Table(title="Detector Plugins", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="green")
        table.add_column("Version", style="dim")
        table.add_column("Description")
        if verbose:
            table.add_column("Author", style="dim")
            table.add_column("Source", style="dim")

        for p in sorted(detectors, key=lambda x: x.name):
            if verbose:
                table.add_row(p.name, p.version, p.description or "", p.author or "-", p.source)
            else:
                table.add_row(p.name, p.version, p.description or "")

        console.print(table)
        console.print()

    if outputs:
        table = Table(title="Output Plugins", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="green")
        table.add_column("Version", style="dim")
        table.add_column("Description")
        if verbose:
            table.add_column("Author", style="dim")
            table.add_column("Source", style="dim")

        for p in sorted(outputs, key=lambda x: x.name):
            if verbose:
                table.add_row(p.name, p.version, p.description or "", p.author or "-", p.source)
            else:
                table.add_row(p.name, p.version, p.description or "")

        console.print(table)
        console.print()

    # Summary
    console.print(f"[dim]Total: {len(detectors)} detector(s), {len(outputs)} output(s)[/dim]")


@plugins_app.command("info")
def plugins_info(
    name: Annotated[
        str,
        typer.Argument(
            help="Name of the plugin to show details for",
        ),
    ],
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (table, json, plain)",
            case_sensitive=False,
        ),
    ] = "table",
) -> None:
    """Show detailed information about a specific plugin.

    Displays comprehensive information about a plugin including its name,
    type, version, author, description, source, and any configuration options.
    """
    from hamburglar.plugins import get_plugin_manager
    from hamburglar.plugins.discovery import (
        format_plugin_details,
        get_plugin_details,
    )

    manager = get_plugin_manager()

    # Ensure plugins are discovered
    if not manager._discovered:
        manager.discover()

    # Get plugin details
    plugin = get_plugin_details(name, manager=manager)

    if plugin is None:
        error_console.print(f"[red]Error:[/red] Plugin '{name}' not found.")
        error_console.print("\nUse 'hamburglar plugins list' to see available plugins.")
        raise typer.Exit(code=EXIT_ERROR)

    # Output based on format
    format_lower = format.lower()
    if format_lower == "json":
        import json

        plugin_dict = {
            "name": plugin.name,
            "type": plugin.plugin_type,
            "version": plugin.version,
            "author": plugin.author,
            "description": plugin.description,
            "source": plugin.source,
            "enabled": plugin.enabled,
            "config": plugin.config,
        }
        console.print(json.dumps(plugin_dict, indent=2))
    elif format_lower == "plain":
        output = format_plugin_details(plugin)
        console.print(output)
    else:
        # Default to table/panel format
        _display_plugin_details(plugin)

    raise typer.Exit(code=EXIT_SUCCESS)


def _display_plugin_details(plugin: "PluginListEntry") -> None:
    """Display plugin details in a rich panel format.

    Args:
        plugin: The plugin to display details for.
    """
    from rich.panel import Panel

    # Build content
    lines = []
    lines.append(f"[bold cyan]Type:[/bold cyan] {plugin.plugin_type}")
    lines.append(f"[bold cyan]Version:[/bold cyan] {plugin.version}")

    if plugin.author:
        lines.append(f"[bold cyan]Author:[/bold cyan] {plugin.author}")

    if plugin.description:
        lines.append(f"[bold cyan]Description:[/bold cyan] {plugin.description}")

    lines.append(f"[bold cyan]Source:[/bold cyan] {plugin.source}")
    lines.append(
        f"[bold cyan]Enabled:[/bold cyan] {'[green]Yes[/green]' if plugin.enabled else '[red]No[/red]'}"
    )

    if plugin.config:
        lines.append("")
        lines.append("[bold cyan]Configuration:[/bold cyan]")
        for key, value in plugin.config.items():
            lines.append(f"  [dim]{key}:[/dim] {value}")

    panel = Panel(
        "\n".join(lines),
        title=f"[bold green]{plugin.name}[/bold green]",
        border_style="cyan",
    )
    console.print(panel)


# ============================================================================
# Config command group
# ============================================================================

config_app = typer.Typer(
    name="config",
    help="Configuration management commands.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(
    show_sources: Annotated[
        bool,
        typer.Option(
            "--sources",
            "-s",
            help="Show which source each setting came from",
        ),
    ] = False,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (yaml, json, toml)",
            case_sensitive=False,
        ),
    ] = "yaml",
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress informational messages",
        ),
    ] = False,
) -> None:
    """Display current configuration with sources.

    Shows the merged configuration from all sources (defaults, config file,
    environment variables, and CLI arguments) with optional source tracking.
    """
    from hamburglar.config import (
        load_config,
    )
    from hamburglar.config.loader import ConfigLoader

    # Reset and reload to get fresh config with source tracking
    reset_config()
    config = load_config()

    # Display info about config file if found
    if not quiet:
        loader = ConfigLoader()
        config_file = loader.find_config_file()
        if config_file:
            console.print(f"[dim]Config file:[/dim] {config_file}")
        else:
            console.print("[dim]No config file found, using defaults[/dim]")
        console.print()

    # Convert config to dict
    config_dict = config.model_dump()

    # Output in requested format
    format_lower = format.lower()
    if format_lower == "json":
        import json

        output = json.dumps(config_dict, indent=2, default=str)
        console.print(output)
    elif format_lower == "toml":
        try:
            import tomli_w

            output = tomli_w.dumps(config_dict)
            console.print(output)
        except ImportError:
            # Fallback to a simple TOML-like format
            console.print("[yellow]Note: tomli-w not installed, using basic format[/yellow]")
            _print_config_as_toml(config_dict)
    else:  # Default to yaml
        try:
            import yaml

            output = yaml.dump(config_dict, default_flow_style=False, sort_keys=False)
            console.print(output)
        except ImportError:
            console.print("[yellow]Note: pyyaml not installed, using JSON format[/yellow]")
            import json

            output = json.dumps(config_dict, indent=2, default=str)
            console.print(output)

    # Show sources if requested
    if show_sources:
        console.print("\n[bold]Configuration Sources:[/bold]")
        _print_config_sources(config_dict)


def _print_config_as_toml(config_dict: dict, prefix: str = "") -> None:
    """Print config dict in a basic TOML-like format."""
    for key, value in config_dict.items():
        if isinstance(value, dict):
            console.print(f"\n[{prefix}{key}]")
            _print_config_as_toml(value, f"{prefix}{key}.")
        elif isinstance(value, list):
            if value:
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                console.print(f"{key} = [{items}]")
            else:
                console.print(f"{key} = []")
        elif isinstance(value, str):
            console.print(f'{key} = "{value}"')
        elif isinstance(value, bool):
            console.print(f"{key} = {str(value).lower()}")
        elif value is None:
            console.print(f"# {key} = null")
        else:
            console.print(f"{key} = {value}")


def _print_config_sources(config_dict: dict, path: str = "") -> None:
    """Print the source for each configuration key."""
    from hamburglar.config import ConfigPriority, get_config_source

    source_colors = {
        ConfigPriority.DEFAULT: "dim",
        ConfigPriority.CONFIG_FILE: "cyan",
        ConfigPriority.ENVIRONMENT: "yellow",
        ConfigPriority.CLI: "green",
    }

    for key, value in config_dict.items():
        current_path = f"{path}.{key}" if path else key
        if isinstance(value, dict):
            _print_config_sources(value, current_path)
        else:
            source = get_config_source(current_path)
            if source:
                color = source_colors.get(source, "white")
                console.print(f"  [{color}]{current_path}[/{color}]: {source.value}")


@config_app.command("init")
def config_init(
    path: Annotated[
        Optional[Path],
        typer.Argument(
            help="Directory to create config file in (default: current directory)",
        ),
    ] = None,
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Config file format (yaml, json, toml)",
            case_sensitive=False,
        ),
    ] = "yaml",
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Overwrite existing config file",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress informational messages",
        ),
    ] = False,
) -> None:
    """Create a default config file in the current directory.

    Creates a new .hamburglar.yml (or .toml/.json based on --format) file
    with all configuration options documented with comments.
    """
    from hamburglar.config.loader import get_default_config_content

    # Determine target directory
    target_dir = Path(path) if path else Path.cwd()
    if not target_dir.exists():
        error_console.print(f"[red]Error:[/red] Directory does not exist: {target_dir}")
        raise typer.Exit(code=EXIT_ERROR)

    # Determine filename based on format
    format_lower = format.lower()
    filenames = {
        "yaml": ".hamburglar.yml",
        "yml": ".hamburglar.yml",
        "json": "hamburglar.config.json",
        "toml": ".hamburglar.toml",
    }

    if format_lower not in filenames:
        error_console.print(
            f"[red]Error:[/red] Unknown format '{format}'. Use 'yaml', 'json', or 'toml'."
        )
        raise typer.Exit(code=EXIT_ERROR)

    config_file = target_dir / filenames[format_lower]

    # Check if file exists
    if config_file.exists() and not force:
        error_console.print(
            f"[red]Error:[/red] Config file already exists: {config_file}\n"
            "Use --force to overwrite."
        )
        raise typer.Exit(code=EXIT_ERROR)

    # Get default content based on format
    try:
        # Map format to loader format name
        loader_format = "yaml" if format_lower in ("yaml", "yml") else format_lower
        content = get_default_config_content(loader_format)
    except ValueError as e:
        error_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=EXIT_ERROR)

    # Write the file
    try:
        config_file.write_text(content, encoding="utf-8")
    except PermissionError:
        error_console.print(f"[red]Error:[/red] Permission denied: {config_file}")
        raise typer.Exit(code=EXIT_ERROR)
    except OSError as e:
        error_console.print(f"[red]Error:[/red] Failed to write config file: {e}")
        raise typer.Exit(code=EXIT_ERROR)

    if not quiet:
        console.print(f"[green]Created config file:[/green] {config_file}")
        console.print("[dim]Edit this file to customize Hamburglar's behavior.[/dim]")

    raise typer.Exit(code=EXIT_SUCCESS)


@config_app.command("validate")
def config_validate(
    path: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to config file to validate (default: auto-detect)",
            exists=True,
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Only show errors, no success message",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed validation information",
        ),
    ] = False,
) -> None:
    """Validate configuration file syntax and values.

    Checks that the configuration file has valid syntax and that all
    values are of the correct type and within allowed ranges.
    """
    from hamburglar.config.loader import ConfigLoader

    loader = ConfigLoader()

    # Find config file if not specified
    if path is None:
        config_file = loader.find_config_file()
        if config_file is None:
            error_console.print(
                "[yellow]No config file found.[/yellow]\n"
                "Run 'hamburglar config init' to create one."
            )
            raise typer.Exit(code=EXIT_ERROR)
    else:
        config_file = path

    if verbose and not quiet:
        console.print(f"[dim]Validating:[/dim] {config_file}")

    # Validate the config file
    errors = loader.validate_config_file(config_file)

    if errors:
        error_console.print(f"[red]Validation failed:[/red] {config_file}\n")
        for error in errors:
            error_console.print(f"  [red]•[/red] {error}")
        raise typer.Exit(code=EXIT_ERROR)

    if not quiet:
        console.print(f"[green]✓[/green] Config file is valid: {config_file}")

    raise typer.Exit(code=EXIT_SUCCESS)


# ============================================================================
# Hexdump command
# ============================================================================


@app.command()
def hexdump(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to file to dump",
            exists=True,
            resolve_path=True,
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write output to file instead of stdout. "
            "If not specified, outputs to stdout.",
        ),
    ] = None,
    color: Annotated[
        bool,
        typer.Option(
            "--color/--no-color",
            help="Enable colorized output (only applies to terminal output, not file output)",
        ),
    ] = True,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress informational messages",
        ),
    ] = False,
) -> None:
    """Display a hexadecimal dump of a file.

    Produces output in the standard hexdump format with:
    - 8-character hex offset
    - 16 bytes of hex values per line (split into two groups of 8)
    - ASCII representation of printable characters

    This command matches the behavior of the original 'hamburglar.py -x' flag.

    Examples:
        hamburglar hexdump binary.dat
        hamburglar hexdump binary.dat --output dump.txt
        hamburglar hexdump binary.dat --no-color
    """
    from hamburglar.utils.hexdump import hexdump as hexdump_func
    from hamburglar.utils.hexdump import hexdump_file, hexdump_rich

    # Check if path is a file (not a directory)
    if path.is_dir():
        _display_error(
            ScanError("Cannot hexdump a directory", path=str(path)),
            hint="Provide a path to a file, not a directory.",
        )
        raise typer.Exit(code=EXIT_ERROR)

    try:
        if output is not None:
            # Write to file
            output_path = output.resolve()

            # Create parent directory if needed
            output_dir = output_path.parent
            if not output_dir.exists():
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                    if not quiet:
                        console.print(f"[dim]Created directory:[/dim] {output_dir}")
                except PermissionError:
                    _display_error(
                        OutputError(
                            "Permission denied creating output directory",
                            output_path=str(output_dir),
                        )
                    )
                    raise typer.Exit(code=EXIT_ERROR) from None

            # Write hexdump to file
            hexdump_file(path, output_path)
            if not quiet:
                console.print(f"[green]Hexdump written to:[/green] {output_path}")

        else:
            # Output to stdout
            # Use colorized output if terminal supports it and color is enabled
            if color and console.is_terminal:
                hexdump_rich(path, console=console)
            else:
                # Plain text output
                output_text = hexdump_func(path)
                console.print(output_text, highlight=False)

    except FileNotFoundError:
        _display_error(
            FileNotFoundError(f"File not found: {path}"),
            hint="Check that the file path is correct.",
        )
        raise typer.Exit(code=EXIT_ERROR) from None
    except PermissionError:
        _display_error(
            PermissionError(f"Permission denied reading file: {path}"),
            hint="Check file permissions or run with appropriate privileges.",
        )
        raise typer.Exit(code=EXIT_ERROR) from None
    except IsADirectoryError:
        _display_error(
            ScanError("Cannot hexdump a directory", path=str(path)),
            hint="Provide a path to a file, not a directory.",
        )
        raise typer.Exit(code=EXIT_ERROR) from None
    except OSError as e:
        _display_error(
            OutputError(f"Error reading file: {e}", output_path=str(path))
        )
        raise typer.Exit(code=EXIT_ERROR) from None

    raise typer.Exit(code=EXIT_SUCCESS)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = None,
) -> None:
    """Hamburglar - A static analysis tool for extracting sensitive information.

    Use 'hamburglar scan <path>' to scan files for secrets and sensitive data.
    Use 'hamburglar scan-git <url/path>' to scan git repositories.
    Use 'hamburglar scan-web <url>' to scan web URLs.
    Use 'hamburglar hexdump <path>' to display a hex dump of a file.
    Use 'hamburglar history' to view stored findings from previous scans.
    Use 'hamburglar report' to generate summary reports from stored data.
    Use 'hamburglar doctor' to check your installation for issues.
    Use 'hamburglar plugins' to list and inspect installed plugins.
    Use 'hamburglar config' to manage configuration settings.
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


def run_cli() -> None:
    """Run the CLI with custom error handling for unknown commands.

    This wrapper catches Click's UsageError for unknown commands and provides
    helpful suggestions for typos.
    """
    import click

    try:
        app()
    except click.exceptions.UsageError as e:
        # Check if this is an unknown command error
        error_msg = str(e)
        if "No such command" in error_msg:
            # Extract the invalid command name from the error
            # Format: "Error: No such command 'xyz'."
            import re

            match = re.search(r"No such command ['\"]([^'\"]+)['\"]", error_msg)
            if match:
                invalid_cmd = match.group(1)
                suggested = get_command_suggestion(invalid_cmd)

                error_console.print()
                if suggested:
                    error_console.print(
                        f"[red]Error:[/red] Unknown command '[bold]{invalid_cmd}[/bold]'."
                    )
                    error_console.print(
                        f"[cyan]Did you mean:[/cyan] [bold green]{suggested}[/bold green]"
                    )
                    error_console.print()
                    error_console.print(f"[dim]Run:[/dim] hamburglar {suggested} --help")
                else:
                    error_console.print(
                        f"[red]Error:[/red] Unknown command '[bold]{invalid_cmd}[/bold]'."
                    )
                    error_console.print(format_available_commands())

                error_console.print()
                error_console.print("[dim]For help:[/dim] hamburglar --help")
                error_console.print(f"[dim]Docs:[/dim] {DOC_LINKS.get('cli', '')}")
                raise SystemExit(2) from None
        # Re-raise other usage errors
        raise


if __name__ == "__main__":
    run_cli()
