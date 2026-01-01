"""Command-line interface for Hamburglar.

This module provides the Typer-based CLI for running Hamburglar scans
with various options for output format, YARA rules, and verbosity.
"""

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Optional

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
from hamburglar.core.models import OutputFormat, ScanConfig
from hamburglar.core.progress import ScanProgress
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.detectors.yara_detector import YaraDetector
from hamburglar.outputs.streaming import StreamingOutput
from hamburglar.scanners import GitScanner

# Valid category names for CLI parsing
VALID_CATEGORIES = {cat.value: cat for cat in PatternCategory}

# Valid confidence levels for CLI parsing
VALID_CONFIDENCE_LEVELS = {conf.value: conf for conf in Confidence}

from hamburglar.outputs.json_output import JsonOutput
from hamburglar.outputs.table_output import TableOutput

# Default concurrency limit for async scanning
DEFAULT_CONCURRENCY = 50


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
            raise typer.BadParameter(
                f"Invalid category '{name}'. Valid categories: {valid_names}"
            )
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
        raise typer.BadParameter(
            f"Invalid confidence level '{level}'. Valid levels: {valid_names}"
        )

    return VALID_CONFIDENCE_LEVELS[level]


if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

# Exit codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_NO_FINDINGS = 2

# Initialize Typer app and Rich consoles
app = typer.Typer(
    name="hamburglar",
    help="Hamburglar - A static analysis tool for extracting sensitive information.",
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)


def _display_error(error: Exception, title: str = "Error") -> None:
    """Display an error with rich formatting.

    Args:
        error: The exception to display.
        title: The title for the error panel.
    """
    if isinstance(error, YaraCompilationError):
        message = f"[bold red]YARA Compilation Error[/bold red]\n\n{error.message}"
        if error.rule_file:
            message += f"\n\n[dim]Rule file:[/dim] {error.rule_file}"
        if error.context:
            for key, value in error.context.items():
                if key != "rule_file":
                    message += f"\n[dim]{key}:[/dim] {value}"
        error_console.print(Panel(message, title="[red]YARA Error[/red]", border_style="red"))
    elif isinstance(error, ScanError):
        message = f"[bold red]Scan Error[/bold red]\n\n{error.message}"
        if error.path:
            message += f"\n\n[dim]Path:[/dim] {error.path}"
        error_console.print(Panel(message, title="[red]Scan Error[/red]", border_style="red"))
    elif isinstance(error, ConfigError):
        message = f"[bold red]Configuration Error[/bold red]\n\n{error.message}"
        if error.config_key:
            message += f"\n\n[dim]Config key:[/dim] {error.config_key}"
        error_console.print(Panel(message, title="[red]Config Error[/red]", border_style="red"))
    elif isinstance(error, OutputError):
        message = f"[bold red]Output Error[/bold red]\n\n{error.message}"
        if error.output_path:
            message += f"\n\n[dim]Output path:[/dim] {error.output_path}"
        error_console.print(Panel(message, title="[red]Output Error[/red]", border_style="red"))
    elif isinstance(error, DetectorError):
        message = f"[bold red]Detector Error[/bold red]\n\n{error.message}"
        if error.detector_name:
            message += f"\n\n[dim]Detector:[/dim] {error.detector_name}"
        error_console.print(Panel(message, title="[red]Detector Error[/red]", border_style="red"))
    elif isinstance(error, HamburglarError):
        message = f"[bold red]Error[/bold red]\n\n{error.message}"
        error_console.print(Panel(message, title=f"[red]{title}[/red]", border_style="red"))
    elif isinstance(error, PermissionError):
        error_console.print(
            Panel(
                f"[bold red]Permission Denied[/bold red]\n\n{error}",
                title="[red]Permission Error[/red]",
                border_style="red",
            )
        )
    elif isinstance(error, FileNotFoundError):
        error_console.print(
            Panel(
                f"[bold red]Path Not Found[/bold red]\n\n{error}",
                title="[red]File Not Found[/red]",
                border_style="red",
            )
        )
    else:
        error_console.print(
            Panel(
                f"[bold red]{title}[/bold red]\n\n{error}",
                title="[red]Error[/red]",
                border_style="red",
            )
        )


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
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive",
            "-r",
            help="Scan directories recursively",
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
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format",
            case_sensitive=False,
        ),
    ] = "table",
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
        int,
        typer.Option(
            "--concurrency",
            "-j",
            help="Maximum number of files to scan concurrently. "
            f"Default: {DEFAULT_CONCURRENCY}",
            min=1,
            max=1000,
        ),
    ] = DEFAULT_CONCURRENCY,
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

    Exit codes:
        0: Success (findings found)
        1: Error occurred during scan
        2: No findings found
    """
    # Set up logging based on verbosity (quiet mode suppresses all non-error output)
    if not quiet:
        setup_logging(verbose=verbose)

    # Validate format option
    format_lower = format.lower()
    if format_lower not in ("json", "table"):
        _display_error(
            ConfigError(
                f"Invalid format '{format}'. Choose 'json' or 'table'.",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = OutputFormat.JSON if format_lower == "json" else OutputFormat.TABLE

    # Parse category filters
    enabled_categories: list[PatternCategory] | None = None
    disabled_categories: list[PatternCategory] | None = None
    use_expanded_patterns = False

    if categories:
        try:
            enabled_categories = parse_categories(categories)
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
    if min_confidence:
        try:
            confidence_filter = parse_confidence(min_confidence)
            use_expanded_patterns = True  # Use expanded patterns when filtering by confidence
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="min_confidence"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if verbose and not quiet:
        console.print(f"[dim]Scanning:[/dim] {path}")
        console.print(f"[dim]Recursive:[/dim] {recursive}")
        console.print(f"[dim]Format:[/dim] {output_format.value}")
        console.print(f"[dim]Concurrency:[/dim] {concurrency}")
        if stream:
            console.print("[dim]Mode:[/dim] Streaming (NDJSON)")
        if enabled_categories:
            console.print(f"[dim]Categories:[/dim] {', '.join(c.value for c in enabled_categories)}")
        if disabled_categories:
            console.print(f"[dim]Excluded categories:[/dim] {', '.join(c.value for c in disabled_categories)}")
        if confidence_filter:
            console.print(f"[dim]Min confidence:[/dim] {confidence_filter.value}")
        if yara:
            console.print(f"[dim]YARA rules:[/dim] {yara}")

    # Build scan configuration
    config = ScanConfig(
        target_path=path,
        recursive=recursive,
        use_yara=yara is not None,
        yara_rules_path=yara,
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

    if verbose and not quiet and use_expanded_patterns:
        console.print(f"[dim]Loaded {regex_detector.get_pattern_count()} patterns[/dim]")

    if yara:
        try:
            yara_detector = YaraDetector(yara)
            detectors.append(yara_detector)
            if verbose and not quiet:
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

    # Handle streaming mode
    if stream:
        asyncio.run(_run_streaming_scan(
            config, detectors, concurrency, output, quiet, verbose
        ))
        return

    # Handle benchmark mode
    if benchmark:
        asyncio.run(_run_benchmark_scan(
            config, detectors, concurrency, quiet
        ))
        return

    # Run the scan with progress bar (non-streaming mode)
    try:
        result = asyncio.run(_run_scan_with_progress(
            config, detectors, concurrency, quiet, verbose
        ))
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
        if not quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error during scan")
        raise typer.Exit(code=EXIT_ERROR) from None

    # Format output
    formatter = JsonOutput() if output_format == OutputFormat.JSON else TableOutput()

    try:
        formatted_output = formatter.format(result)
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(OutputError(f"Failed to format output: {e}"))
        raise typer.Exit(code=EXIT_ERROR) from None

    # Write to file or stdout (unless quiet mode and no findings)
    if output:
        try:
            output.write_text(formatted_output)
            if not quiet:
                console.print(f"[green]Output written to:[/green] {output}")
        except PermissionError as e:
            _display_error(e)
            raise typer.Exit(code=EXIT_ERROR) from None
        except OSError as e:
            _display_error(OutputError(f"Failed to write output file: {e}", output_path=str(output)))
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not quiet:
        # For JSON output, use print() directly to avoid Rich's text wrapping
        # which can break JSON parsing. For table output, use Rich console
        # for proper formatting.
        if output_format == OutputFormat.JSON:
            print(formatted_output)
        else:
            console.print(formatted_output)

    # Determine exit code based on findings
    if len(result.findings) == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    # Show warning for high severity findings in verbose mode
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and verbose and not quiet:
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
    from hamburglar.core.models import ScanResult

    # Progress tracking state
    progress_state = {
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
        discover_task = progress.add_task(
            "[cyan]Discovering files...", total=None, stats=""
        )

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
                console.print(f"[green]Streamed {findings_count} findings to:[/green] {output_path}")
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
    format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format",
            case_sensitive=False,
        ),
    ] = "table",
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
    # Set up logging based on verbosity
    if not quiet:
        setup_logging(verbose=verbose)

    # Validate format option
    format_lower = format.lower()
    if format_lower not in ("json", "table"):
        _display_error(
            ConfigError(
                f"Invalid format '{format}'. Choose 'json' or 'table'.",
                config_key="format",
            )
        )
        raise typer.Exit(code=EXIT_ERROR)

    output_format = OutputFormat.JSON if format_lower == "json" else OutputFormat.TABLE

    # Parse category filters
    enabled_categories: list[PatternCategory] | None = None
    disabled_categories: list[PatternCategory] | None = None
    use_expanded_patterns = False

    if categories:
        try:
            enabled_categories = parse_categories(categories)
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
    if min_confidence:
        try:
            confidence_filter = parse_confidence(min_confidence)
            use_expanded_patterns = True
        except typer.BadParameter as e:
            _display_error(ConfigError(str(e), config_key="min_confidence"))
            raise typer.Exit(code=EXIT_ERROR) from None

    if verbose and not quiet:
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
            console.print(f"[dim]Categories:[/dim] {', '.join(c.value for c in enabled_categories)}")
        if disabled_categories:
            console.print(f"[dim]Excluded categories:[/dim] {', '.join(c.value for c in disabled_categories)}")
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

    if verbose and not quiet and use_expanded_patterns:
        console.print(f"[dim]Loaded {regex_detector.get_pattern_count()} patterns[/dim]")

    # Handle streaming mode
    if stream:
        asyncio.run(_run_git_streaming_scan(
            target, detectors, depth, branch, include_history, clone_dir, output, quiet, verbose
        ))
        return

    # Run the scan with progress bar (non-streaming mode)
    try:
        result = asyncio.run(_run_git_scan_with_progress(
            target, detectors, depth, branch, include_history, clone_dir, quiet, verbose
        ))
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
        if not quiet:
            error_console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(e, title="Error during git scan")
        raise typer.Exit(code=EXIT_ERROR) from None

    # Format output
    formatter = JsonOutput() if output_format == OutputFormat.JSON else TableOutput()

    try:
        formatted_output = formatter.format(result)
    except HamburglarError as e:
        _display_error(e)
        raise typer.Exit(code=EXIT_ERROR) from None
    except Exception as e:
        _display_error(OutputError(f"Failed to format output: {e}"))
        raise typer.Exit(code=EXIT_ERROR) from None

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
            _display_error(OutputError(f"Failed to write output file: {e}", output_path=str(output)))
            raise typer.Exit(code=EXIT_ERROR) from None
    elif not quiet:
        if output_format == OutputFormat.JSON:
            print(formatted_output)
        else:
            console.print(formatted_output)

    # Determine exit code based on findings
    if len(result.findings) == 0:
        raise typer.Exit(code=EXIT_NO_FINDINGS)

    # Show warning for high severity findings in verbose mode
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and verbose and not quiet:
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
    from hamburglar.core.models import ScanResult

    # Progress tracking state
    progress_state = {
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
        main_task = progress.add_task(
            "[cyan]Scanning git repository...", total=None, stats=""
        )

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
                    stats_parts.append(
                        f"[yellow]{last_progress.findings_count} findings[/yellow]"
                    )
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
                console.print(f"[green]Streamed {findings_count} findings to:[/green] {output_path}")
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
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()
