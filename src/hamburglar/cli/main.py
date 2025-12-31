"""Command-line interface for Hamburglar.

This module provides the Typer-based CLI for running Hamburglar scans
with various options for output format, YARA rules, and verbosity.
"""

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel

from hamburglar import __version__
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
from hamburglar.core.scanner import Scanner
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.detectors.yara_detector import YaraDetector
from hamburglar.outputs.json_output import JsonOutput
from hamburglar.outputs.table_output import TableOutput

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

    if verbose and not quiet:
        console.print(f"[dim]Scanning:[/dim] {path}")
        console.print(f"[dim]Recursive:[/dim] {recursive}")
        console.print(f"[dim]Format:[/dim] {output_format.value}")
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
    detectors: list[BaseDetector] = [RegexDetector()]

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

    # Run the scan
    scanner = Scanner(config, detectors)

    if verbose and not quiet:
        console.print("[dim]Starting scan...[/dim]")

    try:
        result = asyncio.run(scanner.scan())
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
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()
