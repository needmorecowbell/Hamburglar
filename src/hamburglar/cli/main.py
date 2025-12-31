"""Command-line interface for Hamburglar.

This module provides the Typer-based CLI for running Hamburglar scans
with various options for output format, YARA rules, and verbosity.
"""

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from hamburglar import __version__
from hamburglar.core.models import OutputFormat, ScanConfig
from hamburglar.core.scanner import Scanner
from hamburglar.detectors import BaseDetector
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.detectors.yara_detector import YaraDetector
from hamburglar.outputs.json_output import JsonOutput
from hamburglar.outputs.table_output import TableOutput

# Initialize Typer app and Rich console
app = typer.Typer(
    name="hamburglar",
    help="Hamburglar - A static analysis tool for extracting sensitive information.",
    add_completion=False,
)
console = Console()


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
    """
    # Validate format option
    format_lower = format.lower()
    if format_lower not in ("json", "table"):
        console.print(f"[red]Error:[/red] Invalid format '{format}'. Choose 'json' or 'table'.")
        raise typer.Exit(code=1)

    output_format = OutputFormat.JSON if format_lower == "json" else OutputFormat.TABLE

    if verbose:
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
            if verbose:
                console.print(f"[dim]Loaded {yara_detector.rule_count} YARA rule file(s)[/dim]")
        except FileNotFoundError as e:
            console.print(f"[red]Error:[/red] YARA rules not found: {e}")
            raise typer.Exit(code=1)
        except ValueError as e:
            console.print(f"[red]Error:[/red] YARA rules error: {e}")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to load YARA rules: {e}")
            raise typer.Exit(code=1)

    # Run the scan
    scanner = Scanner(config, detectors)

    if verbose:
        console.print("[dim]Starting scan...[/dim]")

    try:
        result = asyncio.run(scanner.scan())
    except Exception as e:
        console.print(f"[red]Error during scan:[/red] {e}")
        raise typer.Exit(code=1)

    # Format output
    if output_format == OutputFormat.JSON:
        formatter = JsonOutput()
    else:
        formatter = TableOutput()

    formatted_output = formatter.format(result)

    # Write to file or stdout
    if output:
        try:
            output.write_text(formatted_output)
            console.print(f"[green]Output written to:[/green] {output}")
        except OSError as e:
            console.print(f"[red]Error writing output file:[/red] {e}")
            raise typer.Exit(code=1)
    else:
        console.print(formatted_output)

    # Exit with non-zero code if findings with HIGH or CRITICAL severity
    from hamburglar.core.models import Severity

    high_severity_count = sum(
        1
        for f in result.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if high_severity_count > 0 and verbose:
        console.print(
            f"[yellow]Warning:[/yellow] Found {high_severity_count} high/critical severity finding(s)"
        )


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
