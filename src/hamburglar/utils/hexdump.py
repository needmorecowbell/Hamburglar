"""Hexadecimal dump utility for file analysis.

Provides a modernized hexdump function compatible with the original hamburglar.py
output format, with optional colorized output using Rich.

Example usage::

    from hamburglar.utils import hexdump

    # Get hexdump as string
    output = hexdump("/path/to/file")
    print(output)

    # Get colorized hexdump for terminal display
    from hamburglar.utils.hexdump import hexdump_rich
    hexdump_rich("/path/to/file")

    # Save hexdump to file
    output = hexdump("/path/to/file")
    with open("output.hexdump", "w") as f:
        f.write(output)
"""

from __future__ import annotations

from pathlib import Path
from typing import IO

from rich.console import Console
from rich.text import Text

# Bytes per line in hexdump output
BYTES_PER_LINE = 16

# Half of bytes per line (for spacing)
HALF_LINE = BYTES_PER_LINE // 2


def hexdump(file_path: str | Path) -> str:
    """Generate a hexadecimal dump of a file.

    Produces output compatible with the original hamburglar.py hexdump format:
    - 8-character hex offset
    - 16 bytes of hex values (split into two groups of 8)
    - ASCII representation of printable characters

    Args:
        file_path: Path to the file to dump

    Returns:
        String containing the complete hexdump

    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read
        IsADirectoryError: If the path is a directory

    Example output::

        00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
        00000010  03 00 3e 00 01 00 00 00  50 10 00 00 00 00 00 00  |..>.....P.......|
    """
    path = Path(file_path)
    lines: list[str] = []

    with path.open("rb") as f:
        offset = 0
        while True:
            chunk = f.read(BYTES_PER_LINE)
            if not chunk:
                break
            lines.append(_format_line(offset, chunk))
            offset += BYTES_PER_LINE

    return "\n".join(lines)


def hexdump_iter(file_path: str | Path):
    """Generate hexdump lines lazily for large files.

    Yields one line at a time to conserve memory when processing large files.

    Args:
        file_path: Path to the file to dump

    Yields:
        Individual hexdump lines

    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read
        IsADirectoryError: If the path is a directory
    """
    path = Path(file_path)

    with path.open("rb") as f:
        offset = 0
        while True:
            chunk = f.read(BYTES_PER_LINE)
            if not chunk:
                break
            yield _format_line(offset, chunk)
            offset += BYTES_PER_LINE


def hexdump_file(file_path: str | Path, output: str | Path | IO[str]) -> None:
    """Write hexdump directly to a file or file-like object.

    Efficiently streams hexdump output to avoid loading entire file into memory.

    Args:
        file_path: Path to the file to dump
        output: Output file path or file-like object

    Raises:
        FileNotFoundError: If the input file does not exist
        PermissionError: If files cannot be read/written
    """
    if isinstance(output, (str, Path)):
        with open(output, "w") as f:
            for line in hexdump_iter(file_path):
                f.write(line + "\n")
    else:
        for line in hexdump_iter(file_path):
            output.write(line + "\n")


def hexdump_rich(
    file_path: str | Path,
    console: Console | None = None,
    highlight_patterns: dict[bytes, str] | None = None,
) -> None:
    """Display colorized hexdump to terminal using Rich.

    Provides colored output with:
    - Blue offset addresses
    - Yellow hex values for non-printable bytes
    - Green hex values for printable bytes
    - Dim ASCII section
    - Optional pattern highlighting

    Args:
        file_path: Path to the file to dump
        console: Rich Console instance (creates new one if not provided)
        highlight_patterns: Optional dict mapping byte patterns to color names.
            When a pattern is found, those bytes are highlighted with the color.

    Example::

        from rich.console import Console
        from hamburglar.utils.hexdump import hexdump_rich

        # Basic colorized output
        hexdump_rich("/path/to/file")

        # Highlight specific patterns
        hexdump_rich(
            "/path/to/file",
            highlight_patterns={
                b"\\x7fELF": "red",  # ELF magic
                b"PK": "magenta",    # ZIP magic
            }
        )
    """
    if console is None:
        console = Console()

    path = Path(file_path)

    with path.open("rb") as f:
        offset = 0
        while True:
            chunk = f.read(BYTES_PER_LINE)
            if not chunk:
                break
            text = _format_line_rich(offset, chunk, highlight_patterns)
            console.print(text)
            offset += BYTES_PER_LINE


def _format_line(offset: int, data: bytes) -> str:
    """Format a single line of hexdump output.

    Args:
        offset: Byte offset at start of line
        data: Up to 16 bytes of data

    Returns:
        Formatted hexdump line
    """
    # Format hex values with space between each byte
    hex_parts = [f"{b:02x}" for b in data]

    # Build hex string with extra space between first and second half
    if len(hex_parts) > HALF_LINE:
        hex_left = " ".join(hex_parts[:HALF_LINE])
        hex_right = " ".join(hex_parts[HALF_LINE:])
        hex_str = f"{hex_left}  {hex_right}"
    else:
        hex_str = " ".join(hex_parts)

    # Pad hex string to fixed width (47 chars: 8*2 + 7 spaces + 2 spaces + 8*2 + 7 spaces)
    hex_str = hex_str.ljust(48)

    # Build ASCII representation
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)

    return f"{offset:08x}  {hex_str} |{ascii_str}|"


def _format_line_rich(
    offset: int, data: bytes, highlight_patterns: dict[bytes, str] | None = None
) -> Text:
    """Format a single line of hexdump output with Rich styling.

    Args:
        offset: Byte offset at start of line
        data: Up to 16 bytes of data
        highlight_patterns: Optional patterns to highlight

    Returns:
        Rich Text object with styled content
    """
    text = Text()

    # Offset in blue
    text.append(f"{offset:08x}  ", style="blue bold")

    # Find highlight positions
    highlight_positions: set[int] = set()
    highlight_colors: dict[int, str] = {}

    if highlight_patterns:
        data_bytes = bytes(data)
        for pattern, color in highlight_patterns.items():
            pos = 0
            while True:
                idx = data_bytes.find(pattern, pos)
                if idx == -1:
                    break
                for i in range(idx, min(idx + len(pattern), len(data))):
                    highlight_positions.add(i)
                    highlight_colors[i] = color
                pos = idx + 1

    # Hex values
    for i, b in enumerate(data):
        # Add separator between halves
        if i == HALF_LINE:
            text.append(" ")

        # Determine style
        if i in highlight_positions:
            style = f"{highlight_colors[i]} bold"
        elif 32 <= b <= 126:
            style = "green"
        else:
            style = "yellow"

        text.append(f"{b:02x}", style=style)

        # Space after each byte except last
        if i < len(data) - 1:
            text.append(" ")

    # Pad remaining hex area if line is short
    remaining = BYTES_PER_LINE - len(data)
    if remaining > 0:
        # Calculate padding needed
        padding = remaining * 3  # 2 hex chars + 1 space per byte
        if len(data) <= HALF_LINE:
            padding += 1  # Extra space for missing separator
        text.append(" " * padding)

    # Separator and ASCII
    text.append("  |", style="dim")

    for i, b in enumerate(data):
        char = chr(b) if 32 <= b <= 126 else "."
        if i in highlight_positions:
            text.append(char, style=f"{highlight_colors[i]} bold")
        else:
            text.append(char, style="dim")

    text.append("|", style="dim")

    return text
