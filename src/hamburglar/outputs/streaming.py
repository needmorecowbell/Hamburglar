"""Streaming output formatter for Hamburglar.

This module provides a streaming output formatter that yields findings as they're
discovered, supporting NDJSON (newline-delimited JSON) format for real-time
piping to other tools.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, TextIO

from hamburglar.core.models import Finding
from hamburglar.outputs import BaseOutput

if TYPE_CHECKING:
    from hamburglar.core.models import ScanResult


class StreamingOutput(BaseOutput):
    """Output formatter that streams findings as NDJSON (Newline-Delimited JSON).

    This formatter is designed for real-time output of findings as they're
    discovered during a scan. It outputs each finding as a single JSON object
    on its own line, allowing for easy piping to other tools like jq.

    NDJSON format is ideal for streaming because:
    - Each line is a complete, valid JSON object
    - Lines can be processed as they arrive without buffering
    - Easy to parse with standard tools (jq, grep, etc.)
    - Memory-efficient for large result sets

    Example output:
        {"file_path": "/path/to/file.txt", "detector_name": "aws_key", ...}
        {"file_path": "/path/to/other.txt", "detector_name": "password", ...}

    Example usage:
        >>> formatter = StreamingOutput()
        >>> async for line in formatter.stream_findings(scanner.scan_stream()):
        ...     print(line, flush=True)

        # Or with a file handle:
        >>> async for line in formatter.stream_findings(scanner.scan_stream()):
        ...     sys.stdout.write(line + '\\n')
        ...     sys.stdout.flush()
    """

    @property
    def name(self) -> str:
        """Return the formatter name."""
        return "ndjson"

    def format(self, result: ScanResult) -> str:
        """Format a complete scan result as NDJSON.

        Each finding is output on its own line as a JSON object.
        This method is for compatibility with BaseOutput but is less
        efficient than using stream_findings for large result sets.

        Args:
            result: The ScanResult to format.

        Returns:
            NDJSON string with each finding on a separate line.
        """
        lines = []
        for finding in result.findings:
            lines.append(self.format_finding(finding))
        return "\n".join(lines)

    def format_finding(self, finding: Finding) -> str:
        """Format a single finding as a JSON string.

        Args:
            finding: The Finding to format.

        Returns:
            A single-line JSON string representation of the finding.
        """
        return finding.model_dump_json()

    async def stream_findings(
        self,
        findings_iterator: AsyncIterator[Finding],
    ) -> AsyncIterator[str]:
        """Stream findings as NDJSON lines as they're discovered.

        This is an async generator that yields formatted JSON lines for each
        finding as it becomes available from the scanner. This enables real-time
        output without waiting for the entire scan to complete.

        Args:
            findings_iterator: An async iterator yielding Finding objects,
                              typically from AsyncScanner.scan_stream().

        Yields:
            JSON-formatted strings, one per finding.

        Example:
            >>> scanner = AsyncScanner(config, detectors)
            >>> formatter = StreamingOutput()
            >>> async for line in formatter.stream_findings(scanner.scan_stream()):
            ...     print(line, flush=True)
        """
        async for finding in findings_iterator:
            yield self.format_finding(finding)

    async def write_stream(
        self,
        findings_iterator: AsyncIterator[Finding],
        output: TextIO,
        flush: bool = True,
    ) -> int:
        """Write streamed findings directly to a file-like object.

        This convenience method writes each finding to the output as it arrives,
        optionally flushing after each write for real-time output.

        Args:
            findings_iterator: An async iterator yielding Finding objects.
            output: A file-like object with write() method (e.g., sys.stdout).
            flush: Whether to flush after each write for real-time output.

        Returns:
            The number of findings written.

        Example:
            >>> import sys
            >>> scanner = AsyncScanner(config, detectors)
            >>> formatter = StreamingOutput()
            >>> count = await formatter.write_stream(scanner.scan_stream(), sys.stdout)
            >>> print(f"Wrote {count} findings", file=sys.stderr)
        """
        count = 0
        async for line in self.stream_findings(findings_iterator):
            output.write(line + "\n")
            if flush:
                output.flush()
            count += 1
        return count

    async def collect_findings(
        self,
        findings_iterator: AsyncIterator[Finding],
        max_findings: int | None = None,
    ) -> list[Finding]:
        """Collect findings from a stream into a list.

        This method collects findings from an async iterator, optionally
        limiting the number of findings collected. Useful for testing or
        when you need to process findings after collection.

        Args:
            findings_iterator: An async iterator yielding Finding objects.
            max_findings: Maximum number of findings to collect, or None for all.

        Returns:
            List of collected Finding objects.

        Example:
            >>> formatter = StreamingOutput()
            >>> findings = await formatter.collect_findings(
            ...     scanner.scan_stream(),
            ...     max_findings=100
            ... )
        """
        findings: list[Finding] = []
        count = 0
        async for finding in findings_iterator:
            findings.append(finding)
            count += 1
            if max_findings is not None and count >= max_findings:
                break
        return findings


class NDJSONStreamWriter:
    """A class for writing NDJSON output with backpressure handling.

    This class provides more control over streaming output, including
    support for async writes with backpressure and buffering options.

    Example:
        >>> async with NDJSONStreamWriter(sys.stdout) as writer:
        ...     async for finding in scanner.scan_stream():
        ...         await writer.write(finding)
    """

    def __init__(
        self,
        output: TextIO,
        buffer_size: int = 100,
        flush_interval: float = 0.1,
    ) -> None:
        """Initialize the NDJSON stream writer.

        Args:
            output: A file-like object to write to.
            buffer_size: Maximum number of findings to buffer before flushing.
            flush_interval: Maximum time between flushes in seconds.
        """
        self._output = output
        self._buffer_size = buffer_size
        self._flush_interval = flush_interval
        self._buffer: list[str] = []
        self._write_count = 0
        self._lock = asyncio.Lock()
        self._closed = False

    async def __aenter__(self) -> NDJSONStreamWriter:
        """Enter the async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the async context manager, flushing any remaining data."""
        await self.flush()
        self._closed = True

    async def write(self, finding: Finding) -> None:
        """Write a finding to the stream.

        The finding is buffered and may not be written immediately.
        Use flush() to ensure all buffered findings are written.

        Args:
            finding: The Finding to write.

        Raises:
            RuntimeError: If the writer has been closed.
        """
        if self._closed:
            raise RuntimeError("Cannot write to a closed stream writer")

        async with self._lock:
            self._buffer.append(finding.model_dump_json())
            self._write_count += 1

            if len(self._buffer) >= self._buffer_size:
                await self._flush_buffer()

    async def flush(self) -> None:
        """Flush all buffered findings to the output."""
        async with self._lock:
            await self._flush_buffer()

    async def _flush_buffer(self) -> None:
        """Internal method to flush the buffer (must be called with lock held)."""
        if not self._buffer:
            return

        # Use to_thread to avoid blocking the event loop on I/O
        lines = "\n".join(self._buffer) + "\n"
        await asyncio.to_thread(self._write_sync, lines)
        self._buffer.clear()

    def _write_sync(self, data: str) -> None:
        """Synchronous write helper for use with to_thread."""
        self._output.write(data)
        self._output.flush()

    @property
    def write_count(self) -> int:
        """Return the total number of findings written."""
        return self._write_count


async def stream_to_ndjson(
    findings_iterator: AsyncIterator[Finding],
    output: TextIO | None = None,
) -> list[str]:
    """Convenience function to stream findings to NDJSON format.

    This function converts an async iterator of findings to NDJSON strings.
    If an output file is provided, it writes to the file and returns an empty list.
    Otherwise, it collects and returns all the formatted strings.

    Args:
        findings_iterator: An async iterator yielding Finding objects.
        output: Optional file-like object to write to. If None, returns strings.

    Returns:
        List of NDJSON strings if output is None, otherwise empty list.

    Example:
        >>> # Collect as strings
        >>> lines = await stream_to_ndjson(scanner.scan_stream())
        >>> for line in lines:
        ...     print(line)

        >>> # Write directly to stdout
        >>> await stream_to_ndjson(scanner.scan_stream(), sys.stdout)
    """
    formatter = StreamingOutput()

    if output is not None:
        await formatter.write_stream(findings_iterator, output)
        return []

    lines: list[str] = []
    async for line in formatter.stream_findings(findings_iterator):
        lines.append(line)
    return lines
