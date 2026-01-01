"""Async scanner module for Hamburglar.

This module provides the AsyncScanner class which handles file discovery,
content reading, and detector orchestration using modern async/await patterns.
It replaces the legacy threading model with asyncio for improved performance
and resource efficiency.
"""

import asyncio
import fnmatch
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, Callable

from hamburglar.core.exceptions import ScanError
from hamburglar.core.models import Finding, ScanConfig, ScanResult
from hamburglar.core.progress import ScanProgress

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

logger = logging.getLogger(__name__)

# Type alias for progress callback
ProgressCallback = Callable[[ScanProgress], None]


class AsyncScanner:
    """Async scanner that uses modern async/await patterns for file scanning.

    The AsyncScanner walks directories (respecting blacklist/whitelist patterns),
    reads file contents asynchronously, passes them to registered detectors,
    and aggregates findings. It provides:

    - Configurable concurrency limit via asyncio.Semaphore
    - Async generator for streaming results as they're discovered
    - Progress tracking with detailed statistics
    - Cancellation support via asyncio.Event
    """

    DEFAULT_CONCURRENCY_LIMIT = 50

    def __init__(
        self,
        config: ScanConfig,
        detectors: list["BaseDetector"] | None = None,
        progress_callback: ProgressCallback | None = None,
        concurrency_limit: int = DEFAULT_CONCURRENCY_LIMIT,
    ):
        """Initialize the async scanner.

        Args:
            config: Scan configuration specifying target, filters, and options.
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
            progress_callback: Optional callback function for progress updates.
                              Called with a ScanProgress dataclass.
            concurrency_limit: Maximum number of concurrent file operations.
                              Defaults to 50.
        """
        self.config = config
        self.detectors = detectors or []
        self.progress_callback = progress_callback
        self.concurrency_limit = concurrency_limit

        # Semaphore for controlling concurrent file access
        self._semaphore = asyncio.Semaphore(concurrency_limit)

        # Cancellation event
        self._cancel_event = asyncio.Event()

        # Progress tracking
        self._files_scanned = 0
        self._files_skipped = 0
        self._bytes_processed = 0
        self._findings_count = 0
        self._errors: list[str] = []
        self._total_files = 0
        self._current_file = ""
        self._start_time: float = 0.0

    @property
    def is_cancelled(self) -> bool:
        """Check if the scan has been cancelled.

        Returns:
            True if cancellation has been requested, False otherwise.
        """
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        """Request cancellation of the ongoing scan.

        This sets the cancellation event, which will cause the scan to
        stop processing new files and return partial results.
        """
        self._cancel_event.set()
        logger.info("Scan cancellation requested")

    def reset(self) -> None:
        """Reset the scanner state for a new scan.

        Clears all counters, errors, and the cancellation event.
        """
        self._cancel_event.clear()
        self._files_scanned = 0
        self._files_skipped = 0
        self._bytes_processed = 0
        self._findings_count = 0
        self._errors = []
        self._total_files = 0
        self._current_file = ""
        self._start_time = 0.0
        # Recreate semaphore with potentially new limit
        self._semaphore = asyncio.Semaphore(self.concurrency_limit)

    def _get_progress(self) -> ScanProgress:
        """Get the current scan progress.

        Returns:
            ScanProgress dataclass with current scan statistics.
        """
        return ScanProgress(
            total_files=self._total_files,
            scanned_files=self._files_scanned,
            current_file=self._current_file,
            bytes_processed=self._bytes_processed,
            findings_count=self._findings_count,
            elapsed_time=time.time() - self._start_time if self._start_time else 0.0,
        )

    def _report_progress(self) -> None:
        """Report progress via callback if one is configured."""
        if self.progress_callback is not None:
            try:
                self.progress_callback(self._get_progress())
            except Exception as e:
                # Don't let callback errors disrupt the scan
                logger.debug(f"Progress callback error: {e}")

    def _matches_pattern(self, path: Path, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns.

        Args:
            path: Path to check.
            patterns: List of glob patterns to match against.

        Returns:
            True if path matches any pattern, False otherwise.
        """
        path_str = str(path)
        name = path.name

        for pattern in patterns:
            # Check if pattern matches the full path or just the name
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path_str, pattern):
                return True
            # Also check if any parent directory matches (for directory patterns)
            for parent in path.parents:
                if fnmatch.fnmatch(parent.name, pattern):
                    return True
        return False

    def _should_scan_file(self, file_path: Path) -> bool:
        """Determine if a file should be scanned based on blacklist/whitelist.

        Args:
            file_path: Path to the file to check.

        Returns:
            True if the file should be scanned, False otherwise.
        """
        # Check blacklist first
        if self._matches_pattern(file_path, self.config.blacklist):
            return False

        # If whitelist is specified, file must match
        return not (
            self.config.whitelist and not self._matches_pattern(file_path, self.config.whitelist)
        )

    async def _discover_files(self) -> list[Path]:
        """Discover all files to scan based on configuration.

        Uses asyncio.to_thread() to run file discovery in a thread pool,
        preventing blocking of the event loop during directory traversal.

        Returns:
            List of file paths to scan.

        Raises:
            ScanError: If the target path does not exist.
        """
        target = self.config.target_path

        if not target.exists():
            raise ScanError(
                f"Target path does not exist: {target}",
                path=str(target),
            )

        if target.is_file():
            if self._should_scan_file(target):
                return [target]
            return []

        # Run file discovery in thread pool to avoid blocking
        return await asyncio.to_thread(self._discover_files_sync, target)

    def _discover_files_sync(self, target: Path) -> list[Path]:
        """Synchronous file discovery helper.

        Args:
            target: Directory path to discover files in.

        Returns:
            List of discovered file paths.
        """
        files: list[Path] = []

        if self.config.recursive:
            try:
                for item in target.rglob("*"):
                    if self.is_cancelled:
                        break
                    try:
                        if item.is_file() and self._should_scan_file(item):
                            files.append(item)
                    except PermissionError:
                        logger.warning(f"Permission denied accessing: {item}")
                        self._errors.append(f"Permission denied: {item}")
                    except OSError as e:
                        logger.error(f"Error accessing file {item}: {e}")
                        self._errors.append(f"Error accessing {item}: {e}")
            except PermissionError as e:
                logger.warning(f"Permission denied during directory walk: {e}")
                self._errors.append(f"Permission denied: {e}")
            except OSError as e:
                logger.error(f"Error during directory walk: {e}")
                self._errors.append(f"Error during directory walk: {e}")
        else:
            try:
                for item in target.iterdir():
                    if self.is_cancelled:
                        break
                    try:
                        if item.is_file() and self._should_scan_file(item):
                            files.append(item)
                    except PermissionError:
                        logger.warning(f"Permission denied accessing: {item}")
                        self._errors.append(f"Permission denied: {item}")
                    except OSError as e:
                        logger.error(f"Error accessing file {item}: {e}")
                        self._errors.append(f"Error accessing {item}: {e}")
            except PermissionError as e:
                logger.warning(f"Permission denied reading directory: {e}")
                self._errors.append(f"Permission denied: {e}")
            except OSError as e:
                logger.error(f"Error reading directory: {e}")
                self._errors.append(f"Error reading directory: {e}")

        return files

    async def _read_file(self, file_path: Path) -> str | None:
        """Read file contents asynchronously.

        Uses asyncio.to_thread() to run file I/O in a thread pool,
        preventing blocking of the event loop.

        Args:
            file_path: Path to the file to read.

        Returns:
            File contents as string, or None if reading failed.
        """

        def _read_sync() -> tuple[str | None, int]:
            try:
                # Try reading as UTF-8 first
                try:
                    content = file_path.read_text(encoding="utf-8")
                    return content, len(content.encode("utf-8"))
                except UnicodeDecodeError:
                    # Fall back to latin-1 which can read any byte sequence
                    logger.debug(f"UTF-8 decode failed for {file_path}, falling back to latin-1")
                    content = file_path.read_text(encoding="latin-1")
                    return content, len(content.encode("latin-1"))
            except PermissionError:
                logger.warning(f"Permission denied reading file: {file_path}")
                self._errors.append(f"Permission denied: {file_path}")
                return None, 0
            except IsADirectoryError:
                logger.warning(f"Path is a directory, not a file: {file_path}")
                self._errors.append(f"Path is a directory: {file_path}")
                return None, 0
            except FileNotFoundError:
                # File may have been deleted during scan
                logger.warning(f"File not found (may have been deleted): {file_path}")
                self._errors.append(f"File not found: {file_path}")
                return None, 0
            except OSError as e:
                # Handles corrupted files, I/O errors, and other OS-level issues
                logger.error(f"Error reading file {file_path}: {e}")
                self._errors.append(f"Error reading {file_path}: {e}")
                return None, 0
            except Exception as e:
                # Catch any unexpected errors to prevent scan failure
                logger.error(f"Unexpected error reading file {file_path}: {e}")
                self._errors.append(f"Unexpected error reading {file_path}: {e}")
                return None, 0

        content, size = await asyncio.to_thread(_read_sync)
        if content is not None:
            self._bytes_processed += size
        return content

    async def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file with all detectors, respecting concurrency limit.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings from all detectors.
        """
        # Check for cancellation before processing
        if self.is_cancelled:
            return []

        async with self._semaphore:
            # Double-check cancellation after acquiring semaphore
            if self.is_cancelled:
                return []

            self._current_file = str(file_path)
            self._report_progress()

            content = await self._read_file(file_path)
            if content is None:
                self._files_skipped += 1
                return []

            self._files_scanned += 1
            findings: list[Finding] = []

            for detector in self.detectors:
                if self.is_cancelled:
                    break
                try:
                    detector_findings = detector.detect(content, str(file_path))
                    findings.extend(detector_findings)
                    self._findings_count += len(detector_findings)
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed on {file_path}: {e}")
                    self._errors.append(f"Detector {detector.name} error on {file_path}: {e}")

            return findings

    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        Discovers files based on configuration, reads their contents,
        and passes them through all registered detectors. Uses asyncio.Semaphore
        to limit concurrent file operations.

        Returns:
            ScanResult containing all findings and scan statistics.

        Raises:
            ScanError: If the target path does not exist.
        """
        self.reset()
        self._start_time = time.time()

        # Discover files to scan
        files = await self._discover_files()
        self._total_files = len(files)
        logger.info(f"Found {len(files)} files to scan")

        # Initial progress report
        self._report_progress()

        # Scan all files concurrently with semaphore-controlled access
        all_findings: list[Finding] = []
        if files and not self.is_cancelled:
            tasks = [self._scan_file(f) for f in files]
            results = await asyncio.gather(*tasks)
            for file_findings in results:
                all_findings.extend(file_findings)

        scan_duration = time.time() - self._start_time
        logger.info(
            f"Scan complete: {self._files_scanned} files scanned, "
            f"{self._files_skipped} skipped, {len(all_findings)} findings"
            + (" (cancelled)" if self.is_cancelled else "")
        )

        return ScanResult(
            target_path=str(self.config.target_path),
            findings=all_findings,
            scan_duration=scan_duration,
            stats={
                "files_discovered": len(files),
                "files_scanned": self._files_scanned,
                "files_skipped": self._files_skipped,
                "bytes_processed": self._bytes_processed,
                "total_findings": len(all_findings),
                "cancelled": self.is_cancelled,
                "errors": self._errors,
            },
        )

    async def scan_stream(self) -> AsyncIterator[Finding]:
        """Execute the scan and stream findings as they're discovered.

        This is an async generator that yields findings as they're found,
        allowing for real-time processing of results.

        Yields:
            Finding objects as they're discovered during the scan.

        Raises:
            ScanError: If the target path does not exist.
        """
        self.reset()
        self._start_time = time.time()

        # Discover files to scan
        files = await self._discover_files()
        self._total_files = len(files)
        logger.info(f"Found {len(files)} files to scan")

        # Initial progress report
        self._report_progress()

        if not files or self.is_cancelled:
            return

        # Create a queue for streaming findings
        findings_queue: asyncio.Queue[Finding | None] = asyncio.Queue()

        async def scan_and_queue(file_path: Path) -> None:
            """Scan a file and put findings in the queue."""
            findings = await self._scan_file(file_path)
            for finding in findings:
                await findings_queue.put(finding)

        async def scan_all_files() -> None:
            """Scan all files and signal completion."""
            tasks = [scan_and_queue(f) for f in files]
            await asyncio.gather(*tasks)
            await findings_queue.put(None)  # Signal completion

        # Start scanning in background
        scan_task = asyncio.create_task(scan_all_files())

        try:
            while True:
                finding = await findings_queue.get()
                if finding is None:
                    break
                yield finding
        finally:
            # Ensure scan task is completed or cancelled
            if not scan_task.done():
                scan_task.cancel()
                try:
                    await scan_task
                except asyncio.CancelledError:
                    pass

        scan_duration = time.time() - self._start_time
        logger.info(
            f"Stream scan complete: {self._files_scanned} files scanned, "
            f"{self._files_skipped} skipped, {self._findings_count} findings"
            + (" (cancelled)" if self.is_cancelled else "")
        )

    def get_stats(self) -> dict:
        """Get current scan statistics.

        Returns:
            Dictionary with current scan statistics.
        """
        return {
            "total_files": self._total_files,
            "files_scanned": self._files_scanned,
            "files_skipped": self._files_skipped,
            "bytes_processed": self._bytes_processed,
            "findings_count": self._findings_count,
            "elapsed_time": time.time() - self._start_time if self._start_time else 0.0,
            "cancelled": self.is_cancelled,
            "errors": self._errors,
        }
