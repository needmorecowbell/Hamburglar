"""Progress tracking module for Hamburglar.

This module provides the ScanProgress dataclass for tracking scan progress
and the ProgressReporter protocol for pluggable progress reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from typing import Any


@dataclass
class ScanProgress:
    """Dataclass tracking scan progress information.

    This dataclass encapsulates all the information needed to track
    and report progress during a file scan operation.

    Attributes:
        total_files: Total number of files to scan.
        scanned_files: Number of files already scanned.
        current_file: Path of the file currently being scanned.
        bytes_processed: Total bytes processed so far.
        findings_count: Number of findings discovered so far.
        elapsed_time: Time elapsed since scan started (in seconds).
        files_remaining: Number of files yet to be scanned (computed automatically).

    Example:
        >>> progress = ScanProgress(
        ...     total_files=100,
        ...     scanned_files=25,
        ...     current_file="/path/to/file.txt",
        ...     bytes_processed=1024000,
        ...     findings_count=5,
        ...     elapsed_time=2.5,
        ... )
        >>> progress.files_remaining
        75
        >>> progress.percent_complete
        25.0
        >>> progress.files_per_second
        10.0
    """

    total_files: int = 0
    scanned_files: int = 0
    current_file: str = ""
    bytes_processed: int = 0
    findings_count: int = 0
    elapsed_time: float = 0.0
    files_remaining: int = field(init=False)

    def __post_init__(self) -> None:
        """Calculate derived fields after initialization."""
        self.files_remaining = self.total_files - self.scanned_files

    @property
    def percent_complete(self) -> float:
        """Calculate the percentage of files scanned.

        Returns:
            Percentage of files scanned (0-100), or 0.0 if no files to scan.
        """
        if self.total_files == 0:
            return 0.0
        return (self.scanned_files / self.total_files) * 100.0

    @property
    def files_per_second(self) -> float:
        """Calculate the scan throughput in files per second.

        Returns:
            Files scanned per second, or 0.0 if no time has elapsed.
        """
        if self.elapsed_time <= 0:
            return 0.0
        return self.scanned_files / self.elapsed_time

    @property
    def bytes_per_second(self) -> float:
        """Calculate the data throughput in bytes per second.

        Returns:
            Bytes processed per second, or 0.0 if no time has elapsed.
        """
        if self.elapsed_time <= 0:
            return 0.0
        return self.bytes_processed / self.elapsed_time

    @property
    def estimated_time_remaining(self) -> float | None:
        """Estimate the remaining time to complete the scan.

        Returns:
            Estimated seconds remaining, or None if cannot be estimated
            (e.g., no files scanned yet or no files remaining).
        """
        if self.scanned_files == 0 or self.files_remaining == 0:
            return None
        time_per_file = self.elapsed_time / self.scanned_files
        return time_per_file * self.files_remaining

    def to_dict(self) -> dict[str, Any]:
        """Convert progress to a dictionary.

        Returns:
            Dictionary representation of the progress state.
        """
        return {
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "current_file": self.current_file,
            "bytes_processed": self.bytes_processed,
            "findings_count": self.findings_count,
            "elapsed_time": self.elapsed_time,
            "files_remaining": self.files_remaining,
            "percent_complete": self.percent_complete,
            "files_per_second": self.files_per_second,
            "bytes_per_second": self.bytes_per_second,
            "estimated_time_remaining": self.estimated_time_remaining,
        }


@runtime_checkable
class ProgressReporter(Protocol):
    """Protocol for pluggable progress reporting.

    Implementations of this protocol can be used to report scan progress
    to various destinations such as console, file, or network endpoints.

    This protocol enables decoupling the scanner from specific progress
    reporting implementations, allowing for flexible and extensible
    progress reporting strategies.

    Example implementation:
        >>> class ConsoleProgressReporter:
        ...     def on_progress(self, progress: ScanProgress) -> None:
        ...         print(f"Scanned {progress.scanned_files}/{progress.total_files}")
        ...
        ...     def on_start(self, total_files: int) -> None:
        ...         print(f"Starting scan of {total_files} files")
        ...
        ...     def on_complete(self, progress: ScanProgress) -> None:
        ...         print(f"Scan complete: {progress.findings_count} findings")
        ...
        ...     def on_error(self, error: str, file_path: str | None = None) -> None:
        ...         print(f"Error: {error}")
    """

    def on_progress(self, progress: ScanProgress) -> None:
        """Called when scan progress is updated.

        This method is called periodically during the scan to report
        the current progress state.

        Args:
            progress: Current scan progress state.
        """
        ...

    def on_start(self, total_files: int) -> None:
        """Called when a scan is starting.

        Args:
            total_files: Total number of files to be scanned.
        """
        ...

    def on_complete(self, progress: ScanProgress) -> None:
        """Called when a scan is complete.

        Args:
            progress: Final scan progress state.
        """
        ...

    def on_error(self, error: str, file_path: str | None = None) -> None:
        """Called when an error occurs during scanning.

        Args:
            error: Error message describing what went wrong.
            file_path: Optional path to the file that caused the error.
        """
        ...


class NullProgressReporter:
    """A no-op progress reporter that ignores all progress updates.

    This is useful as a default when no progress reporting is needed,
    avoiding None checks throughout the code.
    """

    def on_progress(self, progress: ScanProgress) -> None:
        """Ignore progress updates."""
        pass

    def on_start(self, total_files: int) -> None:
        """Ignore start notification."""
        pass

    def on_complete(self, progress: ScanProgress) -> None:
        """Ignore complete notification."""
        pass

    def on_error(self, error: str, file_path: str | None = None) -> None:
        """Ignore error notification."""
        pass


class CallbackProgressReporter:
    """A progress reporter that delegates to a callback function.

    This provides backward compatibility with the existing callback-based
    progress reporting in AsyncScanner.

    Example:
        >>> def my_callback(progress: ScanProgress) -> None:
        ...     print(f"Progress: {progress.percent_complete:.1f}%")
        ...
        >>> reporter = CallbackProgressReporter(my_callback)
        >>> reporter.on_progress(ScanProgress(total_files=100, scanned_files=50))
        Progress: 50.0%
    """

    def __init__(
        self,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        start_callback: Callable[[int], None] | None = None,
        complete_callback: Callable[[ScanProgress], None] | None = None,
        error_callback: Callable[[str, str | None], None] | None = None,
    ) -> None:
        """Initialize the callback progress reporter.

        Args:
            progress_callback: Called for progress updates.
            start_callback: Called when scan starts.
            complete_callback: Called when scan completes.
            error_callback: Called on errors.
        """
        self._progress_callback = progress_callback
        self._start_callback = start_callback
        self._complete_callback = complete_callback
        self._error_callback = error_callback

    def on_progress(self, progress: ScanProgress) -> None:
        """Call the progress callback if set."""
        if self._progress_callback is not None:
            self._progress_callback(progress)

    def on_start(self, total_files: int) -> None:
        """Call the start callback if set."""
        if self._start_callback is not None:
            self._start_callback(total_files)

    def on_complete(self, progress: ScanProgress) -> None:
        """Call the complete callback if set."""
        if self._complete_callback is not None:
            self._complete_callback(progress)

    def on_error(self, error: str, file_path: str | None = None) -> None:
        """Call the error callback if set."""
        if self._error_callback is not None:
            self._error_callback(error, file_path)


# Import Callable here to avoid circular imports and TYPE_CHECKING issues
from typing import Callable  # noqa: E402
