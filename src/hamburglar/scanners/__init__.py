"""Scanner module for Hamburglar.

This module provides the base scanner interface and implementations for various
scanning modes including directory scanning, git repository scanning, and web
URL scanning.

The BaseScanner abstract class defines the common interface that all scanners
must implement, including async scan() method and scanner_type property.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Callable

from hamburglar.core.models import Finding, ScanResult
from hamburglar.core.progress import ScanProgress

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

# Type alias for progress callback
ProgressCallback = Callable[[ScanProgress], None]


class BaseScanner(ABC):
    """Abstract base class for all scanner implementations.

    This class defines the interface that all scanners must implement.
    Scanners are responsible for discovering content from various sources
    (directories, git repositories, URLs) and passing that content through
    detectors to find sensitive information.

    Attributes:
        detectors: List of detector instances to use for scanning.
        progress_callback: Optional callback for reporting scan progress.
    """

    def __init__(
        self,
        detectors: list["BaseDetector"] | None = None,
        progress_callback: ProgressCallback | None = None,
    ):
        """Initialize the base scanner.

        Args:
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
            progress_callback: Optional callback function for progress updates.
                              Called with a ScanProgress dataclass.
        """
        self.detectors = detectors or []
        self.progress_callback = progress_callback

    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Return the type identifier for this scanner.

        Returns:
            A string identifier for the scanner type (e.g., "directory", "git", "web").
        """

    @abstractmethod
    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        This method should discover content from the scanner's source,
        pass it through all registered detectors, and return the results.

        Returns:
            ScanResult containing all findings and scan statistics.

        Raises:
            ScanError: If there's an error during the scan.
        """

    async def scan_stream(self) -> AsyncIterator[Finding]:
        """Execute the scan and stream findings as they're discovered.

        This is an optional async generator that yields findings as they're
        found, allowing for real-time processing of results. Subclasses may
        override this method to provide streaming support.

        The default implementation falls back to the regular scan() method
        and yields all findings at once.

        Yields:
            Finding objects as they're discovered during the scan.

        Raises:
            ScanError: If there's an error during the scan.
        """
        result = await self.scan()
        for finding in result.findings:
            yield finding

    def cancel(self) -> None:
        """Request cancellation of the ongoing scan.

        Subclasses should implement this to support scan cancellation.
        The default implementation does nothing.
        """

    @property
    def is_cancelled(self) -> bool:
        """Check if the scan has been cancelled.

        Returns:
            True if cancellation has been requested, False otherwise.
            Default implementation always returns False.
        """
        return False

    def _report_progress(self, progress: ScanProgress) -> None:
        """Report progress via callback if one is configured.

        Args:
            progress: The current scan progress to report.
        """
        if self.progress_callback is not None:
            try:
                self.progress_callback(progress)
            except Exception:
                # Don't let callback errors disrupt the scan
                pass


from hamburglar.scanners.directory import DirectoryScanner
from hamburglar.scanners.git import GitScanner
from hamburglar.scanners.git_history import GitHistoryScanner
from hamburglar.scanners.web import WebScanner

__all__ = [
    "BaseScanner",
    "DirectoryScanner",
    "GitScanner",
    "GitHistoryScanner",
    "ProgressCallback",
    "WebScanner",
]
