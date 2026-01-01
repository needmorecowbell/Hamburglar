"""Scan statistics module for Hamburglar.

This module provides the ScanStats class for comprehensive scan statistics
tracking, including file counts, byte processing, timing, and findings
categorization by detector and severity.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hamburglar.core.models import Finding


class SkipReason(str, Enum):
    """Reasons why a file may be skipped during scanning."""

    PERMISSION_DENIED = "permission_denied"
    FILE_NOT_FOUND = "file_not_found"
    READ_ERROR = "read_error"
    BLACKLISTED = "blacklisted"
    NOT_WHITELISTED = "not_whitelisted"
    BINARY_FILE = "binary_file"
    TOO_LARGE = "too_large"
    ENCODING_ERROR = "encoding_error"
    DETECTOR_ERROR = "detector_error"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass
class SkippedFile:
    """Information about a skipped file.

    Attributes:
        file_path: Path to the file that was skipped.
        reason: Reason the file was skipped.
        detail: Optional additional detail about why the file was skipped.
    """

    file_path: str
    reason: SkipReason
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with file path, reason, and optional detail.
        """
        result: dict[str, Any] = {
            "file_path": self.file_path,
            "reason": self.reason.value,
        }
        if self.detail:
            result["detail"] = self.detail
        return result


@dataclass
class ScanStats:
    """Comprehensive scan statistics tracking.

    This dataclass tracks all relevant statistics during a scan operation,
    including file counts, bytes processed, timing information, and
    findings categorized by detector and severity.

    Attributes:
        total_files_discovered: Total number of files discovered for scanning.
        total_files_scanned: Number of files successfully scanned.
        total_bytes_processed: Total bytes of file content processed.
        skipped_files: List of files that were skipped with reasons.
        findings_by_detector: Counter of findings grouped by detector name.
        findings_by_severity: Counter of findings grouped by severity level.
        scan_start_time: Unix timestamp when the scan started.
        scan_end_time: Unix timestamp when the scan ended (None if ongoing).
        errors: List of error messages encountered during scan.

    Example:
        >>> stats = ScanStats()
        >>> stats.start()
        >>> stats.add_scanned_file("/path/to/file.py", 1024)
        >>> stats.add_finding("RegexDetector", "high")
        >>> stats.stop()
        >>> stats.files_per_second
        1000.0  # example value
    """

    total_files_discovered: int = 0
    total_files_scanned: int = 0
    total_bytes_processed: int = 0
    skipped_files: list[SkippedFile] = field(default_factory=list)
    findings_by_detector: Counter[str] = field(default_factory=Counter)
    findings_by_severity: Counter[str] = field(default_factory=Counter)
    scan_start_time: float | None = None
    scan_end_time: float | None = None
    errors: list[str] = field(default_factory=list)

    # Private tracking for internal state
    _total_findings: int = field(default=0, init=False, repr=False)

    def start(self) -> None:
        """Mark the start of the scan.

        Records the current timestamp as the scan start time.
        """
        self.scan_start_time = time.time()
        self.scan_end_time = None

    def stop(self) -> None:
        """Mark the end of the scan.

        Records the current timestamp as the scan end time.
        """
        self.scan_end_time = time.time()

    def reset(self) -> None:
        """Reset all statistics to their initial state.

        Clears all counters, lists, and timing information.
        """
        self.total_files_discovered = 0
        self.total_files_scanned = 0
        self.total_bytes_processed = 0
        self.skipped_files = []
        self.findings_by_detector = Counter()
        self.findings_by_severity = Counter()
        self.scan_start_time = None
        self.scan_end_time = None
        self.errors = []
        self._total_findings = 0

    def set_discovered_files(self, count: int) -> None:
        """Set the total number of files discovered.

        Args:
            count: Number of files discovered for scanning.
        """
        self.total_files_discovered = count

    def add_scanned_file(self, file_path: str, bytes_count: int) -> None:
        """Record a successfully scanned file.

        Args:
            file_path: Path to the file that was scanned.
            bytes_count: Number of bytes processed from the file.
        """
        self.total_files_scanned += 1
        self.total_bytes_processed += bytes_count

    def add_skipped_file(
        self,
        file_path: str,
        reason: SkipReason,
        detail: str | None = None,
    ) -> None:
        """Record a skipped file with reason.

        Args:
            file_path: Path to the file that was skipped.
            reason: Reason the file was skipped.
            detail: Optional additional detail about why the file was skipped.
        """
        self.skipped_files.append(SkippedFile(file_path, reason, detail))

    def add_finding(
        self,
        detector_name: str,
        severity: str | None = None,
    ) -> None:
        """Record a finding from a detector.

        Args:
            detector_name: Name of the detector that found the match.
            severity: Severity level of the finding (e.g., "high", "critical").
        """
        self._total_findings += 1
        self.findings_by_detector[detector_name] += 1
        if severity:
            self.findings_by_severity[severity] += 1

    def add_findings(self, findings: list[Finding]) -> None:
        """Record multiple findings at once.

        Args:
            findings: List of Finding objects to record.
        """
        for finding in findings:
            self.add_finding(
                finding.detector_name,
                finding.severity.value if finding.severity else None,
            )

    def add_error(self, error: str) -> None:
        """Record an error that occurred during scanning.

        Args:
            error: Error message to record.
        """
        self.errors.append(error)

    @property
    def scan_duration(self) -> float:
        """Calculate the scan duration in seconds.

        Returns:
            Duration in seconds, or 0.0 if scan hasn't started.
            If scan is ongoing, returns elapsed time so far.
        """
        if self.scan_start_time is None:
            return 0.0
        end_time = self.scan_end_time if self.scan_end_time is not None else time.time()
        return end_time - self.scan_start_time

    @property
    def files_per_second(self) -> float:
        """Calculate the file scanning throughput.

        Returns:
            Files scanned per second, or 0.0 if no time has elapsed.
        """
        duration = self.scan_duration
        if duration <= 0:
            return 0.0
        return self.total_files_scanned / duration

    @property
    def bytes_per_second(self) -> float:
        """Calculate the byte processing throughput.

        Returns:
            Bytes processed per second, or 0.0 if no time has elapsed.
        """
        duration = self.scan_duration
        if duration <= 0:
            return 0.0
        return self.total_bytes_processed / duration

    @property
    def total_files_skipped(self) -> int:
        """Get the total number of skipped files.

        Returns:
            Number of files that were skipped.
        """
        return len(self.skipped_files)

    @property
    def total_findings(self) -> int:
        """Get the total number of findings.

        Returns:
            Total count of all findings across all detectors.
        """
        return self._total_findings

    @property
    def skipped_by_reason(self) -> Counter[str]:
        """Get counts of skipped files grouped by reason.

        Returns:
            Counter mapping reason values to counts.
        """
        counter: Counter[str] = Counter()
        for skipped in self.skipped_files:
            counter[skipped.reason.value] += 1
        return counter

    @property
    def is_running(self) -> bool:
        """Check if the scan is currently running.

        Returns:
            True if scan has started but not ended, False otherwise.
        """
        return self.scan_start_time is not None and self.scan_end_time is None

    @property
    def is_complete(self) -> bool:
        """Check if the scan has completed.

        Returns:
            True if scan has both started and ended, False otherwise.
        """
        return self.scan_start_time is not None and self.scan_end_time is not None

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of key statistics.

        Returns:
            Dictionary with the most important scan statistics.
        """
        return {
            "total_files_discovered": self.total_files_discovered,
            "total_files_scanned": self.total_files_scanned,
            "total_files_skipped": self.total_files_skipped,
            "total_bytes_processed": self.total_bytes_processed,
            "total_findings": self.total_findings,
            "scan_duration": self.scan_duration,
            "files_per_second": self.files_per_second,
            "bytes_per_second": self.bytes_per_second,
            "error_count": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert all statistics to a dictionary.

        Returns:
            Complete dictionary representation of all statistics.
        """
        return {
            "total_files_discovered": self.total_files_discovered,
            "total_files_scanned": self.total_files_scanned,
            "total_files_skipped": self.total_files_skipped,
            "total_bytes_processed": self.total_bytes_processed,
            "skipped_files": [sf.to_dict() for sf in self.skipped_files],
            "skipped_by_reason": dict(self.skipped_by_reason),
            "findings_by_detector": dict(self.findings_by_detector),
            "findings_by_severity": dict(self.findings_by_severity),
            "total_findings": self.total_findings,
            "scan_start_time": self.scan_start_time,
            "scan_end_time": self.scan_end_time,
            "scan_duration": self.scan_duration,
            "files_per_second": self.files_per_second,
            "bytes_per_second": self.bytes_per_second,
            "is_running": self.is_running,
            "is_complete": self.is_complete,
            "errors": self.errors,
        }

    def merge(self, other: ScanStats) -> None:
        """Merge statistics from another ScanStats instance.

        This is useful for aggregating statistics from parallel scans.
        Note: Timing information is not merged - use the master instance's
        timing for overall duration.

        Args:
            other: Another ScanStats instance to merge in.
        """
        self.total_files_discovered += other.total_files_discovered
        self.total_files_scanned += other.total_files_scanned
        self.total_bytes_processed += other.total_bytes_processed
        self.skipped_files.extend(other.skipped_files)
        self.findings_by_detector.update(other.findings_by_detector)
        self.findings_by_severity.update(other.findings_by_severity)
        self._total_findings += other._total_findings
        self.errors.extend(other.errors)

    def __add__(self, other: ScanStats) -> ScanStats:
        """Combine two ScanStats instances into a new one.

        Creates a new ScanStats with combined counts from both instances.
        The timing information comes from self.

        Args:
            other: Another ScanStats instance to combine with.

        Returns:
            New ScanStats instance with combined statistics.
        """
        result = ScanStats(
            total_files_discovered=self.total_files_discovered + other.total_files_discovered,
            total_files_scanned=self.total_files_scanned + other.total_files_scanned,
            total_bytes_processed=self.total_bytes_processed + other.total_bytes_processed,
            skipped_files=self.skipped_files + other.skipped_files,
            findings_by_detector=self.findings_by_detector + other.findings_by_detector,
            findings_by_severity=self.findings_by_severity + other.findings_by_severity,
            scan_start_time=self.scan_start_time,
            scan_end_time=self.scan_end_time,
            errors=self.errors + other.errors,
        )
        result._total_findings = self._total_findings + other._total_findings
        return result

    def format_duration(self) -> str:
        """Format the scan duration as a human-readable string.

        Returns:
            Formatted duration string (e.g., "1m 30.5s" or "45.2s").
        """
        duration = self.scan_duration
        if duration >= 60:
            minutes = int(duration // 60)
            seconds = duration % 60
            return f"{minutes}m {seconds:.1f}s"
        return f"{duration:.2f}s"

    def format_bytes(self, byte_count: int | None = None) -> str:
        """Format bytes as a human-readable string.

        Args:
            byte_count: Number of bytes to format. If None, uses
                       total_bytes_processed.

        Returns:
            Formatted byte string (e.g., "1.5 MB", "256 KB").
        """
        if byte_count is None:
            byte_count = self.total_bytes_processed

        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.1f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"

    def format_throughput(self) -> str:
        """Format the throughput as a human-readable string.

        Returns:
            Formatted throughput string (e.g., "150 files/s, 2.5 MB/s").
        """
        fps = self.files_per_second
        bps = self.bytes_per_second
        return f"{fps:.1f} files/s, {self.format_bytes(int(bps))}/s"

    def __str__(self) -> str:
        """Return a human-readable summary string.

        Returns:
            Multi-line summary of scan statistics.
        """
        lines = [
            "Scan Statistics:",
            f"  Files: {self.total_files_scanned}/{self.total_files_discovered} scanned "
            f"({self.total_files_skipped} skipped)",
            f"  Bytes: {self.format_bytes()}",
            f"  Findings: {self.total_findings}",
            f"  Duration: {self.format_duration()}",
            f"  Throughput: {self.format_throughput()}",
        ]
        if self.errors:
            lines.append(f"  Errors: {len(self.errors)}")
        return "\n".join(lines)
