"""Memory profiling and performance tracking module for Hamburglar.

This module provides utilities for optional memory tracking, peak memory usage
reporting, per-detector timing statistics, and exportable performance reports.
"""

from __future__ import annotations

import gc
import os
import sys
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Generator, TypeVar

if TYPE_CHECKING:
    pass

# Check if psutil is available for memory tracking
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None  # type: ignore[assignment]


@dataclass
class MemorySnapshot:
    """A snapshot of memory usage at a point in time.

    Attributes:
        timestamp: Unix timestamp when the snapshot was taken.
        rss_bytes: Resident Set Size (physical memory) in bytes.
        vms_bytes: Virtual Memory Size in bytes.
        percent: Percentage of system memory used by this process.
        label: Optional label describing what was happening when snapshot was taken.
    """

    timestamp: float
    rss_bytes: int
    vms_bytes: int
    percent: float
    label: str = ""

    @classmethod
    def take(cls, label: str = "") -> "MemorySnapshot":
        """Take a memory snapshot of the current process.

        Args:
            label: Optional label for the snapshot.

        Returns:
            MemorySnapshot with current memory usage, or zeros if psutil unavailable.
        """
        timestamp = time.time()
        if PSUTIL_AVAILABLE:
            process = psutil.Process(os.getpid())
            mem_info = process.memory_info()
            mem_percent = process.memory_percent()
            return cls(
                timestamp=timestamp,
                rss_bytes=mem_info.rss,
                vms_bytes=mem_info.vms,
                percent=mem_percent,
                label=label,
            )
        return cls(
            timestamp=timestamp,
            rss_bytes=0,
            vms_bytes=0,
            percent=0.0,
            label=label,
        )

    def format_rss(self) -> str:
        """Format RSS memory as a human-readable string.

        Returns:
            Formatted memory string (e.g., "150.5 MB").
        """
        return format_bytes(self.rss_bytes)

    def format_vms(self) -> str:
        """Format VMS memory as a human-readable string.

        Returns:
            Formatted memory string (e.g., "300.2 MB").
        """
        return format_bytes(self.vms_bytes)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all snapshot fields.
        """
        return {
            "timestamp": self.timestamp,
            "rss_bytes": self.rss_bytes,
            "vms_bytes": self.vms_bytes,
            "percent": self.percent,
            "label": self.label,
        }


@dataclass
class TimingStats:
    """Statistics for timed operations.

    Tracks execution counts, total time, min/max/average duration.

    Attributes:
        name: Name of the operation being timed.
        total_time: Total time spent in this operation (seconds).
        call_count: Number of times the operation was called.
        min_time: Minimum duration of a single call (seconds).
        max_time: Maximum duration of a single call (seconds).
    """

    name: str
    total_time: float = 0.0
    call_count: int = 0
    min_time: float = float("inf")
    max_time: float = 0.0

    def record(self, duration: float) -> None:
        """Record a timing measurement.

        Args:
            duration: Duration of the operation in seconds.
        """
        self.call_count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)

    @property
    def avg_time(self) -> float:
        """Calculate average time per call.

        Returns:
            Average duration in seconds, or 0.0 if no calls recorded.
        """
        if self.call_count == 0:
            return 0.0
        return self.total_time / self.call_count

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all timing statistics.
        """
        return {
            "name": self.name,
            "total_time": self.total_time,
            "call_count": self.call_count,
            "min_time": self.min_time if self.call_count > 0 else 0.0,
            "max_time": self.max_time,
            "avg_time": self.avg_time,
        }

    def __str__(self) -> str:
        """Return a human-readable summary.

        Returns:
            Formatted timing statistics string.
        """
        if self.call_count == 0:
            return f"{self.name}: no calls"
        return (
            f"{self.name}: {self.call_count} calls, "
            f"total={self.total_time:.3f}s, "
            f"avg={self.avg_time * 1000:.2f}ms, "
            f"min={self.min_time * 1000:.2f}ms, "
            f"max={self.max_time * 1000:.2f}ms"
        )


@dataclass
class DetectorTimingStats:
    """Per-detector timing statistics.

    Tracks detection time for each detector separately, plus aggregated stats.

    Attributes:
        detector_name: Name of the detector.
        detect_time: Timing stats for the detect() method.
        files_processed: Number of files processed by this detector.
        findings_count: Number of findings produced by this detector.
    """

    detector_name: str
    detect_time: TimingStats = field(init=False)
    files_processed: int = 0
    findings_count: int = 0

    def __post_init__(self) -> None:
        """Initialize the detect_time stats."""
        self.detect_time = TimingStats(name=f"{self.detector_name}.detect")

    def record_detection(
        self, duration: float, findings: int = 0
    ) -> None:
        """Record a detection operation.

        Args:
            duration: Time taken for detection in seconds.
            findings: Number of findings from this detection.
        """
        self.detect_time.record(duration)
        self.files_processed += 1
        self.findings_count += findings

    @property
    def avg_time_per_file(self) -> float:
        """Calculate average detection time per file.

        Returns:
            Average time in seconds per file, or 0.0 if no files processed.
        """
        return self.detect_time.avg_time

    @property
    def findings_per_file(self) -> float:
        """Calculate average findings per file.

        Returns:
            Average findings per file, or 0.0 if no files processed.
        """
        if self.files_processed == 0:
            return 0.0
        return self.findings_count / self.files_processed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary with all detector timing statistics.
        """
        return {
            "detector_name": self.detector_name,
            "files_processed": self.files_processed,
            "findings_count": self.findings_count,
            "findings_per_file": self.findings_per_file,
            "timing": self.detect_time.to_dict(),
        }

    def __str__(self) -> str:
        """Return a human-readable summary.

        Returns:
            Formatted detector timing string.
        """
        return (
            f"{self.detector_name}: "
            f"{self.files_processed} files, "
            f"{self.findings_count} findings, "
            f"{self.detect_time.avg_time * 1000:.2f}ms avg"
        )


class MemoryProfiler:
    """Memory profiler for tracking memory usage during scans.

    This class provides optional memory tracking capabilities including
    snapshots, peak memory detection, and memory delta reporting.

    Example:
        >>> profiler = MemoryProfiler(enabled=True)
        >>> profiler.start()
        >>> # ... do work ...
        >>> profiler.snapshot("after processing")
        >>> profiler.stop()
        >>> print(profiler.peak_memory_rss)
        157286400
    """

    def __init__(self, enabled: bool = True) -> None:
        """Initialize the memory profiler.

        Args:
            enabled: Whether memory tracking is enabled.
                    If psutil is not available, tracking is disabled regardless.
        """
        self._enabled = enabled and PSUTIL_AVAILABLE
        self._snapshots: list[MemorySnapshot] = []
        self._start_snapshot: MemorySnapshot | None = None
        self._end_snapshot: MemorySnapshot | None = None
        self._peak_rss: int = 0
        self._peak_vms: int = 0
        self._is_running = False

    @property
    def enabled(self) -> bool:
        """Check if memory tracking is enabled.

        Returns:
            True if tracking is enabled and psutil is available.
        """
        return self._enabled

    @property
    def is_running(self) -> bool:
        """Check if profiling is currently running.

        Returns:
            True if start() was called but stop() hasn't been called.
        """
        return self._is_running

    @property
    def snapshots(self) -> list[MemorySnapshot]:
        """Get all recorded snapshots.

        Returns:
            List of memory snapshots taken during profiling.
        """
        return self._snapshots.copy()

    @property
    def peak_memory_rss(self) -> int:
        """Get peak RSS (physical) memory usage in bytes.

        Returns:
            Peak RSS in bytes, or 0 if tracking is disabled.
        """
        return self._peak_rss

    @property
    def peak_memory_vms(self) -> int:
        """Get peak VMS (virtual) memory usage in bytes.

        Returns:
            Peak VMS in bytes, or 0 if tracking is disabled.
        """
        return self._peak_vms

    @property
    def memory_delta_rss(self) -> int:
        """Get the change in RSS memory from start to end.

        Returns:
            Bytes difference between end and start RSS, or 0 if not complete.
        """
        if self._start_snapshot is None or self._end_snapshot is None:
            return 0
        return self._end_snapshot.rss_bytes - self._start_snapshot.rss_bytes

    @property
    def memory_delta_vms(self) -> int:
        """Get the change in VMS memory from start to end.

        Returns:
            Bytes difference between end and start VMS, or 0 if not complete.
        """
        if self._start_snapshot is None or self._end_snapshot is None:
            return 0
        return self._end_snapshot.vms_bytes - self._start_snapshot.vms_bytes

    def start(self) -> None:
        """Start memory profiling.

        Takes an initial snapshot and begins tracking peak memory.
        """
        if not self._enabled:
            return

        self._snapshots = []
        self._start_snapshot = MemorySnapshot.take("start")
        self._end_snapshot = None
        self._peak_rss = self._start_snapshot.rss_bytes
        self._peak_vms = self._start_snapshot.vms_bytes
        self._snapshots.append(self._start_snapshot)
        self._is_running = True

    def stop(self) -> None:
        """Stop memory profiling.

        Takes a final snapshot and updates peak memory.
        """
        if not self._enabled or not self._is_running:
            return

        self._end_snapshot = MemorySnapshot.take("end")
        self._snapshots.append(self._end_snapshot)
        self._update_peak(self._end_snapshot)
        self._is_running = False

    def snapshot(self, label: str = "") -> MemorySnapshot | None:
        """Take a memory snapshot.

        Args:
            label: Optional label for the snapshot.

        Returns:
            The snapshot taken, or None if tracking is disabled.
        """
        if not self._enabled:
            return None

        snap = MemorySnapshot.take(label)
        self._snapshots.append(snap)
        self._update_peak(snap)
        return snap

    def _update_peak(self, snap: MemorySnapshot) -> None:
        """Update peak memory values from a snapshot.

        Args:
            snap: Memory snapshot to check for new peaks.
        """
        if snap.rss_bytes > self._peak_rss:
            self._peak_rss = snap.rss_bytes
        if snap.vms_bytes > self._peak_vms:
            self._peak_vms = snap.vms_bytes

    def get_report(self) -> dict[str, Any]:
        """Get a memory profiling report.

        Returns:
            Dictionary with memory profiling results.
        """
        return {
            "enabled": self._enabled,
            "is_running": self._is_running,
            "peak_rss_bytes": self._peak_rss,
            "peak_rss_formatted": format_bytes(self._peak_rss),
            "peak_vms_bytes": self._peak_vms,
            "peak_vms_formatted": format_bytes(self._peak_vms),
            "memory_delta_rss_bytes": self.memory_delta_rss,
            "memory_delta_rss_formatted": format_bytes(abs(self.memory_delta_rss)),
            "memory_delta_vms_bytes": self.memory_delta_vms,
            "snapshot_count": len(self._snapshots),
            "snapshots": [s.to_dict() for s in self._snapshots],
        }

    def reset(self) -> None:
        """Reset the profiler state.

        Clears all snapshots and peak values.
        """
        self._snapshots = []
        self._start_snapshot = None
        self._end_snapshot = None
        self._peak_rss = 0
        self._peak_vms = 0
        self._is_running = False


@dataclass
class PerformanceReport:
    """Comprehensive performance report for a scan operation.

    Aggregates memory profiling, detector timing stats, and overall metrics.

    Attributes:
        start_time: Unix timestamp when the operation started.
        end_time: Unix timestamp when the operation ended.
        total_files: Total number of files processed.
        total_bytes: Total bytes processed.
        memory_profiler: Memory profiler with memory stats.
        detector_stats: Per-detector timing statistics.
        custom_timings: Additional custom timing measurements.
    """

    start_time: float = 0.0
    end_time: float = 0.0
    total_files: int = 0
    total_bytes: int = 0
    memory_profiler: MemoryProfiler = field(default_factory=lambda: MemoryProfiler(enabled=False))
    detector_stats: dict[str, DetectorTimingStats] = field(default_factory=dict)
    custom_timings: dict[str, TimingStats] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Get total operation duration in seconds.

        Returns:
            Duration in seconds, or 0 if not completed.
        """
        if self.end_time == 0.0 or self.start_time == 0.0:
            return 0.0
        return self.end_time - self.start_time

    @property
    def files_per_second(self) -> float:
        """Calculate file processing throughput.

        Returns:
            Files per second, or 0 if no time elapsed.
        """
        if self.duration <= 0:
            return 0.0
        return self.total_files / self.duration

    @property
    def bytes_per_second(self) -> float:
        """Calculate byte processing throughput.

        Returns:
            Bytes per second, or 0 if no time elapsed.
        """
        if self.duration <= 0:
            return 0.0
        return self.total_bytes / self.duration

    def start(self) -> None:
        """Start the performance report timing."""
        self.start_time = time.time()
        self.memory_profiler.start()

    def stop(self) -> None:
        """Stop the performance report timing."""
        self.end_time = time.time()
        self.memory_profiler.stop()

    def add_detector_timing(
        self,
        detector_name: str,
        duration: float,
        findings: int = 0,
    ) -> None:
        """Record timing for a detector.

        Args:
            detector_name: Name of the detector.
            duration: Time taken for detection in seconds.
            findings: Number of findings from this detection.
        """
        if detector_name not in self.detector_stats:
            self.detector_stats[detector_name] = DetectorTimingStats(detector_name)
        self.detector_stats[detector_name].record_detection(duration, findings)

    def add_custom_timing(self, name: str, duration: float) -> None:
        """Record a custom timing measurement.

        Args:
            name: Name of the operation.
            duration: Time taken in seconds.
        """
        if name not in self.custom_timings:
            self.custom_timings[name] = TimingStats(name)
        self.custom_timings[name].record(duration)

    def get_detector_timing(self, detector_name: str) -> DetectorTimingStats | None:
        """Get timing stats for a specific detector.

        Args:
            detector_name: Name of the detector.

        Returns:
            DetectorTimingStats or None if not found.
        """
        return self.detector_stats.get(detector_name)

    def to_dict(self) -> dict[str, Any]:
        """Export the performance report as a dictionary.

        Returns:
            Complete dictionary representation of the performance report.
        """
        return {
            "summary": {
                "start_time": self.start_time,
                "end_time": self.end_time,
                "duration_seconds": self.duration,
                "total_files": self.total_files,
                "total_bytes": self.total_bytes,
                "files_per_second": self.files_per_second,
                "bytes_per_second": self.bytes_per_second,
                "bytes_per_second_formatted": format_bytes(int(self.bytes_per_second)) + "/s",
            },
            "memory": self.memory_profiler.get_report(),
            "detectors": {
                name: stats.to_dict()
                for name, stats in self.detector_stats.items()
            },
            "custom_timings": {
                name: stats.to_dict()
                for name, stats in self.custom_timings.items()
            },
        }

    def to_json(self) -> str:
        """Export the performance report as JSON.

        Returns:
            JSON string representation of the report.
        """
        import json

        return json.dumps(self.to_dict(), indent=2)

    def __str__(self) -> str:
        """Return a human-readable summary.

        Returns:
            Multi-line formatted performance report.
        """
        lines = [
            "Performance Report",
            "=" * 50,
            f"Duration: {self.duration:.2f}s",
            f"Files: {self.total_files} ({self.files_per_second:.1f} files/s)",
            f"Bytes: {format_bytes(self.total_bytes)} ({format_bytes(int(self.bytes_per_second))}/s)",
        ]

        if self.memory_profiler.enabled:
            lines.extend([
                "",
                "Memory:",
                f"  Peak RSS: {format_bytes(self.memory_profiler.peak_memory_rss)}",
                f"  Peak VMS: {format_bytes(self.memory_profiler.peak_memory_vms)}",
                f"  Delta RSS: {'+' if self.memory_profiler.memory_delta_rss >= 0 else ''}"
                f"{format_bytes(abs(self.memory_profiler.memory_delta_rss))}",
            ])

        if self.detector_stats:
            lines.extend(["", "Detector Timing:"])
            for name, stats in sorted(self.detector_stats.items()):
                lines.append(f"  {stats}")

        if self.custom_timings:
            lines.extend(["", "Custom Timings:"])
            for name, stats in sorted(self.custom_timings.items()):
                lines.append(f"  {stats}")

        return "\n".join(lines)


class PerformanceProfiler:
    """Context manager and utility class for performance profiling.

    Provides convenient methods for timing operations and tracking memory.

    Example:
        >>> profiler = PerformanceProfiler(memory_tracking=True)
        >>> with profiler.profile():
        ...     with profiler.time_detector("RegexDetector"):
        ...         # detection code
        ...         pass
        >>> print(profiler.report)
    """

    def __init__(self, memory_tracking: bool = True) -> None:
        """Initialize the performance profiler.

        Args:
            memory_tracking: Whether to enable memory tracking.
        """
        self._memory_tracking = memory_tracking
        self._report = PerformanceReport(
            memory_profiler=MemoryProfiler(enabled=memory_tracking)
        )
        self._is_profiling = False

    @property
    def report(self) -> PerformanceReport:
        """Get the current performance report.

        Returns:
            The PerformanceReport being built.
        """
        return self._report

    @property
    def is_profiling(self) -> bool:
        """Check if profiling is currently active.

        Returns:
            True if profiling is active.
        """
        return self._is_profiling

    def start(self) -> None:
        """Start profiling."""
        self._is_profiling = True
        self._report.start()

    def stop(self) -> None:
        """Stop profiling."""
        self._report.stop()
        self._is_profiling = False

    def reset(self) -> None:
        """Reset the profiler for a new run."""
        self._report = PerformanceReport(
            memory_profiler=MemoryProfiler(enabled=self._memory_tracking)
        )
        self._is_profiling = False

    @contextmanager
    def profile(self) -> Generator[PerformanceReport, None, None]:
        """Context manager for profiling a code block.

        Yields:
            The PerformanceReport being built.

        Example:
            >>> profiler = PerformanceProfiler()
            >>> with profiler.profile() as report:
            ...     # do work
            ...     pass
            >>> print(report.duration)
        """
        self.start()
        try:
            yield self._report
        finally:
            self.stop()

    @contextmanager
    def time_detector(
        self,
        detector_name: str,
        findings_callback: Callable[[], int] | None = None,
    ) -> Generator[None, None, None]:
        """Context manager for timing a detector's operation.

        Args:
            detector_name: Name of the detector being timed.
            findings_callback: Optional callback that returns finding count.

        Yields:
            None

        Example:
            >>> profiler = PerformanceProfiler()
            >>> with profiler.time_detector("RegexDetector"):
            ...     results = detector.detect(content)
        """
        start = time.perf_counter()
        findings = 0
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            if findings_callback is not None:
                try:
                    findings = findings_callback()
                except Exception:
                    pass
            self._report.add_detector_timing(detector_name, duration, findings)

    @contextmanager
    def time_operation(self, name: str) -> Generator[None, None, None]:
        """Context manager for timing a custom operation.

        Args:
            name: Name of the operation.

        Yields:
            None

        Example:
            >>> profiler = PerformanceProfiler()
            >>> with profiler.time_operation("file_read"):
            ...     content = file.read()
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self._report.add_custom_timing(name, duration)

    def record_files(self, count: int) -> None:
        """Record the number of files processed.

        Args:
            count: Number of files processed.
        """
        self._report.total_files = count

    def add_files(self, count: int = 1) -> None:
        """Add to the file count.

        Args:
            count: Number of files to add.
        """
        self._report.total_files += count

    def record_bytes(self, count: int) -> None:
        """Record the number of bytes processed.

        Args:
            count: Number of bytes processed.
        """
        self._report.total_bytes = count

    def add_bytes(self, count: int) -> None:
        """Add to the byte count.

        Args:
            count: Number of bytes to add.
        """
        self._report.total_bytes += count

    def memory_snapshot(self, label: str = "") -> MemorySnapshot | None:
        """Take a memory snapshot.

        Args:
            label: Optional label for the snapshot.

        Returns:
            The snapshot, or None if memory tracking is disabled.
        """
        return self._report.memory_profiler.snapshot(label)


# Type variable for generic function wrapping
F = TypeVar("F", bound=Callable[..., Any])


def timed(func: F) -> F:
    """Decorator to time function execution.

    The timing is printed to stderr. For production use, prefer
    the PerformanceProfiler context managers.

    Args:
        func: Function to time.

    Returns:
        Wrapped function that prints timing info.

    Example:
        >>> @timed
        ... def slow_function():
        ...     time.sleep(0.1)
        >>> slow_function()
        slow_function: 100.5ms
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.perf_counter()
        try:
            return func(*args, **kwargs)
        finally:
            duration = time.perf_counter() - start
            print(f"{func.__name__}: {duration * 1000:.2f}ms", file=sys.stderr)

    return wrapper  # type: ignore[return-value]


def format_bytes(byte_count: int) -> str:
    """Format bytes as a human-readable string.

    Args:
        byte_count: Number of bytes to format.

    Returns:
        Formatted string (e.g., "1.5 MB", "256 KB").
    """
    if byte_count < 1024:
        return f"{byte_count} B"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    elif byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.1f} MB"
    else:
        return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def force_gc() -> int:
    """Force garbage collection and return count of collected objects.

    Returns:
        Number of unreachable objects collected.
    """
    return gc.collect()


def get_current_memory_rss() -> int:
    """Get current RSS memory usage in bytes.

    Returns:
        RSS bytes, or 0 if psutil is not available.
    """
    if not PSUTIL_AVAILABLE:
        return 0
    return psutil.Process(os.getpid()).memory_info().rss


def is_memory_tracking_available() -> bool:
    """Check if memory tracking is available.

    Returns:
        True if psutil is installed and available.
    """
    return PSUTIL_AVAILABLE
