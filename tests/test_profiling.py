"""Tests for the profiling module."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from hamburglar.core.profiling import (
    DetectorTimingStats,
    MemoryProfiler,
    MemorySnapshot,
    PerformanceProfiler,
    PerformanceReport,
    TimingStats,
    format_bytes,
    force_gc,
    get_current_memory_rss,
    is_memory_tracking_available,
    timed,
)


class TestFormatBytes:
    """Tests for the format_bytes utility function."""

    def test_format_bytes(self):
        """Test formatting bytes at various scales."""
        assert format_bytes(512) == "512 B"
        assert format_bytes(1023) == "1023 B"

    def test_format_kilobytes(self):
        """Test formatting kilobytes."""
        assert "KB" in format_bytes(1024)
        assert "KB" in format_bytes(1024 * 100)
        result = format_bytes(2048)
        assert "2.0" in result and "KB" in result

    def test_format_megabytes(self):
        """Test formatting megabytes."""
        result = format_bytes(5 * 1024 * 1024)
        assert "5.0" in result and "MB" in result

    def test_format_gigabytes(self):
        """Test formatting gigabytes."""
        result = format_bytes(2 * 1024 * 1024 * 1024)
        assert "2.0" in result and "GB" in result


class TestMemorySnapshot:
    """Tests for MemorySnapshot dataclass."""

    def test_creation(self):
        """Test creating a snapshot manually."""
        snap = MemorySnapshot(
            timestamp=1234567890.0,
            rss_bytes=100 * 1024 * 1024,
            vms_bytes=200 * 1024 * 1024,
            percent=5.5,
            label="test",
        )
        assert snap.rss_bytes == 100 * 1024 * 1024
        assert snap.vms_bytes == 200 * 1024 * 1024
        assert snap.percent == 5.5
        assert snap.label == "test"

    def test_take_snapshot(self):
        """Test taking a live snapshot."""
        snap = MemorySnapshot.take("test label")
        assert snap.timestamp > 0
        assert snap.label == "test label"
        # Values may be 0 if psutil is not available

    def test_format_rss(self):
        """Test formatting RSS memory."""
        snap = MemorySnapshot(
            timestamp=0,
            rss_bytes=150 * 1024 * 1024,
            vms_bytes=0,
            percent=0,
        )
        result = snap.format_rss()
        assert "MB" in result
        assert "150" in result

    def test_format_vms(self):
        """Test formatting VMS memory."""
        snap = MemorySnapshot(
            timestamp=0,
            rss_bytes=0,
            vms_bytes=300 * 1024 * 1024,
            percent=0,
        )
        result = snap.format_vms()
        assert "MB" in result
        assert "300" in result

    def test_to_dict(self):
        """Test converting to dictionary."""
        snap = MemorySnapshot(
            timestamp=1234567890.0,
            rss_bytes=1024,
            vms_bytes=2048,
            percent=1.5,
            label="test",
        )
        d = snap.to_dict()
        assert d["timestamp"] == 1234567890.0
        assert d["rss_bytes"] == 1024
        assert d["vms_bytes"] == 2048
        assert d["percent"] == 1.5
        assert d["label"] == "test"


class TestTimingStats:
    """Tests for TimingStats dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        stats = TimingStats(name="test")
        assert stats.name == "test"
        assert stats.total_time == 0.0
        assert stats.call_count == 0
        assert stats.min_time == float("inf")
        assert stats.max_time == 0.0

    def test_record_single(self):
        """Test recording a single timing."""
        stats = TimingStats(name="test")
        stats.record(0.5)

        assert stats.call_count == 1
        assert stats.total_time == 0.5
        assert stats.min_time == 0.5
        assert stats.max_time == 0.5

    def test_record_multiple(self):
        """Test recording multiple timings."""
        stats = TimingStats(name="test")
        stats.record(0.1)
        stats.record(0.2)
        stats.record(0.3)

        assert stats.call_count == 3
        assert abs(stats.total_time - 0.6) < 0.001
        assert stats.min_time == 0.1
        assert stats.max_time == 0.3

    def test_avg_time(self):
        """Test average time calculation."""
        stats = TimingStats(name="test")
        assert stats.avg_time == 0.0  # No calls

        stats.record(0.1)
        stats.record(0.3)
        assert abs(stats.avg_time - 0.2) < 0.001

    def test_to_dict(self):
        """Test converting to dictionary."""
        stats = TimingStats(name="test")
        stats.record(0.1)
        stats.record(0.2)

        d = stats.to_dict()
        assert d["name"] == "test"
        assert d["call_count"] == 2
        assert abs(d["total_time"] - 0.3) < 0.001
        assert d["min_time"] == 0.1
        assert d["max_time"] == 0.2
        assert abs(d["avg_time"] - 0.15) < 0.001

    def test_to_dict_no_calls(self):
        """Test to_dict with no recorded calls."""
        stats = TimingStats(name="empty")
        d = stats.to_dict()
        assert d["min_time"] == 0.0  # Should be 0, not inf
        assert d["call_count"] == 0

    def test_str_no_calls(self):
        """Test string representation with no calls."""
        stats = TimingStats(name="empty")
        result = str(stats)
        assert "empty" in result
        assert "no calls" in result

    def test_str_with_calls(self):
        """Test string representation with calls."""
        stats = TimingStats(name="operation")
        stats.record(0.1)
        stats.record(0.2)

        result = str(stats)
        assert "operation" in result
        assert "2 calls" in result
        assert "ms" in result


class TestDetectorTimingStats:
    """Tests for DetectorTimingStats dataclass."""

    def test_creation(self):
        """Test creating detector timing stats."""
        stats = DetectorTimingStats(detector_name="RegexDetector")
        assert stats.detector_name == "RegexDetector"
        assert stats.files_processed == 0
        assert stats.findings_count == 0
        assert stats.detect_time.name == "RegexDetector.detect"

    def test_record_detection(self):
        """Test recording a detection."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        stats.record_detection(0.1, findings=3)

        assert stats.files_processed == 1
        assert stats.findings_count == 3
        assert stats.detect_time.call_count == 1

    def test_record_multiple_detections(self):
        """Test recording multiple detections."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        stats.record_detection(0.1, findings=2)
        stats.record_detection(0.2, findings=1)
        stats.record_detection(0.15, findings=0)

        assert stats.files_processed == 3
        assert stats.findings_count == 3
        assert stats.detect_time.call_count == 3

    def test_avg_time_per_file(self):
        """Test average time per file."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        stats.record_detection(0.1)
        stats.record_detection(0.3)

        assert abs(stats.avg_time_per_file - 0.2) < 0.001

    def test_findings_per_file(self):
        """Test findings per file calculation."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        assert stats.findings_per_file == 0.0  # No files

        stats.record_detection(0.1, findings=4)
        stats.record_detection(0.1, findings=6)
        assert stats.findings_per_file == 5.0

    def test_to_dict(self):
        """Test converting to dictionary."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        stats.record_detection(0.1, findings=2)

        d = stats.to_dict()
        assert d["detector_name"] == "TestDetector"
        assert d["files_processed"] == 1
        assert d["findings_count"] == 2
        assert d["findings_per_file"] == 2.0
        assert "timing" in d

    def test_str_representation(self):
        """Test string representation."""
        stats = DetectorTimingStats(detector_name="TestDetector")
        stats.record_detection(0.05, findings=3)
        stats.record_detection(0.05, findings=2)

        result = str(stats)
        assert "TestDetector" in result
        assert "2 files" in result
        assert "5 findings" in result
        assert "ms" in result


class TestMemoryProfiler:
    """Tests for MemoryProfiler class."""

    def test_init_enabled(self):
        """Test initialization with tracking enabled."""
        profiler = MemoryProfiler(enabled=True)
        # May be False if psutil is not available
        assert isinstance(profiler.enabled, bool)

    def test_init_disabled(self):
        """Test initialization with tracking disabled."""
        profiler = MemoryProfiler(enabled=False)
        assert profiler.enabled is False

    def test_not_running_initially(self):
        """Test that profiler is not running initially."""
        profiler = MemoryProfiler(enabled=True)
        assert profiler.is_running is False

    def test_start_stop(self):
        """Test starting and stopping the profiler."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()
        # is_running is True only if psutil is available
        if profiler.enabled:
            assert profiler.is_running is True

        profiler.stop()
        assert profiler.is_running is False

    def test_snapshots_collected(self):
        """Test that snapshots are collected."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()
        profiler.snapshot("middle")
        profiler.stop()

        # Should have at least start, middle, and end snapshots (if enabled)
        if profiler.enabled:
            assert len(profiler.snapshots) >= 3
        else:
            # If psutil is not available, no snapshots are collected
            assert len(profiler.snapshots) == 0

    def test_snapshot_when_disabled(self):
        """Test that snapshot returns None when disabled."""
        profiler = MemoryProfiler(enabled=False)
        result = profiler.snapshot("test")
        assert result is None

    def test_peak_memory_tracking(self):
        """Test peak memory tracking."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        # Allocate some memory
        data = [i for i in range(100000)]
        profiler.snapshot("after allocation")

        # Peak should be at least as much as current
        assert profiler.peak_memory_rss >= 0

        del data
        profiler.stop()

    def test_memory_delta(self):
        """Test memory delta calculation."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()
        profiler.stop()

        # Delta should be calculable (may be 0 or small)
        delta = profiler.memory_delta_rss
        assert isinstance(delta, int)

    def test_memory_delta_not_started(self):
        """Test memory delta when profiler hasn't run."""
        profiler = MemoryProfiler(enabled=True)
        assert profiler.memory_delta_rss == 0
        assert profiler.memory_delta_vms == 0

    def test_get_report(self):
        """Test getting a memory report."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()
        profiler.snapshot("test")
        profiler.stop()

        report = profiler.get_report()
        assert "enabled" in report
        assert "is_running" in report
        assert "peak_rss_bytes" in report
        assert "peak_rss_formatted" in report
        assert "snapshots" in report

    def test_reset(self):
        """Test resetting the profiler."""
        profiler = MemoryProfiler(enabled=True)
        profiler.start()
        profiler.snapshot("test")
        profiler.stop()

        profiler.reset()

        assert profiler.is_running is False
        assert len(profiler.snapshots) == 0
        assert profiler.peak_memory_rss == 0


class TestPerformanceReport:
    """Tests for PerformanceReport dataclass."""

    def test_default_values(self):
        """Test default initialization."""
        report = PerformanceReport()
        assert report.start_time == 0.0
        assert report.end_time == 0.0
        assert report.total_files == 0
        assert report.total_bytes == 0
        assert report.detector_stats == {}
        assert report.custom_timings == {}

    def test_duration(self):
        """Test duration calculation."""
        report = PerformanceReport()
        assert report.duration == 0.0  # Not started

        report.start_time = 100.0
        report.end_time = 102.5
        assert report.duration == 2.5

    def test_files_per_second(self):
        """Test files per second calculation."""
        report = PerformanceReport()
        assert report.files_per_second == 0.0  # No duration

        report.start_time = 100.0
        report.end_time = 102.0
        report.total_files = 200
        assert report.files_per_second == 100.0

    def test_bytes_per_second(self):
        """Test bytes per second calculation."""
        report = PerformanceReport()
        report.start_time = 100.0
        report.end_time = 102.0
        report.total_bytes = 2048
        assert report.bytes_per_second == 1024.0

    def test_start_stop(self):
        """Test start and stop methods."""
        report = PerformanceReport()
        before = time.time()
        report.start()
        after_start = time.time()

        time.sleep(0.01)

        before_stop = time.time()
        report.stop()
        after_stop = time.time()

        assert before <= report.start_time <= after_start
        assert before_stop <= report.end_time <= after_stop
        assert report.duration >= 0.01

    def test_add_detector_timing(self):
        """Test adding detector timing."""
        report = PerformanceReport()
        report.add_detector_timing("RegexDetector", 0.1, findings=3)
        report.add_detector_timing("RegexDetector", 0.2, findings=2)
        report.add_detector_timing("YaraDetector", 0.3, findings=1)

        assert "RegexDetector" in report.detector_stats
        assert "YaraDetector" in report.detector_stats

        regex_stats = report.detector_stats["RegexDetector"]
        assert regex_stats.files_processed == 2
        assert regex_stats.findings_count == 5

    def test_add_custom_timing(self):
        """Test adding custom timing."""
        report = PerformanceReport()
        report.add_custom_timing("file_read", 0.05)
        report.add_custom_timing("file_read", 0.03)
        report.add_custom_timing("encoding_detect", 0.01)

        assert "file_read" in report.custom_timings
        assert "encoding_detect" in report.custom_timings
        assert report.custom_timings["file_read"].call_count == 2

    def test_get_detector_timing(self):
        """Test getting detector timing."""
        report = PerformanceReport()
        report.add_detector_timing("TestDetector", 0.1)

        stats = report.get_detector_timing("TestDetector")
        assert stats is not None
        assert stats.detector_name == "TestDetector"

        missing = report.get_detector_timing("NonExistent")
        assert missing is None

    def test_to_dict(self):
        """Test exporting to dictionary."""
        report = PerformanceReport()
        report.start()
        report.total_files = 100
        report.total_bytes = 1024000
        report.add_detector_timing("TestDetector", 0.1, findings=5)
        report.add_custom_timing("operation", 0.05)
        report.stop()

        d = report.to_dict()

        assert "summary" in d
        assert "memory" in d
        assert "detectors" in d
        assert "custom_timings" in d

        assert d["summary"]["total_files"] == 100
        assert d["summary"]["total_bytes"] == 1024000
        assert "TestDetector" in d["detectors"]
        assert "operation" in d["custom_timings"]

    def test_to_json(self):
        """Test exporting to JSON."""
        report = PerformanceReport()
        report.start()
        report.total_files = 50
        report.add_detector_timing("Detector", 0.1)
        report.stop()

        json_str = report.to_json()
        parsed = json.loads(json_str)

        assert parsed["summary"]["total_files"] == 50
        assert "Detector" in parsed["detectors"]

    def test_str_representation(self):
        """Test string representation."""
        report = PerformanceReport()
        report.start()
        report.total_files = 100
        report.total_bytes = 1024 * 1024
        report.add_detector_timing("RegexDetector", 0.1, findings=5)
        report.add_custom_timing("file_read", 0.05)
        report.stop()

        output = str(report)

        assert "Performance Report" in output
        assert "Duration" in output
        assert "Files" in output
        assert "Bytes" in output
        assert "RegexDetector" in output
        assert "file_read" in output


class TestPerformanceProfiler:
    """Tests for PerformanceProfiler class."""

    def test_init(self):
        """Test initialization."""
        profiler = PerformanceProfiler(memory_tracking=True)
        assert profiler.report is not None
        assert profiler.is_profiling is False

    def test_start_stop(self):
        """Test starting and stopping profiling."""
        profiler = PerformanceProfiler()
        profiler.start()
        assert profiler.is_profiling is True

        profiler.stop()
        assert profiler.is_profiling is False
        assert profiler.report.duration > 0

    def test_reset(self):
        """Test resetting the profiler."""
        profiler = PerformanceProfiler()
        profiler.start()
        profiler.report.total_files = 100
        profiler.stop()

        profiler.reset()

        assert profiler.is_profiling is False
        assert profiler.report.total_files == 0

    def test_profile_context_manager(self):
        """Test the profile() context manager."""
        profiler = PerformanceProfiler()

        with profiler.profile() as report:
            assert profiler.is_profiling is True
            time.sleep(0.01)

        assert profiler.is_profiling is False
        assert report.duration >= 0.01

    def test_time_detector_context_manager(self):
        """Test the time_detector() context manager."""
        profiler = PerformanceProfiler()
        profiler.start()

        with profiler.time_detector("TestDetector"):
            time.sleep(0.01)

        profiler.stop()

        stats = profiler.report.get_detector_timing("TestDetector")
        assert stats is not None
        assert stats.detect_time.call_count == 1
        assert stats.detect_time.total_time >= 0.01

    def test_time_detector_with_findings_callback(self):
        """Test time_detector with findings callback."""
        profiler = PerformanceProfiler()
        profiler.start()

        findings_count = [0]  # Use list for mutable reference

        def get_findings():
            return findings_count[0]

        with profiler.time_detector("TestDetector", findings_callback=get_findings):
            findings_count[0] = 5

        profiler.stop()

        stats = profiler.report.get_detector_timing("TestDetector")
        assert stats.findings_count == 5

    def test_time_operation_context_manager(self):
        """Test the time_operation() context manager."""
        profiler = PerformanceProfiler()
        profiler.start()

        with profiler.time_operation("custom_op"):
            time.sleep(0.01)

        profiler.stop()

        timing = profiler.report.custom_timings.get("custom_op")
        assert timing is not None
        assert timing.call_count == 1
        assert timing.total_time >= 0.01

    def test_record_files(self):
        """Test recording file count."""
        profiler = PerformanceProfiler()
        profiler.record_files(100)
        assert profiler.report.total_files == 100

    def test_add_files(self):
        """Test adding to file count."""
        profiler = PerformanceProfiler()
        profiler.add_files(10)
        profiler.add_files(5)
        assert profiler.report.total_files == 15

    def test_record_bytes(self):
        """Test recording byte count."""
        profiler = PerformanceProfiler()
        profiler.record_bytes(1024)
        assert profiler.report.total_bytes == 1024

    def test_add_bytes(self):
        """Test adding to byte count."""
        profiler = PerformanceProfiler()
        profiler.add_bytes(512)
        profiler.add_bytes(256)
        assert profiler.report.total_bytes == 768

    def test_memory_snapshot(self):
        """Test taking a memory snapshot."""
        profiler = PerformanceProfiler(memory_tracking=True)
        profiler.start()

        snap = profiler.memory_snapshot("test")
        # May be None if psutil is not available

        profiler.stop()

    def test_memory_tracking_disabled(self):
        """Test with memory tracking disabled."""
        profiler = PerformanceProfiler(memory_tracking=False)
        profiler.start()

        snap = profiler.memory_snapshot("test")
        assert snap is None

        profiler.stop()


class TestTimedDecorator:
    """Tests for the @timed decorator."""

    def test_timed_decorator(self, capsys):
        """Test that timed decorator prints timing."""
        @timed
        def slow_function():
            time.sleep(0.01)
            return "result"

        result = slow_function()

        assert result == "result"
        captured = capsys.readouterr()
        assert "slow_function" in captured.err
        assert "ms" in captured.err

    def test_timed_decorator_preserves_function(self):
        """Test that timed decorator preserves function attributes."""
        @timed
        def my_function():
            """Docstring."""
            pass

        assert my_function.__name__ == "my_function"


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_is_memory_tracking_available(self):
        """Test is_memory_tracking_available function."""
        result = is_memory_tracking_available()
        assert isinstance(result, bool)

    def test_get_current_memory_rss(self):
        """Test get_current_memory_rss function."""
        rss = get_current_memory_rss()
        assert isinstance(rss, int)
        assert rss >= 0

    def test_force_gc(self):
        """Test force_gc function."""
        # Create some garbage
        _ = [object() for _ in range(1000)]

        collected = force_gc()
        assert isinstance(collected, int)
        assert collected >= 0


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_profiler_exception_in_context(self):
        """Test profiler handles exceptions in context."""
        profiler = PerformanceProfiler()

        with pytest.raises(ValueError):
            with profiler.profile():
                raise ValueError("test error")

        # Profiler should still be stopped
        assert profiler.is_profiling is False
        assert profiler.report.duration > 0

    def test_detector_timing_exception_in_callback(self):
        """Test detector timing handles exception in callback."""
        profiler = PerformanceProfiler()
        profiler.start()

        def failing_callback():
            raise RuntimeError("callback error")

        # Should not raise
        with profiler.time_detector("Test", findings_callback=failing_callback):
            pass

        profiler.stop()
        stats = profiler.report.get_detector_timing("Test")
        assert stats.findings_count == 0  # Default when callback fails

    def test_many_detectors(self):
        """Test with many detectors."""
        report = PerformanceReport()
        for i in range(100):
            report.add_detector_timing(f"Detector{i}", 0.001, findings=i)

        assert len(report.detector_stats) == 100

        d = report.to_dict()
        assert len(d["detectors"]) == 100

    def test_many_timings(self):
        """Test with many timing recordings."""
        stats = TimingStats(name="stress_test")
        for i in range(10000):
            stats.record(0.001)

        assert stats.call_count == 10000
        assert abs(stats.total_time - 10.0) < 0.001

    def test_zero_duration(self):
        """Test with zero duration operations."""
        stats = TimingStats(name="fast")
        stats.record(0.0)
        stats.record(0.0)

        assert stats.avg_time == 0.0
        assert stats.min_time == 0.0
        assert stats.max_time == 0.0

    def test_memory_profiler_without_psutil(self):
        """Test memory profiler behavior simulation without psutil."""
        # Create a profiler that's explicitly disabled
        profiler = MemoryProfiler(enabled=False)

        profiler.start()
        assert profiler.is_running is False  # Doesn't start when disabled

        snap = profiler.snapshot("test")
        assert snap is None

        profiler.stop()
        assert profiler.peak_memory_rss == 0

    def test_empty_performance_report_export(self):
        """Test exporting an empty performance report."""
        report = PerformanceReport()
        d = report.to_dict()

        assert d["summary"]["duration_seconds"] == 0.0
        assert d["detectors"] == {}
        assert d["custom_timings"] == {}

    def test_str_with_memory_disabled(self):
        """Test string representation with memory disabled."""
        report = PerformanceReport(
            memory_profiler=MemoryProfiler(enabled=False)
        )
        report.start()
        report.total_files = 50
        report.total_bytes = 1024
        report.stop()

        output = str(report)
        assert "Performance Report" in output
        assert "Files" in output
        # Memory section should not appear
        assert "Peak RSS" not in output
