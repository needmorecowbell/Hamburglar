"""Tests for the ScanStats module."""

import time
from collections import Counter

import pytest

from hamburglar.core.models import Finding, Severity
from hamburglar.core.stats import ScanStats, SkipReason, SkippedFile


class TestSkippedFile:
    """Tests for SkippedFile dataclass."""

    def test_basic_creation(self):
        """Test creating a SkippedFile with required fields."""
        skipped = SkippedFile(
            file_path="/path/to/file.txt",
            reason=SkipReason.PERMISSION_DENIED,
        )
        assert skipped.file_path == "/path/to/file.txt"
        assert skipped.reason == SkipReason.PERMISSION_DENIED
        assert skipped.detail is None

    def test_creation_with_detail(self):
        """Test creating a SkippedFile with detail."""
        skipped = SkippedFile(
            file_path="/path/to/file.txt",
            reason=SkipReason.READ_ERROR,
            detail="I/O error occurred",
        )
        assert skipped.detail == "I/O error occurred"

    def test_to_dict_without_detail(self):
        """Test to_dict() without detail."""
        skipped = SkippedFile(
            file_path="/path/to/file.txt",
            reason=SkipReason.BLACKLISTED,
        )
        result = skipped.to_dict()
        assert result == {
            "file_path": "/path/to/file.txt",
            "reason": "blacklisted",
        }
        assert "detail" not in result

    def test_to_dict_with_detail(self):
        """Test to_dict() with detail."""
        skipped = SkippedFile(
            file_path="/path/to/file.txt",
            reason=SkipReason.TOO_LARGE,
            detail="File exceeds 10MB limit",
        )
        result = skipped.to_dict()
        assert result == {
            "file_path": "/path/to/file.txt",
            "reason": "too_large",
            "detail": "File exceeds 10MB limit",
        }


class TestSkipReason:
    """Tests for SkipReason enum."""

    def test_all_reasons_have_string_values(self):
        """Test that all skip reasons are string enums."""
        for reason in SkipReason:
            assert isinstance(reason.value, str)

    def test_expected_reasons_exist(self):
        """Test that expected skip reasons are defined."""
        expected = [
            "permission_denied",
            "file_not_found",
            "read_error",
            "blacklisted",
            "not_whitelisted",
            "binary_file",
            "too_large",
            "encoding_error",
            "detector_error",
            "cancelled",
            "unknown",
        ]
        actual = [r.value for r in SkipReason]
        for exp in expected:
            assert exp in actual


class TestScanStats:
    """Tests for ScanStats dataclass."""

    def test_default_values(self):
        """Test that ScanStats initializes with correct defaults."""
        stats = ScanStats()
        assert stats.total_files_discovered == 0
        assert stats.total_files_scanned == 0
        assert stats.total_bytes_processed == 0
        assert stats.skipped_files == []
        assert stats.findings_by_detector == Counter()
        assert stats.findings_by_severity == Counter()
        assert stats.scan_start_time is None
        assert stats.scan_end_time is None
        assert stats.errors == []

    def test_start_sets_timestamp(self):
        """Test that start() sets the scan start time."""
        stats = ScanStats()
        before = time.time()
        stats.start()
        after = time.time()
        assert stats.scan_start_time is not None
        assert before <= stats.scan_start_time <= after
        assert stats.scan_end_time is None

    def test_stop_sets_timestamp(self):
        """Test that stop() sets the scan end time."""
        stats = ScanStats()
        stats.start()
        time.sleep(0.01)  # Small delay to ensure measurable duration
        before = time.time()
        stats.stop()
        after = time.time()
        assert stats.scan_end_time is not None
        assert before <= stats.scan_end_time <= after

    def test_reset_clears_all_state(self):
        """Test that reset() clears all state."""
        stats = ScanStats()
        stats.start()
        stats.set_discovered_files(100)
        stats.add_scanned_file("/test.py", 1024)
        stats.add_skipped_file("/skip.py", SkipReason.BLACKLISTED)
        stats.add_finding("RegexDetector", "high")
        stats.add_error("Test error")
        stats.stop()

        stats.reset()

        assert stats.total_files_discovered == 0
        assert stats.total_files_scanned == 0
        assert stats.total_bytes_processed == 0
        assert stats.skipped_files == []
        assert stats.findings_by_detector == Counter()
        assert stats.findings_by_severity == Counter()
        assert stats.scan_start_time is None
        assert stats.scan_end_time is None
        assert stats.errors == []
        assert stats.total_findings == 0

    def test_set_discovered_files(self):
        """Test setting discovered files count."""
        stats = ScanStats()
        stats.set_discovered_files(150)
        assert stats.total_files_discovered == 150

    def test_add_scanned_file(self):
        """Test adding scanned files."""
        stats = ScanStats()
        stats.add_scanned_file("/file1.py", 1024)
        stats.add_scanned_file("/file2.py", 2048)

        assert stats.total_files_scanned == 2
        assert stats.total_bytes_processed == 3072

    def test_add_skipped_file(self):
        """Test adding skipped files."""
        stats = ScanStats()
        stats.add_skipped_file("/file1.py", SkipReason.PERMISSION_DENIED)
        stats.add_skipped_file("/file2.py", SkipReason.BLACKLISTED, "In .git directory")

        assert len(stats.skipped_files) == 2
        assert stats.skipped_files[0].file_path == "/file1.py"
        assert stats.skipped_files[0].reason == SkipReason.PERMISSION_DENIED
        assert stats.skipped_files[1].detail == "In .git directory"

    def test_add_finding_with_severity(self):
        """Test adding findings with severity."""
        stats = ScanStats()
        stats.add_finding("RegexDetector", "high")
        stats.add_finding("RegexDetector", "medium")
        stats.add_finding("YaraDetector", "critical")

        assert stats.total_findings == 3
        assert stats.findings_by_detector["RegexDetector"] == 2
        assert stats.findings_by_detector["YaraDetector"] == 1
        assert stats.findings_by_severity["high"] == 1
        assert stats.findings_by_severity["medium"] == 1
        assert stats.findings_by_severity["critical"] == 1

    def test_add_finding_without_severity(self):
        """Test adding findings without severity."""
        stats = ScanStats()
        stats.add_finding("RegexDetector")
        stats.add_finding("RegexDetector", None)

        assert stats.total_findings == 2
        assert stats.findings_by_detector["RegexDetector"] == 2
        assert stats.findings_by_severity == Counter()

    def test_add_findings_from_finding_objects(self):
        """Test adding multiple Finding objects at once."""
        stats = ScanStats()
        findings = [
            Finding(
                file_path="/test1.py",
                detector_name="RegexDetector",
                matches=["API_KEY"],
                severity=Severity.HIGH,
            ),
            Finding(
                file_path="/test2.py",
                detector_name="YaraDetector",
                matches=["secret"],
                severity=Severity.CRITICAL,
            ),
            Finding(
                file_path="/test3.py",
                detector_name="RegexDetector",
                matches=["password"],
                severity=Severity.HIGH,
            ),
        ]
        stats.add_findings(findings)

        assert stats.total_findings == 3
        assert stats.findings_by_detector["RegexDetector"] == 2
        assert stats.findings_by_detector["YaraDetector"] == 1
        assert stats.findings_by_severity["high"] == 2
        assert stats.findings_by_severity["critical"] == 1

    def test_add_error(self):
        """Test adding error messages."""
        stats = ScanStats()
        stats.add_error("Error reading file")
        stats.add_error("Permission denied")

        assert len(stats.errors) == 2
        assert "Error reading file" in stats.errors
        assert "Permission denied" in stats.errors


class TestScanStatsProperties:
    """Tests for ScanStats computed properties."""

    def test_scan_duration_not_started(self):
        """Test scan_duration when scan hasn't started."""
        stats = ScanStats()
        assert stats.scan_duration == 0.0

    def test_scan_duration_running(self):
        """Test scan_duration while scan is running."""
        stats = ScanStats()
        stats.start()
        time.sleep(0.05)  # 50ms delay
        duration = stats.scan_duration
        assert duration >= 0.05
        assert duration < 1.0  # Sanity check

    def test_scan_duration_complete(self):
        """Test scan_duration after scan completes."""
        stats = ScanStats()
        stats.start()
        time.sleep(0.05)
        stats.stop()
        time.sleep(0.05)  # Duration shouldn't increase after stop

        duration = stats.scan_duration
        assert duration >= 0.05
        assert duration < 0.1  # Should be close to 50ms

    def test_files_per_second_no_time(self):
        """Test files_per_second with no elapsed time."""
        stats = ScanStats()
        assert stats.files_per_second == 0.0

    def test_files_per_second(self):
        """Test files_per_second calculation."""
        stats = ScanStats()
        stats.scan_start_time = time.time() - 2.0  # Pretend started 2 seconds ago
        stats.scan_end_time = time.time()
        stats.total_files_scanned = 100

        fps = stats.files_per_second
        assert fps >= 49.0  # Should be around 50 files/sec
        assert fps <= 51.0

    def test_bytes_per_second_no_time(self):
        """Test bytes_per_second with no elapsed time."""
        stats = ScanStats()
        assert stats.bytes_per_second == 0.0

    def test_bytes_per_second(self):
        """Test bytes_per_second calculation."""
        stats = ScanStats()
        stats.scan_start_time = time.time() - 2.0
        stats.scan_end_time = time.time()
        stats.total_bytes_processed = 2048

        bps = stats.bytes_per_second
        assert bps >= 1000  # Should be around 1024 bytes/sec
        assert bps <= 1100

    def test_total_files_skipped(self):
        """Test total_files_skipped property."""
        stats = ScanStats()
        assert stats.total_files_skipped == 0

        stats.add_skipped_file("/f1.py", SkipReason.BLACKLISTED)
        stats.add_skipped_file("/f2.py", SkipReason.TOO_LARGE)
        assert stats.total_files_skipped == 2

    def test_skipped_by_reason(self):
        """Test skipped_by_reason property."""
        stats = ScanStats()
        stats.add_skipped_file("/f1.py", SkipReason.BLACKLISTED)
        stats.add_skipped_file("/f2.py", SkipReason.BLACKLISTED)
        stats.add_skipped_file("/f3.py", SkipReason.TOO_LARGE)
        stats.add_skipped_file("/f4.py", SkipReason.PERMISSION_DENIED)

        by_reason = stats.skipped_by_reason
        assert by_reason["blacklisted"] == 2
        assert by_reason["too_large"] == 1
        assert by_reason["permission_denied"] == 1

    def test_is_running(self):
        """Test is_running property."""
        stats = ScanStats()
        assert stats.is_running is False

        stats.start()
        assert stats.is_running is True

        stats.stop()
        assert stats.is_running is False

    def test_is_complete(self):
        """Test is_complete property."""
        stats = ScanStats()
        assert stats.is_complete is False

        stats.start()
        assert stats.is_complete is False

        stats.stop()
        assert stats.is_complete is True


class TestScanStatsSerialization:
    """Tests for ScanStats serialization methods."""

    def test_get_summary(self):
        """Test get_summary() returns key statistics."""
        stats = ScanStats()
        stats.start()
        stats.set_discovered_files(100)
        stats.add_scanned_file("/test.py", 1024)
        stats.add_skipped_file("/skip.py", SkipReason.BLACKLISTED)
        stats.add_finding("RegexDetector", "high")
        stats.add_error("Test error")
        stats.stop()

        summary = stats.get_summary()

        assert summary["total_files_discovered"] == 100
        assert summary["total_files_scanned"] == 1
        assert summary["total_files_skipped"] == 1
        assert summary["total_bytes_processed"] == 1024
        assert summary["total_findings"] == 1
        assert summary["scan_duration"] > 0
        assert summary["files_per_second"] >= 0
        assert summary["bytes_per_second"] >= 0
        assert summary["error_count"] == 1

    def test_to_dict(self):
        """Test to_dict() returns complete dictionary."""
        stats = ScanStats()
        stats.start()
        stats.set_discovered_files(50)
        stats.add_scanned_file("/test.py", 512)
        stats.add_skipped_file("/skip.py", SkipReason.TOO_LARGE, "Exceeds limit")
        stats.add_finding("YaraDetector", "critical")
        stats.stop()

        result = stats.to_dict()

        # Check all expected keys
        assert "total_files_discovered" in result
        assert "total_files_scanned" in result
        assert "total_files_skipped" in result
        assert "total_bytes_processed" in result
        assert "skipped_files" in result
        assert "skipped_by_reason" in result
        assert "findings_by_detector" in result
        assert "findings_by_severity" in result
        assert "total_findings" in result
        assert "scan_start_time" in result
        assert "scan_end_time" in result
        assert "scan_duration" in result
        assert "files_per_second" in result
        assert "bytes_per_second" in result
        assert "is_running" in result
        assert "is_complete" in result
        assert "errors" in result

        # Check values
        assert result["total_files_discovered"] == 50
        assert result["total_files_scanned"] == 1
        assert len(result["skipped_files"]) == 1
        assert result["skipped_files"][0]["reason"] == "too_large"
        assert result["skipped_by_reason"]["too_large"] == 1
        assert result["findings_by_detector"]["YaraDetector"] == 1
        assert result["findings_by_severity"]["critical"] == 1


class TestScanStatsMerging:
    """Tests for ScanStats merging functionality."""

    def test_merge(self):
        """Test merging stats from another instance."""
        stats1 = ScanStats()
        stats1.set_discovered_files(50)
        stats1.add_scanned_file("/file1.py", 1024)
        stats1.add_finding("RegexDetector", "high")
        stats1.add_error("Error 1")

        stats2 = ScanStats()
        stats2.set_discovered_files(30)
        stats2.add_scanned_file("/file2.py", 2048)
        stats2.add_skipped_file("/skip.py", SkipReason.BLACKLISTED)
        stats2.add_finding("YaraDetector", "critical")
        stats2.add_error("Error 2")

        stats1.merge(stats2)

        assert stats1.total_files_discovered == 80
        assert stats1.total_files_scanned == 2
        assert stats1.total_bytes_processed == 3072
        assert len(stats1.skipped_files) == 1
        assert stats1.total_findings == 2
        assert stats1.findings_by_detector["RegexDetector"] == 1
        assert stats1.findings_by_detector["YaraDetector"] == 1
        assert len(stats1.errors) == 2

    def test_add_operator(self):
        """Test combining stats with + operator."""
        stats1 = ScanStats()
        stats1.start()
        stats1.set_discovered_files(100)
        stats1.add_scanned_file("/file1.py", 1024)
        stats1.add_finding("RegexDetector", "medium")
        stats1.stop()

        stats2 = ScanStats()
        stats2.set_discovered_files(50)
        stats2.add_scanned_file("/file2.py", 512)
        stats2.add_finding("RegexDetector", "low")

        combined = stats1 + stats2

        # Check combined values
        assert combined.total_files_discovered == 150
        assert combined.total_files_scanned == 2
        assert combined.total_bytes_processed == 1536
        assert combined.total_findings == 2
        assert combined.findings_by_detector["RegexDetector"] == 2

        # Check timing comes from stats1
        assert combined.scan_start_time == stats1.scan_start_time
        assert combined.scan_end_time == stats1.scan_end_time

        # Original stats unchanged
        assert stats1.total_files_discovered == 100
        assert stats2.total_files_discovered == 50


class TestScanStatsFormatting:
    """Tests for ScanStats formatting methods."""

    def test_format_duration_seconds(self):
        """Test format_duration for durations under a minute."""
        stats = ScanStats()
        stats.scan_start_time = time.time() - 45.5
        stats.scan_end_time = time.time()

        formatted = stats.format_duration()
        assert "45" in formatted
        assert "s" in formatted
        assert "m" not in formatted

    def test_format_duration_minutes(self):
        """Test format_duration for durations over a minute."""
        stats = ScanStats()
        stats.scan_start_time = time.time() - 90.5
        stats.scan_end_time = time.time()

        formatted = stats.format_duration()
        assert "1m" in formatted
        assert "30" in formatted or "31" in formatted  # Allow small timing variance

    def test_format_bytes_bytes(self):
        """Test format_bytes for byte-level values."""
        stats = ScanStats()
        assert stats.format_bytes(512) == "512 B"

    def test_format_bytes_kilobytes(self):
        """Test format_bytes for kilobyte-level values."""
        stats = ScanStats()
        assert "KB" in stats.format_bytes(2048)
        assert "2.0" in stats.format_bytes(2048)

    def test_format_bytes_megabytes(self):
        """Test format_bytes for megabyte-level values."""
        stats = ScanStats()
        result = stats.format_bytes(5 * 1024 * 1024)
        assert "MB" in result
        assert "5.0" in result

    def test_format_bytes_gigabytes(self):
        """Test format_bytes for gigabyte-level values."""
        stats = ScanStats()
        result = stats.format_bytes(2 * 1024 * 1024 * 1024)
        assert "GB" in result
        assert "2.0" in result

    def test_format_bytes_uses_total_by_default(self):
        """Test format_bytes uses total_bytes_processed when no arg given."""
        stats = ScanStats()
        stats.total_bytes_processed = 5120
        result = stats.format_bytes()
        assert "KB" in result

    def test_format_throughput(self):
        """Test format_throughput formatting."""
        stats = ScanStats()
        stats.scan_start_time = time.time() - 1.0
        stats.scan_end_time = time.time()
        stats.total_files_scanned = 100
        stats.total_bytes_processed = 1024 * 1024  # 1 MB

        formatted = stats.format_throughput()
        assert "files/s" in formatted
        assert "/s" in formatted  # bytes per second

    def test_str_representation(self):
        """Test __str__ returns readable summary."""
        stats = ScanStats()
        stats.start()
        stats.set_discovered_files(100)
        stats.add_scanned_file("/test.py", 2048)
        stats.add_skipped_file("/skip.py", SkipReason.BLACKLISTED)
        stats.add_finding("RegexDetector", "high")
        stats.stop()

        output = str(stats)

        assert "Scan Statistics" in output
        assert "Files:" in output
        assert "Bytes:" in output
        assert "Findings:" in output
        assert "Duration:" in output
        assert "Throughput:" in output


class TestScanStatsEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_stats_serialization(self):
        """Test that empty stats serialize correctly."""
        stats = ScanStats()
        summary = stats.get_summary()
        full = stats.to_dict()

        assert summary["total_files_discovered"] == 0
        assert summary["scan_duration"] == 0.0
        assert full["skipped_files"] == []
        assert full["errors"] == []

    def test_large_byte_counts(self):
        """Test handling of large byte counts."""
        stats = ScanStats()
        large_count = 10 * 1024 * 1024 * 1024  # 10 GB
        stats.add_scanned_file("/large.bin", large_count)

        assert stats.total_bytes_processed == large_count
        formatted = stats.format_bytes()
        assert "GB" in formatted

    def test_many_findings(self):
        """Test handling of many findings."""
        stats = ScanStats()
        for i in range(1000):
            detector = f"Detector{i % 5}"
            severity = ["low", "medium", "high", "critical", "info"][i % 5]
            stats.add_finding(detector, severity)

        assert stats.total_findings == 1000
        assert sum(stats.findings_by_detector.values()) == 1000
        assert sum(stats.findings_by_severity.values()) == 1000

    def test_many_skipped_files(self):
        """Test handling of many skipped files."""
        stats = ScanStats()
        reasons = list(SkipReason)
        for i in range(500):
            reason = reasons[i % len(reasons)]
            stats.add_skipped_file(f"/file{i}.txt", reason)

        assert stats.total_files_skipped == 500
        by_reason = stats.skipped_by_reason
        assert sum(by_reason.values()) == 500

    def test_concurrent_operations(self):
        """Test that merge doesn't corrupt state."""
        stats1 = ScanStats()
        stats2 = ScanStats()

        # Populate both
        for i in range(100):
            stats1.add_finding("DetectorA", "high")
            stats2.add_finding("DetectorB", "low")

        original_total = stats1.total_findings
        stats1.merge(stats2)

        assert stats1.total_findings == original_total + 100
        assert stats2.total_findings == 100  # stats2 unchanged
