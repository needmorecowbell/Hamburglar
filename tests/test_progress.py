"""Tests for the progress module.

This module tests the ScanProgress dataclass and ProgressReporter protocol,
including the NullProgressReporter and CallbackProgressReporter implementations.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.progress import (  # noqa: E402
    CallbackProgressReporter,
    NullProgressReporter,
    ProgressReporter,
    ScanProgress,
)


class TestScanProgress:
    """Tests for the ScanProgress dataclass."""

    def test_basic_initialization(self) -> None:
        """Test basic ScanProgress initialization."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=25,
            current_file="/path/to/file.txt",
            bytes_processed=1024000,
            findings_count=5,
            elapsed_time=2.5,
        )

        assert progress.total_files == 100
        assert progress.scanned_files == 25
        assert progress.current_file == "/path/to/file.txt"
        assert progress.bytes_processed == 1024000
        assert progress.findings_count == 5
        assert progress.elapsed_time == 2.5

    def test_default_values(self) -> None:
        """Test that ScanProgress has sensible default values."""
        progress = ScanProgress()

        assert progress.total_files == 0
        assert progress.scanned_files == 0
        assert progress.current_file == ""
        assert progress.bytes_processed == 0
        assert progress.findings_count == 0
        assert progress.elapsed_time == 0.0

    def test_files_remaining_computed(self) -> None:
        """Test that files_remaining is computed correctly."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=25,
        )

        assert progress.files_remaining == 75

    def test_files_remaining_at_start(self) -> None:
        """Test files_remaining when no files are scanned."""
        progress = ScanProgress(total_files=50, scanned_files=0)

        assert progress.files_remaining == 50

    def test_files_remaining_at_end(self) -> None:
        """Test files_remaining when all files are scanned."""
        progress = ScanProgress(total_files=50, scanned_files=50)

        assert progress.files_remaining == 0

    def test_percent_complete(self) -> None:
        """Test percent_complete calculation."""
        progress = ScanProgress(total_files=100, scanned_files=25)

        assert progress.percent_complete == 25.0

    def test_percent_complete_zero_files(self) -> None:
        """Test percent_complete when there are no files."""
        progress = ScanProgress(total_files=0, scanned_files=0)

        assert progress.percent_complete == 0.0

    def test_percent_complete_all_done(self) -> None:
        """Test percent_complete when all files are scanned."""
        progress = ScanProgress(total_files=100, scanned_files=100)

        assert progress.percent_complete == 100.0

    def test_percent_complete_partial(self) -> None:
        """Test percent_complete with non-round numbers."""
        progress = ScanProgress(total_files=3, scanned_files=1)

        assert abs(progress.percent_complete - 33.333333) < 0.001

    def test_files_per_second(self) -> None:
        """Test files_per_second calculation."""
        progress = ScanProgress(
            scanned_files=100,
            elapsed_time=10.0,
        )

        assert progress.files_per_second == 10.0

    def test_files_per_second_no_elapsed_time(self) -> None:
        """Test files_per_second when no time has elapsed."""
        progress = ScanProgress(
            scanned_files=100,
            elapsed_time=0.0,
        )

        assert progress.files_per_second == 0.0

    def test_files_per_second_negative_time(self) -> None:
        """Test files_per_second handles negative time gracefully."""
        progress = ScanProgress(
            scanned_files=100,
            elapsed_time=-1.0,
        )

        assert progress.files_per_second == 0.0

    def test_bytes_per_second(self) -> None:
        """Test bytes_per_second calculation."""
        progress = ScanProgress(
            bytes_processed=10240000,  # 10 MB
            elapsed_time=10.0,
        )

        assert progress.bytes_per_second == 1024000.0  # 1 MB/s

    def test_bytes_per_second_no_elapsed_time(self) -> None:
        """Test bytes_per_second when no time has elapsed."""
        progress = ScanProgress(
            bytes_processed=10240000,
            elapsed_time=0.0,
        )

        assert progress.bytes_per_second == 0.0

    def test_estimated_time_remaining(self) -> None:
        """Test estimated_time_remaining calculation."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=50,
            elapsed_time=10.0,  # 50 files in 10 seconds = 0.2 sec/file
        )

        # 50 remaining files * 0.2 sec/file = 10 seconds
        assert progress.estimated_time_remaining == 10.0

    def test_estimated_time_remaining_no_files_scanned(self) -> None:
        """Test estimated_time_remaining when no files are scanned."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=0,
            elapsed_time=1.0,
        )

        assert progress.estimated_time_remaining is None

    def test_estimated_time_remaining_no_files_remaining(self) -> None:
        """Test estimated_time_remaining when all files are done."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=100,
            elapsed_time=10.0,
        )

        assert progress.estimated_time_remaining is None

    def test_to_dict(self) -> None:
        """Test to_dict method returns all expected fields."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=50,
            current_file="/path/to/file.txt",
            bytes_processed=1024000,
            findings_count=5,
            elapsed_time=10.0,
        )

        result = progress.to_dict()

        assert result["total_files"] == 100
        assert result["scanned_files"] == 50
        assert result["current_file"] == "/path/to/file.txt"
        assert result["bytes_processed"] == 1024000
        assert result["findings_count"] == 5
        assert result["elapsed_time"] == 10.0
        assert result["files_remaining"] == 50
        assert result["percent_complete"] == 50.0
        assert result["files_per_second"] == 5.0
        assert result["bytes_per_second"] == 102400.0
        assert result["estimated_time_remaining"] == 10.0

    def test_to_dict_with_none_estimate(self) -> None:
        """Test to_dict when estimated_time_remaining is None."""
        progress = ScanProgress(
            total_files=100,
            scanned_files=0,
            elapsed_time=0.0,
        )

        result = progress.to_dict()

        assert result["estimated_time_remaining"] is None


class TestProgressReporterProtocol:
    """Tests for the ProgressReporter protocol."""

    def test_null_reporter_is_progress_reporter(self) -> None:
        """Test that NullProgressReporter implements ProgressReporter."""
        reporter = NullProgressReporter()
        assert isinstance(reporter, ProgressReporter)

    def test_callback_reporter_is_progress_reporter(self) -> None:
        """Test that CallbackProgressReporter implements ProgressReporter."""
        reporter = CallbackProgressReporter()
        assert isinstance(reporter, ProgressReporter)

    def test_custom_class_can_implement_protocol(self) -> None:
        """Test that a custom class can implement ProgressReporter."""

        class CustomReporter:
            def on_progress(self, progress: ScanProgress) -> None:
                pass

            def on_start(self, total_files: int) -> None:
                pass

            def on_complete(self, progress: ScanProgress) -> None:
                pass

            def on_error(self, error: str, file_path: str | None = None) -> None:
                pass

        reporter = CustomReporter()
        assert isinstance(reporter, ProgressReporter)


class TestNullProgressReporter:
    """Tests for NullProgressReporter."""

    def test_on_progress_does_nothing(self) -> None:
        """Test that on_progress does nothing."""
        reporter = NullProgressReporter()
        progress = ScanProgress(total_files=100, scanned_files=50)

        # Should not raise
        reporter.on_progress(progress)

    def test_on_start_does_nothing(self) -> None:
        """Test that on_start does nothing."""
        reporter = NullProgressReporter()

        # Should not raise
        reporter.on_start(100)

    def test_on_complete_does_nothing(self) -> None:
        """Test that on_complete does nothing."""
        reporter = NullProgressReporter()
        progress = ScanProgress(total_files=100, scanned_files=100)

        # Should not raise
        reporter.on_complete(progress)

    def test_on_error_does_nothing(self) -> None:
        """Test that on_error does nothing."""
        reporter = NullProgressReporter()

        # Should not raise
        reporter.on_error("Some error")
        reporter.on_error("Some error", "/path/to/file.txt")


class TestCallbackProgressReporter:
    """Tests for CallbackProgressReporter."""

    def test_progress_callback_called(self) -> None:
        """Test that progress callback is called."""
        called_with: list[ScanProgress] = []

        def callback(progress: ScanProgress) -> None:
            called_with.append(progress)

        reporter = CallbackProgressReporter(progress_callback=callback)
        progress = ScanProgress(total_files=100, scanned_files=50)

        reporter.on_progress(progress)

        assert len(called_with) == 1
        assert called_with[0] is progress

    def test_progress_callback_not_called_if_none(self) -> None:
        """Test that no error occurs if progress callback is None."""
        reporter = CallbackProgressReporter(progress_callback=None)
        progress = ScanProgress(total_files=100, scanned_files=50)

        # Should not raise
        reporter.on_progress(progress)

    def test_start_callback_called(self) -> None:
        """Test that start callback is called."""
        called_with: list[int] = []

        def callback(total_files: int) -> None:
            called_with.append(total_files)

        reporter = CallbackProgressReporter(start_callback=callback)

        reporter.on_start(100)

        assert len(called_with) == 1
        assert called_with[0] == 100

    def test_start_callback_not_called_if_none(self) -> None:
        """Test that no error occurs if start callback is None."""
        reporter = CallbackProgressReporter(start_callback=None)

        # Should not raise
        reporter.on_start(100)

    def test_complete_callback_called(self) -> None:
        """Test that complete callback is called."""
        called_with: list[ScanProgress] = []

        def callback(progress: ScanProgress) -> None:
            called_with.append(progress)

        reporter = CallbackProgressReporter(complete_callback=callback)
        progress = ScanProgress(total_files=100, scanned_files=100)

        reporter.on_complete(progress)

        assert len(called_with) == 1
        assert called_with[0] is progress

    def test_complete_callback_not_called_if_none(self) -> None:
        """Test that no error occurs if complete callback is None."""
        reporter = CallbackProgressReporter(complete_callback=None)
        progress = ScanProgress(total_files=100, scanned_files=100)

        # Should not raise
        reporter.on_complete(progress)

    def test_error_callback_called(self) -> None:
        """Test that error callback is called."""
        called_with: list[tuple[str, str | None]] = []

        def callback(error: str, file_path: str | None) -> None:
            called_with.append((error, file_path))

        reporter = CallbackProgressReporter(error_callback=callback)

        reporter.on_error("Some error", "/path/to/file.txt")

        assert len(called_with) == 1
        assert called_with[0] == ("Some error", "/path/to/file.txt")

    def test_error_callback_called_without_file_path(self) -> None:
        """Test that error callback is called without file path."""
        called_with: list[tuple[str, str | None]] = []

        def callback(error: str, file_path: str | None) -> None:
            called_with.append((error, file_path))

        reporter = CallbackProgressReporter(error_callback=callback)

        reporter.on_error("Some error")

        assert len(called_with) == 1
        assert called_with[0] == ("Some error", None)

    def test_error_callback_not_called_if_none(self) -> None:
        """Test that no error occurs if error callback is None."""
        reporter = CallbackProgressReporter(error_callback=None)

        # Should not raise
        reporter.on_error("Some error")
        reporter.on_error("Some error", "/path/to/file.txt")

    def test_all_callbacks_work_together(self) -> None:
        """Test that all callbacks can be used together."""
        progress_calls: list[ScanProgress] = []
        start_calls: list[int] = []
        complete_calls: list[ScanProgress] = []
        error_calls: list[tuple[str, str | None]] = []

        reporter = CallbackProgressReporter(
            progress_callback=lambda p: progress_calls.append(p),
            start_callback=lambda t: start_calls.append(t),
            complete_callback=lambda p: complete_calls.append(p),
            error_callback=lambda e, f: error_calls.append((e, f)),
        )

        # Simulate a scan lifecycle
        reporter.on_start(100)
        reporter.on_progress(ScanProgress(total_files=100, scanned_files=25))
        reporter.on_error("Warning", "/some/file.txt")
        reporter.on_progress(ScanProgress(total_files=100, scanned_files=50))
        reporter.on_complete(ScanProgress(total_files=100, scanned_files=100))

        assert len(start_calls) == 1
        assert start_calls[0] == 100
        assert len(progress_calls) == 2
        assert len(error_calls) == 1
        assert len(complete_calls) == 1

    def test_default_initialization_with_no_callbacks(self) -> None:
        """Test that CallbackProgressReporter works with no callbacks."""
        reporter = CallbackProgressReporter()

        # All methods should work without raising
        reporter.on_start(100)
        reporter.on_progress(ScanProgress(total_files=100, scanned_files=50))
        reporter.on_error("Some error")
        reporter.on_complete(ScanProgress(total_files=100, scanned_files=100))


class TestImportsFromCore:
    """Tests for imports from hamburglar.core."""

    def test_imports_from_core_init(self) -> None:
        """Test that progress classes can be imported from hamburglar.core."""
        from hamburglar.core import (
            CallbackProgressReporter,
            NullProgressReporter,
            ProgressReporter,
            ScanProgress,
        )

        # Verify they are the correct types
        assert ScanProgress is not None
        assert ProgressReporter is not None
        assert NullProgressReporter is not None
        assert CallbackProgressReporter is not None


class TestScanProgressEdgeCases:
    """Edge case tests for ScanProgress."""

    def test_large_numbers(self) -> None:
        """Test ScanProgress with large numbers."""
        progress = ScanProgress(
            total_files=1_000_000,
            scanned_files=500_000,
            bytes_processed=10_000_000_000_000,  # 10 TB
            findings_count=1_000_000,
            elapsed_time=3600.0,  # 1 hour
        )

        assert progress.files_remaining == 500_000
        assert progress.percent_complete == 50.0
        assert progress.files_per_second == pytest.approx(138.888888, rel=0.01)

    def test_very_small_elapsed_time(self) -> None:
        """Test calculations with very small elapsed time."""
        progress = ScanProgress(
            scanned_files=1,
            elapsed_time=0.001,  # 1 millisecond
        )

        assert progress.files_per_second == 1000.0

    def test_high_precision_elapsed_time(self) -> None:
        """Test with high precision elapsed time."""
        progress = ScanProgress(
            scanned_files=1,
            bytes_processed=1024,
            elapsed_time=0.123456789,
        )

        assert progress.files_per_second == pytest.approx(8.1, rel=0.1)
        assert progress.bytes_per_second == pytest.approx(8294.4, rel=0.1)

    def test_zero_files_edge_cases(self) -> None:
        """Test behavior with zero total files."""
        progress = ScanProgress(total_files=0, scanned_files=0)

        assert progress.files_remaining == 0
        assert progress.percent_complete == 0.0
        assert progress.estimated_time_remaining is None
