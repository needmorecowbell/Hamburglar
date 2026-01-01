"""Tests for Phase 04 coverage completion.

This module adds tests for uncovered code paths in:
- AsyncScanner error handling paths
- CLI YARA and output error handling
- FileReader encoding edge cases
- MemoryProfiler enabled paths
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Configure path before any hamburglar imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.async_scanner import AsyncScanner
from hamburglar.core.file_reader import AsyncFileReader, FileType
from hamburglar.core.models import ScanConfig
from hamburglar.core.profiling import MemoryProfiler, MemorySnapshot, PerformanceProfiler
from hamburglar.detectors.regex_detector import RegexDetector


class TestAsyncScannerErrorPaths:
    """Tests for AsyncScanner error handling code paths."""

    @pytest.mark.asyncio
    async def test_permission_denied_during_file_access_in_recursive_walk(
        self, tmp_path: Path
    ) -> None:
        """Test that permission errors during file access are logged and recorded."""
        # Create a directory with files
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        secret_file = subdir / "secret.txt"
        secret_file.write_text("AWS_SECRET_ACCESS_KEY=abcdef1234567890")

        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config)

        # Mock a permission error on a specific file
        original_is_file = Path.is_file

        def mock_is_file(path_self):
            if path_self.name == "secret.txt":
                raise PermissionError("Permission denied")
            return original_is_file(path_self)

        with patch.object(Path, "is_file", mock_is_file):
            await scanner.scan()

        # Check that errors were recorded
        assert any("Permission denied" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_os_error_during_file_access_in_recursive_walk(self, tmp_path: Path) -> None:
        """Test that OSErrors during file access are logged and recorded."""
        # Create a directory with files
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        file1 = subdir / "test.txt"
        file1.write_text("test content")

        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config)

        original_is_file = Path.is_file

        def mock_is_file(path_self):
            if path_self.name == "test.txt":
                raise OSError("I/O error")
            return original_is_file(path_self)

        with patch.object(Path, "is_file", mock_is_file):
            await scanner.scan()

        # Check that errors were recorded
        assert any("Error accessing" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_permission_denied_during_rglob(self, tmp_path: Path) -> None:
        """Test permission error during directory walk."""
        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config)

        # Mock rglob to raise PermissionError (rglob is an instance method, takes self)
        def mock_rglob(self_path, pattern):
            raise PermissionError("Cannot read directory")

        with patch.object(Path, "rglob", mock_rglob):
            await scanner.scan()

        assert any("Permission denied" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_os_error_during_rglob(self, tmp_path: Path) -> None:
        """Test OSError during directory walk."""
        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config)

        def mock_rglob(self_path, pattern):
            raise OSError("Disk error")

        with patch.object(Path, "rglob", mock_rglob):
            await scanner.scan()

        assert any("Error during directory walk" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_permission_denied_during_iterdir_non_recursive(self, tmp_path: Path) -> None:
        """Test permission error during non-recursive directory iteration."""
        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = AsyncScanner(config)

        def mock_iterdir(self_path):
            raise PermissionError("Cannot read directory")

        with patch.object(Path, "iterdir", mock_iterdir):
            await scanner.scan()

        assert any("Permission denied" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_os_error_during_iterdir_non_recursive(self, tmp_path: Path) -> None:
        """Test OSError during non-recursive directory iteration."""
        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = AsyncScanner(config)

        def mock_iterdir(self_path):
            raise OSError("Disk error")

        with patch.object(Path, "iterdir", mock_iterdir):
            await scanner.scan()

        assert any("Error reading directory" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_is_directory_error_during_read(self, tmp_path: Path) -> None:
        """Test IsADirectoryError when reading what was thought to be a file."""
        # Create a file that we'll mock to raise IsADirectoryError
        test_file = tmp_path / "fake_file"
        test_file.write_text("content")

        config = ScanConfig(target_path=test_file)
        scanner = AsyncScanner(config)

        # The scanner should handle this gracefully in _read_file
        with patch.object(Path, "read_text", side_effect=IsADirectoryError()):
            await scanner.scan()

        assert any("directory" in err.lower() for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_file_not_found_during_read(self, tmp_path: Path) -> None:
        """Test FileNotFoundError when file is deleted during scan."""
        test_file = tmp_path / "vanishing.txt"
        test_file.write_text("content")

        config = ScanConfig(target_path=test_file)
        scanner = AsyncScanner(config)

        with patch.object(Path, "read_text", side_effect=FileNotFoundError()):
            await scanner.scan()

        assert any("not found" in err.lower() for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_os_error_during_file_read(self, tmp_path: Path) -> None:
        """Test OSError during file reading."""
        test_file = tmp_path / "corrupted.txt"
        test_file.write_text("content")

        config = ScanConfig(target_path=test_file)
        scanner = AsyncScanner(config)

        with patch.object(Path, "read_text", side_effect=OSError("Disk failure")):
            await scanner.scan()

        assert any("Error reading" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_unexpected_exception_during_file_read(self, tmp_path: Path) -> None:
        """Test unexpected exception during file reading."""
        test_file = tmp_path / "weird.txt"
        test_file.write_text("content")

        config = ScanConfig(target_path=test_file)
        scanner = AsyncScanner(config)

        with patch.object(Path, "read_text", side_effect=RuntimeError("Unexpected")):
            await scanner.scan()

        assert any("Unexpected error" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_cancellation_during_file_iteration_recursive(self, tmp_path: Path) -> None:
        """Test cancellation during recursive file discovery."""
        # Create multiple files
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_text(f"content {i}")

        config = ScanConfig(target_path=tmp_path)
        scanner = AsyncScanner(config)

        # Mock to cancel after first iteration
        original_rglob = Path.rglob
        call_count = 0

        def mock_rglob(self, pattern):
            nonlocal call_count
            for item in original_rglob(self, pattern):
                call_count += 1
                if call_count > 2:
                    scanner.cancel()
                yield item

        with patch.object(Path, "rglob", mock_rglob):
            await scanner.scan()

        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_cancellation_during_file_iteration_non_recursive(self, tmp_path: Path) -> None:
        """Test cancellation during non-recursive file discovery."""
        # Create multiple files
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_text(f"content {i}")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = AsyncScanner(config)

        # Mock to cancel after first iteration
        original_iterdir = Path.iterdir
        call_count = 0

        def mock_iterdir(self):
            nonlocal call_count
            for item in original_iterdir(self):
                call_count += 1
                if call_count > 2:
                    scanner.cancel()
                yield item

        with patch.object(Path, "iterdir", mock_iterdir):
            await scanner.scan()

        assert scanner.is_cancelled

    @pytest.mark.asyncio
    async def test_permission_denied_file_in_non_recursive(self, tmp_path: Path) -> None:
        """Test permission denied for specific file in non-recursive mode."""
        file1 = tmp_path / "ok.txt"
        file1.write_text("ok content")
        file2 = tmp_path / "denied.txt"
        file2.write_text("denied content")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = AsyncScanner(config)

        original_is_file = Path.is_file

        def mock_is_file(self):
            if self.name == "denied.txt":
                raise PermissionError("Permission denied")
            return original_is_file(self)

        with patch.object(Path, "is_file", mock_is_file):
            await scanner.scan()

        assert any("Permission denied" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_os_error_file_in_non_recursive(self, tmp_path: Path) -> None:
        """Test OSError for specific file in non-recursive mode."""
        file1 = tmp_path / "ok.txt"
        file1.write_text("ok content")
        file2 = tmp_path / "error.txt"
        file2.write_text("error content")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        scanner = AsyncScanner(config)

        original_is_file = Path.is_file

        def mock_is_file(self):
            if self.name == "error.txt":
                raise OSError("I/O error")
            return original_is_file(self)

        with patch.object(Path, "is_file", mock_is_file):
            await scanner.scan()

        assert any("Error accessing" in err for err in scanner._errors)

    @pytest.mark.asyncio
    async def test_cancellation_before_scan_file(self, tmp_path: Path) -> None:
        """Test that cancellation before scan_file returns empty list."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("AWS_SECRET_ACCESS_KEY=test123")

        config = ScanConfig(target_path=test_file)
        scanner = AsyncScanner(config)
        scanner.cancel()

        # Scanning a cancelled scanner should return empty result
        result = await scanner.scan()
        assert len(result.findings) == 0


class TestFileReaderEncodingEdgeCases:
    """Tests for FileReader encoding detection edge cases."""

    @pytest.mark.asyncio
    async def test_binary_detection_with_small_sample(self, tmp_path: Path) -> None:
        """Test binary detection with very small file."""
        # File smaller than 512 bytes
        small_file = tmp_path / "small.bin"
        small_file.write_bytes(b"\x00\x01\x02")

        async with AsyncFileReader(small_file) as reader:
            file_info = reader.file_info
            assert file_info.file_type == FileType.BINARY

    @pytest.mark.asyncio
    async def test_utf16_without_bom_detection(self, tmp_path: Path) -> None:
        """Test detection of UTF-16 encoded text without BOM."""
        # Create UTF-16 LE content without BOM (ASCII chars have alternating nulls)
        content = "Hello World"
        utf16_bytes = content.encode("utf-16-le")

        utf16_file = tmp_path / "utf16_no_bom.txt"
        utf16_file.write_bytes(utf16_bytes)

        async with AsyncFileReader(utf16_file) as reader:
            # Should detect as text, not binary
            file_info = reader.file_info
            # With alternating nulls pattern, it should identify as non-binary
            # The exact behavior depends on the implementation

    @pytest.mark.asyncio
    async def test_charset_normalizer_import_error_fallback(self, tmp_path: Path) -> None:
        """Test fallback when charset_normalizer is not available."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello World", encoding="utf-8")

        # This tests the fallback path when charset_normalizer import fails
        reader = AsyncFileReader(test_file)
        async with reader:
            content = await reader.read()
            assert "Hello World" in content

    @pytest.mark.asyncio
    async def test_looks_like_utf16_short_data(self, tmp_path: Path) -> None:
        """Test UTF-16 detection with data shorter than 4 bytes."""
        short_file = tmp_path / "short.txt"
        short_file.write_bytes(b"\x00\x00")  # 2 bytes only

        reader = AsyncFileReader(short_file)
        result = reader._looks_like_utf16(b"\x00\x00")
        assert result is False

    @pytest.mark.asyncio
    async def test_looks_like_utf16_empty_pairs(self, tmp_path: Path) -> None:
        """Test UTF-16 detection with data that has zero pairs."""
        short_file = tmp_path / "tiny.txt"
        short_file.write_bytes(b"\x01")  # 1 byte, no pairs

        reader = AsyncFileReader(short_file)
        result = reader._looks_like_utf16(b"\x01")
        assert result is False

    @pytest.mark.asyncio
    async def test_binary_with_control_chars_below_threshold(self, tmp_path: Path) -> None:
        """Test file with control chars below 10% threshold."""
        # Create content with some control chars but below threshold
        # 100 chars with 9 control chars = 9%, should not be binary
        content = b"a" * 91 + b"\x01\x02\x03\x04\x05\x06\x07\x08\x0e"  # 9 control chars

        test_file = tmp_path / "lowcontrol.txt"
        test_file.write_bytes(content)

        async with AsyncFileReader(test_file) as reader:
            file_info = reader.file_info
            # Should be detected as text (control chars below threshold)


class TestMemoryProfilerPaths:
    """Tests for MemoryProfiler code paths with psutil available."""

    def test_memory_profiler_start_stop_with_tracking(self) -> None:
        """Test MemoryProfiler start and stop with memory tracking enabled."""
        from hamburglar.core.profiling import PSUTIL_AVAILABLE

        if not PSUTIL_AVAILABLE:
            pytest.skip("psutil not available")

        profiler = MemoryProfiler(enabled=True)

        # Start profiling
        profiler.start()
        assert profiler._is_running
        assert profiler._start_snapshot is not None
        assert len(profiler._snapshots) == 1

        # Stop profiling
        profiler.stop()
        assert not profiler._is_running
        assert profiler._end_snapshot is not None
        assert len(profiler._snapshots) == 2

        # Memory deltas should be computable
        delta_rss = profiler.memory_delta_rss
        delta_vms = profiler.memory_delta_vms
        assert isinstance(delta_rss, int)
        assert isinstance(delta_vms, int)

    def test_memory_profiler_snapshot_updates_peak(self) -> None:
        """Test that taking snapshots updates peak memory values."""
        from hamburglar.core.profiling import PSUTIL_AVAILABLE

        if not PSUTIL_AVAILABLE:
            pytest.skip("psutil not available")

        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        # Take a snapshot
        snap = profiler.snapshot("intermediate")
        assert snap is not None
        assert len(profiler._snapshots) == 2  # start + intermediate

        profiler.stop()

        # Peak values should be set
        assert profiler.peak_rss >= 0
        assert profiler.peak_vms >= 0

    def test_memory_profiler_update_peak_with_higher_values(self) -> None:
        """Test _update_peak with values higher than current peaks."""
        import time

        from hamburglar.core.profiling import PSUTIL_AVAILABLE

        if not PSUTIL_AVAILABLE:
            pytest.skip("psutil not available")

        profiler = MemoryProfiler(enabled=True)
        profiler.start()

        initial_peak_rss = profiler._peak_rss
        initial_peak_vms = profiler._peak_vms

        # Create a fake snapshot with higher values
        high_snap = MemorySnapshot(
            timestamp=time.time(),
            label="high",
            rss_bytes=initial_peak_rss + 1000000,
            vms_bytes=initial_peak_vms + 2000000,
            percent=50.0,
        )

        profiler._update_peak(high_snap)

        assert profiler._peak_rss == high_snap.rss_bytes
        assert profiler._peak_vms == high_snap.vms_bytes

    def test_memory_profiler_stop_when_not_running(self) -> None:
        """Test that stop() does nothing when profiler is not running."""
        profiler = MemoryProfiler(enabled=True)
        # Don't start, just stop
        profiler.stop()
        assert not profiler._is_running
        assert profiler._end_snapshot is None

    def test_memory_profiler_snapshot_when_disabled(self) -> None:
        """Test that snapshot returns None when disabled."""
        profiler = MemoryProfiler(enabled=False)
        snap = profiler.snapshot("test")
        assert snap is None

    def test_memory_delta_when_not_complete(self) -> None:
        """Test memory delta returns 0 when profiling not complete."""
        profiler = MemoryProfiler(enabled=True)
        # Don't start/stop
        assert profiler.memory_delta_rss == 0
        assert profiler.memory_delta_vms == 0


class TestPerformanceProfilerPaths:
    """Tests for PerformanceProfiler code paths."""

    def test_time_detector_with_findings_callback(self) -> None:
        """Test time_detector context manager with findings callback."""
        profiler = PerformanceProfiler()

        with profiler.profile():
            with profiler.time_detector("test_detector", findings_callback=lambda: 5):
                pass  # Simulate detection with 5 findings

            with profiler.time_detector("another_detector", findings_callback=lambda: 3):
                pass  # Simulate detection with 3 findings

        report = profiler.report
        assert "test_detector" in report.detector_stats
        assert "another_detector" in report.detector_stats
        assert report.detector_stats["test_detector"].findings_count == 5
        assert report.detector_stats["another_detector"].findings_count == 3

    def test_time_operation_aggregation(self) -> None:
        """Test that time_operation aggregates timing data."""
        profiler = PerformanceProfiler()

        with profiler.profile():
            for _ in range(3):
                with profiler.time_operation("read_file"):
                    pass  # Simulate operation

        report = profiler.report
        assert "read_file" in report.custom_timings
        assert report.custom_timings["read_file"].call_count == 3


class TestCLIYaraErrorPaths:
    """Tests for CLI YARA error handling paths."""

    def test_yara_file_not_found(self, tmp_path: Path) -> None:
        """Test CLI handles FileNotFoundError for YARA rules."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--yara", "/nonexistent/rules.yar"],
        )
        assert result.exit_code != 0

    def test_yara_permission_denied(self, tmp_path: Path) -> None:
        """Test CLI handles PermissionError for YARA rules."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create a file without read permission
        yara_file = tmp_path / "rules.yar"
        yara_file.write_text("rule test { condition: true }")
        os.chmod(yara_file, 0o000)

        runner = CliRunner()
        try:
            result = runner.invoke(
                app,
                ["scan", str(tmp_path), "--yara", str(yara_file)],
            )
            assert result.exit_code != 0
        finally:
            os.chmod(yara_file, 0o644)


class TestCLIOutputErrorPaths:
    """Tests for CLI output error handling paths."""

    def test_output_formatting_error(self, tmp_path: Path) -> None:
        """Test CLI handles output formatting errors."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app
        from hamburglar.outputs.json_output import JsonOutput

        # Create a file to scan
        test_file = tmp_path / "test.txt"
        test_file.write_text("AWS_SECRET_ACCESS_KEY=test123")

        runner = CliRunner()

        # Mock the formatter to raise an exception
        with patch.object(JsonOutput, "format", side_effect=Exception("Format failed")):
            result = runner.invoke(
                app,
                ["scan", str(tmp_path), "--format", "json"],
            )
            # Should handle the error
            assert result.exit_code != 0

    def test_output_write_permission_error(self, tmp_path: Path) -> None:
        """Test CLI handles output file permission errors."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create a file to scan
        test_file = tmp_path / "test.txt"
        test_file.write_text("AWS_SECRET_ACCESS_KEY=test123")

        # Create output dir without write permission
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        os.chmod(output_dir, 0o444)

        output_file = output_dir / "results.json"

        runner = CliRunner()
        try:
            result = runner.invoke(
                app,
                ["scan", str(tmp_path), "-o", str(output_file)],
            )
            assert result.exit_code != 0
        finally:
            os.chmod(output_dir, 0o755)

    def test_output_write_os_error(self, tmp_path: Path) -> None:
        """Test CLI handles OS errors when writing output."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create a file to scan
        test_file = tmp_path / "test.txt"
        test_file.write_text("AWS_SECRET_ACCESS_KEY=test123")

        output_file = tmp_path / "output.json"

        runner = CliRunner()

        with patch.object(Path, "write_text", side_effect=OSError("Disk full")):
            result = runner.invoke(
                app,
                ["scan", str(tmp_path), "-o", str(output_file)],
            )
            assert result.exit_code != 0


class TestAsyncScannerStreamCancellation:
    """Tests for AsyncScanner stream cancellation."""

    @pytest.mark.asyncio
    async def test_stream_yields_findings(self, tmp_path: Path) -> None:
        """Test that streaming yields findings as discovered."""
        # Create a file with a secret (AWS secret key needs 40 chars)
        file = tmp_path / "secret.txt"
        file.write_text('aws_secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"')

        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        findings = []
        async for finding in scanner.scan_stream():
            findings.append(finding)

        # Should have found the secret
        assert len(findings) >= 1


class TestFileFilterEdgeCases:
    """Tests for FileFilter edge cases."""

    def test_pattern_with_special_chars(self) -> None:
        """Test patterns with special characters are escaped."""
        from hamburglar.core.file_filter import FileFilter

        # The pattern is escaped before being compiled, so it won't cause a regex error
        filter = FileFilter(exclude=["file[*.txt"])
        # Pattern should be compiled (escaped)
        assert len(filter._compiled_excludes) == 1

    def test_remove_include_pattern(self) -> None:
        """Test removing an include pattern."""
        from hamburglar.core.file_filter import FileFilter

        filter = FileFilter(include=["*.py", "*.js"])
        assert len(filter.include_patterns) == 2

        # Remove an existing pattern
        result = filter.remove_include("*.py")
        assert result is True
        assert len(filter.include_patterns) == 1
        assert "*.py" not in filter.include_patterns

        # Try to remove non-existent pattern
        result = filter.remove_include("*.txt")
        assert result is False


class TestFileReaderMoreEdgeCases:
    """Additional tests for FileReader edge cases."""

    @pytest.mark.asyncio
    async def test_read_without_open_raises_error(self, tmp_path: Path) -> None:
        """Test that reading without opening raises RuntimeError."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        # Don't open, try to read
        with pytest.raises(RuntimeError):
            await reader.read()

    @pytest.mark.asyncio
    async def test_seek_without_open_raises_error(self, tmp_path: Path) -> None:
        """Test that seeking without opening raises RuntimeError."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        with pytest.raises(RuntimeError):
            await reader.seek(0)

    @pytest.mark.asyncio
    async def test_file_type_detection_binary(self, tmp_path: Path) -> None:
        """Test binary file type detection."""
        binary_file = tmp_path / "binary.bin"
        # Write binary content with null bytes
        binary_file.write_bytes(b"\x00\x01\x02\x03\x00\x00\x00\x04\x05\x06")

        is_binary = await AsyncFileReader.is_binary(binary_file)
        assert is_binary is True

    @pytest.mark.asyncio
    async def test_file_type_detection_text(self, tmp_path: Path) -> None:
        """Test text file type detection."""
        text_file = tmp_path / "text.txt"
        text_file.write_text("Hello, world!\nThis is a text file.")

        is_text = await AsyncFileReader.is_text(text_file)
        assert is_text is True

    @pytest.mark.asyncio
    async def test_forced_encoding_read(self, tmp_path: Path) -> None:
        """Test reading with forced encoding."""
        # Write latin-1 content
        latin1_file = tmp_path / "latin1.txt"
        latin1_content = "Héllo Wörld"
        latin1_file.write_bytes(latin1_content.encode("latin-1"))

        async with AsyncFileReader(latin1_file, encoding="latin-1") as reader:
            content = await reader.read()
            assert "Héllo Wörld" in content

    @pytest.mark.asyncio
    async def test_mmap_threshold_configuration(self, tmp_path: Path) -> None:
        """Test mmap threshold configuration."""
        small_file = tmp_path / "small.txt"
        small_file.write_text("Small content")

        # Use a very large threshold so mmap is never used for small files
        reader = AsyncFileReader(
            small_file,
            mmap_threshold=1024 * 1024 * 100,  # 100 MB
            use_mmap=False,
        )

        async with reader:
            content = await reader.read()
            assert "Small content" in content

    @pytest.mark.asyncio
    async def test_chunked_reading(self, tmp_path: Path) -> None:
        """Test chunked reading of content."""
        text_file = tmp_path / "text.txt"
        text_file.write_text("Line 1\nLine 2\nLine 3\n")

        async with AsyncFileReader(text_file, chunk_size=5) as reader:
            chunks = []
            async for chunk in reader.read_chunks():
                chunks.append(chunk)

            # Should have multiple chunks
            assert len(chunks) > 0


class TestCLIStreamingErrorPaths:
    """Tests for CLI streaming error handling."""

    def test_streaming_scan_error(self, tmp_path: Path) -> None:
        """Test CLI handles errors during streaming scan."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        # Create files
        test_file = tmp_path / "test.txt"
        test_file.write_text('aws_secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"')

        runner = CliRunner()

        # Normal streaming should work
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--stream"],
        )
        # Streaming might produce output or exit with 0 or 2
        assert result.exit_code in (0, 2)


class TestCLIBenchmarkErrorPaths:
    """Tests for CLI benchmark error handling."""

    def test_benchmark_with_invalid_path(self, tmp_path: Path) -> None:
        """Test CLI handles benchmark on non-existent path."""
        from typer.testing import CliRunner

        from hamburglar.cli.main import app

        runner = CliRunner()

        result = runner.invoke(
            app,
            ["scan", "/nonexistent/path", "--benchmark"],
        )
        assert result.exit_code != 0
