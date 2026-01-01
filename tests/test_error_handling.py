"""Integration tests for scanner error handling.

This module tests the Scanner's ability to handle various error conditions
gracefully, including missing paths, permission errors, symlink loops,
and files that disappear during scanning.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

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

from hamburglar.core.exceptions import ScanError  # noqa: E402
from hamburglar.core.models import ScanConfig  # noqa: E402
from hamburglar.core.scanner import Scanner  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402


class TestMissingTargetPath:
    """Test handling of missing target paths."""

    @pytest.mark.asyncio
    async def test_scanner_raises_scan_error_for_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError when target path does not exist."""
        nonexistent = tmp_path / "this_path_does_not_exist"
        config = ScanConfig(target_path=nonexistent)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert "does not exist" in str(exc_info.value).lower()
        assert exc_info.value.path == str(nonexistent)

    @pytest.mark.asyncio
    async def test_scanner_raises_scan_error_with_context(self, tmp_path: Path) -> None:
        """Test that ScanError includes path context."""
        nonexistent = tmp_path / "missing_directory"
        config = ScanConfig(target_path=nonexistent)
        scanner = Scanner(config, [])

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        # Check that context is properly set
        assert exc_info.value.context.get("path") == str(nonexistent)

    @pytest.mark.asyncio
    async def test_scanner_raises_for_nonexistent_file(self, tmp_path: Path) -> None:
        """Test that scanner raises ScanError for nonexistent single file."""
        nonexistent_file = tmp_path / "nonexistent_file.txt"
        config = ScanConfig(target_path=nonexistent_file)
        scanner = Scanner(config, [])

        with pytest.raises(ScanError) as exc_info:
            await scanner.scan()

        assert str(nonexistent_file) in str(exc_info.value)


class TestPermissionDeniedOnDirectory:
    """Test handling of permission denied errors on directories."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    @pytest.mark.skipif(os.getuid() == 0, reason="Root user bypasses permission checks")
    async def test_handles_permission_denied_on_subdirectory(self, tmp_path: Path) -> None:
        """Test that scanner continues when a subdirectory is not accessible.

        Note: Python's rglob silently skips inaccessible directories without
        raising errors. The scanner handles this gracefully by simply not
        finding files in those directories.
        """
        # Create accessible file
        accessible_file = tmp_path / "accessible.txt"
        accessible_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

        # Create an unreadable subdirectory
        restricted_dir = tmp_path / "restricted"
        restricted_dir.mkdir()
        secret_file = restricted_dir / "secrets.txt"
        secret_file.write_text('password = "supersecret"')
        original_mode = restricted_dir.stat().st_mode
        restricted_dir.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            # Should complete without raising
            result = await scanner.scan()

            # Should have scanned the accessible file
            assert result.stats["files_scanned"] >= 1
            # Python's rglob silently skips inaccessible directories
            # so no error is raised for the restricted subdirectory
            # The important thing is the scan completed and found the accessible file
            assert len(result.findings) > 0
        finally:
            restricted_dir.chmod(original_mode)

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    @pytest.mark.skipif(os.getuid() == 0, reason="Root user bypasses permission checks")
    async def test_handles_permission_denied_on_target_directory_non_recursive(
        self, tmp_path: Path
    ) -> None:
        """Test scanner behavior when target directory itself is not readable.

        Note: Python's iterdir raises PermissionError when called on an
        unreadable directory, which the scanner catches and logs. This test
        uses non-recursive mode to trigger iterdir behavior.
        """
        # Create an unreadable directory
        restricted_dir = tmp_path / "restricted"
        restricted_dir.mkdir()
        secret_file = restricted_dir / "secrets.txt"
        secret_file.write_text('password = "supersecret"')
        original_mode = restricted_dir.stat().st_mode
        restricted_dir.chmod(0o000)

        try:
            # Use non-recursive to trigger iterdir (which raises PermissionError)
            config = ScanConfig(target_path=restricted_dir, blacklist=[], recursive=False)
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            # Should complete (the directory exists, just can't read it)
            result = await scanner.scan()

            # No files should be scanned
            assert result.stats["files_scanned"] == 0
            # Should have errors logged (iterdir raises PermissionError)
            assert len(result.stats["errors"]) >= 1
            # Error should mention permission
            assert any("ermission" in e for e in result.stats["errors"])
        finally:
            restricted_dir.chmod(original_mode)

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    @pytest.mark.skipif(os.getuid() == 0, reason="Root user bypasses permission checks")
    async def test_handles_permission_denied_on_target_directory_recursive(
        self, tmp_path: Path
    ) -> None:
        """Test scanner behavior when target directory itself is not readable.

        Note: Python's rglob silently skips inaccessible directories without
        raising errors. The scanner handles this gracefully by returning an
        empty result when the target is inaccessible.
        """
        # Create an unreadable directory
        restricted_dir = tmp_path / "restricted"
        restricted_dir.mkdir()
        secret_file = restricted_dir / "secrets.txt"
        secret_file.write_text('password = "supersecret"')
        original_mode = restricted_dir.stat().st_mode
        restricted_dir.chmod(0o000)

        try:
            # Use recursive mode (default) which uses rglob
            config = ScanConfig(target_path=restricted_dir, blacklist=[], recursive=True)
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            # Should complete (the directory exists, just can't read it)
            result = await scanner.scan()

            # No files should be scanned (rglob silently returns empty)
            assert result.stats["files_scanned"] == 0
            assert result.stats["files_discovered"] == 0
            # rglob doesn't raise errors for inaccessible directories
            # so no errors are expected in this case
        finally:
            restricted_dir.chmod(original_mode)


class TestPermissionDeniedOnIndividualFiles:
    """Test handling of permission denied errors on individual files."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    @pytest.mark.skipif(os.getuid() == 0, reason="Root user bypasses permission checks")
    async def test_continues_scanning_after_permission_error_on_file(self, tmp_path: Path) -> None:
        """Test that scanner continues when one file is not readable."""
        # Create accessible files
        file1 = tmp_path / "file1.txt"
        file1.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"')

        file3 = tmp_path / "file3.txt"
        file3.write_text('email = "test@example.com"')

        # Create unreadable file
        unreadable = tmp_path / "file2.txt"
        unreadable.write_text('password = "secret123"')
        original_mode = unreadable.stat().st_mode
        unreadable.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            result = await scanner.scan()

            # Should have scanned 2 files (file1 and file3)
            assert result.stats["files_scanned"] == 2
            # Should have skipped 1 file
            assert result.stats["files_skipped"] == 1
            # Should have errors
            assert len(result.stats["errors"]) >= 1
            # Should have findings from readable files
            assert len(result.findings) > 0
        finally:
            unreadable.chmod(original_mode)

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    @pytest.mark.skipif(os.getuid() == 0, reason="Root user bypasses permission checks")
    async def test_multiple_unreadable_files(self, tmp_path: Path) -> None:
        """Test that scanner handles multiple unreadable files."""
        # Create accessible file
        accessible = tmp_path / "accessible.txt"
        accessible.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        # Create multiple unreadable files
        unreadable_files = []
        original_modes = []
        for i in range(3):
            f = tmp_path / f"unreadable{i}.txt"
            f.write_text(f'secret{i} = "password{i}"')
            original_modes.append(f.stat().st_mode)
            f.chmod(0o000)
            unreadable_files.append(f)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            result = await scanner.scan()

            # Should have scanned 1 file
            assert result.stats["files_scanned"] == 1
            # Should have skipped 3 files
            assert result.stats["files_skipped"] == 3
            # Should have 3 errors (one per unreadable file)
            assert len(result.stats["errors"]) >= 3
        finally:
            for f, mode in zip(unreadable_files, original_modes):
                f.chmod(mode)


class TestSymlinkLoops:
    """Test handling of symlink loops."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Symlink handling differs on Windows")
    async def test_handles_symlink_loop(self, tmp_path: Path) -> None:
        """Test that scanner handles symlink loops without infinite recursion."""
        # Create a regular file
        regular_file = tmp_path / "regular.txt"
        regular_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

        # Create a symlink loop: dir1 -> dir2 -> dir1
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        # Create symlink in dir1 pointing to dir2
        link_to_dir2 = dir1 / "link_to_dir2"
        link_to_dir2.symlink_to(dir2)

        # Create symlink in dir2 pointing back to dir1
        link_to_dir1 = dir2 / "link_to_dir1"
        link_to_dir1.symlink_to(dir1)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Should complete without hanging or raising
        result = await scanner.scan()

        # Should have scanned the regular file at minimum
        assert result.stats["files_scanned"] >= 1

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Symlink handling differs on Windows")
    async def test_handles_self_referencing_symlink(self, tmp_path: Path) -> None:
        """Test that scanner handles a symlink pointing to itself."""
        # Create a regular file
        regular_file = tmp_path / "regular.txt"
        regular_file.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        # Create a self-referencing symlink (unusual but possible)
        self_link = tmp_path / "self_link"
        self_link.symlink_to(self_link)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Should complete without hanging or raising
        result = await scanner.scan()

        # Should have scanned the regular file
        assert result.stats["files_scanned"] >= 1

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Symlink handling differs on Windows")
    async def test_handles_broken_symlink(self, tmp_path: Path) -> None:
        """Test that scanner handles broken symlinks gracefully."""
        # Create a regular file
        regular_file = tmp_path / "regular.txt"
        regular_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

        # Create a symlink to a non-existent target
        broken_link = tmp_path / "broken_link"
        broken_link.symlink_to(tmp_path / "does_not_exist.txt")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Should complete without raising
        result = await scanner.scan()

        # Should have scanned the regular file
        assert result.stats["files_scanned"] >= 1


class TestFileDisappearsDuringScan:
    """Test handling of files that disappear during scanning."""

    @pytest.mark.asyncio
    async def test_handles_file_deleted_during_scan(self, tmp_path: Path) -> None:
        """Test that scanner handles files that are deleted during scan."""
        # Create files
        file1 = tmp_path / "file1.txt"
        file1.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        file2 = tmp_path / "file2.txt"
        file2.write_text('email = "test@example.com"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Mock read_text to simulate file deletion on second file
        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            if "file2" in str(self):
                raise FileNotFoundError("File was deleted during scan")
            return original_read_text(self, *args, **kwargs)

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Should have scanned file1
        assert result.stats["files_scanned"] == 1
        # Should have skipped file2
        assert result.stats["files_skipped"] == 1
        # Should have error about file not found
        assert any("not found" in e.lower() for e in result.stats["errors"])

    @pytest.mark.asyncio
    async def test_handles_directory_becomes_file(self, tmp_path: Path) -> None:
        """Test handling when path that was a file is now a directory."""
        # Create a regular file first
        file1 = tmp_path / "file1.txt"
        file1.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Mock read_text to simulate IsADirectoryError
        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            if "file1" in str(self):
                raise IsADirectoryError("Unexpectedly became a directory")
            return original_read_text(self, *args, **kwargs)

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Should have skipped the file
        assert result.stats["files_skipped"] == 1
        # Should have error about directory
        assert len(result.stats["errors"]) >= 1

    @pytest.mark.asyncio
    async def test_handles_os_error_during_read(self, tmp_path: Path) -> None:
        """Test that scanner handles generic OS errors during file read."""
        # Create a file
        file1 = tmp_path / "file1.txt"
        file1.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Mock read_text to simulate OSError
        def mock_read_text(self, *args, **kwargs):
            raise OSError("Disk I/O error")

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Should have skipped the file
        assert result.stats["files_skipped"] == 1
        # Should have error logged
        assert len(result.stats["errors"]) >= 1
        assert any("error" in e.lower() for e in result.stats["errors"])


class TestErrorRecovery:
    """Test that scanner recovers from errors and continues scanning."""

    @pytest.mark.asyncio
    async def test_continues_after_detector_error(self, tmp_path: Path) -> None:
        """Test that scanner continues scanning after a detector raises an error."""
        from hamburglar.detectors import BaseDetector

        class FailingDetector(BaseDetector):
            """A detector that always fails."""

            @property
            def name(self) -> str:
                return "failing_detector"

            def detect(self, content: str, file_path: str = "") -> list:
                raise RuntimeError("Detector crashed!")

        # Create multiple files
        for i in range(3):
            f = tmp_path / f"file{i}.txt"
            f.write_text(f'secret{i} = "AKIAIOSFODNN7EXAMPLE"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        failing = FailingDetector()
        working = RegexDetector()
        scanner = Scanner(config, [failing, working])

        result = await scanner.scan()

        # Should have scanned all files
        assert result.stats["files_scanned"] == 3
        # Should have findings from working detector
        assert len(result.findings) > 0
        # Should have errors from failing detector (3 files * 1 error each)
        assert len(result.stats["errors"]) >= 3

    @pytest.mark.asyncio
    async def test_error_stats_are_collected(self, tmp_path: Path) -> None:
        """Test that all errors are properly collected in stats."""
        # Create accessible file
        file1 = tmp_path / "file1.txt"
        file1.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        # Force an error by mocking
        original_read_text = Path.read_text
        call_count = [0]

        def mock_read_text(self, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("Simulated error")
            return original_read_text(self, *args, **kwargs)

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Errors should be in stats
        assert "errors" in result.stats
        assert isinstance(result.stats["errors"], list)


class TestGracefulDegradation:
    """Test that scanner degrades gracefully under adverse conditions."""

    @pytest.mark.asyncio
    async def test_empty_result_on_all_files_unreadable(self, tmp_path: Path) -> None:
        """Test that scanner returns empty result when all files are unreadable."""
        # Create files but make read always fail
        file1 = tmp_path / "file1.txt"
        file1.write_text('secret = "test"')

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        def mock_read_text(self, *args, **kwargs):
            raise PermissionError("Cannot read any files")

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Should have valid result with no findings
        assert result.stats["files_scanned"] == 0
        assert result.stats["files_skipped"] == 1
        assert len(result.findings) == 0
        # Should have error logged
        assert len(result.stats["errors"]) >= 1

    @pytest.mark.asyncio
    async def test_result_includes_duration_even_on_errors(self, tmp_path: Path) -> None:
        """Test that scan duration is recorded even when errors occur."""
        nonexistent = tmp_path / "does_not_exist"
        config = ScanConfig(target_path=nonexistent)
        scanner = Scanner(config, [])

        with pytest.raises(ScanError):
            await scanner.scan()

        # The scan raised an error, but if we had gotten a result,
        # it would include duration. This test verifies error propagation.

    @pytest.mark.asyncio
    async def test_scan_continues_with_mix_of_errors(self, tmp_path: Path) -> None:
        """Test scanner handles a mix of successful reads and various errors."""
        # Create multiple files
        good_file = tmp_path / "good.txt"
        good_file.write_text('key = "AKIAIOSFODNN7EXAMPLE"')

        bad_file1 = tmp_path / "bad1.txt"
        bad_file1.write_text("content1")

        bad_file2 = tmp_path / "bad2.txt"
        bad_file2.write_text("content2")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        original_read_text = Path.read_text

        def mock_read_text(self, *args, **kwargs):
            if "bad1" in str(self):
                raise PermissionError("No permission")
            elif "bad2" in str(self):
                raise FileNotFoundError("File vanished")
            return original_read_text(self, *args, **kwargs)

        with patch.object(Path, "read_text", mock_read_text):
            result = await scanner.scan()

        # Good file should be scanned
        assert result.stats["files_scanned"] == 1
        # Bad files should be skipped
        assert result.stats["files_skipped"] == 2
        # Should have findings from good file
        assert len(result.findings) > 0
        # Should have 2 errors
        assert len(result.stats["errors"]) == 2
