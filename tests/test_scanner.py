"""Integration tests for the Scanner class.

This module tests the Scanner's ability to discover files, respect
blacklist/whitelist patterns, scan content with detectors, and handle
various edge cases like empty directories and permission errors.
"""

from __future__ import annotations

import asyncio
import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

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

from hamburglar.core.models import ScanConfig, Severity
from hamburglar.core.scanner import Scanner
from hamburglar.detectors import BaseDetector
from hamburglar.detectors.regex_detector import RegexDetector


class TestScannerWithSecrets:
    """Test scanning directories with secrets and finding them."""

    @pytest.mark.asyncio
    async def test_scan_directory_finds_secrets(self, temp_directory: Path) -> None:
        """Test that scanner finds secrets in a directory with known secrets."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.target_path == str(temp_directory)
        assert len(result.findings) > 0
        assert result.stats["files_scanned"] > 0
        assert result.stats["total_findings"] > 0

    @pytest.mark.asyncio
    async def test_scan_finds_aws_keys(self, temp_directory: Path) -> None:
        """Test that scanner detects AWS API keys."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        aws_findings = [
            f for f in result.findings if "AWS" in f.detector_name.upper()
        ]
        assert len(aws_findings) > 0, "Should find AWS keys in temp_directory"

    @pytest.mark.asyncio
    async def test_scan_finds_emails(self, temp_directory: Path) -> None:
        """Test that scanner detects email addresses."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        email_findings = [
            f for f in result.findings if "email" in f.detector_name.lower()
        ]
        assert len(email_findings) > 0, "Should find emails in temp_directory"

    @pytest.mark.asyncio
    async def test_scan_finds_private_keys(self, temp_directory: Path) -> None:
        """Test that scanner detects RSA private key headers."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        key_findings = [
            f for f in result.findings if "private key" in f.detector_name.lower()
        ]
        assert len(key_findings) > 0, "Should find private key headers in temp_directory"

    @pytest.mark.asyncio
    async def test_scan_single_file(self, temp_directory: Path) -> None:
        """Test scanning a single file rather than a directory."""
        single_file = temp_directory / "secrets.txt"
        config = ScanConfig(target_path=single_file)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_scan_nested_files(self, temp_directory: Path) -> None:
        """Test that scanner finds secrets in nested subdirectories."""
        config = ScanConfig(target_path=temp_directory, recursive=True)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Check that we found findings in the nested file (contains ethereum address)
        nested_findings = [
            f for f in result.findings if "subdir" in f.file_path
        ]
        assert len(nested_findings) > 0, "Should find secrets in nested subdir"


class TestBlacklistPatterns:
    """Test that scanner respects blacklist patterns."""

    @pytest.mark.asyncio
    async def test_blacklist_excludes_files(self, temp_directory: Path) -> None:
        """Test that blacklisted files are not scanned."""
        config = ScanConfig(target_path=temp_directory, blacklist=["*.txt"])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Only config.py should be scanned (txt files are blacklisted)
        scanned_files = [f.file_path for f in result.findings]
        for file_path in scanned_files:
            assert not file_path.endswith(".txt"), "Should not scan .txt files"

    @pytest.mark.asyncio
    async def test_blacklist_excludes_directories(self, temp_directory: Path) -> None:
        """Test that blacklisted directories are not scanned."""
        config = ScanConfig(target_path=temp_directory, blacklist=["subdir"])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Files in subdir should not be scanned
        for finding in result.findings:
            assert "subdir" not in finding.file_path, "Should not scan files in subdir"

    @pytest.mark.asyncio
    async def test_blacklist_multiple_patterns(self, temp_directory: Path) -> None:
        """Test blacklist with multiple patterns."""
        config = ScanConfig(
            target_path=temp_directory,
            blacklist=["*.txt", "*.py", "subdir"]
        )
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # All files should be excluded
        assert result.stats["files_scanned"] == 0

    @pytest.mark.asyncio
    async def test_default_blacklist_excludes_git(self, temp_directory: Path) -> None:
        """Test that default blacklist excludes .git directories."""
        # Create a .git directory with a file
        git_dir = temp_directory / ".git"
        git_dir.mkdir()
        git_file = git_dir / "config"
        git_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"')

        config = ScanConfig(target_path=temp_directory)  # Uses default blacklist
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Findings should not include anything from .git
        for finding in result.findings:
            assert ".git" not in finding.file_path, "Should not scan files in .git"

    @pytest.mark.asyncio
    async def test_default_blacklist_excludes_pycache(self, temp_directory: Path) -> None:
        """Test that default blacklist excludes __pycache__ directories."""
        # Create a __pycache__ directory with a file
        pycache_dir = temp_directory / "__pycache__"
        pycache_dir.mkdir()
        pycache_file = pycache_dir / "module.cpython-311.pyc"
        pycache_file.write_text('secret = "password123"')

        config = ScanConfig(target_path=temp_directory)  # Uses default blacklist
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Findings should not include anything from __pycache__
        for finding in result.findings:
            assert "__pycache__" not in finding.file_path


class TestWhitelistPatterns:
    """Test that scanner respects whitelist patterns."""

    @pytest.mark.asyncio
    async def test_whitelist_only_includes_matching_files(
        self, temp_directory: Path
    ) -> None:
        """Test that only whitelisted files are scanned."""
        config = ScanConfig(target_path=temp_directory, whitelist=["*.py"])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Only config.py should be scanned
        scanned_files = {f.file_path for f in result.findings}
        for file_path in scanned_files:
            assert file_path.endswith(".py"), "Should only scan .py files"

    @pytest.mark.asyncio
    async def test_whitelist_multiple_patterns(self, temp_directory: Path) -> None:
        """Test whitelist with multiple patterns."""
        config = ScanConfig(
            target_path=temp_directory,
            whitelist=["*.py", "secrets.txt"],
            blacklist=[]  # Clear default blacklist
        )
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Should only scan config.py and secrets.txt
        assert result.stats["files_scanned"] >= 2

    @pytest.mark.asyncio
    async def test_whitelist_no_matching_files(self, temp_directory: Path) -> None:
        """Test whitelist with pattern that matches no files."""
        config = ScanConfig(target_path=temp_directory, whitelist=["*.xyz"])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_whitelist_combined_with_blacklist(self, temp_directory: Path) -> None:
        """Test that blacklist takes precedence over whitelist."""
        config = ScanConfig(
            target_path=temp_directory,
            whitelist=["*.txt"],
            blacklist=["clean.txt"]
        )
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # clean.txt should be excluded even though *.txt is whitelisted
        for finding in result.findings:
            assert "clean.txt" not in finding.file_path


class TestEmptyDirectories:
    """Test handling of empty directories."""

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, tmp_path: Path) -> None:
        """Test scanning an empty directory returns empty result."""
        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert result.stats["files_scanned"] == 0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_only_subdirs(self, tmp_path: Path) -> None:
        """Test scanning a directory with only empty subdirectories."""
        (tmp_path / "subdir1").mkdir()
        (tmp_path / "subdir2").mkdir()
        (tmp_path / "subdir1" / "subdir3").mkdir()

        config = ScanConfig(target_path=tmp_path)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert len(result.findings) == 0


class TestNonRecursiveScanning:
    """Test non-recursive scanning mode."""

    @pytest.mark.asyncio
    async def test_non_recursive_ignores_subdirectories(
        self, temp_directory: Path
    ) -> None:
        """Test that non-recursive mode doesn't scan subdirectories."""
        config = ScanConfig(target_path=temp_directory, recursive=False)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Should not find any findings from subdir/nested.txt
        for finding in result.findings:
            assert "subdir" not in finding.file_path


class TestPermissionErrors:
    """Test handling of permission errors."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        os.name == "nt", reason="Permission tests not reliable on Windows"
    )
    async def test_handles_unreadable_file_gracefully(self, tmp_path: Path) -> None:
        """Test that scanner handles unreadable files gracefully."""
        # Create a file and make it unreadable
        unreadable_file = tmp_path / "unreadable.txt"
        unreadable_file.write_text('secret = "AKIAIOSFODNN7EXAMPLE"')
        original_mode = unreadable_file.stat().st_mode
        unreadable_file.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            result = await scanner.scan()

            # Should complete without raising, but skip the unreadable file
            assert result.stats["files_skipped"] >= 1
            assert len(result.stats["errors"]) >= 1
        finally:
            # Restore permissions for cleanup
            unreadable_file.chmod(original_mode)

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        os.name == "nt", reason="Permission tests not reliable on Windows"
    )
    async def test_handles_unreadable_directory_gracefully(
        self, tmp_path: Path
    ) -> None:
        """Test that scanner handles unreadable directories gracefully."""
        # Create a directory and make it unreadable
        unreadable_dir = tmp_path / "unreadable_dir"
        unreadable_dir.mkdir()
        secret_file = unreadable_dir / "secrets.txt"
        secret_file.write_text('api_key = "secret123"')
        original_mode = unreadable_dir.stat().st_mode
        unreadable_dir.chmod(0o000)

        try:
            config = ScanConfig(target_path=tmp_path, blacklist=[])
            detector = RegexDetector()
            scanner = Scanner(config, [detector])

            # Should complete without raising
            result = await scanner.scan()
            assert isinstance(result.target_path, str)
        finally:
            # Restore permissions for cleanup
            unreadable_dir.chmod(original_mode)

    @pytest.mark.asyncio
    async def test_handles_nonexistent_path(self, tmp_path: Path) -> None:
        """Test that scanner handles nonexistent paths gracefully."""
        nonexistent = tmp_path / "does_not_exist"
        config = ScanConfig(target_path=nonexistent)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.stats["files_discovered"] == 0
        assert len(result.findings) == 0


class TestScannerWithNoDetectors:
    """Test scanner behavior with no detectors."""

    @pytest.mark.asyncio
    async def test_scan_with_no_detectors(self, temp_directory: Path) -> None:
        """Test that scanner works without any detectors."""
        config = ScanConfig(target_path=temp_directory)
        scanner = Scanner(config, detectors=None)

        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0
        assert len(result.findings) == 0  # No findings without detectors

    @pytest.mark.asyncio
    async def test_scan_with_empty_detector_list(self, temp_directory: Path) -> None:
        """Test that scanner works with empty detector list."""
        config = ScanConfig(target_path=temp_directory)
        scanner = Scanner(config, detectors=[])

        result = await scanner.scan()

        assert result.stats["files_scanned"] > 0
        assert len(result.findings) == 0


class TestScannerWithMultipleDetectors:
    """Test scanner with multiple detectors."""

    @pytest.mark.asyncio
    async def test_multiple_detectors(self, temp_directory: Path) -> None:
        """Test that scanner runs all detectors."""
        # Create two detectors with different patterns
        detector1 = RegexDetector(
            patterns={
                "Test Pattern 1": {
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "severity": Severity.HIGH,
                    "description": "AWS Key",
                }
            },
            use_defaults=False,
        )
        detector2 = RegexDetector(
            patterns={
                "Test Pattern 2": {
                    "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                    "severity": Severity.MEDIUM,
                    "description": "Email",
                }
            },
            use_defaults=False,
        )

        config = ScanConfig(target_path=temp_directory)
        scanner = Scanner(config, [detector1, detector2])

        result = await scanner.scan()

        detector_names = {f.detector_name for f in result.findings}
        assert "regex:Test Pattern 1" in detector_names
        assert "regex:Test Pattern 2" in detector_names


class TestScannerDetectorErrors:
    """Test handling of detector errors."""

    @pytest.mark.asyncio
    async def test_detector_error_handling(self, temp_directory: Path) -> None:
        """Test that scanner handles detector errors gracefully."""

        class FailingDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "failing"

            def detect(self, content: str, file_path: str = "") -> list:
                raise RuntimeError("Detector failure!")

        config = ScanConfig(target_path=temp_directory)
        failing_detector = FailingDetector()
        working_detector = RegexDetector()
        scanner = Scanner(config, [failing_detector, working_detector])

        result = await scanner.scan()

        # Should still get findings from the working detector
        assert len(result.findings) > 0
        # Should have error logged
        assert len(result.stats["errors"]) > 0


class TestScanResult:
    """Test scan result properties."""

    @pytest.mark.asyncio
    async def test_scan_duration_is_recorded(self, temp_directory: Path) -> None:
        """Test that scan duration is recorded."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert result.scan_duration > 0

    @pytest.mark.asyncio
    async def test_scan_stats_are_complete(self, temp_directory: Path) -> None:
        """Test that all expected stats are present."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        assert "files_discovered" in result.stats
        assert "files_scanned" in result.stats
        assert "files_skipped" in result.stats
        assert "total_findings" in result.stats
        assert "errors" in result.stats


class TestBinaryFileHandling:
    """Test handling of binary files."""

    @pytest.mark.asyncio
    async def test_binary_file_handling(self, tmp_path: Path) -> None:
        """Test that scanner handles binary files gracefully."""
        # Create a binary file
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Should complete without error
        assert result.stats["files_scanned"] >= 1

    @pytest.mark.asyncio
    async def test_mixed_content_file(self, tmp_path: Path) -> None:
        """Test file with mixed text and binary content."""
        mixed_file = tmp_path / "mixed.txt"
        # Text with embedded null bytes and a secret
        content = b'normal text\x00\x00AKIAIOSFODNN7EXAMPLE\x00more text'
        mixed_file.write_bytes(content)

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = Scanner(config, [detector])

        result = await scanner.scan()

        # Should still find the AWS key in mixed content
        aws_findings = [f for f in result.findings if "AWS" in f.detector_name.upper()]
        assert len(aws_findings) > 0
