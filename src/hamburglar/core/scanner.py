"""Core scanner module for Hamburglar.

This module provides the Scanner class which handles file discovery,
content reading, and detector orchestration for scanning targets.
"""

import asyncio
import fnmatch
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from hamburglar.core.models import Finding, ScanConfig, ScanResult

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

logger = logging.getLogger(__name__)


class Scanner:
    """Scans files and directories for sensitive information.

    The Scanner walks directories (respecting blacklist/whitelist patterns),
    reads file contents, passes them to registered detectors, and aggregates
    the findings into a ScanResult.
    """

    def __init__(self, config: ScanConfig, detectors: list["BaseDetector"] | None = None):
        """Initialize the scanner.

        Args:
            config: Scan configuration specifying target, filters, and options.
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
        """
        self.config = config
        self.detectors = detectors or []
        self._files_scanned = 0
        self._files_skipped = 0
        self._errors: list[str] = []

    def _matches_pattern(self, path: Path, patterns: list[str]) -> bool:
        """Check if a path matches any of the given glob patterns.

        Args:
            path: Path to check.
            patterns: List of glob patterns to match against.

        Returns:
            True if path matches any pattern, False otherwise.
        """
        path_str = str(path)
        name = path.name

        for pattern in patterns:
            # Check if pattern matches the full path or just the name
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path_str, pattern):
                return True
            # Also check if any parent directory matches (for directory patterns)
            for parent in path.parents:
                if fnmatch.fnmatch(parent.name, pattern):
                    return True
        return False

    def _should_scan_file(self, file_path: Path) -> bool:
        """Determine if a file should be scanned based on blacklist/whitelist.

        Args:
            file_path: Path to the file to check.

        Returns:
            True if the file should be scanned, False otherwise.
        """
        # Check blacklist first
        if self._matches_pattern(file_path, self.config.blacklist):
            return False

        # If whitelist is specified, file must match
        return not (
            self.config.whitelist and not self._matches_pattern(file_path, self.config.whitelist)
        )

    def _discover_files(self) -> list[Path]:
        """Discover all files to scan based on configuration.

        Returns:
            List of file paths to scan.
        """
        target = self.config.target_path

        if not target.exists():
            logger.warning(f"Target path does not exist: {target}")
            return []

        if target.is_file():
            if self._should_scan_file(target):
                return [target]
            return []

        files: list[Path] = []
        if self.config.recursive:
            try:
                for item in target.rglob("*"):
                    if item.is_file() and self._should_scan_file(item):
                        files.append(item)
            except PermissionError as e:
                logger.warning(f"Permission denied during directory walk: {e}")
                self._errors.append(f"Permission denied: {e}")
        else:
            try:
                for item in target.iterdir():
                    if item.is_file() and self._should_scan_file(item):
                        files.append(item)
            except PermissionError as e:
                logger.warning(f"Permission denied reading directory: {e}")
                self._errors.append(f"Permission denied: {e}")

        return files

    async def _read_file(self, file_path: Path) -> str | None:
        """Read file contents asynchronously.

        Args:
            file_path: Path to the file to read.

        Returns:
            File contents as string, or None if reading failed.
        """

        def _read_sync() -> str | None:
            try:
                # Try reading as UTF-8 first
                try:
                    return file_path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    # Fall back to latin-1 which can read any byte sequence
                    return file_path.read_text(encoding="latin-1")
            except PermissionError:
                logger.warning(f"Permission denied reading file: {file_path}")
                self._errors.append(f"Permission denied: {file_path}")
                return None
            except OSError as e:
                logger.warning(f"Error reading file {file_path}: {e}")
                self._errors.append(f"Error reading {file_path}: {e}")
                return None

        # Run file I/O in thread pool to not block the event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _read_sync)

    async def _scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file with all detectors.

        Args:
            file_path: Path to the file to scan.

        Returns:
            List of findings from all detectors.
        """
        content = await self._read_file(file_path)
        if content is None:
            self._files_skipped += 1
            return []

        self._files_scanned += 1
        findings: list[Finding] = []

        for detector in self.detectors:
            try:
                detector_findings = detector.detect(content, str(file_path))
                findings.extend(detector_findings)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed on {file_path}: {e}")
                self._errors.append(f"Detector {detector.name} error on {file_path}: {e}")

        return findings

    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        Discovers files based on configuration, reads their contents,
        and passes them through all registered detectors.

        Returns:
            ScanResult containing all findings and scan statistics.
        """
        start_time = time.time()

        # Reset counters
        self._files_scanned = 0
        self._files_skipped = 0
        self._errors = []

        # Discover files to scan
        files = self._discover_files()
        logger.info(f"Found {len(files)} files to scan")

        # Scan all files concurrently
        all_findings: list[Finding] = []
        if files:
            tasks = [self._scan_file(f) for f in files]
            results = await asyncio.gather(*tasks)
            for file_findings in results:
                all_findings.extend(file_findings)

        scan_duration = time.time() - start_time

        return ScanResult(
            target_path=str(self.config.target_path),
            findings=all_findings,
            scan_duration=scan_duration,
            stats={
                "files_discovered": len(files),
                "files_scanned": self._files_scanned,
                "files_skipped": self._files_skipped,
                "total_findings": len(all_findings),
                "errors": self._errors,
            },
        )
