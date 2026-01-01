"""JSON Lines file storage backend for Hamburglar.

This module provides simple file-based persistence of scan results using
JSON Lines format (newline-delimited JSON), suitable for CI/CD pipelines
and simple storage needs without database dependencies.
"""

from __future__ import annotations

import fcntl
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage import (
    BaseStorage,
    FindingFilter,
    ScanFilter,
    ScanStatistics,
    StorageError,
    StoredScan,
)


class JsonFileStorage(BaseStorage):
    """JSON Lines file-based storage backend for scan results.

    This storage backend appends scan results to a JSON Lines file
    (one JSON object per line), providing simple persistence suitable
    for CI/CD pipelines and environments without database access.

    Features:
        - Appends scan results to a single file
        - JSON Lines format for easy streaming and parsing
        - No external dependencies required
        - Thread-safe writes using file locking
        - Supports reading historical scans
        - Simple file-based persistence

    Format:
        Each line is a complete JSON object representing a stored scan:
        {"scan_id": "...", "stored_at": "...", "scan_result": {...}}

    Example:
        >>> with JsonFileStorage("scans.jsonl") as storage:
        ...     scan_id = storage.save_scan(result)
        ...     scans = storage.get_scans()
        ...     stats = storage.get_statistics()

    Args:
        file_path: Path to the JSON Lines file. If the file doesn't exist,
            it will be created on first write. Parent directories must exist.
    """

    def __init__(self, file_path: str | Path) -> None:
        """Initialize the JSON file storage backend.

        Args:
            file_path: Path to the JSON Lines file for storing scans.
        """
        self._file_path = Path(file_path) if isinstance(file_path, str) else file_path
        self._closed = False

    @property
    def name(self) -> str:
        """Return the storage backend name."""
        return "json_file"

    @property
    def file_path(self) -> Path:
        """Return the storage file path."""
        return self._file_path

    def save_scan(self, result: ScanResult) -> str:
        """Save a scan result to the JSON Lines file.

        Appends the scan result as a new line in the file using
        file locking to ensure thread-safe writes.

        Args:
            result: The ScanResult to store.

        Returns:
            A unique scan ID for the stored scan.

        Raises:
            StorageError: If the save operation fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="save_scan",
            )

        scan_id = str(uuid.uuid4())
        stored_at = datetime.now(timezone.utc)

        try:
            # Ensure parent directory exists
            self._file_path.parent.mkdir(parents=True, exist_ok=True)

            # Serialize the scan result
            record = self._serialize_stored_scan(scan_id, stored_at, result)
            json_line = json.dumps(record, ensure_ascii=False) + "\n"

            # Append with file locking for thread safety
            with open(self._file_path, "a", encoding="utf-8") as f:
                self._lock_file(f)
                try:
                    f.write(json_line)
                finally:
                    self._unlock_file(f)

        except OSError as e:
            raise StorageError(
                f"Failed to write to file: {e}",
                backend=self.name,
                operation="save_scan",
            ) from e
        except (TypeError, ValueError) as e:
            raise StorageError(
                f"Failed to serialize scan result: {e}",
                backend=self.name,
                operation="save_scan",
            ) from e

        return scan_id

    def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
        """Retrieve stored scans matching the filter criteria.

        Reads all scans from the file and filters them according to
        the provided criteria.

        Args:
            filter: Optional filter criteria. If None, returns all scans.

        Returns:
            A list of StoredScan objects ordered by stored_at descending.

        Raises:
            StorageError: If the retrieval fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="get_scans",
            )

        try:
            scans = self._read_all_scans()
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to read scans: {e}",
                backend=self.name,
                operation="get_scans",
            ) from e

        # Apply filters
        if filter is not None:
            scans = self._filter_scans(scans, filter)

        # Sort by stored_at descending
        scans.sort(key=lambda s: s.stored_at, reverse=True)

        # Apply offset and limit
        if filter is not None:
            if filter.offset:
                scans = scans[filter.offset:]
            if filter.limit:
                scans = scans[:filter.limit]

        return scans

    def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
        """Retrieve findings matching the filter criteria.

        Reads all scans from the file and extracts findings that
        match the provided criteria.

        Args:
            filter: Optional filter criteria. If None, returns all findings.

        Returns:
            A list of Finding objects.

        Raises:
            StorageError: If the retrieval fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="get_findings",
            )

        try:
            scans = self._read_all_scans()
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to read findings: {e}",
                backend=self.name,
                operation="get_findings",
            ) from e

        # Sort scans by stored_at descending for consistent ordering
        scans.sort(key=lambda s: s.stored_at, reverse=True)

        # Extract and filter findings
        findings: list[Finding] = []
        for scan in scans:
            # Apply scan-level filters
            if filter is not None:
                if filter.since and scan.stored_at < filter.since:
                    continue
                if filter.until and scan.stored_at > filter.until:
                    continue
                if filter.target_path and not scan.scan_result.target_path.startswith(
                    filter.target_path
                ):
                    continue

            # Extract findings from this scan
            for finding in scan.scan_result.findings:
                if self._matches_finding_filter(finding, filter):
                    findings.append(finding)

        # Apply offset and limit
        if filter is not None:
            if filter.offset:
                findings = findings[filter.offset:]
            if filter.limit:
                findings = findings[:filter.limit]

        return findings

    def get_statistics(self) -> ScanStatistics:
        """Get aggregate statistics across all stored scans.

        Returns:
            A ScanStatistics object with summary data.

        Raises:
            StorageError: If the statistics calculation fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="get_statistics",
            )

        try:
            scans = self._read_all_scans()
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to calculate statistics: {e}",
                backend=self.name,
                operation="get_statistics",
            ) from e

        if not scans:
            return ScanStatistics()

        # Calculate statistics
        total_scans = len(scans)
        total_findings = 0
        all_files: set[str] = set()
        findings_by_severity: dict[str, int] = {}
        findings_by_detector: dict[str, int] = {}
        scans_by_date: dict[str, int] = {}
        total_duration = 0.0
        first_scan_date: datetime | None = None
        last_scan_date: datetime | None = None

        for scan in scans:
            # Count findings
            total_findings += len(scan.scan_result.findings)
            total_duration += scan.scan_result.scan_duration

            # Track files
            for finding in scan.scan_result.findings:
                all_files.add(finding.file_path)

                # Count by severity
                severity = finding.severity.value
                findings_by_severity[severity] = (
                    findings_by_severity.get(severity, 0) + 1
                )

                # Count by detector
                detector = finding.detector_name
                findings_by_detector[detector] = (
                    findings_by_detector.get(detector, 0) + 1
                )

            # Count by date
            scan_date = scan.stored_at.strftime("%Y-%m-%d")
            scans_by_date[scan_date] = scans_by_date.get(scan_date, 0) + 1

            # Track first/last dates
            if first_scan_date is None or scan.stored_at < first_scan_date:
                first_scan_date = scan.stored_at
            if last_scan_date is None or scan.stored_at > last_scan_date:
                last_scan_date = scan.stored_at

        # Calculate averages
        average_findings_per_scan = total_findings / total_scans if total_scans > 0 else 0.0
        average_scan_duration = total_duration / total_scans if total_scans > 0 else 0.0

        return ScanStatistics(
            total_scans=total_scans,
            total_findings=total_findings,
            total_files_scanned=len(all_files),
            findings_by_severity=findings_by_severity,
            findings_by_detector=findings_by_detector,
            scans_by_date=scans_by_date,
            first_scan_date=first_scan_date,
            last_scan_date=last_scan_date,
            average_findings_per_scan=average_findings_per_scan,
            average_scan_duration=average_scan_duration,
        )

    def get_scan_by_id(self, scan_id: str) -> StoredScan | None:
        """Retrieve a specific scan by its ID.

        Args:
            scan_id: The unique scan identifier.

        Returns:
            The StoredScan if found, None otherwise.

        Raises:
            StorageError: If the retrieval fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="get_scan_by_id",
            )

        try:
            scans = self._read_all_scans()
        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to retrieve scan: {e}",
                backend=self.name,
                operation="get_scan_by_id",
            ) from e

        for scan in scans:
            if scan.scan_id == scan_id:
                return scan
        return None

    def clear(self) -> None:
        """Delete all scans from the storage file.

        This removes the file if it exists.

        Raises:
            StorageError: If the clear operation fails.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="clear",
            )

        try:
            if self._file_path.exists():
                self._file_path.unlink()
        except OSError as e:
            raise StorageError(
                f"Failed to clear storage file: {e}",
                backend=self.name,
                operation="clear",
            ) from e

    def close(self) -> None:
        """Close the storage backend.

        After calling this method, the storage backend cannot be used.
        """
        self._closed = True

    def _read_all_scans(self) -> list[StoredScan]:
        """Read all scans from the storage file.

        Returns:
            A list of all StoredScan objects in the file.

        Raises:
            StorageError: If the file cannot be read or parsed.
        """
        if not self._file_path.exists():
            return []

        scans: list[StoredScan] = []

        try:
            with open(self._file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        record = json.loads(line)
                        scan = self._deserialize_stored_scan(record)
                        scans.append(scan)
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        raise StorageError(
                            f"Invalid JSON on line {line_num}: {e}",
                            backend=self.name,
                            operation="read",
                        ) from e

        except OSError as e:
            raise StorageError(
                f"Failed to read file: {e}",
                backend=self.name,
                operation="read",
            ) from e

        return scans

    def _serialize_stored_scan(
        self, scan_id: str, stored_at: datetime, result: ScanResult
    ) -> dict[str, Any]:
        """Serialize a scan result to a dictionary for JSON storage.

        Args:
            scan_id: The unique scan identifier.
            stored_at: When the scan was stored.
            result: The ScanResult to serialize.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "scan_id": scan_id,
            "stored_at": stored_at.isoformat(),
            "scan_result": {
                "target_path": result.target_path,
                "scan_duration": result.scan_duration,
                "stats": result.stats,
                "findings": [
                    {
                        "file_path": f.file_path,
                        "detector_name": f.detector_name,
                        "severity": f.severity.value,
                        "matches": f.matches,
                        "metadata": f.metadata,
                    }
                    for f in result.findings
                ],
            },
        }

    def _deserialize_stored_scan(self, record: dict[str, Any]) -> StoredScan:
        """Deserialize a dictionary to a StoredScan object.

        Args:
            record: The dictionary to deserialize.

        Returns:
            A StoredScan object.

        Raises:
            KeyError: If required fields are missing.
            ValueError: If the data is invalid.
        """
        scan_result_data = record["scan_result"]
        findings = [
            Finding(
                file_path=f["file_path"],
                detector_name=f["detector_name"],
                severity=Severity(f["severity"]),
                matches=f["matches"],
                metadata=f.get("metadata", {}),
            )
            for f in scan_result_data["findings"]
        ]

        scan_result = ScanResult(
            target_path=scan_result_data["target_path"],
            findings=findings,
            scan_duration=scan_result_data["scan_duration"],
            stats=scan_result_data.get("stats", {}),
        )

        return StoredScan(
            scan_id=record["scan_id"],
            scan_result=scan_result,
            stored_at=datetime.fromisoformat(record["stored_at"]),
            metadata=record.get("metadata", {}),
        )

    def _filter_scans(
        self, scans: list[StoredScan], filter: ScanFilter
    ) -> list[StoredScan]:
        """Filter scans according to the provided criteria.

        Args:
            scans: The scans to filter.
            filter: The filter criteria.

        Returns:
            A filtered list of scans.
        """
        result: list[StoredScan] = []

        for scan in scans:
            # Filter by target path prefix
            if filter.target_path and not scan.scan_result.target_path.startswith(
                filter.target_path
            ):
                continue

            # Filter by date range
            if filter.since and scan.stored_at < filter.since:
                continue
            if filter.until and scan.stored_at > filter.until:
                continue

            # Filter by findings count
            findings_count = len(scan.scan_result.findings)
            if filter.min_findings is not None and findings_count < filter.min_findings:
                continue
            if filter.max_findings is not None and findings_count > filter.max_findings:
                continue

            result.append(scan)

        return result

    def _matches_finding_filter(
        self, finding: Finding, filter: FindingFilter | None
    ) -> bool:
        """Check if a finding matches the filter criteria.

        Args:
            finding: The finding to check.
            filter: The filter criteria.

        Returns:
            True if the finding matches, False otherwise.
        """
        if filter is None:
            return True

        # Filter by file path prefix
        if filter.file_path and not finding.file_path.startswith(filter.file_path):
            return False

        # Filter by detector name
        if filter.detector_name and finding.detector_name != filter.detector_name:
            return False

        # Filter by severity
        if filter.severity and finding.severity not in filter.severity:
            return False

        return True

    def _lock_file(self, f: TextIO) -> None:
        """Acquire an exclusive lock on the file.

        Args:
            f: The file object to lock.
        """
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        except (OSError, AttributeError):
            # fcntl not available on Windows, skip locking
            pass

    def _unlock_file(self, f: TextIO) -> None:
        """Release the lock on the file.

        Args:
            f: The file object to unlock.
        """
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (OSError, AttributeError):
            # fcntl not available on Windows, skip unlocking
            pass
