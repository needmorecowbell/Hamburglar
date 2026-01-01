"""Comprehensive tests for JsonFileStorage backend.

This module tests the JSON Lines file storage backend for persisting and
querying scan results, including file operations, CRUD operations, filtering,
statistics, and thread-safe concurrent access.
"""

from __future__ import annotations

import concurrent.futures
import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

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

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage import (
    BaseStorage,
    FindingFilter,
    JsonFileStorage,
    ScanFilter,
    StorageError,
    StorageRegistry,
    StoredScan,
)

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Return a sample scan result for testing."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE"],
                severity=Severity.HIGH,
                metadata={"line": 5, "context": "aws_key = 'AKIAIOSFODNN7EXAMPLE'"},
            ),
            Finding(
                file_path="/tmp/test/config.py",
                detector_name="email",
                matches=["admin@example.com"],
                severity=Severity.LOW,
            ),
        ],
        scan_duration=2.5,
        stats={"files_scanned": 10, "files_skipped": 2, "errors": 0},
    )


@pytest.fixture
def second_scan_result() -> ScanResult:
    """Return a second sample scan result for testing."""
    return ScanResult(
        target_path="/tmp/other",
        findings=[
            Finding(
                file_path="/tmp/other/api.py",
                detector_name="api_key",
                matches=["sk_live_1234567890"],
                severity=Severity.CRITICAL,
                metadata={"line": 15},
            ),
        ],
        scan_duration=1.5,
        stats={"files_scanned": 5, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def empty_scan_result() -> ScanResult:
    """Return an empty scan result for testing."""
    return ScanResult(
        target_path="/tmp/empty",
        findings=[],
        scan_duration=0.5,
        stats={"files_scanned": 5, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def json_storage(tmp_path: Path) -> JsonFileStorage:
    """Return a JsonFileStorage instance using a temp file."""
    storage = JsonFileStorage(tmp_path / "scans.jsonl")
    yield storage
    storage.close()


@pytest.fixture
def json_storage_path(tmp_path: Path) -> Path:
    """Return a temp path for JSON storage."""
    return tmp_path / "scans.jsonl"


# ============================================================================
# Test JsonFileStorage Initialization
# ============================================================================


class TestJsonFileStorageInit:
    """Tests for JsonFileStorage initialization and configuration."""

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        """JsonFileStorage should accept string paths."""
        file_path = str(tmp_path / "scans.jsonl")
        with JsonFileStorage(file_path) as storage:
            assert storage.file_path == Path(file_path)

    def test_accepts_path_object(self, tmp_path: Path) -> None:
        """JsonFileStorage should accept Path objects."""
        file_path = tmp_path / "scans.jsonl"
        with JsonFileStorage(file_path) as storage:
            assert storage.file_path == file_path

    def test_name_property_returns_json_file(self, json_storage: JsonFileStorage) -> None:
        """name property should return 'json_file'."""
        assert json_storage.name == "json_file"

    def test_is_base_storage_subclass(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should be a BaseStorage subclass."""
        assert isinstance(json_storage, BaseStorage)

    def test_file_not_created_until_write(self, json_storage_path: Path) -> None:
        """Storage file should not exist until first write."""
        with JsonFileStorage(json_storage_path) as storage:
            assert not json_storage_path.exists()

    def test_creates_parent_directories_on_write(
        self, tmp_path: Path, sample_scan_result: ScanResult
    ) -> None:
        """JsonFileStorage should create parent directories on write."""
        file_path = tmp_path / "nested" / "dir" / "scans.jsonl"
        with JsonFileStorage(file_path) as storage:
            storage.save_scan(sample_scan_result)
            assert file_path.exists()


# ============================================================================
# Test save_scan Method
# ============================================================================


class TestSaveScan:
    """Tests for saving scan results."""

    def test_returns_unique_scan_id(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should return a unique scan ID."""
        id1 = json_storage.save_scan(sample_scan_result)
        id2 = json_storage.save_scan(sample_scan_result)

        assert id1 != id2
        assert len(id1) > 0
        assert len(id2) > 0

    def test_creates_file_on_first_write(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should create the file on first write."""
        assert not json_storage.file_path.exists()
        json_storage.save_scan(sample_scan_result)
        assert json_storage.file_path.exists()

    def test_writes_valid_json_lines(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should write valid JSON lines."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        with open(json_storage.file_path, encoding="utf-8") as f:
            lines = f.readlines()

        assert len(lines) == 2
        for line in lines:
            record = json.loads(line.strip())
            assert "scan_id" in record
            assert "stored_at" in record
            assert "scan_result" in record

    def test_preserves_scan_metadata(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should preserve scan metadata."""
        scan_id = json_storage.save_scan(sample_scan_result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == "/tmp/test"
        assert scan.scan_result.scan_duration == 2.5
        assert scan.scan_result.stats["files_scanned"] == 10

    def test_preserves_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should preserve all findings."""
        scan_id = json_storage.save_scan(sample_scan_result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert len(scan.scan_result.findings) == 2

        aws_finding = next(f for f in scan.scan_result.findings if f.detector_name == "aws_key")
        assert aws_finding.matches == ["AKIAIOSFODNN7EXAMPLE"]
        assert aws_finding.severity == Severity.HIGH
        assert aws_finding.metadata["line"] == 5

    def test_saves_empty_scan(
        self, json_storage: JsonFileStorage, empty_scan_result: ScanResult
    ) -> None:
        """save_scan should handle scans with no findings."""
        scan_id = json_storage.save_scan(empty_scan_result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.findings == []

    def test_raises_error_when_closed(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should raise StorageError when storage is closed."""
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.save_scan(sample_scan_result)

    def test_appends_to_existing_file(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should append to existing file."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        scans = json_storage.get_scans()
        assert len(scans) == 3


# ============================================================================
# Test get_scans Method
# ============================================================================


class TestGetScans:
    """Tests for retrieving stored scans."""

    def test_returns_all_scans(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_scans should return all stored scans."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(second_scan_result)

        scans = json_storage.get_scans()
        assert len(scans) == 2

    def test_returns_empty_list_when_no_file(self, json_storage: JsonFileStorage) -> None:
        """get_scans should return empty list when file doesn't exist."""
        scans = json_storage.get_scans()
        assert scans == []

    def test_returns_stored_scan_objects(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should return StoredScan objects."""
        json_storage.save_scan(sample_scan_result)
        scans = json_storage.get_scans()

        assert len(scans) == 1
        assert isinstance(scans[0], StoredScan)
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_includes_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should include findings in scan results."""
        json_storage.save_scan(sample_scan_result)
        scans = json_storage.get_scans()

        assert len(scans[0].scan_result.findings) == 2

    def test_orders_by_stored_at_descending(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should order results by stored_at descending."""
        json_storage.save_scan(sample_scan_result)
        time.sleep(0.1)
        json_storage.save_scan(sample_scan_result)

        scans = json_storage.get_scans()
        assert scans[0].stored_at >= scans[1].stored_at

    def test_filter_by_target_path(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by target path prefix."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(second_scan_result)

        filter = ScanFilter(target_path="/tmp/test")
        scans = json_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_filter_by_since(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should filter by since datetime."""
        json_storage.save_scan(sample_scan_result)

        # Future date should return no results
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = ScanFilter(since=future)
        scans = json_storage.get_scans(filter)
        assert len(scans) == 0

        # Past date should return results
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = ScanFilter(since=past)
        scans = json_storage.get_scans(filter)
        assert len(scans) == 1

    def test_filter_by_until(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should filter by until datetime."""
        json_storage.save_scan(sample_scan_result)

        # Future date should return results
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = ScanFilter(until=future)
        scans = json_storage.get_scans(filter)
        assert len(scans) == 1

        # Past date should return no results
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = ScanFilter(until=past)
        scans = json_storage.get_scans(filter)
        assert len(scans) == 0

    def test_filter_by_min_findings(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by minimum findings count."""
        json_storage.save_scan(sample_scan_result)  # 2 findings
        json_storage.save_scan(empty_scan_result)  # 0 findings

        filter = ScanFilter(min_findings=1)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_filter_by_max_findings(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by maximum findings count."""
        json_storage.save_scan(sample_scan_result)  # 2 findings
        json_storage.save_scan(empty_scan_result)  # 0 findings

        filter = ScanFilter(max_findings=0)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/empty"

    def test_filter_with_limit(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should respect limit parameter."""
        for _ in range(5):
            json_storage.save_scan(sample_scan_result)

        filter = ScanFilter(limit=3)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 3

    def test_filter_with_offset(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should respect offset parameter."""
        for _ in range(5):
            json_storage.save_scan(sample_scan_result)

        filter = ScanFilter(offset=2)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 3

    def test_filter_with_limit_and_offset(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should handle limit and offset together."""
        for _ in range(10):
            json_storage.save_scan(sample_scan_result)

        filter = ScanFilter(limit=3, offset=2)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 3

    def test_combined_filters(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should combine multiple filters with AND logic."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(empty_scan_result)

        filter = ScanFilter(target_path="/tmp/test", min_findings=1)
        scans = json_storage.get_scans(filter)

        assert len(scans) == 1

    def test_none_filter_returns_all(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans with None filter should return all scans."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        scans = json_storage.get_scans(None)
        assert len(scans) == 2

    def test_raises_error_when_closed(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should raise StorageError when storage is closed."""
        json_storage.save_scan(sample_scan_result)
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.get_scans()


# ============================================================================
# Test get_findings Method
# ============================================================================


class TestGetFindings:
    """Tests for retrieving findings."""

    def test_returns_all_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should return all findings."""
        json_storage.save_scan(sample_scan_result)
        findings = json_storage.get_findings()

        assert len(findings) == 2

    def test_returns_empty_list_when_no_findings(self, json_storage: JsonFileStorage) -> None:
        """get_findings should return empty list when no findings exist."""
        findings = json_storage.get_findings()
        assert findings == []

    def test_returns_finding_objects(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should return Finding objects."""
        json_storage.save_scan(sample_scan_result)
        findings = json_storage.get_findings()

        assert all(isinstance(f, Finding) for f in findings)

    def test_filter_by_file_path(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by file path prefix."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(file_path="/tmp/test/secrets")
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_filter_by_detector_name(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by detector name."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(detector_name="email")
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].matches == ["admin@example.com"]

    def test_filter_by_single_severity(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by single severity level."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH])
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_filter_by_multiple_severities(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by multiple severity levels."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH, Severity.LOW])
        findings = json_storage.get_findings(filter)

        assert len(findings) == 2

    def test_filter_by_target_path(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_findings should filter by scan target path."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(second_scan_result)

        filter = FindingFilter(target_path="/tmp/test")
        findings = json_storage.get_findings(filter)

        assert len(findings) == 2

    def test_filter_by_since(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by since datetime."""
        json_storage.save_scan(sample_scan_result)

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = FindingFilter(since=future)
        findings = json_storage.get_findings(filter)

        assert len(findings) == 0

    def test_filter_by_until(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by until datetime."""
        json_storage.save_scan(sample_scan_result)

        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = FindingFilter(until=past)
        findings = json_storage.get_findings(filter)

        assert len(findings) == 0

    def test_filter_with_limit(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should respect limit parameter."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(limit=1)
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1

    def test_filter_with_offset(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should respect offset parameter."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(offset=1)
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1

    def test_combined_filters(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should combine multiple filters."""
        json_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH], detector_name="aws_key")
        findings = json_storage.get_findings(filter)

        assert len(findings) == 1

    def test_preserves_metadata(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should preserve finding metadata."""
        json_storage.save_scan(sample_scan_result)
        findings = json_storage.get_findings()

        aws_finding = next(f for f in findings if f.detector_name == "aws_key")
        assert aws_finding.metadata["line"] == 5

    def test_raises_error_when_closed(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should raise StorageError when storage is closed."""
        json_storage.save_scan(sample_scan_result)
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.get_findings()


# ============================================================================
# Test get_statistics Method
# ============================================================================


class TestGetStatistics:
    """Tests for calculating aggregate statistics."""

    def test_empty_storage_statistics(self, json_storage: JsonFileStorage) -> None:
        """get_statistics should handle empty storage."""
        stats = json_storage.get_statistics()

        assert stats.total_scans == 0
        assert stats.total_findings == 0
        assert stats.total_files_scanned == 0
        assert stats.first_scan_date is None
        assert stats.last_scan_date is None

    def test_counts_scans(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count total scans."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        stats = json_storage.get_statistics()
        assert stats.total_scans == 2

    def test_counts_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count total findings."""
        json_storage.save_scan(sample_scan_result)  # 2 findings
        json_storage.save_scan(sample_scan_result)  # 2 findings

        stats = json_storage.get_statistics()
        assert stats.total_findings == 4

    def test_counts_unique_files(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count unique files scanned."""
        json_storage.save_scan(sample_scan_result)

        stats = json_storage.get_statistics()
        assert stats.total_files_scanned == 2

    def test_findings_by_severity(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_statistics should group findings by severity."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(second_scan_result)

        stats = json_storage.get_statistics()

        assert stats.findings_by_severity["high"] == 1
        assert stats.findings_by_severity["low"] == 1
        assert stats.findings_by_severity["critical"] == 1

    def test_findings_by_detector(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should group findings by detector."""
        json_storage.save_scan(sample_scan_result)

        stats = json_storage.get_statistics()

        assert stats.findings_by_detector["aws_key"] == 1
        assert stats.findings_by_detector["email"] == 1

    def test_scans_by_date(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should group scans by date."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        stats = json_storage.get_statistics()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        assert today in stats.scans_by_date
        assert stats.scans_by_date[today] == 2

    def test_first_and_last_scan_dates(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should track first and last scan dates."""
        json_storage.save_scan(sample_scan_result)

        stats = json_storage.get_statistics()

        assert stats.first_scan_date is not None
        assert stats.last_scan_date is not None
        assert isinstance(stats.first_scan_date, datetime)
        assert isinstance(stats.last_scan_date, datetime)

    def test_average_findings_per_scan(
        self,
        json_storage: JsonFileStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_statistics should calculate average findings per scan."""
        json_storage.save_scan(sample_scan_result)  # 2 findings
        json_storage.save_scan(empty_scan_result)  # 0 findings

        stats = json_storage.get_statistics()

        assert stats.average_findings_per_scan == 1.0

    def test_average_scan_duration(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should calculate average scan duration."""
        json_storage.save_scan(sample_scan_result)  # 2.5s

        stats = json_storage.get_statistics()

        assert stats.average_scan_duration == 2.5

    def test_raises_error_when_closed(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should raise StorageError when storage is closed."""
        json_storage.save_scan(sample_scan_result)
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.get_statistics()


# ============================================================================
# Test get_scan_by_id Method
# ============================================================================


class TestGetScanById:
    """Tests for retrieving scans by ID."""

    def test_returns_scan_by_id(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scan_by_id should return the correct scan."""
        scan_id = json_storage.save_scan(sample_scan_result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_id == scan_id
        assert scan.scan_result.target_path == "/tmp/test"

    def test_returns_none_for_unknown_id(self, json_storage: JsonFileStorage) -> None:
        """get_scan_by_id should return None for unknown IDs."""
        scan = json_storage.get_scan_by_id("nonexistent-id")
        assert scan is None

    def test_includes_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scan_by_id should include findings."""
        scan_id = json_storage.save_scan(sample_scan_result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert len(scan.scan_result.findings) == 2

    def test_raises_error_when_closed(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scan_by_id should raise StorageError when storage is closed."""
        scan_id = json_storage.save_scan(sample_scan_result)
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.get_scan_by_id(scan_id)


# ============================================================================
# Test clear Method
# ============================================================================


class TestClear:
    """Tests for clearing all data."""

    def test_removes_storage_file(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should remove the storage file."""
        json_storage.save_scan(sample_scan_result)
        assert json_storage.file_path.exists()

        json_storage.clear()
        assert not json_storage.file_path.exists()

    def test_clears_all_scans(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should remove all scans."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)
        json_storage.clear()

        scans = json_storage.get_scans()
        assert len(scans) == 0

    def test_clears_all_findings(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should remove all findings."""
        json_storage.save_scan(sample_scan_result)
        json_storage.clear()

        findings = json_storage.get_findings()
        assert len(findings) == 0

    def test_resets_statistics(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should reset statistics."""
        json_storage.save_scan(sample_scan_result)
        json_storage.clear()

        stats = json_storage.get_statistics()
        assert stats.total_scans == 0
        assert stats.total_findings == 0

    def test_handles_nonexistent_file(self, json_storage: JsonFileStorage) -> None:
        """clear should handle nonexistent file gracefully."""
        json_storage.clear()  # Should not raise
        assert not json_storage.file_path.exists()

    def test_raises_error_when_closed(self, json_storage: JsonFileStorage) -> None:
        """clear should raise StorageError when storage is closed."""
        json_storage.close()

        with pytest.raises(StorageError, match="closed"):
            json_storage.clear()


# ============================================================================
# Test Context Manager
# ============================================================================


class TestContextManager:
    """Tests for context manager support."""

    def test_supports_context_manager(self, tmp_path: Path) -> None:
        """JsonFileStorage should work as a context manager."""
        file_path = tmp_path / "scans.jsonl"
        with JsonFileStorage(file_path) as storage:
            assert isinstance(storage, JsonFileStorage)

    def test_closes_on_exit(self, tmp_path: Path) -> None:
        """Context manager should close storage on exit."""
        file_path = tmp_path / "scans.jsonl"
        storage = JsonFileStorage(file_path)
        with storage:
            pass

        with pytest.raises(StorageError, match="closed"):
            storage.get_scans()

    def test_closes_on_exception(self, tmp_path: Path, sample_scan_result: ScanResult) -> None:
        """Context manager should close storage even on exception."""
        file_path = tmp_path / "scans.jsonl"
        storage = JsonFileStorage(file_path)

        with pytest.raises(ValueError), storage:
            storage.save_scan(sample_scan_result)
            raise ValueError("Test error")

        with pytest.raises(StorageError, match="closed"):
            storage.get_scans()


# ============================================================================
# Test Concurrent Access
# ============================================================================


class TestConcurrentAccess:
    """Tests for thread-safe concurrent access."""

    def test_concurrent_saves(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """Multiple threads should be able to save concurrently."""
        num_threads = 10
        results: list[str] = []
        lock = threading.Lock()

        def save_scan() -> None:
            scan_id = json_storage.save_scan(sample_scan_result)
            with lock:
                results.append(scan_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(save_scan) for _ in range(num_threads)]
            concurrent.futures.wait(futures)

        assert len(results) == num_threads
        assert len(set(results)) == num_threads  # All IDs unique

        # Verify all scans were written
        scans = json_storage.get_scans()
        assert len(scans) == num_threads

    def test_concurrent_reads(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """Multiple threads should be able to read concurrently."""
        json_storage.save_scan(sample_scan_result)
        json_storage.save_scan(sample_scan_result)

        num_threads = 10
        results: list[int] = []
        lock = threading.Lock()

        def read_scans() -> None:
            scans = json_storage.get_scans()
            with lock:
                results.append(len(scans))

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(read_scans) for _ in range(num_threads)]
            concurrent.futures.wait(futures)

        assert all(r == 2 for r in results)

    def test_concurrent_save_and_read(
        self, json_storage: JsonFileStorage, sample_scan_result: ScanResult
    ) -> None:
        """Mixed read and write operations should work concurrently."""
        json_storage.save_scan(sample_scan_result)

        errors: list[Exception] = []
        lock = threading.Lock()

        def save_or_read(should_save: bool) -> None:
            try:
                if should_save:
                    json_storage.save_scan(sample_scan_result)
                else:
                    json_storage.get_scans()
            except Exception as e:
                with lock:
                    errors.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(20):
                futures.append(executor.submit(save_or_read, i % 2 == 0))
            concurrent.futures.wait(futures)

        assert len(errors) == 0


# ============================================================================
# Test Error Handling
# ============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_raises_error_on_invalid_json(self, tmp_path: Path) -> None:
        """JsonFileStorage should raise StorageError for invalid JSON."""
        file_path = tmp_path / "scans.jsonl"
        file_path.write_text("invalid json\n")

        with JsonFileStorage(file_path) as storage:
            with pytest.raises(StorageError, match="Invalid JSON"):
                storage.get_scans()

    def test_raises_error_on_missing_fields(self, tmp_path: Path) -> None:
        """JsonFileStorage should raise StorageError for missing required fields."""
        file_path = tmp_path / "scans.jsonl"
        file_path.write_text('{"scan_id": "test"}\n')  # Missing scan_result

        with JsonFileStorage(file_path) as storage:
            with pytest.raises(StorageError, match="Invalid JSON"):
                storage.get_scans()

    def test_error_includes_backend_name(self, json_storage: JsonFileStorage) -> None:
        """StorageError should include backend name."""
        json_storage.close()

        try:
            json_storage.get_scans()
        except StorageError as e:
            assert e.backend == "json_file"

    def test_error_includes_operation(self, json_storage: JsonFileStorage) -> None:
        """StorageError should include operation name."""
        json_storage.close()

        try:
            json_storage.get_scans()
        except StorageError as e:
            assert e.operation == "get_scans"

    def test_handles_empty_lines(self, tmp_path: Path, sample_scan_result: ScanResult) -> None:
        """JsonFileStorage should handle empty lines in file."""
        file_path = tmp_path / "scans.jsonl"

        with JsonFileStorage(file_path) as storage:
            storage.save_scan(sample_scan_result)

        # Add empty lines
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("\n\n")

        with JsonFileStorage(file_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 1


# ============================================================================
# Test Registry Integration
# ============================================================================


class TestRegistryIntegration:
    """Tests for StorageRegistry integration."""

    def test_can_register_with_registry(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should be registrable with StorageRegistry."""
        registry = StorageRegistry()
        registry.register(json_storage)

        assert "json_file" in registry
        assert registry.get("json_file") is json_storage

    def test_can_unregister_from_registry(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should be unregistrable from StorageRegistry."""
        registry = StorageRegistry()
        registry.register(json_storage)
        registry.unregister("json_file")

        assert "json_file" not in registry


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_unicode_content(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle Unicode content."""
        result = ScanResult(
            target_path="/tmp/unicode_\u6d4b\u8bd5",
            findings=[
                Finding(
                    file_path="/tmp/unicode_\u6d4b\u8bd5/\u6587\u4ef6.txt",
                    detector_name="test",
                    matches=["\u5bc6\u94a5: \u30d1\u30b9\u30ef\u30fc\u30c9", "\U0001f510 secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == "/tmp/unicode_\u6d4b\u8bd5"
        assert scan.scan_result.findings[0].matches[1] == "\U0001f510 secret"

    def test_large_match_list(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle large match lists."""
        large_matches = [f"match_{i}" for i in range(1000)]
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=large_matches,
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert len(scan.scan_result.findings[0].matches) == 1000

    def test_empty_metadata(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle empty metadata."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["match"],
                    severity=Severity.MEDIUM,
                    metadata={},
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        findings = json_storage.get_findings()

        assert len(findings) == 1
        assert findings[0].metadata == {}

    def test_special_characters_in_paths(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle special characters in paths."""
        result = ScanResult(
            target_path="/tmp/path with spaces/test's dir",
            findings=[
                Finding(
                    file_path='/tmp/path with spaces/test\'s dir/file "quoted".txt',
                    detector_name="test",
                    matches=["match"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == "/tmp/path with spaces/test's dir"

    def test_zero_duration_scan(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle zero duration scans."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=0.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.scan_duration == 0.0

    def test_very_long_target_path(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle very long paths."""
        long_path = "/tmp/" + "a" * 500
        result = ScanResult(
            target_path=long_path,
            findings=[],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == long_path

    def test_newlines_in_matches(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle newlines in match content."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["line1\nline2\nline3"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.findings[0].matches[0] == "line1\nline2\nline3"

    def test_complex_metadata(self, json_storage: JsonFileStorage) -> None:
        """JsonFileStorage should handle complex nested metadata."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["match"],
                    severity=Severity.MEDIUM,
                    metadata={
                        "nested": {"deep": {"value": 123}},
                        "list": [1, 2, 3],
                        "bool": True,
                        "null": None,
                    },
                )
            ],
            scan_duration=1.0,
            stats={"complex": {"stat": "value"}},
        )

        scan_id = json_storage.save_scan(result)
        scan = json_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.findings[0].metadata["nested"]["deep"]["value"] == 123
        assert scan.scan_result.stats["complex"]["stat"] == "value"


# ============================================================================
# Test CI/CD Pipeline Use Cases
# ============================================================================


class TestCICDUseCases:
    """Tests for CI/CD pipeline use cases."""

    def test_multiple_runs_append_results(
        self, json_storage_path: Path, sample_scan_result: ScanResult
    ) -> None:
        """Multiple pipeline runs should append to the same file."""
        # First run
        with JsonFileStorage(json_storage_path) as storage:
            storage.save_scan(sample_scan_result)

        # Second run
        with JsonFileStorage(json_storage_path) as storage:
            storage.save_scan(sample_scan_result)

        # Third run
        with JsonFileStorage(json_storage_path) as storage:
            storage.save_scan(sample_scan_result)
            scans = storage.get_scans()
            assert len(scans) == 3

    def test_file_persists_across_sessions(
        self, json_storage_path: Path, sample_scan_result: ScanResult
    ) -> None:
        """Data should persist across storage sessions."""
        # Write in one session
        with JsonFileStorage(json_storage_path) as storage:
            scan_id = storage.save_scan(sample_scan_result)

        # Read in another session
        with JsonFileStorage(json_storage_path) as storage:
            scan = storage.get_scan_by_id(scan_id)
            assert scan is not None
            assert scan.scan_id == scan_id

    def test_trend_analysis_across_runs(self, json_storage_path: Path) -> None:
        """Statistics should work across multiple pipeline runs."""
        for i in range(5):
            with JsonFileStorage(json_storage_path) as storage:
                result = ScanResult(
                    target_path=f"/project/run_{i}",
                    findings=[
                        Finding(
                            file_path=f"/project/run_{i}/file.txt",
                            detector_name="test",
                            matches=[f"secret_{i}"],
                            severity=Severity.HIGH,
                        )
                    ],
                    scan_duration=float(i) + 0.5,
                    stats={},
                )
                storage.save_scan(result)

        with JsonFileStorage(json_storage_path) as storage:
            stats = storage.get_statistics()
            assert stats.total_scans == 5
            assert stats.total_findings == 5
            assert stats.average_scan_duration == 2.5  # (0.5+1.5+2.5+3.5+4.5)/5


# ============================================================================
# Test Module Exports
# ============================================================================


class TestModuleExports:
    """Tests for module-level exports."""

    def test_json_file_storage_exported(self) -> None:
        """JsonFileStorage should be exported from storage module."""
        from hamburglar.storage import JsonFileStorage as JFS

        assert JFS is not None
        assert JFS.__name__ == "JsonFileStorage"

    def test_in_module_all(self) -> None:
        """JsonFileStorage should be in __all__."""
        from hamburglar import storage

        assert "JsonFileStorage" in storage.__all__
