"""Comprehensive tests for SqliteStorage backend.

This module tests the SQLite storage backend for persisting and querying
scan results, including database creation, CRUD operations, filtering,
statistics, and concurrent access.
"""

from __future__ import annotations

import concurrent.futures
import os
import sqlite3
import sys
import tempfile
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
    ScanFilter,
    ScanStatistics,
    SqliteStorage,
    StorageError,
    StorageRegistry,
    StoredScan,
    default_registry,
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
def memory_storage() -> SqliteStorage:
    """Return an in-memory SQLite storage instance."""
    storage = SqliteStorage(":memory:")
    yield storage
    storage.close()


@pytest.fixture
def file_storage(tmp_path: Path) -> SqliteStorage:
    """Return a file-based SQLite storage instance."""
    db_path = tmp_path / "test.db"
    storage = SqliteStorage(db_path)
    yield storage
    storage.close()


# ============================================================================
# Test SqliteStorage Initialization
# ============================================================================


class TestSqliteStorageInit:
    """Tests for SqliteStorage initialization and configuration."""

    def test_creates_in_memory_database(self) -> None:
        """SqliteStorage should create an in-memory database."""
        with SqliteStorage(":memory:") as storage:
            assert storage.db_path == ":memory:"
            assert storage.name == "sqlite"

    def test_creates_file_database(self, tmp_path: Path) -> None:
        """SqliteStorage should create a file-based database."""
        db_path = tmp_path / "test.db"
        with SqliteStorage(db_path) as storage:
            assert storage.db_path == str(db_path)
            assert db_path.exists()

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        """SqliteStorage should create parent directories if they don't exist."""
        db_path = tmp_path / "nested" / "dir" / "test.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with SqliteStorage(db_path) as storage:
            assert db_path.exists()

    def test_accepts_path_object(self, tmp_path: Path) -> None:
        """SqliteStorage should accept Path objects."""
        db_path = tmp_path / "test.db"
        with SqliteStorage(db_path) as storage:
            assert storage.db_path == str(db_path)

    def test_accepts_string_path(self, tmp_path: Path) -> None:
        """SqliteStorage should accept string paths."""
        db_path = str(tmp_path / "test.db")
        with SqliteStorage(db_path) as storage:
            assert storage.db_path == db_path

    def test_name_property_returns_sqlite(self, memory_storage: SqliteStorage) -> None:
        """name property should return 'sqlite'."""
        assert memory_storage.name == "sqlite"

    def test_is_base_storage_subclass(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should be a BaseStorage subclass."""
        assert isinstance(memory_storage, BaseStorage)


# ============================================================================
# Test Database Schema
# ============================================================================


class TestDatabaseSchema:
    """Tests for database schema creation."""

    def test_creates_scans_table(self, memory_storage: SqliteStorage) -> None:
        """Schema should include scans table."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
        assert cursor.fetchone() is not None
        cursor.close()

    def test_creates_findings_table(self, memory_storage: SqliteStorage) -> None:
        """Schema should include findings table."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'")
        assert cursor.fetchone() is not None
        cursor.close()

    def test_creates_detectors_table(self, memory_storage: SqliteStorage) -> None:
        """Schema should include detectors table."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='detectors'")
        assert cursor.fetchone() is not None
        cursor.close()

    def test_creates_schema_version_table(self, memory_storage: SqliteStorage) -> None:
        """Schema should include schema_version table."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        assert cursor.fetchone() is not None
        cursor.close()

    def test_schema_version_is_set(self, memory_storage: SqliteStorage) -> None:
        """Schema version should be set."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT version FROM schema_version")
        row = cursor.fetchone()
        assert row is not None
        assert row["version"] == 1
        cursor.close()

    def test_creates_indexes(self, memory_storage: SqliteStorage) -> None:
        """Schema should create necessary indexes."""
        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row["name"] for row in cursor.fetchall()}
        cursor.close()

        assert "idx_scans_target_path" in indexes
        assert "idx_scans_stored_at" in indexes
        assert "idx_findings_scan_id" in indexes
        assert "idx_findings_file_path" in indexes
        assert "idx_findings_detector_name" in indexes
        assert "idx_findings_severity" in indexes


# ============================================================================
# Test save_scan Method
# ============================================================================


class TestSaveScan:
    """Tests for saving scan results."""

    def test_returns_unique_scan_id(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should return a unique scan ID."""
        id1 = memory_storage.save_scan(sample_scan_result)
        id2 = memory_storage.save_scan(sample_scan_result)

        assert id1 != id2
        assert len(id1) > 0
        assert len(id2) > 0

    def test_saves_scan_metadata(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should store scan metadata correctly."""
        scan_id = memory_storage.save_scan(sample_scan_result)

        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        cursor.close()

        assert row is not None
        assert row["target_path"] == "/tmp/test"
        assert row["scan_duration"] == 2.5

    def test_saves_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should store all findings."""
        scan_id = memory_storage.save_scan(sample_scan_result)

        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM findings WHERE scan_id = ?", (scan_id,))
        count = cursor.fetchone()["count"]
        cursor.close()

        assert count == 2

    def test_saves_finding_details(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should store complete finding details."""
        memory_storage.save_scan(sample_scan_result)

        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE detector_name = 'aws_key'")
        row = cursor.fetchone()
        cursor.close()

        assert row is not None
        assert row["file_path"] == "/tmp/test/secrets.txt"
        assert row["severity"] == "high"
        assert row["line_number"] == 5

    def test_saves_empty_scan(
        self, memory_storage: SqliteStorage, empty_scan_result: ScanResult
    ) -> None:
        """save_scan should handle scans with no findings."""
        scan_id = memory_storage.save_scan(empty_scan_result)

        scans = memory_storage.get_scans()
        assert len(scans) == 1
        assert scans[0].scan_result.findings == []

    def test_registers_detector(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should register detector names."""
        memory_storage.save_scan(sample_scan_result)

        conn = memory_storage._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM detectors")
        detectors = {row["name"] for row in cursor.fetchall()}
        cursor.close()

        assert "aws_key" in detectors
        assert "email" in detectors

    def test_stores_scan_stats_as_json(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should store stats as JSON."""
        scan_id = memory_storage.save_scan(sample_scan_result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.stats["files_scanned"] == 10
        assert scan.scan_result.stats["files_skipped"] == 2

    def test_raises_error_when_closed(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """save_scan should raise StorageError when storage is closed."""
        memory_storage.close()

        with pytest.raises(StorageError, match="closed"):
            memory_storage.save_scan(sample_scan_result)


# ============================================================================
# Test get_scans Method
# ============================================================================


class TestGetScans:
    """Tests for retrieving stored scans."""

    def test_returns_all_scans(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_scans should return all stored scans."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(second_scan_result)

        scans = memory_storage.get_scans()
        assert len(scans) == 2

    def test_returns_empty_list_when_no_scans(self, memory_storage: SqliteStorage) -> None:
        """get_scans should return empty list when no scans exist."""
        scans = memory_storage.get_scans()
        assert scans == []

    def test_returns_stored_scan_objects(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should return StoredScan objects."""
        memory_storage.save_scan(sample_scan_result)
        scans = memory_storage.get_scans()

        assert len(scans) == 1
        assert isinstance(scans[0], StoredScan)
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_includes_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should include findings in scan results."""
        memory_storage.save_scan(sample_scan_result)
        scans = memory_storage.get_scans()

        assert len(scans[0].scan_result.findings) == 2

    def test_orders_by_stored_at_descending(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should order results by stored_at descending."""
        memory_storage.save_scan(sample_scan_result)
        time.sleep(0.1)
        memory_storage.save_scan(sample_scan_result)

        scans = memory_storage.get_scans()
        assert scans[0].stored_at >= scans[1].stored_at

    def test_filter_by_target_path(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by target path prefix."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(second_scan_result)

        filter = ScanFilter(target_path="/tmp/test")
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_filter_by_since(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should filter by since datetime."""
        memory_storage.save_scan(sample_scan_result)

        # Future date should return no results
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = ScanFilter(since=future)
        scans = memory_storage.get_scans(filter)
        assert len(scans) == 0

        # Past date should return results
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = ScanFilter(since=past)
        scans = memory_storage.get_scans(filter)
        assert len(scans) == 1

    def test_filter_by_until(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should filter by until datetime."""
        memory_storage.save_scan(sample_scan_result)

        # Future date should return results
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = ScanFilter(until=future)
        scans = memory_storage.get_scans(filter)
        assert len(scans) == 1

        # Past date should return no results
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = ScanFilter(until=past)
        scans = memory_storage.get_scans(filter)
        assert len(scans) == 0

    def test_filter_by_min_findings(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by minimum findings count."""
        memory_storage.save_scan(sample_scan_result)  # 2 findings
        memory_storage.save_scan(empty_scan_result)   # 0 findings

        filter = ScanFilter(min_findings=1)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_filter_by_max_findings(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should filter by maximum findings count."""
        memory_storage.save_scan(sample_scan_result)  # 2 findings
        memory_storage.save_scan(empty_scan_result)   # 0 findings

        filter = ScanFilter(max_findings=0)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/empty"

    def test_filter_with_limit(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should respect limit parameter."""
        for _ in range(5):
            memory_storage.save_scan(sample_scan_result)

        filter = ScanFilter(limit=3)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 3

    def test_filter_with_offset(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should respect offset parameter."""
        for _ in range(5):
            memory_storage.save_scan(sample_scan_result)

        filter = ScanFilter(offset=2)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 3

    def test_filter_with_limit_and_offset(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans should handle limit and offset together."""
        for _ in range(10):
            memory_storage.save_scan(sample_scan_result)

        filter = ScanFilter(limit=3, offset=2)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 3

    def test_combined_filters(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_scans should combine multiple filters with AND logic."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(empty_scan_result)

        filter = ScanFilter(target_path="/tmp/test", min_findings=1)
        scans = memory_storage.get_scans(filter)

        assert len(scans) == 1

    def test_none_filter_returns_all(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scans with None filter should return all scans."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(sample_scan_result)

        scans = memory_storage.get_scans(None)
        assert len(scans) == 2


# ============================================================================
# Test get_findings Method
# ============================================================================


class TestGetFindings:
    """Tests for retrieving findings."""

    def test_returns_all_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should return all findings."""
        memory_storage.save_scan(sample_scan_result)
        findings = memory_storage.get_findings()

        assert len(findings) == 2

    def test_returns_empty_list_when_no_findings(
        self, memory_storage: SqliteStorage
    ) -> None:
        """get_findings should return empty list when no findings exist."""
        findings = memory_storage.get_findings()
        assert findings == []

    def test_returns_finding_objects(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should return Finding objects."""
        memory_storage.save_scan(sample_scan_result)
        findings = memory_storage.get_findings()

        assert all(isinstance(f, Finding) for f in findings)

    def test_filter_by_file_path(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by file path prefix."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(file_path="/tmp/test/secrets")
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_filter_by_detector_name(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by detector name."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(detector_name="email")
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].matches == ["admin@example.com"]

    def test_filter_by_single_severity(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by single severity level."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH])
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_filter_by_multiple_severities(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by multiple severity levels."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH, Severity.LOW])
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 2

    def test_filter_by_target_path(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_findings should filter by scan target path."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(second_scan_result)

        filter = FindingFilter(target_path="/tmp/test")
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 2

    def test_filter_by_since(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by since datetime."""
        memory_storage.save_scan(sample_scan_result)

        future = datetime.now(timezone.utc) + timedelta(hours=1)
        filter = FindingFilter(since=future)
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 0

    def test_filter_by_until(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should filter by until datetime."""
        memory_storage.save_scan(sample_scan_result)

        past = datetime.now(timezone.utc) - timedelta(hours=1)
        filter = FindingFilter(until=past)
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 0

    def test_filter_with_limit(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should respect limit parameter."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(limit=1)
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1

    def test_filter_with_offset(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should respect offset parameter."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(offset=1)
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1

    def test_combined_filters(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should combine multiple filters."""
        memory_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH], detector_name="aws_key")
        findings = memory_storage.get_findings(filter)

        assert len(findings) == 1

    def test_preserves_metadata(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should preserve finding metadata."""
        memory_storage.save_scan(sample_scan_result)
        findings = memory_storage.get_findings()

        aws_finding = next(f for f in findings if f.detector_name == "aws_key")
        assert aws_finding.metadata["line"] == 5


# ============================================================================
# Test get_statistics Method
# ============================================================================


class TestGetStatistics:
    """Tests for calculating aggregate statistics."""

    def test_empty_database_statistics(self, memory_storage: SqliteStorage) -> None:
        """get_statistics should handle empty database."""
        stats = memory_storage.get_statistics()

        assert stats.total_scans == 0
        assert stats.total_findings == 0
        assert stats.total_files_scanned == 0
        assert stats.first_scan_date is None
        assert stats.last_scan_date is None

    def test_counts_scans(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count total scans."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(sample_scan_result)

        stats = memory_storage.get_statistics()
        assert stats.total_scans == 2

    def test_counts_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count total findings."""
        memory_storage.save_scan(sample_scan_result)  # 2 findings
        memory_storage.save_scan(sample_scan_result)  # 2 findings

        stats = memory_storage.get_statistics()
        assert stats.total_findings == 4

    def test_counts_unique_files(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count unique files scanned."""
        memory_storage.save_scan(sample_scan_result)

        stats = memory_storage.get_statistics()
        assert stats.total_files_scanned == 2

    def test_findings_by_severity(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        second_scan_result: ScanResult,
    ) -> None:
        """get_statistics should group findings by severity."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(second_scan_result)

        stats = memory_storage.get_statistics()

        assert stats.findings_by_severity["high"] == 1
        assert stats.findings_by_severity["low"] == 1
        assert stats.findings_by_severity["critical"] == 1

    def test_findings_by_detector(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should group findings by detector."""
        memory_storage.save_scan(sample_scan_result)

        stats = memory_storage.get_statistics()

        assert stats.findings_by_detector["aws_key"] == 1
        assert stats.findings_by_detector["email"] == 1

    def test_scans_by_date(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should group scans by date."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(sample_scan_result)

        stats = memory_storage.get_statistics()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        assert today in stats.scans_by_date
        assert stats.scans_by_date[today] == 2

    def test_first_and_last_scan_dates(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should track first and last scan dates."""
        memory_storage.save_scan(sample_scan_result)

        stats = memory_storage.get_statistics()

        assert stats.first_scan_date is not None
        assert stats.last_scan_date is not None
        assert isinstance(stats.first_scan_date, datetime)
        assert isinstance(stats.last_scan_date, datetime)

    def test_average_findings_per_scan(
        self,
        memory_storage: SqliteStorage,
        sample_scan_result: ScanResult,
        empty_scan_result: ScanResult,
    ) -> None:
        """get_statistics should calculate average findings per scan."""
        memory_storage.save_scan(sample_scan_result)  # 2 findings
        memory_storage.save_scan(empty_scan_result)   # 0 findings

        stats = memory_storage.get_statistics()

        assert stats.average_findings_per_scan == 1.0

    def test_average_scan_duration(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should calculate average scan duration."""
        memory_storage.save_scan(sample_scan_result)  # 2.5s

        stats = memory_storage.get_statistics()

        assert stats.average_scan_duration == 2.5


# ============================================================================
# Test get_scan_by_id Method
# ============================================================================


class TestGetScanById:
    """Tests for retrieving scans by ID."""

    def test_returns_scan_by_id(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scan_by_id should return the correct scan."""
        scan_id = memory_storage.save_scan(sample_scan_result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_id == scan_id
        assert scan.scan_result.target_path == "/tmp/test"

    def test_returns_none_for_unknown_id(self, memory_storage: SqliteStorage) -> None:
        """get_scan_by_id should return None for unknown IDs."""
        scan = memory_storage.get_scan_by_id("nonexistent-id")
        assert scan is None

    def test_includes_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_scan_by_id should include findings."""
        scan_id = memory_storage.save_scan(sample_scan_result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert len(scan.scan_result.findings) == 2


# ============================================================================
# Test delete_scan Method
# ============================================================================


class TestDeleteScan:
    """Tests for deleting scans."""

    def test_deletes_scan(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """delete_scan should remove the scan."""
        scan_id = memory_storage.save_scan(sample_scan_result)
        result = memory_storage.delete_scan(scan_id)

        assert result is True
        assert memory_storage.get_scan_by_id(scan_id) is None

    def test_deletes_findings_with_scan(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """delete_scan should remove associated findings."""
        scan_id = memory_storage.save_scan(sample_scan_result)
        memory_storage.delete_scan(scan_id)

        findings = memory_storage.get_findings()
        assert len(findings) == 0

    def test_returns_false_for_unknown_id(self, memory_storage: SqliteStorage) -> None:
        """delete_scan should return False for unknown IDs."""
        result = memory_storage.delete_scan("nonexistent-id")
        assert result is False


# ============================================================================
# Test clear Method
# ============================================================================


class TestClear:
    """Tests for clearing all data."""

    def test_removes_all_scans(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should remove all scans."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.save_scan(sample_scan_result)
        memory_storage.clear()

        scans = memory_storage.get_scans()
        assert len(scans) == 0

    def test_removes_all_findings(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should remove all findings."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.clear()

        findings = memory_storage.get_findings()
        assert len(findings) == 0

    def test_resets_statistics(
        self, memory_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """clear should reset statistics."""
        memory_storage.save_scan(sample_scan_result)
        memory_storage.clear()

        stats = memory_storage.get_statistics()
        assert stats.total_scans == 0
        assert stats.total_findings == 0


# ============================================================================
# Test Context Manager
# ============================================================================


class TestContextManager:
    """Tests for context manager support."""

    def test_supports_context_manager(self) -> None:
        """SqliteStorage should work as a context manager."""
        with SqliteStorage(":memory:") as storage:
            assert isinstance(storage, SqliteStorage)

    def test_closes_on_exit(self) -> None:
        """Context manager should close storage on exit."""
        storage = SqliteStorage(":memory:")
        with storage:
            pass

        with pytest.raises(StorageError, match="closed"):
            storage.get_scans()

    def test_closes_on_exception(self, sample_scan_result: ScanResult) -> None:
        """Context manager should close storage even on exception."""
        storage = SqliteStorage(":memory:")

        with pytest.raises(ValueError):
            with storage:
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
        self, file_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """Multiple threads should be able to save concurrently."""
        num_threads = 10
        results: list[str] = []
        lock = threading.Lock()

        def save_scan() -> None:
            scan_id = file_storage.save_scan(sample_scan_result)
            with lock:
                results.append(scan_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(save_scan) for _ in range(num_threads)]
            concurrent.futures.wait(futures)

        assert len(results) == num_threads
        assert len(set(results)) == num_threads  # All IDs unique

    def test_concurrent_reads(
        self, file_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """Multiple threads should be able to read concurrently."""
        file_storage.save_scan(sample_scan_result)
        file_storage.save_scan(sample_scan_result)

        num_threads = 10
        results: list[int] = []
        lock = threading.Lock()

        def read_scans() -> None:
            scans = file_storage.get_scans()
            with lock:
                results.append(len(scans))

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(read_scans) for _ in range(num_threads)]
            concurrent.futures.wait(futures)

        assert all(r == 2 for r in results)

    def test_concurrent_save_and_read(
        self, file_storage: SqliteStorage, sample_scan_result: ScanResult
    ) -> None:
        """Mixed read and write operations should work concurrently."""
        file_storage.save_scan(sample_scan_result)

        errors: list[Exception] = []
        lock = threading.Lock()

        def save_or_read(should_save: bool) -> None:
            try:
                if should_save:
                    file_storage.save_scan(sample_scan_result)
                else:
                    file_storage.get_scans()
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
# Test File-based Storage
# ============================================================================


class TestFileBasedStorage:
    """Tests for file-based SQLite storage."""

    def test_persists_to_file(
        self, tmp_path: Path, sample_scan_result: ScanResult
    ) -> None:
        """Data should persist to file."""
        db_path = tmp_path / "test.db"

        # Save in one instance
        with SqliteStorage(db_path) as storage:
            storage.save_scan(sample_scan_result)

        # Read in another instance
        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 1

    def test_database_file_exists(self, tmp_path: Path) -> None:
        """Database file should be created on disk."""
        db_path = tmp_path / "test.db"

        with SqliteStorage(db_path):
            pass

        assert db_path.exists()

    def test_uses_wal_mode(self, tmp_path: Path) -> None:
        """File-based storage should use WAL journal mode."""
        db_path = tmp_path / "test.db"

        with SqliteStorage(db_path) as storage:
            conn = storage._get_connection()
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode")
            mode = cursor.fetchone()[0]
            cursor.close()

            assert mode.lower() == "wal"


# ============================================================================
# Test Error Handling
# ============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_raises_storage_error_on_invalid_path(self) -> None:
        """SqliteStorage should raise StorageError for invalid paths."""
        # Try to create database in non-existent directory
        with pytest.raises(StorageError, match="connect"):
            SqliteStorage("/nonexistent/directory/db.sqlite")

    def test_error_includes_backend_name(
        self, memory_storage: SqliteStorage
    ) -> None:
        """StorageError should include backend name."""
        memory_storage.close()

        try:
            memory_storage.get_scans()
        except StorageError as e:
            assert e.backend == "sqlite"

    def test_error_includes_operation(
        self, memory_storage: SqliteStorage
    ) -> None:
        """StorageError should include operation name."""
        memory_storage.close()

        try:
            memory_storage.get_scans()
        except StorageError as e:
            assert e.operation == "connect"


# ============================================================================
# Test Registry Integration
# ============================================================================


class TestRegistryIntegration:
    """Tests for StorageRegistry integration."""

    def test_can_register_with_registry(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should be registrable with StorageRegistry."""
        registry = StorageRegistry()
        registry.register(memory_storage)

        assert "sqlite" in registry
        assert registry.get("sqlite") is memory_storage

    def test_can_unregister_from_registry(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should be unregistrable from StorageRegistry."""
        registry = StorageRegistry()
        registry.register(memory_storage)
        registry.unregister("sqlite")

        assert "sqlite" not in registry


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_unicode_content(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle Unicode content."""
        result = ScanResult(
            target_path="/tmp/unicode_测试",
            findings=[
                Finding(
                    file_path="/tmp/unicode_测试/文件.txt",
                    detector_name="test",
                    matches=["密钥: パスワード", "🔐 secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
            stats={},
        )

        scan_id = memory_storage.save_scan(result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == "/tmp/unicode_测试"
        assert scan.scan_result.findings[0].matches[1] == "🔐 secret"

    def test_large_match_list(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle large match lists."""
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

        scan_id = memory_storage.save_scan(result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert len(scan.scan_result.findings[0].matches) == 1000

    def test_empty_metadata(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle empty metadata."""
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

        scan_id = memory_storage.save_scan(result)
        findings = memory_storage.get_findings()

        assert len(findings) == 1
        assert findings[0].metadata == {}

    def test_special_characters_in_paths(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle special characters in paths."""
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

        scan_id = memory_storage.save_scan(result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == "/tmp/path with spaces/test's dir"

    def test_zero_duration_scan(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle zero duration scans."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=0.0,
            stats={},
        )

        scan_id = memory_storage.save_scan(result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.scan_duration == 0.0

    def test_very_long_target_path(self, memory_storage: SqliteStorage) -> None:
        """SqliteStorage should handle very long paths."""
        long_path = "/tmp/" + "a" * 500
        result = ScanResult(
            target_path=long_path,
            findings=[],
            scan_duration=1.0,
            stats={},
        )

        scan_id = memory_storage.save_scan(result)
        scan = memory_storage.get_scan_by_id(scan_id)

        assert scan is not None
        assert scan.scan_result.target_path == long_path


# ============================================================================
# Test Module Exports
# ============================================================================


class TestModuleExports:
    """Tests for module-level exports."""

    def test_sqlite_storage_exported(self) -> None:
        """SqliteStorage should be exported from storage module."""
        from hamburglar.storage import SqliteStorage as SS

        assert SS is not None
        assert SS.__name__ == "SqliteStorage"

    def test_in_module_all(self) -> None:
        """SqliteStorage should be in __all__."""
        from hamburglar import storage

        assert "SqliteStorage" in storage.__all__
