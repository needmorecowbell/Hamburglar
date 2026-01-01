"""Comprehensive tests for storage module base classes.

This module tests the BaseStorage abstract class, filter dataclasses,
StorageRegistry, and related utilities for storing and retrieving scan results.
"""

from __future__ import annotations

import sys
from abc import ABC
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage import (
    BaseStorage,
    FindingFilter,
    ScanFilter,
    ScanStatistics,
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
                metadata={"line": 5},
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
def empty_scan_result() -> ScanResult:
    """Return an empty scan result for testing."""
    return ScanResult(
        target_path="/tmp/empty",
        findings=[],
        scan_duration=0.5,
        stats={"files_scanned": 5, "files_skipped": 0, "errors": 0},
    )


class MockStorage(BaseStorage):
    """Mock storage implementation for testing BaseStorage interface."""

    def __init__(self, name: str = "mock") -> None:
        self._name = name
        self._scans: list[StoredScan] = []
        self._closed = False

    @property
    def name(self) -> str:
        return self._name

    def save_scan(self, result: ScanResult) -> str:
        scan_id = f"scan_{len(self._scans)}"
        stored = StoredScan(
            scan_id=scan_id,
            scan_result=result,
            stored_at=datetime.now(timezone.utc),
        )
        self._scans.append(stored)
        return scan_id

    def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
        scans = self._scans.copy()

        if filter is not None:
            if filter.target_path:
                scans = [s for s in scans if s.scan_result.target_path.startswith(filter.target_path)]
            if filter.min_findings is not None:
                scans = [s for s in scans if len(s.scan_result.findings) >= filter.min_findings]
            if filter.max_findings is not None:
                scans = [s for s in scans if len(s.scan_result.findings) <= filter.max_findings]
            if filter.since:
                scans = [s for s in scans if s.stored_at >= filter.since]
            if filter.until:
                scans = [s for s in scans if s.stored_at <= filter.until]
            if filter.offset:
                scans = scans[filter.offset:]
            if filter.limit:
                scans = scans[:filter.limit]

        return scans

    def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
        findings = []
        for scan in self._scans:
            findings.extend(scan.scan_result.findings)

        if filter is not None:
            if filter.file_path:
                findings = [f for f in findings if f.file_path.startswith(filter.file_path)]
            if filter.detector_name:
                findings = [f for f in findings if f.detector_name == filter.detector_name]
            if filter.severity:
                findings = [f for f in findings if f.severity in filter.severity]
            if filter.offset:
                findings = findings[filter.offset:]
            if filter.limit:
                findings = findings[:filter.limit]

        return findings

    def get_statistics(self) -> ScanStatistics:
        stats = ScanStatistics(
            total_scans=len(self._scans),
            total_findings=sum(len(s.scan_result.findings) for s in self._scans),
        )
        return stats

    def close(self) -> None:
        self._closed = True

    @property
    def is_closed(self) -> bool:
        return self._closed


@pytest.fixture
def mock_storage() -> MockStorage:
    """Return a mock storage instance for testing."""
    return MockStorage()


@pytest.fixture
def fresh_registry() -> StorageRegistry:
    """Return a fresh storage registry for testing."""
    return StorageRegistry()


# ============================================================================
# Test BaseStorage Abstract Class
# ============================================================================


class TestBaseStorageInterface:
    """Tests for the BaseStorage abstract base class."""

    def test_is_abstract_base_class(self) -> None:
        """BaseStorage should be an ABC."""
        assert issubclass(BaseStorage, ABC)

    def test_cannot_instantiate_directly(self) -> None:
        """BaseStorage cannot be instantiated directly."""
        with pytest.raises(TypeError, match="abstract"):
            BaseStorage()  # type: ignore

    def test_name_is_abstract_property(self) -> None:
        """name should be an abstract property."""
        # Create a class missing name property
        with pytest.raises(TypeError, match="abstract"):
            class IncompleteStorage(BaseStorage):
                def save_scan(self, result: ScanResult) -> str:
                    return "id"

                def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
                    return []

                def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
                    return []

                def get_statistics(self) -> ScanStatistics:
                    return ScanStatistics()

            IncompleteStorage()  # type: ignore

    def test_save_scan_is_abstract(self) -> None:
        """save_scan should be an abstract method."""
        with pytest.raises(TypeError, match="abstract"):
            class IncompleteStorage(BaseStorage):
                @property
                def name(self) -> str:
                    return "incomplete"

                def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
                    return []

                def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
                    return []

                def get_statistics(self) -> ScanStatistics:
                    return ScanStatistics()

            IncompleteStorage()  # type: ignore

    def test_get_scans_is_abstract(self) -> None:
        """get_scans should be an abstract method."""
        with pytest.raises(TypeError, match="abstract"):
            class IncompleteStorage(BaseStorage):
                @property
                def name(self) -> str:
                    return "incomplete"

                def save_scan(self, result: ScanResult) -> str:
                    return "id"

                def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
                    return []

                def get_statistics(self) -> ScanStatistics:
                    return ScanStatistics()

            IncompleteStorage()  # type: ignore

    def test_get_findings_is_abstract(self) -> None:
        """get_findings should be an abstract method."""
        with pytest.raises(TypeError, match="abstract"):
            class IncompleteStorage(BaseStorage):
                @property
                def name(self) -> str:
                    return "incomplete"

                def save_scan(self, result: ScanResult) -> str:
                    return "id"

                def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
                    return []

                def get_statistics(self) -> ScanStatistics:
                    return ScanStatistics()

            IncompleteStorage()  # type: ignore

    def test_get_statistics_is_abstract(self) -> None:
        """get_statistics should be an abstract method."""
        with pytest.raises(TypeError, match="abstract"):
            class IncompleteStorage(BaseStorage):
                @property
                def name(self) -> str:
                    return "incomplete"

                def save_scan(self, result: ScanResult) -> str:
                    return "id"

                def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
                    return []

                def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
                    return []

            IncompleteStorage()  # type: ignore

    def test_close_has_default_implementation(self, mock_storage: MockStorage) -> None:
        """close should have a default no-op implementation."""
        # The base class close method should be callable without error
        mock_storage.close()
        assert mock_storage.is_closed

    def test_context_manager_support(self, mock_storage: MockStorage) -> None:
        """BaseStorage should support context manager protocol."""
        with mock_storage as storage:
            assert storage is mock_storage
            assert not mock_storage.is_closed

        assert mock_storage.is_closed

    def test_context_manager_calls_close(self) -> None:
        """Context manager exit should call close."""
        storage = MockStorage()
        with storage:
            pass
        assert storage.is_closed


# ============================================================================
# Test MockStorage Implementation
# ============================================================================


class TestMockStorageImplementation:
    """Tests for the MockStorage implementation to verify correct behavior."""

    def test_save_scan_returns_id(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """save_scan should return a unique scan ID."""
        scan_id = mock_storage.save_scan(sample_scan_result)
        assert scan_id == "scan_0"

        scan_id2 = mock_storage.save_scan(sample_scan_result)
        assert scan_id2 == "scan_1"

    def test_get_scans_returns_stored_scans(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """get_scans should return stored scans."""
        mock_storage.save_scan(sample_scan_result)
        scans = mock_storage.get_scans()
        assert len(scans) == 1
        assert scans[0].scan_result.target_path == sample_scan_result.target_path

    def test_get_findings_returns_all_findings(
        self, mock_storage: MockStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_findings should return findings from all stored scans."""
        mock_storage.save_scan(sample_scan_result)
        findings = mock_storage.get_findings()
        assert len(findings) == 2

    def test_get_statistics_counts_correctly(
        self, mock_storage: MockStorage, sample_scan_result: ScanResult
    ) -> None:
        """get_statistics should count scans and findings correctly."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)
        stats = mock_storage.get_statistics()
        assert stats.total_scans == 2
        assert stats.total_findings == 4

    def test_name_property(self, mock_storage: MockStorage) -> None:
        """name property should return the storage name."""
        assert mock_storage.name == "mock"

    def test_custom_name(self) -> None:
        """MockStorage should accept custom name."""
        storage = MockStorage(name="custom")
        assert storage.name == "custom"


# ============================================================================
# Test ScanFilter Dataclass
# ============================================================================


class TestScanFilter:
    """Tests for the ScanFilter dataclass."""

    def test_default_values(self) -> None:
        """ScanFilter should have sensible defaults."""
        filter = ScanFilter()
        assert filter.since is None
        assert filter.until is None
        assert filter.target_path is None
        assert filter.min_findings is None
        assert filter.max_findings is None
        assert filter.limit is None
        assert filter.offset == 0

    def test_since_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """since filter should filter scans by date."""
        mock_storage.save_scan(sample_scan_result)
        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        filter = ScanFilter(since=future)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 0

    def test_until_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """until filter should filter scans by date."""
        mock_storage.save_scan(sample_scan_result)
        past = datetime(2000, 1, 1, tzinfo=timezone.utc)
        filter = ScanFilter(until=past)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 0

    def test_target_path_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """target_path filter should filter by path prefix."""
        mock_storage.save_scan(sample_scan_result)
        filter = ScanFilter(target_path="/tmp/test")
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 1

        filter = ScanFilter(target_path="/nonexistent")
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 0

    def test_min_findings_filter(
        self, mock_storage: MockStorage, sample_scan_result: ScanResult, empty_scan_result: ScanResult
    ) -> None:
        """min_findings filter should filter by minimum finding count."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(empty_scan_result)

        filter = ScanFilter(min_findings=1)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/test"

    def test_max_findings_filter(
        self, mock_storage: MockStorage, sample_scan_result: ScanResult, empty_scan_result: ScanResult
    ) -> None:
        """max_findings filter should filter by maximum finding count."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(empty_scan_result)

        filter = ScanFilter(max_findings=0)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 1
        assert scans[0].scan_result.target_path == "/tmp/empty"

    def test_limit_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """limit filter should limit the number of results."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)

        filter = ScanFilter(limit=2)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 2

    def test_offset_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """offset filter should skip results."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)

        filter = ScanFilter(offset=1)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 2

    def test_combined_filters(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """Multiple filters should combine with AND logic."""
        mock_storage.save_scan(sample_scan_result)
        mock_storage.save_scan(sample_scan_result)

        filter = ScanFilter(target_path="/tmp", min_findings=1, limit=1)
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 1


# ============================================================================
# Test FindingFilter Dataclass
# ============================================================================


class TestFindingFilter:
    """Tests for the FindingFilter dataclass."""

    def test_default_values(self) -> None:
        """FindingFilter should have sensible defaults."""
        filter = FindingFilter()
        assert filter.since is None
        assert filter.until is None
        assert filter.file_path is None
        assert filter.detector_name is None
        assert filter.severity is None
        assert filter.target_path is None
        assert filter.limit is None
        assert filter.offset == 0

    def test_file_path_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """file_path filter should filter findings by path prefix."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(file_path="/tmp/test/secrets")
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_detector_name_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """detector_name filter should filter by detector."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(detector_name="email")
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 1
        assert findings[0].matches == ["admin@example.com"]

    def test_severity_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """severity filter should filter by severity levels."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH])
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 1
        assert findings[0].detector_name == "aws_key"

    def test_severity_filter_multiple(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """severity filter should support multiple severity levels."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(severity=[Severity.HIGH, Severity.LOW])
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 2

    def test_limit_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """limit filter should limit finding results."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(limit=1)
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 1

    def test_offset_filter(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """offset filter should skip finding results."""
        mock_storage.save_scan(sample_scan_result)

        filter = FindingFilter(offset=1)
        findings = mock_storage.get_findings(filter)
        assert len(findings) == 1


# ============================================================================
# Test StoredScan Dataclass
# ============================================================================


class TestStoredScan:
    """Tests for the StoredScan dataclass."""

    def test_required_fields(self, sample_scan_result: ScanResult) -> None:
        """StoredScan should require scan_id, scan_result, and stored_at."""
        now = datetime.now(timezone.utc)
        stored = StoredScan(
            scan_id="test-1",
            scan_result=sample_scan_result,
            stored_at=now,
        )
        assert stored.scan_id == "test-1"
        assert stored.scan_result is sample_scan_result
        assert stored.stored_at == now

    def test_default_metadata(self, sample_scan_result: ScanResult) -> None:
        """StoredScan should have empty dict as default metadata."""
        stored = StoredScan(
            scan_id="test-1",
            scan_result=sample_scan_result,
            stored_at=datetime.now(timezone.utc),
        )
        assert stored.metadata == {}

    def test_custom_metadata(self, sample_scan_result: ScanResult) -> None:
        """StoredScan should accept custom metadata."""
        metadata = {"source": "ci", "pipeline_id": "123"}
        stored = StoredScan(
            scan_id="test-1",
            scan_result=sample_scan_result,
            stored_at=datetime.now(timezone.utc),
            metadata=metadata,
        )
        assert stored.metadata == metadata


# ============================================================================
# Test ScanStatistics Dataclass
# ============================================================================


class TestScanStatistics:
    """Tests for the ScanStatistics dataclass."""

    def test_default_values(self) -> None:
        """ScanStatistics should have sensible defaults."""
        stats = ScanStatistics()
        assert stats.total_scans == 0
        assert stats.total_findings == 0
        assert stats.total_files_scanned == 0
        assert stats.findings_by_severity == {}
        assert stats.findings_by_detector == {}
        assert stats.scans_by_date == {}
        assert stats.first_scan_date is None
        assert stats.last_scan_date is None
        assert stats.average_findings_per_scan == 0.0
        assert stats.average_scan_duration == 0.0

    def test_populated_statistics(self) -> None:
        """ScanStatistics should accept all fields."""
        now = datetime.now(timezone.utc)
        stats = ScanStatistics(
            total_scans=10,
            total_findings=50,
            total_files_scanned=100,
            findings_by_severity={"high": 20, "low": 30},
            findings_by_detector={"aws_key": 25, "email": 25},
            scans_by_date={"2024-01-01": 5, "2024-01-02": 5},
            first_scan_date=now,
            last_scan_date=now,
            average_findings_per_scan=5.0,
            average_scan_duration=2.5,
        )
        assert stats.total_scans == 10
        assert stats.total_findings == 50
        assert stats.total_files_scanned == 100
        assert stats.average_findings_per_scan == 5.0
        assert stats.average_scan_duration == 2.5


# ============================================================================
# Test StorageError Exception
# ============================================================================


class TestStorageError:
    """Tests for the StorageError exception class."""

    def test_basic_error(self) -> None:
        """StorageError should accept a message."""
        error = StorageError("Connection failed")
        assert str(error) == "Connection failed"
        assert error.message == "Connection failed"
        assert error.backend is None
        assert error.operation is None

    def test_error_with_backend(self) -> None:
        """StorageError should format message with backend name."""
        error = StorageError("Connection failed", backend="sqlite")
        assert str(error) == "[sqlite] Connection failed"
        assert error.backend == "sqlite"

    def test_error_with_operation(self) -> None:
        """StorageError should format message with operation."""
        error = StorageError("Connection failed", operation="save")
        assert str(error) == "save: Connection failed"
        assert error.operation == "save"

    def test_error_with_all_context(self) -> None:
        """StorageError should format message with all context."""
        error = StorageError("Connection failed", backend="sqlite", operation="save")
        assert str(error) == "[sqlite] save: Connection failed"

    def test_error_is_exception(self) -> None:
        """StorageError should be an Exception subclass."""
        error = StorageError("Test")
        assert isinstance(error, Exception)

    def test_error_can_be_raised(self) -> None:
        """StorageError should be raisable."""
        with pytest.raises(StorageError, match="Test error"):
            raise StorageError("Test error")


# ============================================================================
# Test StorageRegistry
# ============================================================================


class TestStorageRegistry:
    """Tests for the StorageRegistry class."""

    def test_empty_registry(self, fresh_registry: StorageRegistry) -> None:
        """Empty registry should have no backends."""
        assert len(fresh_registry) == 0
        assert fresh_registry.list_names() == []
        assert fresh_registry.get_all() == []

    def test_register_backend(self, fresh_registry: StorageRegistry) -> None:
        """register should add a backend to the registry."""
        storage = MockStorage()
        fresh_registry.register(storage)
        assert len(fresh_registry) == 1
        assert "mock" in fresh_registry
        assert fresh_registry.list_names() == ["mock"]

    def test_register_duplicate_raises_error(self, fresh_registry: StorageRegistry) -> None:
        """register should raise ValueError for duplicate names."""
        storage1 = MockStorage(name="test")
        storage2 = MockStorage(name="test")
        fresh_registry.register(storage1)

        with pytest.raises(ValueError, match="already registered"):
            fresh_registry.register(storage2)

    def test_get_backend(self, fresh_registry: StorageRegistry) -> None:
        """get should return the registered backend."""
        storage = MockStorage()
        fresh_registry.register(storage)
        retrieved = fresh_registry.get("mock")
        assert retrieved is storage

    def test_get_nonexistent_raises_error(self, fresh_registry: StorageRegistry) -> None:
        """get should raise KeyError for unknown backends."""
        with pytest.raises(KeyError, match="not registered"):
            fresh_registry.get("nonexistent")

    def test_unregister_backend(self, fresh_registry: StorageRegistry) -> None:
        """unregister should remove a backend from the registry."""
        storage = MockStorage()
        fresh_registry.register(storage)
        fresh_registry.unregister("mock")
        assert len(fresh_registry) == 0
        assert "mock" not in fresh_registry

    def test_unregister_nonexistent_raises_error(self, fresh_registry: StorageRegistry) -> None:
        """unregister should raise KeyError for unknown backends."""
        with pytest.raises(KeyError, match="not registered"):
            fresh_registry.unregister("nonexistent")

    def test_get_all_returns_all_backends(self, fresh_registry: StorageRegistry) -> None:
        """get_all should return all registered backends."""
        storage1 = MockStorage(name="mock1")
        storage2 = MockStorage(name="mock2")
        fresh_registry.register(storage1)
        fresh_registry.register(storage2)

        backends = fresh_registry.get_all()
        assert len(backends) == 2
        assert storage1 in backends
        assert storage2 in backends

    def test_list_names_returns_all_names(self, fresh_registry: StorageRegistry) -> None:
        """list_names should return all backend names."""
        storage1 = MockStorage(name="alpha")
        storage2 = MockStorage(name="beta")
        fresh_registry.register(storage1)
        fresh_registry.register(storage2)

        names = fresh_registry.list_names()
        assert set(names) == {"alpha", "beta"}

    def test_contains_check(self, fresh_registry: StorageRegistry) -> None:
        """__contains__ should check if a backend is registered."""
        storage = MockStorage(name="test")
        fresh_registry.register(storage)

        assert "test" in fresh_registry
        assert "other" not in fresh_registry

    def test_len_returns_count(self, fresh_registry: StorageRegistry) -> None:
        """__len__ should return the number of registered backends."""
        assert len(fresh_registry) == 0

        fresh_registry.register(MockStorage(name="a"))
        assert len(fresh_registry) == 1

        fresh_registry.register(MockStorage(name="b"))
        assert len(fresh_registry) == 2


# ============================================================================
# Test Default Registry
# ============================================================================


class TestDefaultRegistry:
    """Tests for the default_registry global instance."""

    def test_default_registry_exists(self) -> None:
        """default_registry should be a StorageRegistry instance."""
        assert isinstance(default_registry, StorageRegistry)

    def test_default_registry_is_usable(self) -> None:
        """default_registry should be functional."""
        # Register and unregister to test basic functionality
        storage = MockStorage(name="test_default_registry")
        if "test_default_registry" in default_registry:
            default_registry.unregister("test_default_registry")

        default_registry.register(storage)
        assert "test_default_registry" in default_registry

        # Clean up
        default_registry.unregister("test_default_registry")
        assert "test_default_registry" not in default_registry


# ============================================================================
# Test Module Exports
# ============================================================================


class TestModuleExports:
    """Tests for module-level exports."""

    def test_all_exports(self) -> None:
        """__all__ should contain all public names."""
        from hamburglar import storage

        expected_exports = [
            "BaseStorage",
            "FindingFilter",
            "ScanFilter",
            "ScanStatistics",
            "StorageError",
            "StorageRegistry",
            "StoredScan",
            "default_registry",
        ]

        for name in expected_exports:
            assert hasattr(storage, name), f"Missing export: {name}"
            assert name in storage.__all__, f"Missing from __all__: {name}"

    def test_base_storage_importable(self) -> None:
        """BaseStorage should be importable from module."""
        from hamburglar.storage import BaseStorage as BS
        # Check by name and structure rather than identity, as module caching
        # can cause different object instances across test sessions
        assert BS.__name__ == "BaseStorage"
        assert hasattr(BS, "save_scan")
        assert hasattr(BS, "get_scans")
        assert hasattr(BS, "get_findings")
        assert hasattr(BS, "get_statistics")

    def test_filter_classes_importable(self) -> None:
        """Filter classes should be importable."""
        from hamburglar.storage import FindingFilter, ScanFilter
        assert ScanFilter is not None
        assert FindingFilter is not None

    def test_dataclasses_are_dataclasses(self) -> None:
        """Filter and statistics classes should be dataclasses."""
        import dataclasses
        assert dataclasses.is_dataclass(ScanFilter)
        assert dataclasses.is_dataclass(FindingFilter)
        assert dataclasses.is_dataclass(StoredScan)
        assert dataclasses.is_dataclass(ScanStatistics)


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_findings_list(self, mock_storage: MockStorage, empty_scan_result: ScanResult) -> None:
        """Storage should handle scans with no findings."""
        scan_id = mock_storage.save_scan(empty_scan_result)
        assert scan_id is not None

        findings = mock_storage.get_findings()
        assert findings == []

        stats = mock_storage.get_statistics()
        assert stats.total_findings == 0

    def test_filter_with_all_none(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """Filter with all None values should return all results."""
        mock_storage.save_scan(sample_scan_result)

        filter = ScanFilter()
        scans = mock_storage.get_scans(filter)
        assert len(scans) == 1

        finding_filter = FindingFilter()
        findings = mock_storage.get_findings(finding_filter)
        assert len(findings) == 2

    def test_none_filter_returns_all(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """None filter should return all results."""
        mock_storage.save_scan(sample_scan_result)

        scans = mock_storage.get_scans(None)
        assert len(scans) == 1

        findings = mock_storage.get_findings(None)
        assert len(findings) == 2

    def test_offset_beyond_results(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """Offset beyond available results should return empty list."""
        mock_storage.save_scan(sample_scan_result)

        filter = ScanFilter(offset=100)
        scans = mock_storage.get_scans(filter)
        assert scans == []

    def test_limit_zero(self, mock_storage: MockStorage, sample_scan_result: ScanResult) -> None:
        """Limit of zero is treated as no limit (implementation defined)."""
        mock_storage.save_scan(sample_scan_result)

        # Note: limit=0 behavior is implementation-specific
        # Some implementations may return empty list, others may treat 0 as "no limit"
        # The mock storage treats 0/None as no limit
        filter = ScanFilter(limit=0)
        scans = mock_storage.get_scans(filter)
        # This documents the current behavior - limit=0 means no limit
        assert len(scans) == 1

    def test_multiple_scan_storage(
        self, mock_storage: MockStorage, sample_scan_result: ScanResult, empty_scan_result: ScanResult
    ) -> None:
        """Storage should handle multiple scans correctly."""
        id1 = mock_storage.save_scan(sample_scan_result)
        id2 = mock_storage.save_scan(empty_scan_result)
        id3 = mock_storage.save_scan(sample_scan_result)

        assert id1 != id2 != id3

        scans = mock_storage.get_scans()
        assert len(scans) == 3

        stats = mock_storage.get_statistics()
        assert stats.total_scans == 3
        assert stats.total_findings == 4  # 2 + 0 + 2
