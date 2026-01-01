"""Storage backend classes for Hamburglar.

This module provides the base storage interface and registry for managing
storage backends that persist scan results for historical analysis and reporting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity


@dataclass
class ScanFilter:
    """Filter criteria for querying stored scans.

    All filter fields are optional. When multiple fields are specified,
    they are combined with AND logic (all conditions must match).

    Attributes:
        since: Only include scans from this datetime onwards.
        until: Only include scans up to this datetime.
        target_path: Filter by target path (exact match or prefix).
        min_findings: Only include scans with at least this many findings.
        max_findings: Only include scans with at most this many findings.
        limit: Maximum number of scans to return.
        offset: Number of scans to skip (for pagination).
    """

    since: datetime | None = None
    until: datetime | None = None
    target_path: str | None = None
    min_findings: int | None = None
    max_findings: int | None = None
    limit: int | None = None
    offset: int = 0


@dataclass
class FindingFilter:
    """Filter criteria for querying stored findings.

    All filter fields are optional. When multiple fields are specified,
    they are combined with AND logic (all conditions must match).

    Attributes:
        since: Only include findings from scans since this datetime.
        until: Only include findings from scans up to this datetime.
        file_path: Filter by file path (exact match or prefix).
        detector_name: Filter by detector name (exact match).
        severity: Filter by severity level(s).
        target_path: Filter by scan target path.
        limit: Maximum number of findings to return.
        offset: Number of findings to skip (for pagination).
    """

    since: datetime | None = None
    until: datetime | None = None
    file_path: str | None = None
    detector_name: str | None = None
    severity: list[Severity] | None = None
    target_path: str | None = None
    limit: int | None = None
    offset: int = 0


@dataclass
class StoredScan:
    """A scan result with storage metadata.

    Wraps a ScanResult with additional metadata about when and how
    it was stored.

    Attributes:
        scan_id: Unique identifier for this stored scan.
        scan_result: The original ScanResult.
        stored_at: When the scan was stored.
        metadata: Additional storage-specific metadata.
    """

    scan_id: str
    scan_result: ScanResult
    stored_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanStatistics:
    """Aggregate statistics across stored scans.

    Provides summary statistics for analysis and reporting.

    Attributes:
        total_scans: Total number of scans stored.
        total_findings: Total number of findings across all scans.
        total_files_scanned: Total unique files scanned.
        findings_by_severity: Count of findings grouped by severity.
        findings_by_detector: Count of findings grouped by detector name.
        scans_by_date: Count of scans grouped by date (YYYY-MM-DD).
        first_scan_date: Date of the earliest stored scan.
        last_scan_date: Date of the most recent stored scan.
        average_findings_per_scan: Average number of findings per scan.
        average_scan_duration: Average scan duration in seconds.
    """

    total_scans: int = 0
    total_findings: int = 0
    total_files_scanned: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_detector: dict[str, int] = field(default_factory=dict)
    scans_by_date: dict[str, int] = field(default_factory=dict)
    first_scan_date: datetime | None = None
    last_scan_date: datetime | None = None
    average_findings_per_scan: float = 0.0
    average_scan_duration: float = 0.0


class BaseStorage(ABC):
    """Abstract base class for all storage backends.

    Subclasses must implement the `name` property and all abstract methods
    to provide specific storage logic for different backends (SQLite, JSON, etc.).

    Example:
        class SqliteStorage(BaseStorage):
            @property
            def name(self) -> str:
                return "sqlite"

            def save_scan(self, result: ScanResult) -> str:
                # Store to SQLite database
                ...
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this storage backend.

        Returns:
            A string identifier for this backend (e.g., 'sqlite', 'json').
        """
        pass

    @abstractmethod
    def save_scan(self, result: ScanResult) -> str:
        """Save a scan result to storage.

        Args:
            result: The ScanResult to store.

        Returns:
            A unique identifier for the stored scan that can be used
            to retrieve it later.

        Raises:
            StorageError: If the save operation fails.
        """
        pass

    @abstractmethod
    def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
        """Retrieve stored scans matching the filter criteria.

        Args:
            filter: Optional filter criteria. If None, returns all scans
                (up to any default limit imposed by the implementation).

        Returns:
            A list of StoredScan objects matching the filter criteria,
            ordered by stored_at descending (most recent first).

        Raises:
            StorageError: If the retrieval operation fails.
        """
        pass

    @abstractmethod
    def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
        """Retrieve findings matching the filter criteria.

        Args:
            filter: Optional filter criteria. If None, returns all findings
                (up to any default limit imposed by the implementation).

        Returns:
            A list of Finding objects matching the filter criteria.

        Raises:
            StorageError: If the retrieval operation fails.
        """
        pass

    @abstractmethod
    def get_statistics(self) -> ScanStatistics:
        """Get aggregate statistics across all stored scans.

        Returns:
            A ScanStatistics object with summary data.

        Raises:
            StorageError: If the statistics calculation fails.
        """
        pass

    def close(self) -> None:
        """Close any open connections or resources.

        Subclasses should override this method if they need to perform
        cleanup when the storage backend is no longer needed.

        This method is called automatically when using the storage
        backend as a context manager.
        """
        pass

    def __enter__(self) -> "BaseStorage":
        """Enter the context manager."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit the context manager and close resources."""
        self.close()


class StorageError(Exception):
    """Base exception for storage-related errors.

    Attributes:
        message: Human-readable error description.
        backend: The storage backend name where the error occurred.
        operation: The operation that failed (e.g., 'save', 'query').
    """

    def __init__(
        self,
        message: str,
        backend: str | None = None,
        operation: str | None = None,
    ) -> None:
        """Initialize a StorageError.

        Args:
            message: Human-readable error description.
            backend: The storage backend name where the error occurred.
            operation: The operation that failed.
        """
        self.message = message
        self.backend = backend
        self.operation = operation
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format the error message with context."""
        parts = []
        if self.backend:
            parts.append(f"[{self.backend}]")
        if self.operation:
            parts.append(f"{self.operation}:")
        parts.append(self.message)
        return " ".join(parts)


class StorageRegistry:
    """Registry for managing and retrieving storage backend instances.

    The registry allows storage backends to be registered by name and retrieved
    for persisting and querying scan results.
    """

    def __init__(self) -> None:
        """Initialize an empty storage registry."""
        self._backends: dict[str, BaseStorage] = {}

    def register(self, backend: BaseStorage) -> None:
        """Register a storage backend instance.

        Args:
            backend: The storage backend instance to register.

        Raises:
            ValueError: If a backend with the same name is already registered.
        """
        if backend.name in self._backends:
            raise ValueError(f"Storage backend '{backend.name}' is already registered")
        self._backends[backend.name] = backend

    def unregister(self, name: str) -> None:
        """Remove a storage backend from the registry.

        Args:
            name: The name of the backend to remove.

        Raises:
            KeyError: If no backend with the given name is registered.
        """
        if name not in self._backends:
            raise KeyError(f"Storage backend '{name}' is not registered")
        del self._backends[name]

    def get(self, name: str) -> BaseStorage:
        """Retrieve a storage backend by name.

        Args:
            name: The name of the backend to retrieve.

        Returns:
            The storage backend instance.

        Raises:
            KeyError: If no backend with the given name is registered.
        """
        if name not in self._backends:
            raise KeyError(f"Storage backend '{name}' is not registered")
        return self._backends[name]

    def get_all(self) -> list[BaseStorage]:
        """Retrieve all registered storage backends.

        Returns:
            A list of all registered backend instances.
        """
        return list(self._backends.values())

    def list_names(self) -> list[str]:
        """List the names of all registered storage backends.

        Returns:
            A list of backend names.
        """
        return list(self._backends.keys())

    def __len__(self) -> int:
        """Return the number of registered storage backends."""
        return len(self._backends)

    def __contains__(self, name: str) -> bool:
        """Check if a storage backend is registered by name."""
        return name in self._backends


# Global registry instance for convenience
default_registry = StorageRegistry()

# Lazy imports to avoid circular import issues
from hamburglar.storage.json_file import JsonFileStorage
from hamburglar.storage.sqlite import SqliteStorage

__all__ = [
    "BaseStorage",
    "FindingFilter",
    "JsonFileStorage",
    "ScanFilter",
    "ScanStatistics",
    "SqliteStorage",
    "StorageError",
    "StorageRegistry",
    "StoredScan",
    "default_registry",
]
