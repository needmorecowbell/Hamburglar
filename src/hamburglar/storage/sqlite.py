"""SQLite storage backend for Hamburglar.

This module provides persistent storage of scan results using SQLite,
enabling historical analysis and trend reporting across multiple scans.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage import (
    BaseStorage,
    FindingFilter,
    ScanFilter,
    ScanStatistics,
    StorageError,
    StoredScan,
)

# Database schema version for migrations
SCHEMA_VERSION = 1


class SqliteStorage(BaseStorage):
    """SQLite-based storage backend for scan results.

    This storage backend persists scan results to a SQLite database,
    enabling historical analysis, trend reporting, and querying of
    findings across multiple scans.

    Features:
        - Full scan result persistence with all finding details
        - Query by date range, file path, detector, and severity
        - Aggregate statistics calculation
        - Thread-safe concurrent access using connection pooling
        - Automatic schema creation and migration support

    Example:
        >>> with SqliteStorage("findings.db") as storage:
        ...     scan_id = storage.save_scan(result)
        ...     findings = storage.get_findings(FindingFilter(severity=[Severity.HIGH]))
        ...     stats = storage.get_statistics()

    Args:
        db_path: Path to the SQLite database file. If the file doesn't exist,
            it will be created. Use ":memory:" for an in-memory database.
        timeout: Database connection timeout in seconds (default: 30.0).
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        timeout: float = 30.0,
    ) -> None:
        """Initialize the SQLite storage backend.

        Args:
            db_path: Path to the SQLite database file or ":memory:" for
                an in-memory database.
            timeout: Connection timeout in seconds.
        """
        self._db_path = str(db_path) if isinstance(db_path, Path) else db_path
        self._timeout = timeout
        self._local = threading.local()
        self._closed = False
        self._lock = threading.RLock()

        # Initialize schema on first connection
        self._init_schema()

    @property
    def name(self) -> str:
        """Return the storage backend name."""
        return "sqlite"

    @property
    def db_path(self) -> str:
        """Return the database file path."""
        return self._db_path

    def _get_connection(self) -> sqlite3.Connection:
        """Get a thread-local database connection.

        Returns:
            A SQLite connection for the current thread.

        Raises:
            StorageError: If the storage has been closed.
        """
        if self._closed:
            raise StorageError(
                "Storage has been closed",
                backend=self.name,
                operation="connect",
            )

        if not hasattr(self._local, "connection") or self._local.connection is None:
            try:
                self._local.connection = sqlite3.connect(
                    self._db_path,
                    timeout=self._timeout,
                    check_same_thread=False,
                )
                # Enable foreign keys
                self._local.connection.execute("PRAGMA foreign_keys = ON")
                # Use WAL mode for better concurrent access
                if self._db_path != ":memory:":
                    self._local.connection.execute("PRAGMA journal_mode = WAL")
                # Return rows as sqlite3.Row for named column access
                self._local.connection.row_factory = sqlite3.Row
            except sqlite3.Error as e:
                raise StorageError(
                    f"Failed to connect to database: {e}",
                    backend=self.name,
                    operation="connect",
                ) from e

        return self._local.connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        """Context manager for database transactions.

        Yields:
            A database cursor within a transaction.

        Raises:
            StorageError: If the transaction fails.
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            raise StorageError(
                f"Transaction failed: {e}",
                backend=self.name,
                operation="transaction",
            ) from e
        finally:
            cursor.close()

    def _init_schema(self) -> None:
        """Initialize the database schema.

        Creates all necessary tables if they don't exist.
        """
        with self._transaction() as cursor:
            # Schema version tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)

            # Scans table - stores scan metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_path TEXT NOT NULL,
                    scan_duration REAL NOT NULL DEFAULT 0.0,
                    stats_json TEXT,
                    stored_at TEXT NOT NULL,
                    metadata_json TEXT
                )
            """)

            # Create index on target_path and stored_at for efficient querying
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target_path
                ON scans(target_path)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_stored_at
                ON scans(stored_at)
            """)

            # Detectors table - stores unique detector definitions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS detectors (
                    detector_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Findings table - stores individual findings
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    detector_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    matches_json TEXT NOT NULL,
                    metadata_json TEXT,
                    line_number INTEGER,
                    context TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                )
            """)

            # Create indexes for common query patterns
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id
                ON findings(scan_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_file_path
                ON findings(file_path)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_detector_name
                ON findings(detector_name)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings(severity)
            """)

            # Set schema version
            cursor.execute(
                """
                INSERT OR REPLACE INTO schema_version (version) VALUES (?)
            """,
                (SCHEMA_VERSION,),
            )

    def save_scan(self, result: ScanResult) -> str:
        """Save a scan result to the database.

        Args:
            result: The ScanResult to store.

        Returns:
            A unique scan ID for the stored scan.

        Raises:
            StorageError: If the save operation fails.
        """
        scan_id = str(uuid.uuid4())
        stored_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._transaction() as cursor:
                # Insert the scan record
                cursor.execute(
                    """
                    INSERT INTO scans (scan_id, target_path, scan_duration, stats_json, stored_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (
                        scan_id,
                        result.target_path,
                        result.scan_duration,
                        json.dumps(result.stats),
                        stored_at,
                    ),
                )

                # Insert all findings
                for finding in result.findings:
                    # Extract line number from metadata if present
                    line_number = finding.metadata.get("line") or finding.metadata.get(
                        "line_number"
                    )
                    context = finding.metadata.get("context")

                    cursor.execute(
                        """
                        INSERT INTO findings (
                            scan_id, file_path, detector_name, severity,
                            matches_json, metadata_json, line_number, context
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            scan_id,
                            finding.file_path,
                            finding.detector_name,
                            finding.severity.value,
                            json.dumps(finding.matches),
                            json.dumps(finding.metadata),
                            line_number,
                            context,
                        ),
                    )

                    # Ensure detector is registered
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO detectors (name) VALUES (?)
                    """,
                        (finding.detector_name,),
                    )

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to save scan: {e}",
                backend=self.name,
                operation="save_scan",
            ) from e

        return scan_id

    def get_scans(self, filter: ScanFilter | None = None) -> list[StoredScan]:
        """Retrieve stored scans matching the filter criteria.

        Args:
            filter: Optional filter criteria. If None, returns all scans.

        Returns:
            A list of StoredScan objects ordered by stored_at descending.

        Raises:
            StorageError: If the retrieval fails.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Build the query dynamically based on filters
            query = "SELECT scan_id, target_path, scan_duration, stats_json, stored_at, metadata_json FROM scans"
            conditions: list[str] = []
            params: list[Any] = []

            if filter is not None:
                if filter.target_path:
                    conditions.append("target_path LIKE ?")
                    params.append(f"{filter.target_path}%")

                if filter.since:
                    conditions.append("stored_at >= ?")
                    params.append(filter.since.isoformat())

                if filter.until:
                    conditions.append("stored_at <= ?")
                    params.append(filter.until.isoformat())

                if filter.min_findings is not None or filter.max_findings is not None:
                    # We need a subquery to count findings
                    subquery = (
                        "(SELECT COUNT(*) FROM findings WHERE findings.scan_id = scans.scan_id)"
                    )
                    if filter.min_findings is not None:
                        conditions.append(f"{subquery} >= ?")
                        params.append(filter.min_findings)
                    if filter.max_findings is not None:
                        conditions.append(f"{subquery} <= ?")
                        params.append(filter.max_findings)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY stored_at DESC"

            if filter is not None:
                if filter.limit:
                    query += " LIMIT ?"
                    params.append(filter.limit)

                if filter.offset:
                    if not filter.limit:
                        # SQLite requires LIMIT before OFFSET
                        query += " LIMIT -1"
                    query += " OFFSET ?"
                    params.append(filter.offset)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            # Convert rows to StoredScan objects
            result: list[StoredScan] = []
            for row in rows:
                # Fetch findings for this scan
                cursor.execute(
                    """
                    SELECT file_path, detector_name, severity, matches_json, metadata_json
                    FROM findings
                    WHERE scan_id = ?
                """,
                    (row["scan_id"],),
                )
                finding_rows = cursor.fetchall()

                findings = [
                    Finding(
                        file_path=f["file_path"],
                        detector_name=f["detector_name"],
                        severity=Severity(f["severity"]),
                        matches=json.loads(f["matches_json"]),
                        metadata=json.loads(f["metadata_json"]) if f["metadata_json"] else {},
                    )
                    for f in finding_rows
                ]

                scan_result = ScanResult(
                    target_path=row["target_path"],
                    findings=findings,
                    scan_duration=row["scan_duration"],
                    stats=json.loads(row["stats_json"]) if row["stats_json"] else {},
                )

                stored_at = datetime.fromisoformat(row["stored_at"])
                metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}

                result.append(
                    StoredScan(
                        scan_id=row["scan_id"],
                        scan_result=scan_result,
                        stored_at=stored_at,
                        metadata=metadata,
                    )
                )

            cursor.close()
            return result

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to retrieve scans: {e}",
                backend=self.name,
                operation="get_scans",
            ) from e

    def get_findings(self, filter: FindingFilter | None = None) -> list[Finding]:
        """Retrieve findings matching the filter criteria.

        Args:
            filter: Optional filter criteria. If None, returns all findings.

        Returns:
            A list of Finding objects.

        Raises:
            StorageError: If the retrieval fails.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Build the query dynamically
            query = """
                SELECT f.file_path, f.detector_name, f.severity, f.matches_json, f.metadata_json,
                       s.stored_at, s.target_path
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
            """
            conditions: list[str] = []
            params: list[Any] = []

            if filter is not None:
                if filter.file_path:
                    conditions.append("f.file_path LIKE ?")
                    params.append(f"{filter.file_path}%")

                if filter.detector_name:
                    conditions.append("f.detector_name = ?")
                    params.append(filter.detector_name)

                if filter.severity:
                    placeholders = ", ".join("?" for _ in filter.severity)
                    conditions.append(f"f.severity IN ({placeholders})")
                    params.extend(s.value for s in filter.severity)

                if filter.target_path:
                    conditions.append("s.target_path LIKE ?")
                    params.append(f"{filter.target_path}%")

                if filter.since:
                    conditions.append("s.stored_at >= ?")
                    params.append(filter.since.isoformat())

                if filter.until:
                    conditions.append("s.stored_at <= ?")
                    params.append(filter.until.isoformat())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY s.stored_at DESC"

            if filter is not None:
                if filter.limit:
                    query += " LIMIT ?"
                    params.append(filter.limit)

                if filter.offset:
                    if not filter.limit:
                        query += " LIMIT -1"
                    query += " OFFSET ?"
                    params.append(filter.offset)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            result = [
                Finding(
                    file_path=row["file_path"],
                    detector_name=row["detector_name"],
                    severity=Severity(row["severity"]),
                    matches=json.loads(row["matches_json"]),
                    metadata=json.loads(row["metadata_json"]) if row["metadata_json"] else {},
                )
                for row in rows
            ]

            cursor.close()
            return result

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to retrieve findings: {e}",
                backend=self.name,
                operation="get_findings",
            ) from e

    def get_statistics(self) -> ScanStatistics:
        """Get aggregate statistics across all stored scans.

        Returns:
            A ScanStatistics object with summary data.

        Raises:
            StorageError: If the statistics calculation fails.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Get total scans
            cursor.execute("SELECT COUNT(*) as count FROM scans")
            total_scans = cursor.fetchone()["count"]

            # Get total findings
            cursor.execute("SELECT COUNT(*) as count FROM findings")
            total_findings = cursor.fetchone()["count"]

            # Get unique files scanned (from findings)
            cursor.execute("SELECT COUNT(DISTINCT file_path) as count FROM findings")
            total_files_scanned = cursor.fetchone()["count"]

            # Get findings by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                GROUP BY severity
            """)
            findings_by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

            # Get findings by detector
            cursor.execute("""
                SELECT detector_name, COUNT(*) as count
                FROM findings
                GROUP BY detector_name
            """)
            findings_by_detector = {row["detector_name"]: row["count"] for row in cursor.fetchall()}

            # Get scans by date
            cursor.execute("""
                SELECT DATE(stored_at) as scan_date, COUNT(*) as count
                FROM scans
                GROUP BY DATE(stored_at)
            """)
            scans_by_date = {row["scan_date"]: row["count"] for row in cursor.fetchall()}

            # Get first and last scan dates
            first_scan_date: datetime | None = None
            last_scan_date: datetime | None = None

            cursor.execute("SELECT MIN(stored_at) as first_date FROM scans")
            first_row = cursor.fetchone()
            if first_row["first_date"]:
                first_scan_date = datetime.fromisoformat(first_row["first_date"])

            cursor.execute("SELECT MAX(stored_at) as last_date FROM scans")
            last_row = cursor.fetchone()
            if last_row["last_date"]:
                last_scan_date = datetime.fromisoformat(last_row["last_date"])

            # Calculate averages
            average_findings_per_scan = 0.0
            average_scan_duration = 0.0

            if total_scans > 0:
                average_findings_per_scan = total_findings / total_scans

                cursor.execute("SELECT AVG(scan_duration) as avg_duration FROM scans")
                avg_row = cursor.fetchone()
                if avg_row["avg_duration"] is not None:
                    average_scan_duration = avg_row["avg_duration"]

            cursor.close()

            return ScanStatistics(
                total_scans=total_scans,
                total_findings=total_findings,
                total_files_scanned=total_files_scanned,
                findings_by_severity=findings_by_severity,
                findings_by_detector=findings_by_detector,
                scans_by_date=scans_by_date,
                first_scan_date=first_scan_date,
                last_scan_date=last_scan_date,
                average_findings_per_scan=average_findings_per_scan,
                average_scan_duration=average_scan_duration,
            )

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to calculate statistics: {e}",
                backend=self.name,
                operation="get_statistics",
            ) from e

    def get_scan_by_id(self, scan_id: str) -> StoredScan | None:
        """Retrieve a specific scan by its ID.

        Args:
            scan_id: The unique scan identifier.

        Returns:
            The StoredScan if found, None otherwise.

        Raises:
            StorageError: If the retrieval fails.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT scan_id, target_path, scan_duration, stats_json, stored_at, metadata_json
                FROM scans WHERE scan_id = ?
            """,
                (scan_id,),
            )
            row = cursor.fetchone()

            if row is None:
                cursor.close()
                return None

            # Fetch findings for this scan
            cursor.execute(
                """
                SELECT file_path, detector_name, severity, matches_json, metadata_json
                FROM findings WHERE scan_id = ?
            """,
                (scan_id,),
            )
            finding_rows = cursor.fetchall()

            findings = [
                Finding(
                    file_path=f["file_path"],
                    detector_name=f["detector_name"],
                    severity=Severity(f["severity"]),
                    matches=json.loads(f["matches_json"]),
                    metadata=json.loads(f["metadata_json"]) if f["metadata_json"] else {},
                )
                for f in finding_rows
            ]

            scan_result = ScanResult(
                target_path=row["target_path"],
                findings=findings,
                scan_duration=row["scan_duration"],
                stats=json.loads(row["stats_json"]) if row["stats_json"] else {},
            )

            stored_at = datetime.fromisoformat(row["stored_at"])
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}

            cursor.close()

            return StoredScan(
                scan_id=row["scan_id"],
                scan_result=scan_result,
                stored_at=stored_at,
                metadata=metadata,
            )

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to retrieve scan by ID: {e}",
                backend=self.name,
                operation="get_scan_by_id",
            ) from e

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all its findings from the database.

        Args:
            scan_id: The unique scan identifier.

        Returns:
            True if the scan was deleted, False if it wasn't found.

        Raises:
            StorageError: If the deletion fails.
        """
        try:
            with self._transaction() as cursor:
                cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                return cursor.rowcount > 0

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to delete scan: {e}",
                backend=self.name,
                operation="delete_scan",
            ) from e

    def clear(self) -> None:
        """Delete all scans and findings from the database.

        Raises:
            StorageError: If the clear operation fails.
        """
        try:
            with self._transaction() as cursor:
                cursor.execute("DELETE FROM findings")
                cursor.execute("DELETE FROM scans")

        except StorageError:
            raise
        except Exception as e:
            raise StorageError(
                f"Failed to clear database: {e}",
                backend=self.name,
                operation="clear",
            ) from e

    def close(self) -> None:
        """Close all database connections.

        After calling this method, the storage backend cannot be used.
        """
        with self._lock:
            self._closed = True
            if hasattr(self._local, "connection") and self._local.connection is not None:
                try:
                    self._local.connection.close()
                except sqlite3.Error:
                    pass
                self._local.connection = None
