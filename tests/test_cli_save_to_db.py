"""Tests for the Hamburglar CLI --save-to-db option.

This module tests the --save-to-db and --db-path options which save
scan results to a SQLite database for historical analysis.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from typer.testing import CliRunner

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.cli.main import (
    DEFAULT_DB_PATH,
    app,
    get_db_path,
    save_to_database,
)
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.storage.sqlite import SqliteStorage

runner = CliRunner()


class TestDefaultDbPath:
    """Test the DEFAULT_DB_PATH constant."""

    def test_default_db_path_is_in_home_directory(self) -> None:
        """Test that default database path is in home directory."""
        assert str(DEFAULT_DB_PATH).startswith(str(Path.home()))

    def test_default_db_path_is_in_hamburglar_directory(self) -> None:
        """Test that default database path is in .hamburglar directory."""
        assert ".hamburglar" in str(DEFAULT_DB_PATH)

    def test_default_db_path_has_correct_filename(self) -> None:
        """Test that default database path has findings.db filename."""
        assert DEFAULT_DB_PATH.name == "findings.db"


class TestGetDbPath:
    """Test the get_db_path helper function."""

    def test_returns_default_when_none(self) -> None:
        """Test that get_db_path returns default when no custom path given."""
        result = get_db_path(None)
        assert result == DEFAULT_DB_PATH

    def test_returns_custom_path_when_provided(self, tmp_path: Path) -> None:
        """Test that get_db_path returns custom path when provided."""
        custom_path = tmp_path / "custom.db"
        result = get_db_path(custom_path)
        assert result == custom_path.resolve()

    def test_resolves_custom_path(self, tmp_path: Path) -> None:
        """Test that custom path is resolved to absolute path."""
        # Create a relative-looking path
        custom_path = tmp_path / "subdir" / ".." / "custom.db"
        result = get_db_path(custom_path)
        # Should resolve to the canonical path
        assert result == (tmp_path / "custom.db").resolve()


class TestSaveToDatabase:
    """Test the save_to_database helper function."""

    def test_saves_scan_result(self, tmp_path: Path) -> None:
        """Test that save_to_database saves the scan result."""
        db_path = tmp_path / "test.db"

        # Create a scan result with findings
        result = ScanResult(
            target_path="/test/path",
            findings=[
                Finding(
                    file_path="/test/path/file.txt",
                    detector_name="test_detector",
                    severity=Severity.HIGH,
                    matches=["match1"],
                    metadata={},
                )
            ],
            scan_duration=1.5,
            stats={"files_scanned": 10},
        )

        # Save to database
        scan_id = save_to_database(result, db_path, quiet=True)

        # Verify the scan was saved
        assert scan_id is not None
        assert db_path.exists()

        # Query the database to verify
        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 1
            assert scans[0].scan_id == scan_id

    def test_creates_database_directory(self, tmp_path: Path) -> None:
        """Test that save_to_database creates the directory if it doesn't exist."""
        db_path = tmp_path / "nested" / "dirs" / "test.db"
        assert not db_path.parent.exists()

        result = ScanResult(
            target_path="/test/path",
            findings=[],
            scan_duration=0.5,
            stats={},
        )

        save_to_database(result, db_path, quiet=True)

        assert db_path.parent.exists()
        assert db_path.exists()

    def test_verbose_mode_shows_scan_id(self, tmp_path: Path, capsys) -> None:
        """Test that verbose mode displays the scan ID."""
        db_path = tmp_path / "test.db"

        result = ScanResult(
            target_path="/test/path",
            findings=[],
            scan_duration=0.5,
            stats={},
        )

        # Note: We can't easily test Rich console output in unit tests
        # This test just verifies the function completes without error
        scan_id = save_to_database(result, db_path, quiet=False, verbose=True)
        assert scan_id is not None


class TestScanSaveToDb:
    """Test --save-to-db option for scan command."""

    def test_save_to_db_creates_database(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db creates the database file."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result.exit_code == 0
        assert db_path.exists()

    def test_save_to_db_stores_findings(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db stores findings in the database."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result.exit_code == 0

        # Query the database
        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 1
            # Should have some findings since temp_directory has secrets
            assert len(scans[0].scan_result.findings) > 0

    def test_save_to_db_with_quiet_mode(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db works with --quiet mode."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        # In quiet mode, there should be no output
        assert result.output == ""
        # But database should still be created
        assert db_path.exists()

    def test_save_to_db_with_verbose_mode(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db shows scan ID in --verbose mode."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
                "--verbose",
            ],
        )
        assert result.exit_code == 0
        assert "Saved to database" in result.output
        assert "Scan ID" in result.output

    def test_save_to_db_creates_nested_directories(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test that --save-to-db creates nested directories for custom db path."""
        db_path = tmp_path / "deep" / "nested" / "path" / "findings.db"
        assert not db_path.parent.exists()

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result.exit_code == 0
        assert db_path.exists()

    def test_db_path_without_save_to_db_is_ignored(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test that --db-path without --save-to-db does not create database."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--db-path",
                str(db_path),
            ],
        )
        # Command should succeed but not create database
        assert result.exit_code == 0
        assert not db_path.exists()

    def test_save_to_db_preserves_target_path(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that saved scan result contains correct target path."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result.exit_code == 0

        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 1
            assert scans[0].scan_result.target_path == str(temp_directory)

    def test_multiple_scans_saved(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that multiple scans can be saved to the same database."""
        db_path = tmp_path / "findings.db"

        # Run first scan
        result1 = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result1.exit_code == 0

        # Run second scan
        result2 = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result2.exit_code == 0

        # Verify both scans were saved
        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 2


class TestScanGitSaveToDb:
    """Test --save-to-db option for scan-git command."""

    def test_scan_git_save_to_db_help_shows_option(self) -> None:
        """Test that scan-git --help shows --save-to-db option."""
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "--save-to-db" in result.output
        assert "--db-path" in result.output


class TestScanWebSaveToDb:
    """Test --save-to-db option for scan-web command."""

    def test_scan_web_save_to_db_help_shows_option(self) -> None:
        """Test that scan-web --help shows --save-to-db option."""
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0
        assert "--save-to-db" in result.output
        assert "--db-path" in result.output


class TestHelpText:
    """Test that help text includes --save-to-db and --db-path options."""

    def test_scan_help_shows_save_to_db(self) -> None:
        """Test that scan --help shows --save-to-db option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--save-to-db" in result.output

    def test_scan_help_shows_db_path(self) -> None:
        """Test that scan --help shows --db-path option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--db-path" in result.output

    def test_scan_git_help_shows_save_to_db(self) -> None:
        """Test that scan-git --help shows --save-to-db option."""
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "--save-to-db" in result.output

    def test_scan_git_help_shows_db_path(self) -> None:
        """Test that scan-git --help shows --db-path option."""
        result = runner.invoke(app, ["scan-git", "--help"])
        assert result.exit_code == 0
        assert "--db-path" in result.output

    def test_scan_web_help_shows_save_to_db(self) -> None:
        """Test that scan-web --help shows --save-to-db option."""
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0
        assert "--save-to-db" in result.output

    def test_scan_web_help_shows_db_path(self) -> None:
        """Test that scan-web --help shows --db-path option."""
        result = runner.invoke(app, ["scan-web", "--help"])
        assert result.exit_code == 0
        assert "--db-path" in result.output


class TestDatabaseSchema:
    """Test that saved data has correct schema."""

    def test_saved_findings_have_correct_structure(
        self, temp_directory: Path, tmp_path: Path
    ) -> None:
        """Test that saved findings have all required fields."""
        db_path = tmp_path / "findings.db"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
            ],
        )
        assert result.exit_code == 0

        # Verify database schema by querying directly
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        # Check scans table
        cursor = conn.execute("SELECT * FROM scans LIMIT 1")
        scan_row = cursor.fetchone()
        assert scan_row is not None
        assert "scan_id" in scan_row.keys()
        assert "target_path" in scan_row.keys()
        assert "scan_duration" in scan_row.keys()
        assert "stored_at" in scan_row.keys()

        # Check findings table
        cursor = conn.execute("SELECT * FROM findings LIMIT 1")
        finding_row = cursor.fetchone()
        if finding_row:
            assert "finding_id" in finding_row.keys()
            assert "scan_id" in finding_row.keys()
            assert "file_path" in finding_row.keys()
            assert "detector_name" in finding_row.keys()
            assert "severity" in finding_row.keys()

        conn.close()


class TestWithOutputOptions:
    """Test --save-to-db works with other output options."""

    def test_save_to_db_with_output_file(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db works alongside --output."""
        db_path = tmp_path / "findings.db"
        output_file = tmp_path / "output.json"

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
                "--output",
                str(output_file),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        assert db_path.exists()
        assert output_file.exists()

    def test_save_to_db_with_output_dir(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db works alongside --output-dir."""
        db_path = tmp_path / "findings.db"
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = runner.invoke(
            app,
            [
                "scan",
                str(temp_directory),
                "--save-to-db",
                "--db-path",
                str(db_path),
                "--output-dir",
                str(output_dir),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        assert db_path.exists()
        # Should have created a file in output_dir
        assert len(list(output_dir.glob("*.json"))) == 1

    def test_save_to_db_with_different_formats(self, temp_directory: Path, tmp_path: Path) -> None:
        """Test that --save-to-db works with different output formats."""
        db_path = tmp_path / "findings.db"

        for fmt in ["json", "table", "sarif", "csv", "html", "markdown"]:
            result = runner.invoke(
                app,
                [
                    "scan",
                    str(temp_directory),
                    "--save-to-db",
                    "--db-path",
                    str(db_path),
                    "--format",
                    fmt,
                ],
            )
            assert result.exit_code == 0, f"Failed with format {fmt}"

        # All scans should be saved
        with SqliteStorage(db_path) as storage:
            scans = storage.get_scans()
            assert len(scans) == 6  # One for each format
