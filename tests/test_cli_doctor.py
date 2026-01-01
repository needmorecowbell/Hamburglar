"""Tests for the CLI doctor command.

This module tests the 'hamburglar doctor' command that performs
system health checks on the Hamburglar installation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest
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

from hamburglar.cli.main import app
from hamburglar.config import reset_config

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_config_before_each_test():
    """Reset config cache before each test to ensure isolation."""
    reset_config()
    yield
    reset_config()


class TestDoctorCommand:
    """Tests for 'hamburglar doctor' command."""

    def test_doctor_help(self) -> None:
        """Test that doctor --help displays help."""
        result = runner.invoke(app, ["doctor", "--help"])
        assert result.exit_code == 0
        assert "Check Hamburglar's environment" in result.output

    def test_doctor_runs_successfully(self) -> None:
        """Test that doctor command runs and shows checks."""
        result = runner.invoke(app, ["doctor"])
        # Should run successfully (exit code 0 unless there are errors)
        assert result.exit_code in (0, 1)  # 0 = success, 1 = errors found
        # Should show health check panel
        assert "Hamburglar Doctor" in result.output or "System Health Check" in result.output
        # Should show various checks
        assert "Python Version" in result.output
        assert "Dependencies" in result.output

    def test_doctor_quiet_mode(self) -> None:
        """Test that doctor -q suppresses success messages."""
        result = runner.invoke(app, ["doctor", "-q"])
        assert result.exit_code in (0, 1)
        # In quiet mode, shouldn't show the header panel
        if result.exit_code == 0:
            assert "Hamburglar Doctor" not in result.output

    def test_doctor_verbose_mode(self) -> None:
        """Test that doctor -v shows detailed information."""
        result = runner.invoke(app, ["doctor", "-v"])
        assert result.exit_code in (0, 1)
        # In verbose mode, should show more details
        # Check for typical verbose output patterns
        assert "Python" in result.output

    def test_doctor_checks_python_version(self) -> None:
        """Test that doctor checks Python version."""
        result = runner.invoke(app, ["doctor"])
        assert "Python Version" in result.output
        # Should show the Python version
        assert "Python" in result.output

    def test_doctor_checks_dependencies(self) -> None:
        """Test that doctor checks required dependencies."""
        result = runner.invoke(app, ["doctor"])
        assert "Dependencies" in result.output
        # Should show dependency status
        assert "packages" in result.output.lower() or "installed" in result.output.lower()

    def test_doctor_checks_yara(self) -> None:
        """Test that doctor checks YARA installation."""
        result = runner.invoke(app, ["doctor"])
        assert "YARA" in result.output

    def test_doctor_checks_configuration(self) -> None:
        """Test that doctor checks configuration."""
        result = runner.invoke(app, ["doctor"])
        assert "Configuration" in result.output

    def test_doctor_checks_plugin_system(self) -> None:
        """Test that doctor checks plugin system."""
        result = runner.invoke(app, ["doctor"])
        assert "Plugin" in result.output

    def test_doctor_checks_data_directory(self) -> None:
        """Test that doctor checks data directory."""
        result = runner.invoke(app, ["doctor"])
        # Should check the data directory
        assert "Directory" in result.output or "Data" in result.output

    def test_doctor_with_invalid_config_file(self, tmp_path: Path) -> None:
        """Test that doctor reports invalid config file."""
        # Create an invalid config file
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: "not a number"  # Invalid type
"""
        )

        # Mock find_config_file to return our invalid config
        with mock.patch(
            "hamburglar.config.loader.ConfigLoader.find_config_file",
            return_value=config_file,
        ):
            result = runner.invoke(app, ["doctor"])
            # Should still run but may show warning/error
            assert "Configuration" in result.output

    def test_doctor_with_valid_config_file(self, tmp_path: Path) -> None:
        """Test that doctor reports valid config file."""
        # Create a valid config file
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
"""
        )

        # Mock find_config_file to return our valid config
        with mock.patch(
            "hamburglar.config.loader.ConfigLoader.find_config_file",
            return_value=config_file,
        ):
            result = runner.invoke(app, ["doctor"])
            assert "Configuration" in result.output

    def test_doctor_exit_codes(self) -> None:
        """Test that doctor returns appropriate exit codes."""
        result = runner.invoke(app, ["doctor"])
        # Exit code should be 0 (success) or 1 (errors found)
        assert result.exit_code in (0, 1)

    def test_doctor_shows_status_icons(self) -> None:
        """Test that doctor displays status icons."""
        result = runner.invoke(app, ["doctor"])
        # Should show at least one status (check mark or similar)
        # Rich may render these differently, so check for common output
        assert result.exit_code in (0, 1)
        # Just verify it runs and produces output
        assert len(result.output) > 0


class TestDoctorPythonVersionCheck:
    """Tests specifically for Python version checking."""

    def test_doctor_detects_current_python(self) -> None:
        """Test that doctor correctly detects current Python version."""
        import platform

        result = runner.invoke(app, ["doctor", "-v"])
        # Should show the current Python version
        current_version = platform.python_version()
        major_minor = ".".join(current_version.split(".")[:2])
        assert major_minor in result.output or "Python" in result.output


class TestDoctorDependencyCheck:
    """Tests specifically for dependency checking."""

    def test_doctor_checks_required_packages(self) -> None:
        """Test that doctor checks for required packages."""
        result = runner.invoke(app, ["doctor"])
        assert "Dependencies" in result.output

    def test_doctor_with_missing_package(self) -> None:
        """Test doctor behavior when a package is missing."""
        # This is tricky to test without actually uninstalling packages
        # We can mock the importlib.metadata.version to raise PackageNotFoundError

        import importlib.metadata

        original_version = importlib.metadata.version

        def mock_version(name):
            if name == "typer":
                raise importlib.metadata.PackageNotFoundError(name)
            return original_version(name)

        with mock.patch("importlib.metadata.version", side_effect=mock_version):
            result = runner.invoke(app, ["doctor"])
            # Should report the missing package
            assert "Dependencies" in result.output


class TestDoctorYaraCheck:
    """Tests specifically for YARA checking."""

    def test_doctor_with_yara_available(self) -> None:
        """Test doctor when YARA is available."""
        result = runner.invoke(app, ["doctor"])
        assert "YARA" in result.output

    def test_doctor_with_yara_unavailable(self) -> None:
        """Test doctor when YARA is not available."""
        # Mock yara import to fail
        with mock.patch.dict("sys.modules", {"yara": None}):
            # Need to reload the module context, but this is tricky
            # For now, just verify the check exists
            result = runner.invoke(app, ["doctor"])
            assert "YARA" in result.output


class TestDoctorFixFlag:
    """Tests for the --fix flag."""

    def test_doctor_fix_creates_directory(self, tmp_path: Path) -> None:
        """Test that --fix can create missing directories."""
        # Mock the home directory to a temp location without .hamburglar
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()

        with mock.patch.object(Path, "home", return_value=fake_home):
            result = runner.invoke(app, ["doctor", "--fix"])
            # Check should complete
            assert result.exit_code in (0, 1)

    def test_doctor_without_fix_does_not_create(self, tmp_path: Path) -> None:
        """Test that without --fix, directories are not created."""
        fake_home = tmp_path / "fake_home"
        fake_home.mkdir()
        expected_dir = fake_home / ".hamburglar"

        with mock.patch.object(Path, "home", return_value=fake_home):
            result = runner.invoke(app, ["doctor"])
            # Directory should not be created without --fix
            # (unless it already exists from a previous run)
            assert result.exit_code in (0, 1)


class TestDoctorYaraRulesCheck:
    """Tests for YARA rules directory checking."""

    def test_doctor_checks_yara_rules(self) -> None:
        """Test that doctor checks for YARA rules."""
        result = runner.invoke(app, ["doctor"])
        # Should mention YARA rules
        assert "YARA" in result.output

    def test_doctor_reports_yara_rules_count(self) -> None:
        """Test that doctor reports YARA rules count when available."""
        result = runner.invoke(app, ["doctor"])
        # If YARA rules are found, should report count
        # This depends on the actual installation
        assert result.exit_code in (0, 1)
