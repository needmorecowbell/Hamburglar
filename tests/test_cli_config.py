"""Tests for the CLI config command group.

This module tests the 'config show', 'config init', and 'config validate'
commands that allow users to manage Hamburglar's configuration.
"""

from __future__ import annotations

import json
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


class TestConfigShowCommand:
    """Tests for 'hamburglar config show' command."""

    def test_config_show_help(self) -> None:
        """Test that config show --help displays help."""
        result = runner.invoke(app, ["config", "show", "--help"])
        assert result.exit_code == 0
        assert "Display current configuration" in result.output

    def test_config_show_default_output(self) -> None:
        """Test that config show displays configuration in YAML format by default."""
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        # Should contain YAML-style output
        assert "scan:" in result.output or "recursive" in result.output

    def test_config_show_json_format(self) -> None:
        """Test that config show --format json outputs valid JSON."""
        result = runner.invoke(app, ["config", "show", "--format", "json", "-q"])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "scan" in data
        assert "detector" in data
        assert "output" in data

    def test_config_show_quiet_mode(self) -> None:
        """Test that config show -q suppresses info messages."""
        result = runner.invoke(app, ["config", "show", "-q"])
        assert result.exit_code == 0
        # Should not contain "Config file:" info line
        assert "Config file:" not in result.output
        assert "No config file found" not in result.output

    def test_config_show_with_sources(self) -> None:
        """Test that config show --sources shows configuration sources."""
        result = runner.invoke(app, ["config", "show", "--sources"])
        assert result.exit_code == 0
        assert "Configuration Sources:" in result.output

    def test_config_show_with_config_file(self, tmp_path: Path) -> None:
        """Test that config show detects and uses config file."""
        # Create a config file
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 100
"""
        )

        # Mock find_config_file to return our temp config
        with mock.patch(
            "hamburglar.config.loader.ConfigLoader.find_config_file",
            return_value=config_file,
        ):
            result = runner.invoke(app, ["config", "show"])
            assert result.exit_code == 0
            # Should mention the config file
            assert str(config_file) in result.output or "Config file:" in result.output


class TestConfigInitCommand:
    """Tests for 'hamburglar config init' command."""

    def test_config_init_help(self) -> None:
        """Test that config init --help displays help."""
        result = runner.invoke(app, ["config", "init", "--help"])
        assert result.exit_code == 0
        assert "Create a default config file" in result.output

    def test_config_init_creates_yaml_by_default(self, tmp_path: Path) -> None:
        """Test that config init creates .hamburglar.yml by default."""
        result = runner.invoke(app, ["config", "init", str(tmp_path)])
        assert result.exit_code == 0
        assert "Created config file" in result.output

        config_file = tmp_path / ".hamburglar.yml"
        assert config_file.exists()
        content = config_file.read_text()
        assert "scan:" in content
        assert "recursive:" in content

    def test_config_init_creates_json(self, tmp_path: Path) -> None:
        """Test that config init --format json creates JSON config."""
        result = runner.invoke(app, ["config", "init", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0

        config_file = tmp_path / "hamburglar.config.json"
        assert config_file.exists()
        content = config_file.read_text()
        # Should be valid JSON
        data = json.loads(content)
        assert "scan" in data

    def test_config_init_creates_toml(self, tmp_path: Path) -> None:
        """Test that config init --format toml creates TOML config."""
        result = runner.invoke(app, ["config", "init", str(tmp_path), "--format", "toml"])
        assert result.exit_code == 0

        config_file = tmp_path / ".hamburglar.toml"
        assert config_file.exists()
        content = config_file.read_text()
        assert "[scan]" in content

    def test_config_init_refuses_overwrite_without_force(self, tmp_path: Path) -> None:
        """Test that config init refuses to overwrite existing file without --force."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text("existing content")

        result = runner.invoke(app, ["config", "init", str(tmp_path)])
        assert result.exit_code != 0
        assert "already exists" in result.output
        assert "--force" in result.output

        # File should not be changed
        assert config_file.read_text() == "existing content"

    def test_config_init_force_overwrites(self, tmp_path: Path) -> None:
        """Test that config init --force overwrites existing file."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text("existing content")

        result = runner.invoke(app, ["config", "init", str(tmp_path), "--force"])
        assert result.exit_code == 0
        assert "Created config file" in result.output

        # File should be overwritten
        content = config_file.read_text()
        assert "scan:" in content
        assert "existing content" not in content

    def test_config_init_nonexistent_directory(self, tmp_path: Path) -> None:
        """Test that config init fails for nonexistent directory."""
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(app, ["config", "init", str(nonexistent)])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_config_init_quiet_mode(self, tmp_path: Path) -> None:
        """Test that config init -q suppresses messages."""
        result = runner.invoke(app, ["config", "init", str(tmp_path), "-q"])
        assert result.exit_code == 0
        # Should not have success message
        assert "Created config file" not in result.output

    def test_config_init_invalid_format(self, tmp_path: Path) -> None:
        """Test that config init rejects invalid format."""
        result = runner.invoke(app, ["config", "init", str(tmp_path), "--format", "xml"])
        assert result.exit_code != 0
        assert "Unknown format" in result.output

    def test_config_init_uses_cwd_by_default(self, tmp_path: Path, monkeypatch) -> None:
        """Test that config init uses current directory when no path specified."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["config", "init"])
        assert result.exit_code == 0

        config_file = tmp_path / ".hamburglar.yml"
        assert config_file.exists()


class TestConfigValidateCommand:
    """Tests for 'hamburglar config validate' command."""

    def test_config_validate_help(self) -> None:
        """Test that config validate --help displays help."""
        result = runner.invoke(app, ["config", "validate", "--help"])
        assert result.exit_code == 0
        assert "Validate configuration file" in result.output

    def test_config_validate_valid_yaml(self, tmp_path: Path) -> None:
        """Test that config validate passes for valid YAML config."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
  recursive: true
output:
  format: json
"""
        )

        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_config_validate_valid_json(self, tmp_path: Path) -> None:
        """Test that config validate passes for valid JSON config."""
        config_file = tmp_path / "hamburglar.config.json"
        config_file.write_text(
            json.dumps(
                {
                    "scan": {"concurrency": 50},
                    "output": {"format": "table"},
                }
            )
        )

        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_config_validate_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        """Test that config validate catches invalid YAML syntax."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
  recursive: [invalid yaml
"""
        )

        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code != 0
        assert "failed" in result.output.lower() or "error" in result.output.lower()

    def test_config_validate_invalid_values(self, tmp_path: Path) -> None:
        """Test that config validate catches invalid configuration values."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: -1
"""
        )

        result = runner.invoke(app, ["config", "validate", str(config_file)])
        assert result.exit_code != 0
        # Should report validation error
        assert "failed" in result.output.lower() or "error" in result.output.lower()

    def test_config_validate_auto_detect(self, tmp_path: Path, monkeypatch) -> None:
        """Test that config validate auto-detects config file."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
"""
        )

        # Mock find_config_file to return our config
        with mock.patch(
            "hamburglar.config.loader.ConfigLoader.find_config_file",
            return_value=config_file,
        ):
            result = runner.invoke(app, ["config", "validate"])
            assert result.exit_code == 0
            assert "valid" in result.output.lower()

    def test_config_validate_no_config_found(self) -> None:
        """Test that config validate reports when no config file found."""
        with mock.patch(
            "hamburglar.config.loader.ConfigLoader.find_config_file",
            return_value=None,
        ):
            result = runner.invoke(app, ["config", "validate"])
            assert result.exit_code != 0
            assert "No config file found" in result.output

    def test_config_validate_quiet_mode(self, tmp_path: Path) -> None:
        """Test that config validate -q only shows errors."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
"""
        )

        result = runner.invoke(app, ["config", "validate", str(config_file), "-q"])
        assert result.exit_code == 0
        # Should not have success message
        assert "valid" not in result.output.lower()

    def test_config_validate_verbose_mode(self, tmp_path: Path) -> None:
        """Test that config validate -v shows detailed info."""
        config_file = tmp_path / ".hamburglar.yml"
        config_file.write_text(
            """
scan:
  concurrency: 50
"""
        )

        result = runner.invoke(app, ["config", "validate", str(config_file), "-v"])
        assert result.exit_code == 0
        # Should show validating message
        assert "Validating:" in result.output


class TestConfigCommandGroup:
    """Tests for the config command group itself."""

    def test_config_help(self) -> None:
        """Test that config --help shows available subcommands."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "show" in result.output
        assert "init" in result.output
        assert "validate" in result.output

    def test_config_no_args_shows_help(self) -> None:
        """Test that config without arguments shows help."""
        result = runner.invoke(app, ["config"])
        # With no_args_is_help=True, Typer exits with code 2
        assert result.exit_code == 2 or result.exit_code == 0
        assert "show" in result.output
        assert "init" in result.output
        assert "validate" in result.output

    def test_main_help_includes_config(self) -> None:
        """Test that main help mentions config command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "config" in result.output


class TestConfigShowFormats:
    """Test different output formats for config show."""

    def test_config_show_toml_fallback(self) -> None:
        """Test that config show --format toml falls back gracefully."""
        # Even if tomli-w is not installed, should not crash
        result = runner.invoke(app, ["config", "show", "--format", "toml", "-q"])
        assert result.exit_code == 0
        # Should have some output
        assert len(result.output) > 0

    def test_config_show_yaml_fallback(self) -> None:
        """Test that config show handles YAML output."""
        result = runner.invoke(app, ["config", "show", "--format", "yaml", "-q"])
        assert result.exit_code == 0
        # Should have some output
        assert len(result.output) > 0

    def test_config_show_json_is_valid(self) -> None:
        """Test that config show --format json produces valid JSON."""
        result = runner.invoke(app, ["config", "show", "--format", "json", "-q"])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, dict)
        # Should have expected top-level keys
        assert "scan" in data
        assert "detector" in data
        assert "output" in data
        assert "yara" in data
