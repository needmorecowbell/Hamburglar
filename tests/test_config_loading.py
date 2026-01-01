"""Tests for configuration loading with proper priority handling.

This module tests that configuration is loaded correctly from various
sources with the proper priority: CLI args > environment variables >
config file > defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from hamburglar.config import (
    ConfigLoader,
    ConfigPriority,
    HamburglarConfig,
    get_config,
    get_config_source,
    load_config,
    reset_config,
)
from hamburglar.config.env import (
    ENV_CATEGORIES,
    ENV_CONCURRENCY,
    ENV_LOG_LEVEL,
    ENV_OUTPUT_FORMAT,
    get_env_overrides,
)
from hamburglar.core.exceptions import ConfigError


class TestConfigDefaults:
    """Test that default configuration values are correct."""

    def test_default_config_has_expected_values(self) -> None:
        """Default configuration should have sensible defaults."""
        config = HamburglarConfig()

        # Scan defaults
        assert config.scan.recursive is True
        assert config.scan.concurrency == 50
        assert config.scan.max_file_size == 10 * 1024 * 1024  # 10 MB
        assert config.scan.timeout == 30.0
        assert ".git" in config.scan.blacklist

        # Detector defaults
        assert config.detector.enabled_categories == []
        assert config.detector.min_confidence == "low"

        # Output defaults
        assert config.output.format.value == "table"
        assert config.output.save_to_db is False

        # YARA defaults
        assert config.yara.enabled is False
        assert config.yara.timeout == 30.0

    def test_default_log_level(self) -> None:
        """Default log level should be info."""
        config = HamburglarConfig()
        assert config.log_level.value == "info"


class TestConfigFileLoading:
    """Test loading configuration from files."""

    def test_config_file_is_found_and_loaded(self, tmp_path: Path) -> None:
        """Config file in directory should be found and loaded."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: 100
  recursive: false
output:
  format: json
"""
        )

        loader = ConfigLoader()
        found = loader.find_config_file(tmp_path)
        assert found == config_path

        config = loader.load(config_path)
        assert config.scan.concurrency == 100
        assert config.scan.recursive is False
        assert config.output.format.value == "json"

    def test_json_config_file(self, tmp_path: Path) -> None:
        """JSON config file should load correctly."""
        config_path = tmp_path / "hamburglar.config.json"
        config_path.write_text(
            """
{
    "scan": {
        "concurrency": 75,
        "max_file_size": "5MB"
    },
    "yara": {
        "enabled": true
    }
}
"""
        )

        loader = ConfigLoader()
        config = loader.load(config_path)
        assert config.scan.concurrency == 75
        assert config.scan.max_file_size == 5 * 1024 * 1024
        assert config.yara.enabled is True

    def test_missing_config_file_uses_defaults(self, tmp_path: Path) -> None:
        """When no config file exists, defaults should be used."""
        reset_config()
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            # Clear environment variables that might affect config
            with mock.patch.dict(os.environ, {}, clear=True):
                config = load_config(use_file=False, use_env=False)

            assert config.scan.concurrency == 50
            assert config.output.format.value == "table"
        finally:
            os.chdir(original_cwd)


class TestEnvironmentVariableOverrides:
    """Test environment variable configuration overrides."""

    def test_env_variables_override_config_file(self, tmp_path: Path) -> None:
        """Environment variables should override config file settings."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: 100
output:
  format: json
"""
        )

        with mock.patch.dict(os.environ, {ENV_CONCURRENCY: "200", ENV_OUTPUT_FORMAT: "table"}):
            reset_config()
            config = load_config(config_path=config_path)

        assert config.scan.concurrency == 200
        assert config.output.format.value == "table"

    def test_env_categories_parsed_correctly(self) -> None:
        """HAMBURGLAR_CATEGORIES should be parsed as comma-separated list."""
        with mock.patch.dict(os.environ, {ENV_CATEGORIES: "api_keys,credentials,crypto"}):
            overrides = get_env_overrides()

        assert overrides["detector"]["enabled_categories"] == ["api_keys", "credentials", "crypto"]

    def test_env_log_level(self) -> None:
        """HAMBURGLAR_LOG_LEVEL should set log level."""
        with mock.patch.dict(os.environ, {ENV_LOG_LEVEL: "debug"}):
            overrides = get_env_overrides()

        assert overrides["log_level"] == "debug"


class TestCLIArgumentOverrides:
    """Test CLI argument configuration overrides."""

    def test_cli_args_override_env_variables(self) -> None:
        """CLI arguments should override environment variables."""
        reset_config()
        with mock.patch.dict(os.environ, {ENV_CONCURRENCY: "100"}):
            config = load_config(cli_args={"concurrency": 200}, use_file=False)

        assert config.scan.concurrency == 200

    def test_cli_args_override_config_file(self, tmp_path: Path) -> None:
        """CLI arguments should override config file settings."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: 50
output:
  format: json
"""
        )

        reset_config()
        config = load_config(
            config_path=config_path,
            cli_args={"concurrency": 150, "format": "table"},
            use_env=False,
        )

        assert config.scan.concurrency == 150
        assert config.output.format.value == "table"


class TestInvalidConfigHandling:
    """Test handling of invalid configuration."""

    def test_invalid_config_raises_helpful_error(self, tmp_path: Path) -> None:
        """Invalid config should raise ConfigError with helpful message."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: "not a number"
"""
        )

        loader = ConfigLoader()
        with pytest.raises(ConfigError) as exc_info:
            loader.load(config_path)

        assert "Invalid configuration" in str(exc_info.value)

    def test_invalid_yaml_raises_error(self, tmp_path: Path) -> None:
        """Invalid YAML syntax should raise ConfigError."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: 50
  invalid: yaml: syntax: here
"""
        )

        loader = ConfigLoader()
        with pytest.raises(ConfigError) as exc_info:
            loader.load(config_path)

        assert "Invalid YAML" in str(exc_info.value) or "Invalid configuration" in str(exc_info.value)

    def test_nonexistent_file_raises_error(self) -> None:
        """Loading nonexistent file should raise ConfigError."""
        loader = ConfigLoader()
        with pytest.raises(ConfigError) as exc_info:
            loader.load("/nonexistent/path/.hamburglar.yml")

        assert "not found" in str(exc_info.value)


class TestConfigMerging:
    """Test configuration merging from multiple sources."""

    def test_full_priority_chain(self, tmp_path: Path) -> None:
        """Test complete priority chain: CLI > env > file > defaults."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: 10
  timeout: 60
  recursive: false
output:
  format: json
"""
        )

        reset_config()
        with mock.patch.dict(
            os.environ,
            {
                ENV_CONCURRENCY: "20",  # Should override file
                ENV_OUTPUT_FORMAT: "csv",  # Should override file
            },
        ):
            config = load_config(
                config_path=config_path,
                cli_args={
                    "concurrency": 30,  # Should override env
                },
            )

        # CLI overrides everything
        assert config.scan.concurrency == 30

        # Env overrides file
        assert config.output.format.value == "csv"

        # File value preserved (not overridden)
        assert config.scan.timeout == 60.0
        assert config.scan.recursive is False


class TestConfigLoader:
    """Test ConfigLoader functionality."""

    def test_find_config_in_parent_directory(self, tmp_path: Path) -> None:
        """Config should be found in parent directories."""
        # Create config in parent
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text("scan:\n  concurrency: 123\n")

        # Create child directory
        child_dir = tmp_path / "subdir" / "nested"
        child_dir.mkdir(parents=True)

        loader = ConfigLoader()
        found = loader.find_config_file(child_dir)
        assert found == config_path

    def test_validate_config_file(self, tmp_path: Path) -> None:
        """validate_config_file should return list of errors."""
        config_path = tmp_path / ".hamburglar.yml"
        config_path.write_text(
            """
scan:
  concurrency: -5
"""
        )

        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)

        # Should have at least one error about negative concurrency
        assert len(errors) > 0
        assert any("concurrency" in e.lower() or "greater" in e.lower() for e in errors)


class TestGetConfig:
    """Test the get_config convenience function."""

    def test_get_config_caches_result(self, tmp_path: Path) -> None:
        """get_config should cache result and return same instance."""
        reset_config()
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            with mock.patch.dict(os.environ, {}, clear=True):
                config1 = get_config()
                config2 = get_config()

            assert config1 is config2
        finally:
            os.chdir(original_cwd)

    def test_get_config_with_cli_args_reloads(self, tmp_path: Path) -> None:
        """get_config with cli_args should reload config."""
        reset_config()
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            with mock.patch.dict(os.environ, {}, clear=True):
                config1 = get_config()
                config2 = get_config(cli_args={"concurrency": 999})

            assert config1.scan.concurrency == 50
            assert config2.scan.concurrency == 999
        finally:
            os.chdir(original_cwd)

    def test_reset_config_clears_cache(self, tmp_path: Path) -> None:
        """reset_config should clear the config cache."""
        reset_config()
        original_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            with mock.patch.dict(os.environ, {}, clear=True):
                config1 = get_config()
                reset_config()
                config2 = get_config()

            # Same values but different instances
            assert config1 is not config2
        finally:
            os.chdir(original_cwd)


class TestFileSizeParsing:
    """Test parsing of file size strings."""

    def test_parse_file_size_with_suffix(self) -> None:
        """File sizes with suffixes should be parsed correctly."""
        config = HamburglarConfig(scan={"max_file_size": "5MB"})
        assert config.scan.max_file_size == 5 * 1024 * 1024

        config = HamburglarConfig(scan={"max_file_size": "1G"})
        assert config.scan.max_file_size == 1024 * 1024 * 1024

        config = HamburglarConfig(scan={"max_file_size": "512K"})
        assert config.scan.max_file_size == 512 * 1024

    def test_parse_file_size_numeric(self) -> None:
        """Numeric file sizes should work."""
        config = HamburglarConfig(scan={"max_file_size": 1000})
        assert config.scan.max_file_size == 1000
