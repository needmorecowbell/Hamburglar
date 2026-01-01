"""Tests for configuration fixture files.

This module tests that all fixture configuration files in tests/fixtures/configs/
are correctly formatted and can be loaded/validated as expected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hamburglar.config import ConfigLoader
from hamburglar.core.exceptions import ConfigError

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "configs"


class TestValidBasicConfigs:
    """Test loading of valid_basic config files in all formats."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_valid_basic_loads_successfully(self, ext: str) -> None:
        """Valid basic config should load without errors."""
        config_path = FIXTURES_DIR / f"valid_basic{ext}"
        loader = ConfigLoader()
        config = loader.load(config_path)

        assert type(config).__name__ == "HamburglarConfig"
        assert config.scan.concurrency == 25
        assert config.scan.max_file_size == 5 * 1024 * 1024  # 5MB
        assert config.scan.recursive is True
        assert config.scan.timeout == 15
        assert config.detector.min_confidence == "medium"
        assert config.detector.enabled_categories == ["api_keys", "credentials"]
        assert config.output.format.value == "json"
        assert config.output.quiet is False
        assert config.yara.enabled is False
        assert config.log_level.value == "info"

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_valid_basic_validates(self, ext: str) -> None:
        """Valid basic config should pass validation."""
        config_path = FIXTURES_DIR / f"valid_basic{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert errors == [], f"Expected no errors, got: {errors}"


class TestValidFullConfigs:
    """Test loading of valid_full config files with all settings."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_valid_full_loads_successfully(self, ext: str) -> None:
        """Valid full config should load all settings correctly."""
        config_path = FIXTURES_DIR / f"valid_full{ext}"
        loader = ConfigLoader()
        config = loader.load(config_path)

        assert type(config).__name__ == "HamburglarConfig"

        # Scan settings
        assert config.scan.recursive is False
        assert config.scan.max_file_size == 50 * 1024 * 1024  # 50MB
        assert config.scan.concurrency == 100
        assert config.scan.timeout == 60.5
        assert ".git" in config.scan.blacklist
        assert "node_modules" in config.scan.blacklist
        assert "*.py" in config.scan.whitelist

        # Detector settings
        assert config.detector.enabled_categories == [
            "api_keys",
            "credentials",
            "crypto",
            "private_keys",
        ]
        assert "generic_high_entropy" in config.detector.disabled_patterns
        assert config.detector.min_confidence == "high"
        assert config.detector.custom_patterns_path == Path("./custom_patterns.yaml")

        # Output settings
        assert config.output.format.value == "sarif"
        assert config.output.output_path == Path("./reports/scan-results")
        assert config.output.save_to_db is True
        assert config.output.db_path == Path("./data/findings.db")
        assert config.output.quiet is True
        assert config.output.verbose is False

        # YARA settings
        assert config.yara.enabled is True
        assert config.yara.rules_path == Path("./yara_rules")
        assert config.yara.timeout == 45.0
        assert config.yara.compiled_rules_path == Path("./compiled_rules.yarc")

        # Log level
        assert config.log_level.value == "debug"

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_valid_full_validates(self, ext: str) -> None:
        """Valid full config should pass validation."""
        config_path = FIXTURES_DIR / f"valid_full{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert errors == [], f"Expected no errors, got: {errors}"


class TestMinimalConfigs:
    """Test loading of minimal config files."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_minimal_loads_with_defaults(self, ext: str) -> None:
        """Minimal config should load with most settings at defaults."""
        config_path = FIXTURES_DIR / f"minimal{ext}"
        loader = ConfigLoader()
        config = loader.load(config_path)

        assert type(config).__name__ == "HamburglarConfig"

        # Only concurrency should be overridden
        assert config.scan.concurrency == 10

        # All other scan settings should be defaults
        assert config.scan.recursive is True
        assert config.scan.max_file_size == 10 * 1024 * 1024  # 10MB default
        assert config.scan.timeout == 30.0  # default

        # All other sections should be defaults
        assert config.detector.min_confidence == "low"  # default
        assert config.output.format.value == "table"  # default
        assert config.yara.enabled is False  # default
        assert config.log_level.value == "info"  # default

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_minimal_validates(self, ext: str) -> None:
        """Minimal config should pass validation."""
        config_path = FIXTURES_DIR / f"minimal{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert errors == [], f"Expected no errors, got: {errors}"


class TestEmptyConfigs:
    """Test loading of empty config files."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_empty_loads_with_all_defaults(self, ext: str) -> None:
        """Empty config should load with all default values."""
        config_path = FIXTURES_DIR / f"empty{ext}"
        loader = ConfigLoader()
        config = loader.load(config_path)

        assert type(config).__name__ == "HamburglarConfig"

        # All settings should be defaults
        assert config.scan.recursive is True
        assert config.scan.max_file_size == 10 * 1024 * 1024
        assert config.scan.concurrency == 50
        assert config.scan.timeout == 30.0
        assert config.detector.min_confidence == "low"
        assert config.detector.enabled_categories == []
        assert config.output.format.value == "table"
        assert config.output.save_to_db is False
        assert config.yara.enabled is False
        assert config.log_level.value == "info"

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_empty_validates(self, ext: str) -> None:
        """Empty config should pass validation."""
        config_path = FIXTURES_DIR / f"empty{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert errors == [], f"Expected no errors, got: {errors}"


class TestInvalidSyntaxConfigs:
    """Test error handling for config files with syntax errors."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_invalid_syntax_raises_config_error(self, ext: str) -> None:
        """Config with syntax errors should raise ConfigError."""
        config_path = FIXTURES_DIR / f"invalid_syntax{ext}"
        loader = ConfigLoader()

        with pytest.raises(ConfigError) as exc_info:
            loader.load(config_path)

        # Error message should indicate parsing issue
        error_msg = str(exc_info.value).lower()
        assert "invalid" in error_msg or "failed" in error_msg or "parse" in error_msg

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_invalid_syntax_validation_returns_errors(self, ext: str) -> None:
        """Validation of config with syntax errors should return errors."""
        config_path = FIXTURES_DIR / f"invalid_syntax{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert len(errors) > 0, "Expected validation errors for invalid syntax"


class TestInvalidValuesConfigs:
    """Test error handling for config files with invalid values."""

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_invalid_values_raises_config_error(self, ext: str) -> None:
        """Config with invalid values should raise ConfigError."""
        config_path = FIXTURES_DIR / f"invalid_values{ext}"
        loader = ConfigLoader()

        with pytest.raises(ConfigError) as exc_info:
            loader.load(config_path)

        # Error message should indicate validation issue
        error_msg = str(exc_info.value)
        assert "Invalid" in error_msg or "validation" in error_msg.lower()

    @pytest.mark.parametrize("ext", [".yml", ".toml", ".json"])
    def test_invalid_values_validation_returns_errors(self, ext: str) -> None:
        """Validation of config with invalid values should return errors."""
        config_path = FIXTURES_DIR / f"invalid_values{ext}"
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_path)
        assert len(errors) > 0, "Expected validation errors for invalid values"


class TestConfigConsistency:
    """Test that equivalent configs in different formats produce same results."""

    def test_valid_basic_configs_are_equivalent(self) -> None:
        """Valid basic configs in all formats should produce equivalent configs."""
        loader = ConfigLoader()

        yml_config = loader.load(FIXTURES_DIR / "valid_basic.yml")
        toml_config = loader.load(FIXTURES_DIR / "valid_basic.toml")
        json_config = loader.load(FIXTURES_DIR / "valid_basic.json")

        # All configs should have identical values
        assert (
            yml_config.scan.concurrency
            == toml_config.scan.concurrency
            == json_config.scan.concurrency
        )
        assert (
            yml_config.scan.max_file_size
            == toml_config.scan.max_file_size
            == json_config.scan.max_file_size
        )
        assert yml_config.scan.recursive == toml_config.scan.recursive == json_config.scan.recursive
        assert (
            yml_config.detector.min_confidence
            == toml_config.detector.min_confidence
            == json_config.detector.min_confidence
        )
        assert (
            yml_config.detector.enabled_categories
            == toml_config.detector.enabled_categories
            == json_config.detector.enabled_categories
        )
        assert yml_config.output.format == toml_config.output.format == json_config.output.format
        assert yml_config.yara.enabled == toml_config.yara.enabled == json_config.yara.enabled
        assert yml_config.log_level == toml_config.log_level == json_config.log_level

    def test_valid_full_configs_are_equivalent(self) -> None:
        """Valid full configs in all formats should produce equivalent configs."""
        loader = ConfigLoader()

        yml_config = loader.load(FIXTURES_DIR / "valid_full.yml")
        toml_config = loader.load(FIXTURES_DIR / "valid_full.toml")
        json_config = loader.load(FIXTURES_DIR / "valid_full.json")

        # Scan settings
        assert yml_config.scan.recursive == toml_config.scan.recursive == json_config.scan.recursive
        assert (
            yml_config.scan.max_file_size
            == toml_config.scan.max_file_size
            == json_config.scan.max_file_size
        )
        assert (
            yml_config.scan.concurrency
            == toml_config.scan.concurrency
            == json_config.scan.concurrency
        )
        assert yml_config.scan.timeout == toml_config.scan.timeout == json_config.scan.timeout

        # Detector settings
        assert (
            yml_config.detector.enabled_categories
            == toml_config.detector.enabled_categories
            == json_config.detector.enabled_categories
        )
        assert (
            yml_config.detector.disabled_patterns
            == toml_config.detector.disabled_patterns
            == json_config.detector.disabled_patterns
        )
        assert (
            yml_config.detector.min_confidence
            == toml_config.detector.min_confidence
            == json_config.detector.min_confidence
        )

        # Output settings
        assert yml_config.output.format == toml_config.output.format == json_config.output.format
        assert (
            yml_config.output.save_to_db
            == toml_config.output.save_to_db
            == json_config.output.save_to_db
        )

        # YARA settings
        assert yml_config.yara.enabled == toml_config.yara.enabled == json_config.yara.enabled
        assert yml_config.yara.timeout == toml_config.yara.timeout == json_config.yara.timeout

        # Log level
        assert yml_config.log_level == toml_config.log_level == json_config.log_level

    def test_minimal_configs_are_equivalent(self) -> None:
        """Minimal configs in all formats should produce equivalent configs."""
        loader = ConfigLoader()

        yml_config = loader.load(FIXTURES_DIR / "minimal.yml")
        toml_config = loader.load(FIXTURES_DIR / "minimal.toml")
        json_config = loader.load(FIXTURES_DIR / "minimal.json")

        assert (
            yml_config.scan.concurrency
            == toml_config.scan.concurrency
            == json_config.scan.concurrency
            == 10
        )

    def test_empty_configs_are_equivalent(self) -> None:
        """Empty configs in all formats should produce equivalent configs."""
        loader = ConfigLoader()

        yml_config = loader.load(FIXTURES_DIR / "empty.yml")
        toml_config = loader.load(FIXTURES_DIR / "empty.toml")
        json_config = loader.load(FIXTURES_DIR / "empty.json")

        # All should have default values
        assert (
            yml_config.scan.concurrency
            == toml_config.scan.concurrency
            == json_config.scan.concurrency
            == 50
        )
        assert yml_config.output.format == toml_config.output.format == json_config.output.format
