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
    ENV_CONFIG_PATH,
    ENV_DB_PATH,
    ENV_LOG_LEVEL,
    ENV_MAX_FILE_SIZE,
    ENV_MIN_CONFIDENCE,
    ENV_OUTPUT_FORMAT,
    ENV_QUIET,
    ENV_RECURSIVE,
    ENV_SAVE_TO_DB,
    ENV_TIMEOUT,
    ENV_VERBOSE,
    ENV_YARA_ENABLED,
    ENV_YARA_RULES,
    get_config_path_from_env,
    get_env_overrides,
    get_env_var_docs,
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


class TestExampleConfigFile:
    """Test that the example configuration file is valid and parseable."""

    def test_example_config_file_is_valid(self) -> None:
        """The example config file should be valid YAML and pass validation."""
        import yaml

        example_path = Path(__file__).parent.parent / "examples" / "hamburglar.example.yml"
        if not example_path.exists():
            pytest.skip("Example config file not found")

        # Should parse as valid YAML
        content = example_path.read_text()
        data = yaml.safe_load(content)

        assert isinstance(data, dict), "Example config should be a dictionary"
        assert "scan" in data, "Example config should have 'scan' section"
        assert "detector" in data, "Example config should have 'detector' section"
        assert "output" in data, "Example config should have 'output' section"
        assert "yara" in data, "Example config should have 'yara' section"

    def test_example_config_file_validates_against_schema(self) -> None:
        """The example config file should validate against the schema."""
        import yaml

        example_path = Path(__file__).parent.parent / "examples" / "hamburglar.example.yml"
        if not example_path.exists():
            pytest.skip("Example config file not found")

        content = example_path.read_text()
        data = yaml.safe_load(content)

        # Remove the plugins section since it's not part of HamburglarConfig schema
        # (plugins are handled separately by PluginManager)
        if "plugins" in data:
            del data["plugins"]

        # Should validate without errors
        config = HamburglarConfig.model_validate(data)

        # Verify some key values from the example
        assert config.scan.recursive is True
        assert config.scan.max_file_size == 10 * 1024 * 1024  # 10MB
        assert config.scan.concurrency == 50
        assert config.output.format.value == "table"
        assert config.yara.enabled is False
        assert config.log_level.value == "info"

    def test_example_config_has_comprehensive_blacklist(self) -> None:
        """The example config should include common exclusion patterns."""
        import yaml

        example_path = Path(__file__).parent.parent / "examples" / "hamburglar.example.yml"
        if not example_path.exists():
            pytest.skip("Example config file not found")

        content = example_path.read_text()
        data = yaml.safe_load(content)

        blacklist = data.get("scan", {}).get("blacklist", [])

        # Check for important exclusions
        assert ".git" in blacklist, "Should exclude .git"
        assert "node_modules" in blacklist, "Should exclude node_modules"
        assert "__pycache__" in blacklist, "Should exclude __pycache__"
        assert any("*.pyc" in str(p) for p in blacklist), "Should exclude .pyc files"


class TestEnvParseBool:
    """Test boolean parsing from environment variables."""

    def test_parse_bool_true_variations(self) -> None:
        """Test various truthy string values."""
        from hamburglar.config.env import _parse_bool

        for value in ["true", "TRUE", "True", "1", "yes", "YES", "on", "ON", "enabled", "ENABLED"]:
            assert _parse_bool(value) is True, f"'{value}' should be True"

    def test_parse_bool_false_variations(self) -> None:
        """Test various falsy string values."""
        from hamburglar.config.env import _parse_bool

        for value in ["false", "FALSE", "0", "no", "NO", "off", "OFF", "disabled", "", "random"]:
            assert _parse_bool(value) is False, f"'{value}' should be False"


class TestEnvParseInt:
    """Test integer parsing from environment variables."""

    def test_parse_int_valid(self) -> None:
        """Test valid integer parsing."""
        from hamburglar.config.env import _parse_int

        assert _parse_int("100") == 100
        assert _parse_int("0") == 0
        assert _parse_int("-50") == -50

    def test_parse_int_invalid(self) -> None:
        """Test invalid integer parsing returns None."""
        from hamburglar.config.env import _parse_int

        assert _parse_int("not_a_number") is None
        assert _parse_int("12.5") is None
        assert _parse_int("") is None


class TestEnvParseFloat:
    """Test float parsing from environment variables."""

    def test_parse_float_valid(self) -> None:
        """Test valid float parsing."""
        from hamburglar.config.env import _parse_float

        assert _parse_float("10.5") == 10.5
        assert _parse_float("0") == 0.0
        assert _parse_float("-5.5") == -5.5
        assert _parse_float("100") == 100.0

    def test_parse_float_invalid(self) -> None:
        """Test invalid float parsing returns None."""
        from hamburglar.config.env import _parse_float

        assert _parse_float("not_a_number") is None
        assert _parse_float("") is None


class TestEnvParseList:
    """Test list parsing from environment variables."""

    def test_parse_list_multiple_items(self) -> None:
        """Test parsing comma-separated list."""
        from hamburglar.config.env import _parse_list

        result = _parse_list("item1,item2,item3")
        assert result == ["item1", "item2", "item3"]

    def test_parse_list_with_spaces(self) -> None:
        """Test parsing list with spaces around items."""
        from hamburglar.config.env import _parse_list

        result = _parse_list("item1, item2 , item3")
        assert result == ["item1", "item2", "item3"]

    def test_parse_list_single_item(self) -> None:
        """Test parsing single item list."""
        from hamburglar.config.env import _parse_list

        result = _parse_list("single")
        assert result == ["single"]

    def test_parse_list_empty(self) -> None:
        """Test parsing empty list."""
        from hamburglar.config.env import _parse_list

        result = _parse_list("")
        assert result == []


class TestGetEnvOverridesComprehensive:
    """Comprehensive tests for get_env_overrides."""

    def test_max_file_size_override(self) -> None:
        """Test HAMBURGLAR_MAX_FILE_SIZE override."""
        with mock.patch.dict(os.environ, {ENV_MAX_FILE_SIZE: "20MB"}):
            overrides = get_env_overrides()
        assert overrides["scan"]["max_file_size"] == "20MB"

    def test_timeout_override(self) -> None:
        """Test HAMBURGLAR_TIMEOUT override."""
        with mock.patch.dict(os.environ, {ENV_TIMEOUT: "60.0"}):
            overrides = get_env_overrides()
        assert overrides["scan"]["timeout"] == 60.0

    def test_timeout_invalid_ignored(self) -> None:
        """Test invalid timeout value is ignored."""
        with mock.patch.dict(os.environ, {ENV_TIMEOUT: "not_a_number"}):
            overrides = get_env_overrides()
        assert "timeout" not in overrides.get("scan", {})

    def test_recursive_override_true(self) -> None:
        """Test HAMBURGLAR_RECURSIVE override with true."""
        with mock.patch.dict(os.environ, {ENV_RECURSIVE: "true"}):
            overrides = get_env_overrides()
        assert overrides["scan"]["recursive"] is True

    def test_recursive_override_false(self) -> None:
        """Test HAMBURGLAR_RECURSIVE override with false."""
        with mock.patch.dict(os.environ, {ENV_RECURSIVE: "false"}):
            overrides = get_env_overrides()
        assert overrides["scan"]["recursive"] is False

    def test_min_confidence_override(self) -> None:
        """Test HAMBURGLAR_MIN_CONFIDENCE override."""
        with mock.patch.dict(os.environ, {ENV_MIN_CONFIDENCE: "HIGH"}):
            overrides = get_env_overrides()
        assert overrides["detector"]["min_confidence"] == "high"

    def test_db_path_override(self) -> None:
        """Test HAMBURGLAR_DB_PATH override."""
        with mock.patch.dict(os.environ, {ENV_DB_PATH: "/tmp/test.db"}):
            overrides = get_env_overrides()
        assert overrides["output"]["db_path"] == Path("/tmp/test.db")

    def test_save_to_db_override(self) -> None:
        """Test HAMBURGLAR_SAVE_TO_DB override."""
        with mock.patch.dict(os.environ, {ENV_SAVE_TO_DB: "true"}):
            overrides = get_env_overrides()
        assert overrides["output"]["save_to_db"] is True

    def test_quiet_override(self) -> None:
        """Test HAMBURGLAR_QUIET override."""
        with mock.patch.dict(os.environ, {ENV_QUIET: "yes"}):
            overrides = get_env_overrides()
        assert overrides["output"]["quiet"] is True

    def test_verbose_override(self) -> None:
        """Test HAMBURGLAR_VERBOSE override."""
        with mock.patch.dict(os.environ, {ENV_VERBOSE: "1"}):
            overrides = get_env_overrides()
        assert overrides["output"]["verbose"] is True

    def test_yara_rules_override(self) -> None:
        """Test HAMBURGLAR_YARA_RULES override."""
        with mock.patch.dict(os.environ, {ENV_YARA_RULES: "/path/to/rules"}):
            overrides = get_env_overrides()
        assert overrides["yara"]["rules_path"] == Path("/path/to/rules")

    def test_yara_enabled_override(self) -> None:
        """Test HAMBURGLAR_YARA_ENABLED override."""
        with mock.patch.dict(os.environ, {ENV_YARA_ENABLED: "enabled"}):
            overrides = get_env_overrides()
        assert overrides["yara"]["enabled"] is True

    def test_concurrency_invalid_ignored(self) -> None:
        """Test invalid concurrency value is ignored."""
        with mock.patch.dict(os.environ, {ENV_CONCURRENCY: "invalid"}):
            overrides = get_env_overrides()
        assert "concurrency" not in overrides.get("scan", {})

    def test_all_overrides_combined(self) -> None:
        """Test multiple environment variables at once."""
        env_vars = {
            ENV_CONCURRENCY: "25",
            ENV_MAX_FILE_SIZE: "5MB",
            ENV_TIMEOUT: "45.0",
            ENV_RECURSIVE: "false",
            ENV_CATEGORIES: "api_keys,credentials",
            ENV_MIN_CONFIDENCE: "medium",
            ENV_OUTPUT_FORMAT: "json",
            ENV_DB_PATH: "/tmp/hamburglar.db",
            ENV_SAVE_TO_DB: "true",
            ENV_QUIET: "true",
            ENV_VERBOSE: "false",
            ENV_YARA_RULES: "/rules",
            ENV_YARA_ENABLED: "true",
            ENV_LOG_LEVEL: "warning",
        }
        with mock.patch.dict(os.environ, env_vars):
            overrides = get_env_overrides()

        assert overrides["scan"]["concurrency"] == 25
        assert overrides["scan"]["max_file_size"] == "5MB"
        assert overrides["scan"]["timeout"] == 45.0
        assert overrides["scan"]["recursive"] is False
        assert overrides["detector"]["enabled_categories"] == ["api_keys", "credentials"]
        assert overrides["detector"]["min_confidence"] == "medium"
        assert overrides["output"]["format"] == "json"
        assert overrides["output"]["db_path"] == Path("/tmp/hamburglar.db")
        assert overrides["output"]["save_to_db"] is True
        assert overrides["output"]["quiet"] is True
        assert overrides["output"]["verbose"] is False
        assert overrides["yara"]["rules_path"] == Path("/rules")
        assert overrides["yara"]["enabled"] is True
        assert overrides["log_level"] == "warning"


class TestGetConfigPathFromEnv:
    """Test get_config_path_from_env function."""

    def test_returns_path_when_exists(self, tmp_path: Path) -> None:
        """Test returns path when file exists."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("scan:\n  concurrency: 10\n")

        with mock.patch.dict(os.environ, {ENV_CONFIG_PATH: str(config_file)}):
            result = get_config_path_from_env()
        assert result == config_file

    def test_returns_none_when_file_not_exists(self, tmp_path: Path) -> None:
        """Test returns None when file doesn't exist."""
        nonexistent = tmp_path / "nonexistent.yml"

        with mock.patch.dict(os.environ, {ENV_CONFIG_PATH: str(nonexistent)}):
            result = get_config_path_from_env()
        assert result is None

    def test_returns_none_when_not_set(self) -> None:
        """Test returns None when env var not set."""
        with mock.patch.dict(os.environ, {}, clear=True):
            result = get_config_path_from_env()
        assert result is None


class TestGetEnvVarDocs:
    """Test get_env_var_docs function."""

    def test_returns_all_env_vars(self) -> None:
        """Test all environment variables are documented."""
        docs = get_env_var_docs()

        expected_vars = [
            ENV_CONFIG_PATH,
            ENV_YARA_RULES,
            ENV_OUTPUT_FORMAT,
            ENV_DB_PATH,
            ENV_CONCURRENCY,
            ENV_LOG_LEVEL,
            ENV_CATEGORIES,
            ENV_MAX_FILE_SIZE,
            ENV_TIMEOUT,
            ENV_RECURSIVE,
            ENV_YARA_ENABLED,
            ENV_SAVE_TO_DB,
            ENV_MIN_CONFIDENCE,
            ENV_QUIET,
            ENV_VERBOSE,
        ]

        for var in expected_vars:
            assert var in docs, f"{var} should be documented"
            assert isinstance(docs[var], str), f"{var} should have string description"
            assert len(docs[var]) > 0, f"{var} should have non-empty description"


class TestConfigLoaderAdvanced:
    """Advanced tests for ConfigLoader edge cases."""

    def test_load_directory_not_file(self, tmp_path: Path) -> None:
        """Test error when path is a directory not a file."""
        loader = ConfigLoader()
        with pytest.raises(ConfigError, match="not a file"):
            loader.load(tmp_path)

    def test_load_yaml_non_dict(self, tmp_path: Path) -> None:
        """Test error when YAML doesn't contain a dict."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("- item1\n- item2\n")  # List, not dict
        loader = ConfigLoader()
        with pytest.raises(ConfigError, match="must contain a mapping"):
            loader.load(config_file)

    def test_load_json_non_dict(self, tmp_path: Path) -> None:
        """Test error when JSON doesn't contain a dict."""
        config_file = tmp_path / "config.json"
        config_file.write_text('["item1", "item2"]')  # Array, not object
        loader = ConfigLoader()
        with pytest.raises(ConfigError, match="must contain an object"):
            loader.load(config_file)

    def test_load_toml_file(self, tmp_path: Path) -> None:
        """Test loading a TOML config file."""
        config_file = tmp_path / ".hamburglar.toml"
        config_file.write_text("""
[scan]
concurrency = 75
recursive = false

[output]
format = "json"
""")
        loader = ConfigLoader()
        config = loader.load(config_file)
        assert config.scan.concurrency == 75
        assert config.scan.recursive is False
        assert config.output.format.value == "json"

    def test_load_hamburglarrc_json(self, tmp_path: Path) -> None:
        """Test loading .hamburglarrc file with JSON content."""
        config_file = tmp_path / ".hamburglarrc"
        config_file.write_text('{"scan": {"concurrency": 25}}')
        loader = ConfigLoader()
        config = loader.load(config_file)
        assert config.scan.concurrency == 25

    def test_load_hamburglarrc_yaml(self, tmp_path: Path) -> None:
        """Test loading .hamburglarrc file with YAML content."""
        config_file = tmp_path / ".hamburglarrc"
        config_file.write_text("scan:\n  concurrency: 30\n")
        loader = ConfigLoader()
        config = loader.load(config_file)
        assert config.scan.concurrency == 30

    def test_validate_config_file_not_found(self, tmp_path: Path) -> None:
        """Test validation with non-existent file."""
        loader = ConfigLoader()
        errors = loader.validate_config_file(tmp_path / "nonexistent.yml")
        assert len(errors) == 1
        assert "not found" in errors[0].lower()

    def test_validate_config_file_not_a_file(self, tmp_path: Path) -> None:
        """Test validation with directory path."""
        loader = ConfigLoader()
        errors = loader.validate_config_file(tmp_path)
        assert len(errors) == 1
        assert "not a file" in errors[0].lower()

    def test_validate_config_file_with_errors(self, tmp_path: Path) -> None:
        """Test validation with invalid config."""
        config_file = tmp_path / "config.yml"
        config_file.write_text("scan:\n  concurrency: invalid\n")
        loader = ConfigLoader()
        errors = loader.validate_config_file(config_file)
        # Should have validation errors
        assert len(errors) >= 1

    def test_find_config_with_search_paths(self, tmp_path: Path) -> None:
        """Test finding config with custom search paths."""
        custom_dir = tmp_path / "custom"
        custom_dir.mkdir()
        config_file = custom_dir / ".hamburglar.yml"
        config_file.write_text("scan:\n  concurrency: 99\n")

        loader = ConfigLoader(search_paths=[custom_dir])
        # Start from an empty directory without config
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        found = loader.find_config_file(empty_dir)
        assert found == config_file


class TestGetDefaultConfigContent:
    """Tests for get_default_config_content function."""

    def test_get_yaml_config(self) -> None:
        """Test generating YAML config content."""
        from hamburglar.config.loader import get_default_config_content

        content = get_default_config_content("yaml")
        assert "scan:" in content
        assert "recursive: true" in content
        assert "# Hamburglar Configuration" in content

    def test_get_toml_config(self) -> None:
        """Test generating TOML config content."""
        from hamburglar.config.loader import get_default_config_content

        content = get_default_config_content("toml")
        assert "[scan]" in content
        assert "recursive = true" in content

    def test_get_json_config(self) -> None:
        """Test generating JSON config content."""
        from hamburglar.config.loader import get_default_config_content
        import json

        content = get_default_config_content("json")
        data = json.loads(content)
        assert "scan" in data
        assert data["scan"]["recursive"] is True

    def test_get_unknown_format_raises(self) -> None:
        """Test unknown format raises ValueError."""
        from hamburglar.config.loader import get_default_config_content

        with pytest.raises(ValueError, match="Unknown format"):
            get_default_config_content("xml")
