"""Tests for configuration schema models and validation.

This module tests that all configuration settings have proper types,
defaults are applied correctly, validation catches invalid values,
and nested settings work correctly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from hamburglar.config.schema import (
    DetectorSettings,
    HamburglarConfig,
    LogLevel,
    OutputFormatConfig,
    OutputSettings,
    ScanSettings,
    YaraSettings,
)


class TestLogLevelEnum:
    """Test LogLevel enum values and behavior."""

    def test_all_log_levels_defined(self) -> None:
        """All expected log levels should be defined."""
        expected_levels = {"debug", "info", "warning", "error", "critical"}
        actual_levels = {level.value for level in LogLevel}
        assert actual_levels == expected_levels

    def test_log_level_is_string_enum(self) -> None:
        """LogLevel should be a string enum."""
        assert LogLevel.INFO == "info"
        assert LogLevel.DEBUG == "debug"
        assert isinstance(LogLevel.WARNING, str)


class TestOutputFormatConfigEnum:
    """Test OutputFormatConfig enum values."""

    def test_all_output_formats_defined(self) -> None:
        """All expected output formats should be defined."""
        expected_formats = {"json", "table", "sarif", "csv", "html", "markdown"}
        actual_formats = {fmt.value for fmt in OutputFormatConfig}
        assert actual_formats == expected_formats

    def test_output_format_is_string_enum(self) -> None:
        """OutputFormatConfig should be a string enum."""
        assert OutputFormatConfig.JSON == "json"
        assert OutputFormatConfig.TABLE == "table"
        assert isinstance(OutputFormatConfig.SARIF, str)


class TestScanSettingsTypes:
    """Test ScanSettings has proper types."""

    def test_recursive_is_bool(self) -> None:
        """recursive setting should be a boolean."""
        settings = ScanSettings()
        assert isinstance(settings.recursive, bool)

    def test_max_file_size_is_int(self) -> None:
        """max_file_size should be an integer."""
        settings = ScanSettings()
        assert isinstance(settings.max_file_size, int)

    def test_concurrency_is_int(self) -> None:
        """concurrency should be an integer."""
        settings = ScanSettings()
        assert isinstance(settings.concurrency, int)

    def test_timeout_is_float(self) -> None:
        """timeout should be a float."""
        settings = ScanSettings()
        assert isinstance(settings.timeout, float)

    def test_blacklist_is_list(self) -> None:
        """blacklist should be a list of strings."""
        settings = ScanSettings()
        assert isinstance(settings.blacklist, list)
        assert all(isinstance(item, str) for item in settings.blacklist)

    def test_whitelist_is_list(self) -> None:
        """whitelist should be a list of strings."""
        settings = ScanSettings()
        assert isinstance(settings.whitelist, list)


class TestScanSettingsDefaults:
    """Test ScanSettings default values."""

    def test_recursive_defaults_to_true(self) -> None:
        """recursive should default to True."""
        settings = ScanSettings()
        assert settings.recursive is True

    def test_max_file_size_defaults_to_10mb(self) -> None:
        """max_file_size should default to 10 MB."""
        settings = ScanSettings()
        assert settings.max_file_size == 10 * 1024 * 1024

    def test_concurrency_defaults_to_50(self) -> None:
        """concurrency should default to 50."""
        settings = ScanSettings()
        assert settings.concurrency == 50

    def test_timeout_defaults_to_30(self) -> None:
        """timeout should default to 30 seconds."""
        settings = ScanSettings()
        assert settings.timeout == 30.0

    def test_blacklist_has_common_excludes(self) -> None:
        """blacklist should include common exclusion patterns."""
        settings = ScanSettings()
        assert ".git" in settings.blacklist
        assert "__pycache__" in settings.blacklist
        assert "node_modules" in settings.blacklist

    def test_whitelist_defaults_to_empty(self) -> None:
        """whitelist should default to empty list."""
        settings = ScanSettings()
        assert settings.whitelist == []


class TestScanSettingsValidation:
    """Test ScanSettings validation catches invalid values."""

    def test_concurrency_must_be_positive(self) -> None:
        """concurrency must be >= 1."""
        with pytest.raises(ValidationError) as exc_info:
            ScanSettings(concurrency=0)
        assert "concurrency" in str(exc_info.value).lower()

    def test_concurrency_max_1000(self) -> None:
        """concurrency must be <= 1000."""
        with pytest.raises(ValidationError) as exc_info:
            ScanSettings(concurrency=1001)
        assert "concurrency" in str(exc_info.value).lower()

    def test_max_file_size_cannot_be_negative(self) -> None:
        """max_file_size must be >= 0."""
        with pytest.raises(ValidationError) as exc_info:
            ScanSettings(max_file_size=-1)
        assert "max_file_size" in str(exc_info.value).lower()

    def test_timeout_cannot_be_negative(self) -> None:
        """timeout must be >= 0."""
        with pytest.raises(ValidationError) as exc_info:
            ScanSettings(timeout=-1)
        assert "timeout" in str(exc_info.value).lower()

    def test_file_size_string_parsing(self) -> None:
        """File sizes with suffixes should be parsed correctly."""
        assert ScanSettings(max_file_size="5MB").max_file_size == 5 * 1024 * 1024
        assert ScanSettings(max_file_size="1G").max_file_size == 1024 * 1024 * 1024
        assert ScanSettings(max_file_size="512K").max_file_size == 512 * 1024
        assert ScanSettings(max_file_size="100B").max_file_size == 100
        assert ScanSettings(max_file_size="2GB").max_file_size == 2 * 1024 * 1024 * 1024
        assert ScanSettings(max_file_size="1KB").max_file_size == 1024

    def test_file_size_numeric_string(self) -> None:
        """Numeric strings should be parsed as bytes."""
        settings = ScanSettings(max_file_size="1000")
        assert settings.max_file_size == 1000

    def test_file_size_case_insensitive(self) -> None:
        """File size suffixes should be case-insensitive."""
        assert ScanSettings(max_file_size="1mb").max_file_size == 1024 * 1024
        assert ScanSettings(max_file_size="1Mb").max_file_size == 1024 * 1024
        assert ScanSettings(max_file_size="1MB").max_file_size == 1024 * 1024


class TestDetectorSettingsTypes:
    """Test DetectorSettings has proper types."""

    def test_enabled_categories_is_list(self) -> None:
        """enabled_categories should be a list of strings."""
        settings = DetectorSettings()
        assert isinstance(settings.enabled_categories, list)

    def test_disabled_patterns_is_list(self) -> None:
        """disabled_patterns should be a list of strings."""
        settings = DetectorSettings()
        assert isinstance(settings.disabled_patterns, list)

    def test_min_confidence_is_string(self) -> None:
        """min_confidence should be a string."""
        settings = DetectorSettings()
        assert isinstance(settings.min_confidence, str)

    def test_custom_patterns_path_is_optional_path(self) -> None:
        """custom_patterns_path should be Path or None."""
        settings = DetectorSettings()
        assert settings.custom_patterns_path is None

        settings = DetectorSettings(custom_patterns_path="/some/path")
        assert isinstance(settings.custom_patterns_path, Path)


class TestDetectorSettingsDefaults:
    """Test DetectorSettings default values."""

    def test_enabled_categories_defaults_to_empty(self) -> None:
        """enabled_categories should default to empty list (all enabled)."""
        settings = DetectorSettings()
        assert settings.enabled_categories == []

    def test_disabled_patterns_defaults_to_empty(self) -> None:
        """disabled_patterns should default to empty list."""
        settings = DetectorSettings()
        assert settings.disabled_patterns == []

    def test_min_confidence_defaults_to_low(self) -> None:
        """min_confidence should default to 'low'."""
        settings = DetectorSettings()
        assert settings.min_confidence == "low"

    def test_custom_patterns_path_defaults_to_none(self) -> None:
        """custom_patterns_path should default to None."""
        settings = DetectorSettings()
        assert settings.custom_patterns_path is None


class TestDetectorSettingsValidation:
    """Test DetectorSettings validation catches invalid values."""

    def test_invalid_confidence_raises_error(self) -> None:
        """Invalid confidence level should raise ValueError."""
        with pytest.raises(ValidationError) as exc_info:
            DetectorSettings(min_confidence="invalid")
        assert "min_confidence" in str(exc_info.value).lower()

    def test_valid_confidence_levels(self) -> None:
        """Valid confidence levels should be accepted."""
        assert DetectorSettings(min_confidence="low").min_confidence == "low"
        assert DetectorSettings(min_confidence="medium").min_confidence == "medium"
        assert DetectorSettings(min_confidence="high").min_confidence == "high"

    def test_confidence_is_case_insensitive(self) -> None:
        """Confidence level should be case-insensitive."""
        assert DetectorSettings(min_confidence="LOW").min_confidence == "low"
        assert DetectorSettings(min_confidence="MEDIUM").min_confidence == "medium"
        assert DetectorSettings(min_confidence="High").min_confidence == "high"

    def test_categories_parsed_from_string(self) -> None:
        """Categories can be specified as comma-separated string."""
        settings = DetectorSettings(enabled_categories="api_keys,credentials,crypto")
        assert settings.enabled_categories == ["api_keys", "credentials", "crypto"]

    def test_categories_strips_whitespace(self) -> None:
        """Categories string parsing should strip whitespace."""
        settings = DetectorSettings(enabled_categories=" api_keys , credentials , crypto ")
        assert settings.enabled_categories == ["api_keys", "credentials", "crypto"]

    def test_categories_handles_empty_string(self) -> None:
        """Empty string should result in empty list."""
        settings = DetectorSettings(enabled_categories="")
        assert settings.enabled_categories == []

    def test_categories_handles_none(self) -> None:
        """None should result in empty list."""
        settings = DetectorSettings(enabled_categories=None)
        assert settings.enabled_categories == []


class TestOutputSettingsTypes:
    """Test OutputSettings has proper types."""

    def test_format_is_enum(self) -> None:
        """format should be OutputFormatConfig enum."""
        settings = OutputSettings()
        assert isinstance(settings.format, OutputFormatConfig)

    def test_output_path_is_optional_path(self) -> None:
        """output_path should be Path or None."""
        settings = OutputSettings()
        assert settings.output_path is None

        settings = OutputSettings(output_path="/some/path")
        assert isinstance(settings.output_path, Path)

    def test_save_to_db_is_bool(self) -> None:
        """save_to_db should be a boolean."""
        settings = OutputSettings()
        assert isinstance(settings.save_to_db, bool)

    def test_db_path_is_path(self) -> None:
        """db_path should be a Path."""
        settings = OutputSettings()
        assert isinstance(settings.db_path, Path)

    def test_quiet_is_bool(self) -> None:
        """quiet should be a boolean."""
        settings = OutputSettings()
        assert isinstance(settings.quiet, bool)

    def test_verbose_is_bool(self) -> None:
        """verbose should be a boolean."""
        settings = OutputSettings()
        assert isinstance(settings.verbose, bool)


class TestOutputSettingsDefaults:
    """Test OutputSettings default values."""

    def test_format_defaults_to_table(self) -> None:
        """format should default to TABLE."""
        settings = OutputSettings()
        assert settings.format == OutputFormatConfig.TABLE

    def test_output_path_defaults_to_none(self) -> None:
        """output_path should default to None (stdout)."""
        settings = OutputSettings()
        assert settings.output_path is None

    def test_save_to_db_defaults_to_false(self) -> None:
        """save_to_db should default to False."""
        settings = OutputSettings()
        assert settings.save_to_db is False

    def test_db_path_defaults_to_home_directory(self) -> None:
        """db_path should default to ~/.hamburglar/findings.db."""
        settings = OutputSettings()
        expected = Path.home() / ".hamburglar" / "findings.db"
        assert settings.db_path == expected

    def test_quiet_defaults_to_false(self) -> None:
        """quiet should default to False."""
        settings = OutputSettings()
        assert settings.quiet is False

    def test_verbose_defaults_to_false(self) -> None:
        """verbose should default to False."""
        settings = OutputSettings()
        assert settings.verbose is False


class TestOutputSettingsValidation:
    """Test OutputSettings validation catches invalid values."""

    def test_invalid_format_raises_error(self) -> None:
        """Invalid format should raise ValueError."""
        with pytest.raises(ValidationError) as exc_info:
            OutputSettings(format="invalid")
        assert "format" in str(exc_info.value).lower()

    def test_valid_formats_accepted(self) -> None:
        """All valid formats should be accepted."""
        assert OutputSettings(format="json").format == OutputFormatConfig.JSON
        assert OutputSettings(format="table").format == OutputFormatConfig.TABLE
        assert OutputSettings(format="sarif").format == OutputFormatConfig.SARIF
        assert OutputSettings(format="csv").format == OutputFormatConfig.CSV
        assert OutputSettings(format="html").format == OutputFormatConfig.HTML
        assert OutputSettings(format="markdown").format == OutputFormatConfig.MARKDOWN

    def test_format_is_case_insensitive(self) -> None:
        """Format should be case-insensitive."""
        assert OutputSettings(format="JSON").format == OutputFormatConfig.JSON
        assert OutputSettings(format="Json").format == OutputFormatConfig.JSON

    def test_format_handles_none(self) -> None:
        """None format should default to TABLE."""
        settings = OutputSettings(format=None)
        assert settings.format == OutputFormatConfig.TABLE


class TestYaraSettingsTypes:
    """Test YaraSettings has proper types."""

    def test_enabled_is_bool(self) -> None:
        """enabled should be a boolean."""
        settings = YaraSettings()
        assert isinstance(settings.enabled, bool)

    def test_rules_path_is_optional_path(self) -> None:
        """rules_path should be Path or None."""
        settings = YaraSettings()
        assert settings.rules_path is None

        settings = YaraSettings(rules_path="/some/path")
        assert isinstance(settings.rules_path, Path)

    def test_timeout_is_float(self) -> None:
        """timeout should be a float."""
        settings = YaraSettings()
        assert isinstance(settings.timeout, float)

    def test_compiled_rules_path_is_optional_path(self) -> None:
        """compiled_rules_path should be Path or None."""
        settings = YaraSettings()
        assert settings.compiled_rules_path is None


class TestYaraSettingsDefaults:
    """Test YaraSettings default values."""

    def test_enabled_defaults_to_false(self) -> None:
        """enabled should default to False."""
        settings = YaraSettings()
        assert settings.enabled is False

    def test_rules_path_defaults_to_none(self) -> None:
        """rules_path should default to None."""
        settings = YaraSettings()
        assert settings.rules_path is None

    def test_timeout_defaults_to_30(self) -> None:
        """timeout should default to 30 seconds."""
        settings = YaraSettings()
        assert settings.timeout == 30.0

    def test_compiled_rules_path_defaults_to_none(self) -> None:
        """compiled_rules_path should default to None."""
        settings = YaraSettings()
        assert settings.compiled_rules_path is None


class TestYaraSettingsValidation:
    """Test YaraSettings validation catches invalid values."""

    def test_timeout_cannot_be_negative(self) -> None:
        """timeout must be >= 0."""
        with pytest.raises(ValidationError) as exc_info:
            YaraSettings(timeout=-1)
        assert "timeout" in str(exc_info.value).lower()

    def test_timeout_can_be_zero(self) -> None:
        """timeout of 0 (unlimited) should be allowed."""
        settings = YaraSettings(timeout=0)
        assert settings.timeout == 0


class TestHamburglarConfigTypes:
    """Test HamburglarConfig has proper nested types."""

    def test_scan_is_scan_settings(self) -> None:
        """scan section should be ScanSettings."""
        config = HamburglarConfig()
        assert isinstance(config.scan, ScanSettings)

    def test_detector_is_detector_settings(self) -> None:
        """detector section should be DetectorSettings."""
        config = HamburglarConfig()
        assert isinstance(config.detector, DetectorSettings)

    def test_output_is_output_settings(self) -> None:
        """output section should be OutputSettings."""
        config = HamburglarConfig()
        assert isinstance(config.output, OutputSettings)

    def test_yara_is_yara_settings(self) -> None:
        """yara section should be YaraSettings."""
        config = HamburglarConfig()
        assert isinstance(config.yara, YaraSettings)

    def test_log_level_is_enum(self) -> None:
        """log_level should be LogLevel enum."""
        config = HamburglarConfig()
        assert isinstance(config.log_level, LogLevel)


class TestHamburglarConfigDefaults:
    """Test HamburglarConfig default values for nested settings."""

    def test_log_level_defaults_to_info(self) -> None:
        """log_level should default to INFO."""
        config = HamburglarConfig()
        assert config.log_level == LogLevel.INFO

    def test_nested_defaults_applied(self) -> None:
        """All nested settings should have their defaults applied."""
        config = HamburglarConfig()

        # Scan defaults
        assert config.scan.recursive is True
        assert config.scan.concurrency == 50

        # Detector defaults
        assert config.detector.min_confidence == "low"

        # Output defaults
        assert config.output.format == OutputFormatConfig.TABLE

        # YARA defaults
        assert config.yara.enabled is False


class TestHamburglarConfigValidation:
    """Test HamburglarConfig validation catches invalid values."""

    def test_invalid_log_level_raises_error(self) -> None:
        """Invalid log level should raise ValueError."""
        with pytest.raises(ValidationError) as exc_info:
            HamburglarConfig(log_level="invalid")
        assert "log_level" in str(exc_info.value).lower()

    def test_valid_log_levels_accepted(self) -> None:
        """All valid log levels should be accepted."""
        assert HamburglarConfig(log_level="debug").log_level == LogLevel.DEBUG
        assert HamburglarConfig(log_level="info").log_level == LogLevel.INFO
        assert HamburglarConfig(log_level="warning").log_level == LogLevel.WARNING
        assert HamburglarConfig(log_level="error").log_level == LogLevel.ERROR
        assert HamburglarConfig(log_level="critical").log_level == LogLevel.CRITICAL

    def test_log_level_is_case_insensitive(self) -> None:
        """Log level should be case-insensitive."""
        assert HamburglarConfig(log_level="DEBUG").log_level == LogLevel.DEBUG
        assert HamburglarConfig(log_level="Debug").log_level == LogLevel.DEBUG

    def test_log_level_handles_none(self) -> None:
        """None log level should default to INFO."""
        config = HamburglarConfig(log_level=None)
        assert config.log_level == LogLevel.INFO


class TestNestedSettingsWork:
    """Test that nested settings are properly created and accessible."""

    def test_nested_dict_creates_settings(self) -> None:
        """Dict input should create proper nested settings objects."""
        config = HamburglarConfig(
            scan={"concurrency": 100, "recursive": False},
            detector={"min_confidence": "high"},
            output={"format": "json"},
            yara={"enabled": True, "timeout": 60},
        )

        assert config.scan.concurrency == 100
        assert config.scan.recursive is False
        assert config.detector.min_confidence == "high"
        assert config.output.format == OutputFormatConfig.JSON
        assert config.yara.enabled is True
        assert config.yara.timeout == 60.0

    def test_partial_nested_dict(self) -> None:
        """Partial dict should merge with defaults."""
        config = HamburglarConfig(scan={"concurrency": 200})

        assert config.scan.concurrency == 200
        assert config.scan.recursive is True  # default preserved
        assert config.scan.timeout == 30.0  # default preserved

    def test_nested_objects_accepted(self) -> None:
        """Pre-constructed settings objects should be accepted."""
        scan = ScanSettings(concurrency=75)
        detector = DetectorSettings(min_confidence="medium")

        config = HamburglarConfig(scan=scan, detector=detector)

        assert config.scan.concurrency == 75
        assert config.detector.min_confidence == "medium"

    def test_deeply_nested_validation(self) -> None:
        """Validation errors in nested settings should propagate."""
        with pytest.raises(ValidationError):
            HamburglarConfig(scan={"concurrency": -1})

        with pytest.raises(ValidationError):
            HamburglarConfig(detector={"min_confidence": "invalid"})

        with pytest.raises(ValidationError):
            HamburglarConfig(output={"format": "invalid"})


class TestToScanConfig:
    """Test the to_scan_config conversion method."""

    def test_to_scan_config_basic(self) -> None:
        """to_scan_config should create valid ScanConfig."""
        config = HamburglarConfig(
            scan={"recursive": True, "blacklist": [".git"], "whitelist": ["*.py"]},
            yara={"enabled": True, "rules_path": "/rules"},
            output={"format": "json"},
        )

        scan_config = config.to_scan_config(Path("/target"))

        assert scan_config.target_path == Path("/target")
        assert scan_config.recursive is True
        assert scan_config.use_yara is True
        assert scan_config.yara_rules_path == Path("/rules")
        assert ".git" in scan_config.blacklist
        assert "*.py" in scan_config.whitelist

    def test_to_scan_config_format_mapping(self) -> None:
        """to_scan_config should map output formats correctly."""
        from hamburglar.core.models import OutputFormat

        for config_format in OutputFormatConfig:
            config = HamburglarConfig(output={"format": config_format.value})
            scan_config = config.to_scan_config(Path("/target"))

            expected = OutputFormat[config_format.name]
            assert scan_config.output_format == expected


class TestConfigExtraFields:
    """Test that extra fields are handled correctly."""

    def test_extra_fields_ignored(self) -> None:
        """Extra fields should be ignored without raising errors."""
        config = HamburglarConfig(
            unknown_field="value",
            another_unknown=123,
        )
        assert not hasattr(config, "unknown_field")
        assert not hasattr(config, "another_unknown")

    def test_nested_extra_fields_ignored(self) -> None:
        """Extra fields in nested settings should be ignored."""
        config = HamburglarConfig(
            scan={"concurrency": 50, "unknown": "value"}
        )
        assert config.scan.concurrency == 50
        assert not hasattr(config.scan, "unknown")
