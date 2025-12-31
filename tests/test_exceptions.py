"""Tests for Hamburglar custom exception hierarchy.

This module contains tests for the exception classes defined in
hamburglar.core.exceptions, verifying that each exception can be raised,
caught, and provides proper error context.
"""

from __future__ import annotations

import pytest

from hamburglar.core.exceptions import (
    ConfigError,
    DetectorError,
    HamburglarError,
    OutputError,
    ScanError,
    YaraCompilationError,
)


class TestHamburglarError:
    """Tests for the base HamburglarError exception."""

    def test_can_be_raised(self) -> None:
        """Test that HamburglarError can be raised and caught."""
        with pytest.raises(HamburglarError):
            raise HamburglarError("Test error")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = HamburglarError("Test message")
        assert error.message == "Test message"

    def test_context_attribute_default(self) -> None:
        """Test that context defaults to empty dict."""
        error = HamburglarError("Test")
        assert error.context == {}

    def test_context_attribute_with_data(self) -> None:
        """Test that context is set when provided."""
        context = {"key": "value", "count": 42}
        error = HamburglarError("Test", context=context)
        assert error.context == context

    def test_str_without_context(self) -> None:
        """Test string representation without context."""
        error = HamburglarError("Test error message")
        assert str(error) == "Test error message"

    def test_str_with_context(self) -> None:
        """Test string representation includes context."""
        error = HamburglarError("Test error", context={"key": "value"})
        result = str(error)
        assert "Test error" in result
        assert "key='value'" in result

    def test_inherits_from_exception(self) -> None:
        """Test that HamburglarError inherits from Exception."""
        error = HamburglarError("Test")
        assert isinstance(error, Exception)

    def test_can_be_caught_as_exception(self) -> None:
        """Test that HamburglarError can be caught as generic Exception."""
        try:
            raise HamburglarError("Test")
        except Exception as e:
            assert isinstance(e, HamburglarError)
        else:
            pytest.fail("HamburglarError was not caught as Exception")


class TestScanError:
    """Tests for the ScanError exception."""

    def test_can_be_raised(self) -> None:
        """Test that ScanError can be raised and caught."""
        with pytest.raises(ScanError):
            raise ScanError("Scan failed")

    def test_can_be_caught_as_hamburglar_error(self) -> None:
        """Test that ScanError can be caught as HamburglarError."""
        with pytest.raises(HamburglarError):
            raise ScanError("Scan failed")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = ScanError("Target not found")
        assert error.message == "Target not found"

    def test_path_attribute(self) -> None:
        """Test that path attribute is set and included in context."""
        error = ScanError("Target not found", path="/nonexistent")
        assert error.path == "/nonexistent"
        assert error.context["path"] == "/nonexistent"

    def test_path_attribute_default(self) -> None:
        """Test that path defaults to None."""
        error = ScanError("Scan failed")
        assert error.path is None

    def test_context_combined_with_path(self) -> None:
        """Test that path is added to provided context."""
        error = ScanError("Error", path="/path", context={"extra": "data"})
        assert error.context["path"] == "/path"
        assert error.context["extra"] == "data"


class TestDetectorError:
    """Tests for the DetectorError exception."""

    def test_can_be_raised(self) -> None:
        """Test that DetectorError can be raised and caught."""
        with pytest.raises(DetectorError):
            raise DetectorError("Detector failed")

    def test_can_be_caught_as_hamburglar_error(self) -> None:
        """Test that DetectorError can be caught as HamburglarError."""
        with pytest.raises(HamburglarError):
            raise DetectorError("Detector failed")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = DetectorError("Regex timeout")
        assert error.message == "Regex timeout"

    def test_detector_name_attribute(self) -> None:
        """Test that detector_name attribute is set and included in context."""
        error = DetectorError("Failed", detector_name="RegexDetector")
        assert error.detector_name == "RegexDetector"
        assert error.context["detector"] == "RegexDetector"

    def test_detector_name_default(self) -> None:
        """Test that detector_name defaults to None."""
        error = DetectorError("Failed")
        assert error.detector_name is None

    def test_context_combined_with_detector_name(self) -> None:
        """Test that detector_name is added to provided context."""
        error = DetectorError("Error", detector_name="YaraDetector", context={"file": "test.py"})
        assert error.context["detector"] == "YaraDetector"
        assert error.context["file"] == "test.py"


class TestConfigError:
    """Tests for the ConfigError exception."""

    def test_can_be_raised(self) -> None:
        """Test that ConfigError can be raised and caught."""
        with pytest.raises(ConfigError):
            raise ConfigError("Invalid configuration")

    def test_can_be_caught_as_hamburglar_error(self) -> None:
        """Test that ConfigError can be caught as HamburglarError."""
        with pytest.raises(HamburglarError):
            raise ConfigError("Invalid configuration")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = ConfigError("Invalid format")
        assert error.message == "Invalid format"

    def test_config_key_attribute(self) -> None:
        """Test that config_key attribute is set and included in context."""
        error = ConfigError("Invalid value", config_key="output_format")
        assert error.config_key == "output_format"
        assert error.context["config_key"] == "output_format"

    def test_config_key_default(self) -> None:
        """Test that config_key defaults to None."""
        error = ConfigError("Error")
        assert error.config_key is None

    def test_context_combined_with_config_key(self) -> None:
        """Test that config_key is added to provided context."""
        error = ConfigError("Error", config_key="recursive", context={"value": False})
        assert error.context["config_key"] == "recursive"
        assert error.context["value"] is False


class TestOutputError:
    """Tests for the OutputError exception."""

    def test_can_be_raised(self) -> None:
        """Test that OutputError can be raised and caught."""
        with pytest.raises(OutputError):
            raise OutputError("Output failed")

    def test_can_be_caught_as_hamburglar_error(self) -> None:
        """Test that OutputError can be caught as HamburglarError."""
        with pytest.raises(HamburglarError):
            raise OutputError("Output failed")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = OutputError("Failed to write file")
        assert error.message == "Failed to write file"

    def test_output_path_attribute(self) -> None:
        """Test that output_path attribute is set and included in context."""
        error = OutputError("Write failed", output_path="/output/report.json")
        assert error.output_path == "/output/report.json"
        assert error.context["output_path"] == "/output/report.json"

    def test_output_path_default(self) -> None:
        """Test that output_path defaults to None."""
        error = OutputError("Error")
        assert error.output_path is None

    def test_context_combined_with_output_path(self) -> None:
        """Test that output_path is added to provided context."""
        error = OutputError("Error", output_path="/file.txt", context={"format": "json"})
        assert error.context["output_path"] == "/file.txt"
        assert error.context["format"] == "json"


class TestYaraCompilationError:
    """Tests for the YaraCompilationError exception."""

    def test_can_be_raised(self) -> None:
        """Test that YaraCompilationError can be raised and caught."""
        with pytest.raises(YaraCompilationError):
            raise YaraCompilationError("Compilation failed")

    def test_can_be_caught_as_hamburglar_error(self) -> None:
        """Test that YaraCompilationError can be caught as HamburglarError."""
        with pytest.raises(HamburglarError):
            raise YaraCompilationError("Compilation failed")

    def test_message_attribute(self) -> None:
        """Test that message attribute is set correctly."""
        error = YaraCompilationError("Syntax error in rule")
        assert error.message == "Syntax error in rule"

    def test_rule_file_attribute(self) -> None:
        """Test that rule_file attribute is set and included in context."""
        error = YaraCompilationError("Syntax error", rule_file="bad_rule.yar")
        assert error.rule_file == "bad_rule.yar"
        assert error.context["rule_file"] == "bad_rule.yar"

    def test_rule_file_default(self) -> None:
        """Test that rule_file defaults to None."""
        error = YaraCompilationError("Error")
        assert error.rule_file is None

    def test_context_combined_with_rule_file(self) -> None:
        """Test that rule_file is added to provided context."""
        error = YaraCompilationError(
            "Error", rule_file="test.yar", context={"line": 10, "column": 5}
        )
        assert error.context["rule_file"] == "test.yar"
        assert error.context["line"] == 10
        assert error.context["column"] == 5

    def test_helpful_error_message_format(self) -> None:
        """Test that error messages include helpful context for debugging."""
        error = YaraCompilationError(
            "Syntax error: unexpected token",
            rule_file="malformed.yar",
            context={"line": 15, "token": "rule"},
        )
        error_str = str(error)
        assert "Syntax error" in error_str
        assert "malformed.yar" in error_str


class TestExceptionHierarchy:
    """Tests for the exception hierarchy structure."""

    def test_all_exceptions_inherit_from_hamburglar_error(self) -> None:
        """Test that all custom exceptions inherit from HamburglarError."""
        exceptions = [
            ScanError("test"),
            DetectorError("test"),
            ConfigError("test"),
            OutputError("test"),
            YaraCompilationError("test"),
        ]
        for exc in exceptions:
            assert isinstance(exc, HamburglarError)

    def test_catching_base_catches_all(self) -> None:
        """Test that catching HamburglarError catches all subclasses."""
        exception_classes = [
            ScanError,
            DetectorError,
            ConfigError,
            OutputError,
            YaraCompilationError,
        ]
        for exc_class in exception_classes:
            try:
                raise exc_class("test error")
            except HamburglarError as e:
                assert e.message == "test error"
            else:
                pytest.fail(f"{exc_class.__name__} was not caught by HamburglarError")

    def test_exception_specificity(self) -> None:
        """Test that specific exceptions can be caught separately."""
        # Each exception should only be caught by its own type or parent
        with pytest.raises(ScanError):
            raise ScanError("scan error")

        with pytest.raises(DetectorError):
            raise DetectorError("detector error")

        with pytest.raises(ConfigError):
            raise ConfigError("config error")

        with pytest.raises(OutputError):
            raise OutputError("output error")

        with pytest.raises(YaraCompilationError):
            raise YaraCompilationError("yara error")

    def test_scan_error_not_caught_by_detector_error(self) -> None:
        """Test that ScanError is not caught by DetectorError handler."""
        try:
            raise ScanError("test")
        except DetectorError:
            pytest.fail("ScanError should not be caught by DetectorError")
        except ScanError:
            pass  # Expected

    def test_exception_args_accessible(self) -> None:
        """Test that exception args are accessible for all exception types."""
        error = ScanError("Test message", path="/test")
        assert error.args[0] == "Test message"
