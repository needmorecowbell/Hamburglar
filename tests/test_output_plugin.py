"""Tests for the OutputPlugin base class.

This module tests the OutputPlugin abstract base class and its utility methods
for building custom output formatter plugins.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure src path is in sys.path for imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput, default_registry
from hamburglar.plugins.output_plugin import OutputPlugin


class SimpleOutputPlugin(OutputPlugin):
    """A simple output plugin for testing."""

    __version__ = "2.0.0"
    __author__ = "Test Author"

    @property
    def name(self) -> str:
        return "simple_test_output"

    def format(self, result: ScanResult) -> str:
        return self.format_as_lines(result)


class ConfigurableOutputPlugin(OutputPlugin):
    """A configurable output plugin for testing."""

    @property
    def name(self) -> str:
        return "configurable_output"

    @property
    def description(self) -> str:
        return "A configurable test output formatter"

    @property
    def file_extension(self) -> str:
        return self.get_config("extension", ".custom")

    def format(self, result: ScanResult) -> str:
        include_meta = self.get_config("include_metadata", False)
        return self.format_as_json(result, include_metadata=include_meta)


class GroupedOutputPlugin(OutputPlugin):
    """An output plugin that groups findings for testing."""

    @property
    def name(self) -> str:
        return "grouped_output"

    def format(self, result: ScanResult) -> str:
        lines: list[str] = []
        grouped = self.group_by_file(result)
        for file_path, findings in grouped.items():
            lines.append(f"=== {file_path} ===")
            for finding in findings:
                lines.append(f"  {finding.detector_name}: {len(finding.matches)} matches")
        return "\n".join(lines)


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset output registry before each test."""
    # Store original outputs
    original = dict(default_registry._outputs)
    yield
    # Restore original outputs
    default_registry._outputs = original


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        file_path="test.py",
        detector_name="test_detector",
        matches=["SECRET_ABC123", "SECRET_XYZ789"],
        severity=Severity.HIGH,
        metadata={"line": 42, "column": 10},
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Create a sample scan result for testing."""
    findings = [
        sample_finding,
        Finding(
            file_path="config.json",
            detector_name="api_keys",
            matches=["api_key_12345"],
            severity=Severity.CRITICAL,
            metadata={"line": 5},
        ),
        Finding(
            file_path="test.py",
            detector_name="passwords",
            matches=["password123"],
            severity=Severity.MEDIUM,
            metadata={},
        ),
    ]
    return ScanResult(
        target_path="/tmp/test",
        findings=findings,
        scan_duration=1.5,
        stats={"files_scanned": 10},
    )


class TestOutputPluginBasics:
    """Basic tests for OutputPlugin class."""

    def test_init_default(self) -> None:
        """Test OutputPlugin initialization with defaults."""
        output = SimpleOutputPlugin()
        assert output.name == "simple_test_output"
        assert output.config == {}

    def test_init_with_config(self) -> None:
        """Test OutputPlugin initialization with configuration."""
        output = ConfigurableOutputPlugin(
            include_metadata=True,
            extension=".json",
        )
        assert output.config == {
            "include_metadata": True,
            "extension": ".json",
        }

    def test_name_property(self) -> None:
        """Test name property returns correct value."""
        output = SimpleOutputPlugin()
        assert output.name == "simple_test_output"

    def test_description_property_from_docstring(self) -> None:
        """Test description property from docstring."""
        output = SimpleOutputPlugin()
        assert "simple output plugin" in output.description.lower()

    def test_description_property_override(self) -> None:
        """Test overridden description property."""
        output = ConfigurableOutputPlugin()
        assert output.description == "A configurable test output formatter"

    def test_version_property(self) -> None:
        """Test version property."""
        output = SimpleOutputPlugin()
        assert output.version == "2.0.0"

    def test_version_property_default(self) -> None:
        """Test version property default value."""
        output = ConfigurableOutputPlugin()
        assert output.version == "1.0.0"

    def test_author_property(self) -> None:
        """Test author property."""
        output = SimpleOutputPlugin()
        assert output.author == "Test Author"

    def test_author_property_default(self) -> None:
        """Test author property default value."""
        output = ConfigurableOutputPlugin()
        assert output.author == ""

    def test_file_extension_default(self) -> None:
        """Test default file extension."""
        output = SimpleOutputPlugin()
        assert output.file_extension == ".txt"

    def test_file_extension_override(self) -> None:
        """Test overridden file extension."""
        output = ConfigurableOutputPlugin(extension=".json")
        assert output.file_extension == ".json"


class TestOutputPluginConfig:
    """Tests for OutputPlugin configuration."""

    def test_get_config_existing_key(self) -> None:
        """Test get_config with existing key."""
        output = ConfigurableOutputPlugin(include_metadata=True)
        assert output.get_config("include_metadata") is True

    def test_get_config_missing_key(self) -> None:
        """Test get_config with missing key returns None."""
        output = ConfigurableOutputPlugin()
        assert output.get_config("nonexistent") is None

    def test_get_config_with_default(self) -> None:
        """Test get_config with default value."""
        output = ConfigurableOutputPlugin()
        assert output.get_config("nonexistent", "default") == "default"

    def test_config_property_returns_copy(self) -> None:
        """Test that config property returns a copy."""
        output = ConfigurableOutputPlugin(key="value")
        config = output.config
        config["key"] = "modified"
        assert output.get_config("key") == "value"


class TestOutputPluginFormatFinding:
    """Tests for format_finding utility method."""

    def test_format_finding_basic(self, sample_finding: Finding) -> None:
        """Test format_finding with basic parameters."""
        output = SimpleOutputPlugin()
        result = output.format_finding(sample_finding)

        assert result["file_path"] == "test.py"
        assert result["detector_name"] == "test_detector"
        assert result["matches"] == ["SECRET_ABC123", "SECRET_XYZ789"]
        assert result["severity"] == "high"
        assert "metadata" not in result

    def test_format_finding_with_metadata(self, sample_finding: Finding) -> None:
        """Test format_finding with metadata included."""
        output = SimpleOutputPlugin()
        result = output.format_finding(sample_finding, include_metadata=True)

        assert "metadata" in result
        assert result["metadata"]["line"] == 42
        assert result["metadata"]["column"] == 10

    def test_format_finding_empty_metadata(self) -> None:
        """Test format_finding with empty metadata."""
        finding = Finding(
            file_path="test.py",
            detector_name="test",
            matches=["match"],
            severity=Severity.LOW,
            metadata={},
        )
        output = SimpleOutputPlugin()
        result = output.format_finding(finding, include_metadata=True)

        # Empty metadata should not include the key
        assert "metadata" not in result


class TestOutputPluginFormatResult:
    """Tests for format_result utility method."""

    def test_format_result_basic(self, sample_scan_result: ScanResult) -> None:
        """Test format_result with basic parameters."""
        output = SimpleOutputPlugin()
        result = output.format_result(sample_scan_result)

        assert "findings" in result
        assert len(result["findings"]) == 3
        assert "summary" in result

    def test_format_result_no_summary(self, sample_scan_result: ScanResult) -> None:
        """Test format_result without summary."""
        output = SimpleOutputPlugin()
        result = output.format_result(sample_scan_result, include_summary=False)

        assert "findings" in result
        assert "summary" not in result

    def test_format_result_with_metadata(self, sample_scan_result: ScanResult) -> None:
        """Test format_result with metadata included."""
        output = SimpleOutputPlugin()
        result = output.format_result(sample_scan_result, include_metadata=True)

        # At least one finding should have metadata
        has_metadata = any("metadata" in f for f in result["findings"])
        assert has_metadata


class TestOutputPluginGetSummary:
    """Tests for get_summary utility method."""

    def test_get_summary(self, sample_scan_result: ScanResult) -> None:
        """Test get_summary returns correct statistics."""
        output = SimpleOutputPlugin()
        summary = output.get_summary(sample_scan_result)

        assert summary["total_findings"] == 3
        assert summary["files_scanned"] == 10
        assert "by_severity" in summary
        assert "by_detector" in summary

    def test_get_summary_severity_counts(self, sample_scan_result: ScanResult) -> None:
        """Test get_summary counts severities correctly."""
        output = SimpleOutputPlugin()
        summary = output.get_summary(sample_scan_result)

        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["medium"] == 1

    def test_get_summary_detector_counts(self, sample_scan_result: ScanResult) -> None:
        """Test get_summary counts detectors correctly."""
        output = SimpleOutputPlugin()
        summary = output.get_summary(sample_scan_result)

        assert summary["by_detector"]["test_detector"] == 1
        assert summary["by_detector"]["api_keys"] == 1
        assert summary["by_detector"]["passwords"] == 1

    def test_get_summary_empty_result(self) -> None:
        """Test get_summary with empty result."""
        output = SimpleOutputPlugin()
        result = ScanResult(
            target_path="/tmp/empty",
            findings=[],
            stats={"files_scanned": 5},
        )
        summary = output.get_summary(result)

        assert summary["total_findings"] == 0
        assert summary["files_scanned"] == 5
        assert summary["by_severity"] == {}
        assert summary["by_detector"] == {}


class TestOutputPluginFormatAsJson:
    """Tests for format_as_json utility method."""

    def test_format_as_json_basic(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_json produces valid JSON."""
        output = SimpleOutputPlugin()
        json_str = output.format_as_json(sample_scan_result)

        # Should be valid JSON
        data = json.loads(json_str)
        assert "findings" in data
        assert "summary" in data

    def test_format_as_json_no_metadata(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_json without metadata."""
        output = SimpleOutputPlugin()
        json_str = output.format_as_json(sample_scan_result, include_metadata=False)

        data = json.loads(json_str)
        for finding in data["findings"]:
            assert "metadata" not in finding

    def test_format_as_json_compact(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_json with compact output."""
        output = SimpleOutputPlugin()
        json_str = output.format_as_json(sample_scan_result, indent=None)

        # Compact JSON should be a single line (no newlines in structure)
        assert "\n" not in json_str.strip()

    def test_format_as_json_indented(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_json with indentation."""
        output = SimpleOutputPlugin()
        json_str = output.format_as_json(sample_scan_result, indent=4)

        # Indented JSON should have multiple lines
        assert "\n" in json_str


class TestOutputPluginFormatAsLines:
    """Tests for format_as_lines utility method."""

    def test_format_as_lines_basic(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_lines produces text output."""
        output = SimpleOutputPlugin()
        text = output.format_as_lines(sample_scan_result)

        lines = text.split("\n")
        assert len(lines) == 3

    def test_format_as_lines_with_severity(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_lines includes severity."""
        output = SimpleOutputPlugin()
        text = output.format_as_lines(sample_scan_result, include_severity=True)

        assert "[high]" in text
        assert "[critical]" in text
        assert "[medium]" in text

    def test_format_as_lines_without_severity(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_lines without severity prefix."""
        output = SimpleOutputPlugin()
        text = output.format_as_lines(sample_scan_result, include_severity=False)

        assert "[high]" not in text
        assert "[critical]" not in text
        assert "[medium]" not in text

    def test_format_as_lines_custom_separator(self, sample_scan_result: ScanResult) -> None:
        """Test format_as_lines with custom separator."""
        output = SimpleOutputPlugin()
        text = output.format_as_lines(sample_scan_result, separator=" | ")

        assert " | " in text
        parts = text.split(" | ")
        assert len(parts) == 3

    def test_format_as_lines_truncates_matches(self) -> None:
        """Test format_as_lines truncates many matches."""
        findings = [
            Finding(
                file_path="test.py",
                detector_name="test",
                matches=["m1", "m2", "m3", "m4", "m5"],
                severity=Severity.HIGH,
                metadata={},
            )
        ]
        result = ScanResult(
            target_path="/tmp/test",
            findings=findings,
            stats={"files_scanned": 1},
        )
        output = SimpleOutputPlugin()
        text = output.format_as_lines(result)

        assert "(+2 more)" in text


class TestOutputPluginGroupBy:
    """Tests for grouping utility methods."""

    def test_group_by_file(self, sample_scan_result: ScanResult) -> None:
        """Test group_by_file groups correctly."""
        output = SimpleOutputPlugin()
        grouped = output.group_by_file(sample_scan_result)

        assert "test.py" in grouped
        assert "config.json" in grouped
        assert len(grouped["test.py"]) == 2
        assert len(grouped["config.json"]) == 1

    def test_group_by_severity(self, sample_scan_result: ScanResult) -> None:
        """Test group_by_severity groups correctly."""
        output = SimpleOutputPlugin()
        grouped = output.group_by_severity(sample_scan_result)

        assert Severity.HIGH in grouped
        assert Severity.CRITICAL in grouped
        assert Severity.MEDIUM in grouped
        assert len(grouped[Severity.HIGH]) == 1
        assert len(grouped[Severity.CRITICAL]) == 1
        assert len(grouped[Severity.MEDIUM]) == 1

    def test_group_by_detector(self, sample_scan_result: ScanResult) -> None:
        """Test group_by_detector groups correctly."""
        output = SimpleOutputPlugin()
        grouped = output.group_by_detector(sample_scan_result)

        assert "test_detector" in grouped
        assert "api_keys" in grouped
        assert "passwords" in grouped

    def test_group_by_empty_result(self) -> None:
        """Test grouping with empty result."""
        output = SimpleOutputPlugin()
        result = ScanResult(
            target_path="/tmp/empty",
            findings=[],
            stats={"files_scanned": 0},
        )

        assert output.group_by_file(result) == {}
        assert output.group_by_severity(result) == {}
        assert output.group_by_detector(result) == {}


class TestOutputPluginFormat:
    """Tests for format method implementation."""

    def test_format_simple(self, sample_scan_result: ScanResult) -> None:
        """Test format with simple output plugin."""
        output = SimpleOutputPlugin()
        text = output.format(sample_scan_result)

        assert "test.py" in text
        assert "config.json" in text

    def test_format_configurable(self, sample_scan_result: ScanResult) -> None:
        """Test format with configuration."""
        output = ConfigurableOutputPlugin(include_metadata=True)
        json_str = output.format(sample_scan_result)

        data = json.loads(json_str)
        # With metadata enabled, some findings should have it
        has_metadata = any("metadata" in f for f in data["findings"])
        assert has_metadata

    def test_format_grouped(self, sample_scan_result: ScanResult) -> None:
        """Test format with grouped output plugin."""
        output = GroupedOutputPlugin()
        text = output.format(sample_scan_result)

        assert "=== test.py ===" in text
        assert "=== config.json ===" in text


class TestOutputPluginRegistry:
    """Tests for registry integration."""

    def test_register(self) -> None:
        """Test registering output with registry."""
        output = SimpleOutputPlugin()
        output.register()
        assert "simple_test_output" in default_registry

    def test_register_duplicate_raises(self) -> None:
        """Test registering duplicate output raises error."""
        output1 = SimpleOutputPlugin()
        output2 = SimpleOutputPlugin()
        output1.register()
        with pytest.raises(ValueError, match="already registered"):
            output2.register()

    def test_unregister(self) -> None:
        """Test unregistering output from registry."""
        output = SimpleOutputPlugin()
        output.register()
        assert "simple_test_output" in default_registry
        output.unregister()
        assert "simple_test_output" not in default_registry

    def test_unregister_not_registered_raises(self) -> None:
        """Test unregistering non-existent output raises error."""
        output = SimpleOutputPlugin()
        with pytest.raises(KeyError, match="not registered"):
            output.unregister()


class TestOutputPluginInheritance:
    """Tests for OutputPlugin inheritance from BaseOutput."""

    def test_is_base_output(self) -> None:
        """Test OutputPlugin inherits from BaseOutput."""
        output = SimpleOutputPlugin()
        # Use the already imported BaseOutput to avoid module isolation issues
        assert isinstance(output, BaseOutput)
        # Also verify via MRO
        assert any(cls.__name__ == "BaseOutput" for cls in type(output).__mro__)

    def test_abstract_methods_required(self) -> None:
        """Test that abstract methods must be implemented."""
        # This should raise TypeError because name and format are abstract
        with pytest.raises(TypeError):

            class IncompletePlugin(OutputPlugin):
                pass

            IncompletePlugin()

    def test_abstract_name_required(self) -> None:
        """Test that name property must be implemented."""
        with pytest.raises(TypeError):

            class NoNamePlugin(OutputPlugin):
                def format(self, result: ScanResult) -> str:
                    return ""

            NoNamePlugin()

    def test_abstract_format_required(self) -> None:
        """Test that format method must be implemented."""
        with pytest.raises(TypeError):

            class NoFormatPlugin(OutputPlugin):
                @property
                def name(self) -> str:
                    return "no_format"

            NoFormatPlugin()


class TestOutputPluginEdgeCases:
    """Edge case tests for OutputPlugin."""

    def test_empty_matches(self) -> None:
        """Test formatting with empty matches list."""
        finding = Finding(
            file_path="test.py",
            detector_name="test",
            matches=[],
            severity=Severity.LOW,
            metadata={},
        )
        result = ScanResult(
            target_path="/tmp/test",
            findings=[finding],
            stats={"files_scanned": 1},
        )
        output = SimpleOutputPlugin()

        # Should not raise an error
        text = output.format(result)
        assert "test.py" in text

    def test_special_characters_in_matches(self) -> None:
        """Test formatting with special characters in matches."""
        finding = Finding(
            file_path="test.py",
            detector_name="test",
            matches=['key="value"', "data: 'test'", "line\nbreak"],
            severity=Severity.HIGH,
            metadata={},
        )
        result = ScanResult(
            target_path="/tmp/test",
            findings=[finding],
            stats={"files_scanned": 1},
        )
        output = ConfigurableOutputPlugin()

        # JSON should handle special characters
        json_str = output.format(result)
        data = json.loads(json_str)
        assert data["findings"][0]["matches"][0] == 'key="value"'

    def test_unicode_content(self) -> None:
        """Test formatting with unicode content."""
        finding = Finding(
            file_path="тест.py",
            detector_name="детектор",
            matches=["密码", "пароль", "🔑"],
            severity=Severity.HIGH,
            metadata={"note": "ユニコード"},
        )
        result = ScanResult(
            target_path="/tmp/test",
            findings=[finding],
            stats={"files_scanned": 1},
        )
        output = SimpleOutputPlugin()

        # Should handle unicode
        text = output.format(result)
        assert "тест.py" in text

    def test_large_result_set(self) -> None:
        """Test formatting with large number of findings."""
        findings = [
            Finding(
                file_path=f"file_{i}.py",
                detector_name="test",
                matches=[f"match_{i}"],
                severity=Severity.LOW,
                metadata={},
            )
            for i in range(1000)
        ]
        result = ScanResult(
            target_path="/tmp/test",
            findings=findings,
            stats={"files_scanned": 1000},
        )
        output = SimpleOutputPlugin()

        # Should handle large results
        text = output.format(result)
        lines = text.split("\n")
        assert len(lines) == 1000
