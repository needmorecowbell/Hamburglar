"""Tests for Hamburglar core data models.

This module contains tests for the Pydantic models used throughout Hamburglar,
including Finding, ScanResult, and ScanConfig.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hamburglar.core.models import (
    Finding,
    OutputFormat,
    ScanConfig,
    ScanResult,
    Severity,
)


class TestSeverityEnum:
    """Tests for the Severity enumeration."""

    def test_severity_values(self) -> None:
        """Test that all expected severity levels exist with correct values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_is_string_enum(self) -> None:
        """Test that Severity values can be used as strings."""
        # String enums inherit from str, so they compare equal to their value
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        # The .value property gives the string value
        assert Severity.CRITICAL.value == "critical"


class TestOutputFormatEnum:
    """Tests for the OutputFormat enumeration."""

    def test_output_format_values(self) -> None:
        """Test that all expected output formats exist."""
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.TABLE.value == "table"

    def test_output_format_is_string_enum(self) -> None:
        """Test that OutputFormat values can be used as strings."""
        # String enums inherit from str, so they compare equal to their value
        assert OutputFormat.JSON == "json"
        assert OutputFormat.TABLE == "table"
        # The .value property gives the string value
        assert OutputFormat.JSON.value == "json"


class TestFindingModel:
    """Tests for the Finding model."""

    def test_finding_creation_minimal(self) -> None:
        """Test creating a Finding with only required fields."""
        finding = Finding(
            file_path="/path/to/file.txt",
            detector_name="test_detector",
        )
        assert finding.file_path == "/path/to/file.txt"
        assert finding.detector_name == "test_detector"
        assert finding.matches == []
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata == {}

    def test_finding_creation_full(self) -> None:
        """Test creating a Finding with all fields specified."""
        finding = Finding(
            file_path="/path/to/secret.py",
            detector_name="aws_key_detector",
            matches=["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"],
            severity=Severity.CRITICAL,
            metadata={"line_numbers": [10, 25], "pattern": "AKIA[A-Z0-9]{16}"},
        )
        assert finding.file_path == "/path/to/secret.py"
        assert finding.detector_name == "aws_key_detector"
        assert len(finding.matches) == 2
        assert finding.matches[0] == "AKIAIOSFODNN7EXAMPLE"
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["line_numbers"] == [10, 25]

    def test_finding_serialization_json(self) -> None:
        """Test that Finding can be serialized to JSON."""
        finding = Finding(
            file_path="/test/file.txt",
            detector_name="email_detector",
            matches=["admin@example.com"],
            severity=Severity.LOW,
            metadata={"context": "configuration file"},
        )
        json_str = finding.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["file_path"] == "/test/file.txt"
        assert parsed["detector_name"] == "email_detector"
        assert parsed["matches"] == ["admin@example.com"]
        assert parsed["severity"] == "low"
        assert parsed["metadata"]["context"] == "configuration file"

    def test_finding_serialization_dict(self) -> None:
        """Test that Finding can be serialized to a dictionary."""
        finding = Finding(
            file_path="/config.py",
            detector_name="api_key_detector",
            matches=["sk_live_abc123"],
            severity=Severity.HIGH,
        )
        data = finding.model_dump()

        assert isinstance(data, dict)
        assert data["file_path"] == "/config.py"
        assert data["detector_name"] == "api_key_detector"
        assert data["severity"] == Severity.HIGH

    def test_finding_with_empty_matches(self) -> None:
        """Test that Finding works with empty matches list."""
        finding = Finding(
            file_path="/file.txt",
            detector_name="test",
            matches=[],
        )
        assert finding.matches == []

    def test_finding_severity_default(self) -> None:
        """Test that default severity is MEDIUM."""
        finding = Finding(
            file_path="/file.txt",
            detector_name="test",
        )
        assert finding.severity == Severity.MEDIUM


class TestScanResultModel:
    """Tests for the ScanResult model."""

    def test_scan_result_creation_minimal(self) -> None:
        """Test creating a ScanResult with only required fields."""
        result = ScanResult(target_path="/scan/target")
        assert result.target_path == "/scan/target"
        assert result.findings == []
        assert result.scan_duration == 0.0
        assert result.stats == {}

    def test_scan_result_creation_full(self) -> None:
        """Test creating a ScanResult with all fields."""
        findings = [
            Finding(
                file_path="/target/secrets.txt",
                detector_name="aws_detector",
                matches=["AKIAIOSFODNN7EXAMPLE"],
                severity=Severity.CRITICAL,
            ),
            Finding(
                file_path="/target/config.py",
                detector_name="email_detector",
                matches=["user@example.com"],
                severity=Severity.LOW,
            ),
        ]
        result = ScanResult(
            target_path="/target",
            findings=findings,
            scan_duration=1.234,
            stats={
                "files_scanned": 10,
                "files_with_findings": 2,
                "total_matches": 2,
                "errors": 0,
            },
        )
        assert result.target_path == "/target"
        assert len(result.findings) == 2
        assert result.scan_duration == 1.234
        assert result.stats["files_scanned"] == 10

    def test_scan_result_with_multiple_findings(self) -> None:
        """Test ScanResult with multiple findings from different detectors."""
        findings = [
            Finding(file_path="/a.txt", detector_name="detector1", matches=["match1"]),
            Finding(file_path="/b.txt", detector_name="detector2", matches=["match2", "match3"]),
            Finding(file_path="/a.txt", detector_name="detector3", matches=["match4"]),
        ]
        result = ScanResult(target_path="/project", findings=findings)

        assert len(result.findings) == 3
        # Multiple findings can have the same file_path
        file_paths = [f.file_path for f in result.findings]
        assert file_paths.count("/a.txt") == 2

    def test_scan_result_serialization_json(self) -> None:
        """Test that ScanResult can be serialized to JSON."""
        finding = Finding(
            file_path="/test.txt",
            detector_name="test_detector",
            matches=["secret"],
            severity=Severity.HIGH,
        )
        result = ScanResult(
            target_path="/project",
            findings=[finding],
            scan_duration=0.5,
            stats={"files_scanned": 5},
        )
        json_str = result.model_dump_json(indent=2)
        parsed = json.loads(json_str)

        assert parsed["target_path"] == "/project"
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["matches"] == ["secret"]
        assert parsed["scan_duration"] == 0.5
        assert parsed["stats"]["files_scanned"] == 5

    def test_scan_result_empty_findings(self) -> None:
        """Test ScanResult with no findings (clean scan)."""
        result = ScanResult(
            target_path="/clean_project",
            findings=[],
            scan_duration=2.0,
            stats={"files_scanned": 100, "files_with_findings": 0},
        )
        assert len(result.findings) == 0
        assert result.stats["files_with_findings"] == 0


class TestScanConfigModel:
    """Tests for the ScanConfig model."""

    def test_scan_config_creation_minimal(self, tmp_path: Path) -> None:
        """Test creating a ScanConfig with only required fields."""
        config = ScanConfig(target_path=tmp_path)
        assert config.target_path == tmp_path
        assert config.recursive is True
        assert config.use_yara is False
        assert config.yara_rules_path is None
        assert config.output_format == OutputFormat.TABLE
        assert config.whitelist == []

    def test_scan_config_creation_full(self, tmp_path: Path) -> None:
        """Test creating a ScanConfig with all fields specified."""
        rules_path = tmp_path / "rules"
        rules_path.mkdir()

        config = ScanConfig(
            target_path=tmp_path,
            recursive=False,
            use_yara=True,
            yara_rules_path=rules_path,
            output_format=OutputFormat.JSON,
            blacklist=[".git", "node_modules", "*.pyc"],
            whitelist=["*.py", "*.js"],
        )
        assert config.target_path == tmp_path
        assert config.recursive is False
        assert config.use_yara is True
        assert config.yara_rules_path == rules_path
        assert config.output_format == OutputFormat.JSON
        assert ".git" in config.blacklist
        assert "*.py" in config.whitelist

    def test_scan_config_defaults(self, tmp_path: Path) -> None:
        """Test that ScanConfig has correct default values."""
        config = ScanConfig(target_path=tmp_path)

        # Check default blacklist patterns
        assert ".git" in config.blacklist
        assert "__pycache__" in config.blacklist
        assert "node_modules" in config.blacklist
        assert ".venv" in config.blacklist
        assert "venv" in config.blacklist
        assert ".env" in config.blacklist
        assert "*.pyc" in config.blacklist
        assert "*.pyo" in config.blacklist

        # Check other defaults
        assert config.recursive is True
        assert config.use_yara is False
        assert config.output_format == OutputFormat.TABLE

    def test_scan_config_path_as_string(self, tmp_path: Path) -> None:
        """Test that ScanConfig accepts path as string and converts to Path."""
        config = ScanConfig(target_path=str(tmp_path))
        assert isinstance(config.target_path, Path)
        assert config.target_path == tmp_path

    def test_scan_config_validation_output_format(self, tmp_path: Path) -> None:
        """Test that ScanConfig validates output format values."""
        # Valid formats should work
        config_json = ScanConfig(target_path=tmp_path, output_format=OutputFormat.JSON)
        assert config_json.output_format == OutputFormat.JSON

        config_table = ScanConfig(target_path=tmp_path, output_format=OutputFormat.TABLE)
        assert config_table.output_format == OutputFormat.TABLE

        # String values should also work due to Pydantic coercion
        config_str = ScanConfig(target_path=tmp_path, output_format="json")
        assert config_str.output_format == OutputFormat.JSON

    def test_scan_config_custom_blacklist(self, tmp_path: Path) -> None:
        """Test that custom blacklist completely overrides defaults."""
        config = ScanConfig(
            target_path=tmp_path,
            blacklist=["custom_dir", "*.log"],
        )
        # Custom blacklist replaces defaults
        assert config.blacklist == ["custom_dir", "*.log"]
        assert ".git" not in config.blacklist

    def test_scan_config_empty_blacklist(self, tmp_path: Path) -> None:
        """Test that empty blacklist can be set."""
        config = ScanConfig(target_path=tmp_path, blacklist=[])
        assert config.blacklist == []

    def test_scan_config_serialization(self, tmp_path: Path) -> None:
        """Test that ScanConfig can be serialized to dict and JSON."""
        config = ScanConfig(
            target_path=tmp_path,
            recursive=True,
            output_format=OutputFormat.JSON,
        )
        data = config.model_dump()

        assert isinstance(data, dict)
        assert "target_path" in data
        assert data["recursive"] is True
        assert data["output_format"] == OutputFormat.JSON

    def test_scan_config_with_whitelist(self, tmp_path: Path) -> None:
        """Test ScanConfig with whitelist patterns."""
        config = ScanConfig(
            target_path=tmp_path,
            whitelist=["*.py", "*.js", "*.ts"],
        )
        assert len(config.whitelist) == 3
        assert "*.py" in config.whitelist
        assert "*.js" in config.whitelist
        assert "*.ts" in config.whitelist

    def test_scan_config_yara_enabled(self, tmp_path: Path) -> None:
        """Test ScanConfig with YARA enabled."""
        rules_dir = tmp_path / "yara_rules"
        rules_dir.mkdir()

        config = ScanConfig(
            target_path=tmp_path,
            use_yara=True,
            yara_rules_path=rules_dir,
        )
        assert config.use_yara is True
        assert config.yara_rules_path == rules_dir

    def test_scan_config_yara_path_without_flag(self, tmp_path: Path) -> None:
        """Test that yara_rules_path can be set independently of use_yara flag."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Path can be set even if use_yara is False
        config = ScanConfig(
            target_path=tmp_path,
            use_yara=False,
            yara_rules_path=rules_dir,
        )
        assert config.use_yara is False
        assert config.yara_rules_path == rules_dir
