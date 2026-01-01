"""Tests for Hamburglar core data models.

This module contains tests for the Pydantic models used throughout Hamburglar,
including Finding, ScanResult, ScanConfig, and specialized finding types.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from hamburglar.core.models import (
    ElementType,
    Finding,
    GitFinding,
    OutputFormat,
    ScanConfig,
    ScanResult,
    SecretOccurrence,
    SecretTimeline,
    Severity,
    WebFinding,
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


class TestElementTypeEnum:
    """Tests for the ElementType enumeration."""

    def test_element_type_values(self) -> None:
        """Test that all expected element types exist with correct values."""
        assert ElementType.SCRIPT.value == "script"
        assert ElementType.INLINE_SCRIPT.value == "inline_script"
        assert ElementType.TEXT.value == "text"
        assert ElementType.ATTRIBUTE.value == "attribute"

    def test_element_type_is_string_enum(self) -> None:
        """Test that ElementType values can be used as strings."""
        assert ElementType.SCRIPT == "script"
        assert ElementType.TEXT == "text"


class TestGitFindingModel:
    """Tests for the GitFinding model."""

    def test_git_finding_creation_minimal(self) -> None:
        """Test creating a GitFinding with only required fields."""
        finding = GitFinding(
            file_path="/path/to/file.txt",
            detector_name="api_key_detector",
            commit_hash="abc123def456",
            author="Test User",
            date="2024-01-15T10:30:00Z",
            file_path_at_commit="/path/to/file.txt",
        )
        assert finding.file_path == "/path/to/file.txt"
        assert finding.detector_name == "api_key_detector"
        assert finding.commit_hash == "abc123def456"
        assert finding.author == "Test User"
        assert finding.date == "2024-01-15T10:30:00Z"
        assert finding.file_path_at_commit == "/path/to/file.txt"
        # Inherited defaults
        assert finding.matches == []
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata == {}

    def test_git_finding_creation_full(self) -> None:
        """Test creating a GitFinding with all fields specified."""
        finding = GitFinding(
            file_path="/current/config.py",
            detector_name="aws_key_detector",
            matches=["AKIAIOSFODNN7EXAMPLE"],
            severity=Severity.CRITICAL,
            metadata={"line_number": 42},
            commit_hash="abc123def456789",
            author="Developer Name",
            date="2024-06-20T14:00:00+00:00",
            file_path_at_commit="/old/config.py",  # File was renamed
        )
        assert finding.file_path == "/current/config.py"
        assert finding.file_path_at_commit == "/old/config.py"
        assert finding.matches == ["AKIAIOSFODNN7EXAMPLE"]
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["line_number"] == 42

    def test_git_finding_serialization_json(self) -> None:
        """Test that GitFinding can be serialized to JSON."""
        finding = GitFinding(
            file_path="/file.txt",
            detector_name="test_detector",
            matches=["secret123"],
            severity=Severity.HIGH,
            commit_hash="deadbeef",
            author="Author",
            date="2024-01-01T00:00:00Z",
            file_path_at_commit="/file.txt",
        )
        json_str = finding.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["file_path"] == "/file.txt"
        assert parsed["commit_hash"] == "deadbeef"
        assert parsed["author"] == "Author"
        assert parsed["date"] == "2024-01-01T00:00:00Z"
        assert parsed["file_path_at_commit"] == "/file.txt"

    def test_git_finding_inherits_from_finding(self) -> None:
        """Test that GitFinding is a subclass of Finding."""
        finding = GitFinding(
            file_path="/file.txt",
            detector_name="test",
            commit_hash="abc",
            author="Test",
            date="2024-01-01",
            file_path_at_commit="/file.txt",
        )
        assert isinstance(finding, Finding)


class TestWebFindingModel:
    """Tests for the WebFinding model."""

    def test_web_finding_creation_minimal(self) -> None:
        """Test creating a WebFinding with only required fields."""
        finding = WebFinding(
            file_path="https://example.com/page.html",
            detector_name="api_key_detector",
            url="https://example.com/page.html",
            element_type=ElementType.TEXT,
        )
        assert finding.file_path == "https://example.com/page.html"
        assert finding.detector_name == "api_key_detector"
        assert finding.url == "https://example.com/page.html"
        assert finding.element_type == ElementType.TEXT
        # Inherited defaults
        assert finding.matches == []
        assert finding.severity == Severity.MEDIUM

    def test_web_finding_creation_full(self) -> None:
        """Test creating a WebFinding with all fields specified."""
        finding = WebFinding(
            file_path="https://example.com/app.js",
            detector_name="stripe_key_detector",
            matches=["sk_live_abc123"],
            severity=Severity.CRITICAL,
            metadata={"script_index": 0},
            url="https://example.com/app.js",
            element_type=ElementType.SCRIPT,
        )
        assert finding.url == "https://example.com/app.js"
        assert finding.element_type == ElementType.SCRIPT
        assert finding.matches == ["sk_live_abc123"]
        assert finding.severity == Severity.CRITICAL

    def test_web_finding_with_inline_script(self) -> None:
        """Test WebFinding with inline script element type."""
        finding = WebFinding(
            file_path="https://example.com/index.html#inline-script-0",
            detector_name="test_detector",
            url="https://example.com/index.html",
            element_type=ElementType.INLINE_SCRIPT,
        )
        assert finding.element_type == ElementType.INLINE_SCRIPT

    def test_web_finding_with_attribute(self) -> None:
        """Test WebFinding with attribute element type."""
        finding = WebFinding(
            file_path="https://example.com/page.html",
            detector_name="data_attribute_detector",
            url="https://example.com/page.html",
            element_type=ElementType.ATTRIBUTE,
        )
        assert finding.element_type == ElementType.ATTRIBUTE

    def test_web_finding_serialization_json(self) -> None:
        """Test that WebFinding can be serialized to JSON."""
        finding = WebFinding(
            file_path="https://example.com/script.js",
            detector_name="test_detector",
            url="https://example.com/script.js",
            element_type=ElementType.SCRIPT,
            matches=["api_key_12345"],
        )
        json_str = finding.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["url"] == "https://example.com/script.js"
        assert parsed["element_type"] == "script"
        assert parsed["matches"] == ["api_key_12345"]

    def test_web_finding_inherits_from_finding(self) -> None:
        """Test that WebFinding is a subclass of Finding."""
        finding = WebFinding(
            file_path="https://example.com",
            detector_name="test",
            url="https://example.com",
            element_type=ElementType.TEXT,
        )
        assert isinstance(finding, Finding)


class TestSecretOccurrenceModel:
    """Tests for the SecretOccurrence model."""

    def test_secret_occurrence_creation_minimal(self) -> None:
        """Test creating a SecretOccurrence with only required fields."""
        occurrence = SecretOccurrence(
            commit_hash="abc123def456",
            author="Test User",
            date="2024-01-15T10:30:00Z",
            file_path="/path/to/secret.py",
            line_type="+",
        )
        assert occurrence.commit_hash == "abc123def456"
        assert occurrence.author == "Test User"
        assert occurrence.date == "2024-01-15T10:30:00Z"
        assert occurrence.file_path == "/path/to/secret.py"
        assert occurrence.line_type == "+"
        assert occurrence.line_number is None

    def test_secret_occurrence_creation_full(self) -> None:
        """Test creating a SecretOccurrence with all fields specified."""
        occurrence = SecretOccurrence(
            commit_hash="abc123def456789",
            author="Developer",
            date="2024-06-20T14:00:00+00:00",
            file_path="/config/secrets.py",
            line_type="-",
            line_number=42,
        )
        assert occurrence.line_type == "-"
        assert occurrence.line_number == 42

    def test_secret_occurrence_line_type_addition(self) -> None:
        """Test SecretOccurrence with addition line type."""
        occurrence = SecretOccurrence(
            commit_hash="abc",
            author="Test",
            date="2024-01-01",
            file_path="/file.py",
            line_type="+",
        )
        assert occurrence.line_type == "+"

    def test_secret_occurrence_line_type_deletion(self) -> None:
        """Test SecretOccurrence with deletion line type."""
        occurrence = SecretOccurrence(
            commit_hash="abc",
            author="Test",
            date="2024-01-01",
            file_path="/file.py",
            line_type="-",
        )
        assert occurrence.line_type == "-"

    def test_secret_occurrence_invalid_line_type(self) -> None:
        """Test that invalid line_type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SecretOccurrence(
                commit_hash="abc",
                author="Test",
                date="2024-01-01",
                file_path="/file.py",
                line_type="x",  # Invalid
            )
        assert "line_type must be '+' or '-'" in str(exc_info.value)

    def test_secret_occurrence_serialization_json(self) -> None:
        """Test that SecretOccurrence can be serialized to JSON."""
        occurrence = SecretOccurrence(
            commit_hash="deadbeef",
            author="Author Name",
            date="2024-01-15T10:00:00Z",
            file_path="/secrets.py",
            line_type="+",
            line_number=10,
        )
        json_str = occurrence.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["commit_hash"] == "deadbeef"
        assert parsed["author"] == "Author Name"
        assert parsed["line_type"] == "+"
        assert parsed["line_number"] == 10


class TestSecretTimelineModel:
    """Tests for the SecretTimeline model."""

    def test_secret_timeline_creation_minimal(self) -> None:
        """Test creating a SecretTimeline with only required fields."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="AKI...XYZ",
            detector_name="aws_key_detector",
        )
        assert timeline.secret_hash == "abc123"
        assert timeline.secret_preview == "AKI...XYZ"
        assert timeline.detector_name == "aws_key_detector"
        assert timeline.severity == Severity.MEDIUM
        assert timeline.first_seen is None
        assert timeline.last_seen is None
        assert timeline.is_removed is False
        assert timeline.occurrences == []
        assert timeline.exposure_duration is None
        assert timeline.affected_files == []

    def test_secret_timeline_creation_full(self) -> None:
        """Test creating a SecretTimeline with all fields specified."""
        first_occurrence = SecretOccurrence(
            commit_hash="first123",
            author="Dev1",
            date="2024-01-01T10:00:00Z",
            file_path="/config.py",
            line_type="+",
            line_number=5,
        )
        last_occurrence = SecretOccurrence(
            commit_hash="last456",
            author="Dev2",
            date="2024-06-01T10:00:00Z",
            file_path="/config.py",
            line_type="-",
            line_number=5,
        )
        timeline = SecretTimeline(
            secret_hash="abc123def456",
            secret_preview="sk_...789",
            detector_name="stripe_key_detector",
            severity=Severity.CRITICAL,
            first_seen=first_occurrence,
            last_seen=last_occurrence,
            is_removed=True,
            occurrences=[first_occurrence, last_occurrence],
            exposure_duration=13132800.0,  # ~152 days
            affected_files=["/config.py"],
        )
        assert timeline.severity == Severity.CRITICAL
        assert timeline.is_removed is True
        assert len(timeline.occurrences) == 2
        assert timeline.exposure_duration == 13132800.0
        assert "/config.py" in timeline.affected_files

    def test_secret_timeline_add_occurrence_first(self) -> None:
        """Test adding first occurrence to timeline."""
        timeline = SecretTimeline(
            secret_hash="abc",
            secret_preview="***",
            detector_name="test",
        )
        occurrence = SecretOccurrence(
            commit_hash="commit1",
            author="Dev",
            date="2024-01-15T10:00:00Z",
            file_path="/file.py",
            line_type="+",
        )
        timeline.add_occurrence(occurrence)

        assert len(timeline.occurrences) == 1
        assert timeline.first_seen == occurrence
        assert timeline.last_seen == occurrence
        assert "/file.py" in timeline.affected_files

    def test_secret_timeline_add_occurrence_tracks_removal(self) -> None:
        """Test that adding a removal occurrence marks timeline as removed."""
        timeline = SecretTimeline(
            secret_hash="abc",
            secret_preview="***",
            detector_name="test",
        )
        # Add initial occurrence
        add_occurrence = SecretOccurrence(
            commit_hash="commit1",
            author="Dev",
            date="2024-01-01T10:00:00Z",
            file_path="/file.py",
            line_type="+",
        )
        timeline.add_occurrence(add_occurrence)
        assert timeline.is_removed is False

        # Add removal occurrence
        remove_occurrence = SecretOccurrence(
            commit_hash="commit2",
            author="Dev",
            date="2024-01-15T10:00:00Z",
            file_path="/file.py",
            line_type="-",
        )
        timeline.add_occurrence(remove_occurrence)
        assert timeline.is_removed is True
        assert timeline.first_seen == add_occurrence
        assert timeline.last_seen == remove_occurrence

    def test_secret_timeline_add_occurrence_calculates_exposure(self) -> None:
        """Test that exposure duration is calculated when secret is removed."""
        timeline = SecretTimeline(
            secret_hash="abc",
            secret_preview="***",
            detector_name="test",
        )
        # Add initial occurrence
        add_occurrence = SecretOccurrence(
            commit_hash="commit1",
            author="Dev",
            date="2024-01-01T10:00:00+00:00",
            file_path="/file.py",
            line_type="+",
        )
        timeline.add_occurrence(add_occurrence)

        # Add removal exactly 1 day later
        remove_occurrence = SecretOccurrence(
            commit_hash="commit2",
            author="Dev",
            date="2024-01-02T10:00:00+00:00",
            file_path="/file.py",
            line_type="-",
        )
        timeline.add_occurrence(remove_occurrence)

        assert timeline.exposure_duration is not None
        assert timeline.exposure_duration == 86400.0  # 24 hours in seconds

    def test_secret_timeline_multiple_files(self) -> None:
        """Test that timeline tracks multiple affected files."""
        timeline = SecretTimeline(
            secret_hash="abc",
            secret_preview="***",
            detector_name="test",
        )
        # Add occurrence in first file
        timeline.add_occurrence(
            SecretOccurrence(
                commit_hash="commit1",
                author="Dev",
                date="2024-01-01T10:00:00Z",
                file_path="/file1.py",
                line_type="+",
            )
        )
        # Add occurrence in second file
        timeline.add_occurrence(
            SecretOccurrence(
                commit_hash="commit2",
                author="Dev",
                date="2024-01-02T10:00:00Z",
                file_path="/file2.py",
                line_type="+",
            )
        )

        assert len(timeline.affected_files) == 2
        assert "/file1.py" in timeline.affected_files
        assert "/file2.py" in timeline.affected_files

    def test_secret_timeline_serialization_json(self) -> None:
        """Test that SecretTimeline can be serialized to JSON."""
        timeline = SecretTimeline(
            secret_hash="abc123",
            secret_preview="sk_...789",
            detector_name="stripe_key_detector",
            severity=Severity.HIGH,
        )
        json_str = timeline.model_dump_json()
        parsed = json.loads(json_str)

        assert parsed["secret_hash"] == "abc123"
        assert parsed["secret_preview"] == "sk_...789"
        assert parsed["detector_name"] == "stripe_key_detector"
        assert parsed["severity"] == "high"
        assert parsed["is_removed"] is False
        assert parsed["occurrences"] == []

    def test_secret_timeline_serialization_with_occurrences(self) -> None:
        """Test that SecretTimeline with occurrences serializes correctly."""
        occurrence = SecretOccurrence(
            commit_hash="abc123",
            author="Test",
            date="2024-01-01T10:00:00Z",
            file_path="/test.py",
            line_type="+",
        )
        timeline = SecretTimeline(
            secret_hash="hash",
            secret_preview="***",
            detector_name="test",
            occurrences=[occurrence],
            affected_files=["/test.py"],
        )
        json_str = timeline.model_dump_json()
        parsed = json.loads(json_str)

        assert len(parsed["occurrences"]) == 1
        assert parsed["occurrences"][0]["commit_hash"] == "abc123"
        assert parsed["affected_files"] == ["/test.py"]

    def test_secret_timeline_no_duplicate_files(self) -> None:
        """Test that affected_files doesn't contain duplicates when using add_occurrence."""
        timeline = SecretTimeline(
            secret_hash="abc",
            secret_preview="***",
            detector_name="test",
        )
        # Add two occurrences in the same file
        timeline.add_occurrence(
            SecretOccurrence(
                commit_hash="commit1",
                author="Dev",
                date="2024-01-01T10:00:00Z",
                file_path="/file.py",
                line_type="+",
            )
        )
        timeline.add_occurrence(
            SecretOccurrence(
                commit_hash="commit2",
                author="Dev",
                date="2024-01-02T10:00:00Z",
                file_path="/file.py",
                line_type="-",
            )
        )

        assert len(timeline.affected_files) == 1
        assert timeline.affected_files == ["/file.py"]
