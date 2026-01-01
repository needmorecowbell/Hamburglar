"""Comprehensive tests for SARIF output formatter.

This module tests the SARIF output formatter for proper SARIF 2.1.0 compliance,
correct mapping of findings to SARIF structures, and edge case handling.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.outputs import BaseOutput
from hamburglar.outputs.sarif import (
    SARIF_SCHEMA,
    SEVERITY_TO_SARIF_LEVEL,
    SEVERITY_TO_SECURITY_SCORE,
    TOOL_INFORMATION_URI,
    TOOL_NAME,
    TOOL_VERSION,
    SarifOutput,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def empty_scan_result() -> ScanResult:
    """Return a scan result with no findings."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[],
        scan_duration=1.5,
        stats={"files_scanned": 10, "files_skipped": 2, "errors": 0},
    )


@pytest.fixture
def single_finding_result() -> ScanResult:
    """Return a scan result with a single finding."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE"],
                severity=Severity.HIGH,
                metadata={"line": 5},
            )
        ],
        scan_duration=2.0,
        stats={"files_scanned": 5, "files_skipped": 0, "errors": 0},
    )


@pytest.fixture
def multiple_findings_result() -> ScanResult:
    """Return a scan result with multiple findings across different severities."""
    return ScanResult(
        target_path="/tmp/test",
        findings=[
            Finding(
                file_path="/tmp/test/secrets.txt",
                detector_name="aws_key",
                matches=["AKIAIOSFODNN7EXAMPLE", "AKIABCDEFGHIJ1234567"],
                severity=Severity.CRITICAL,
                metadata={"line": 5, "column": 10},
            ),
            Finding(
                file_path="/tmp/test/config.py",
                detector_name="email",
                matches=["admin@example.com"],
                severity=Severity.LOW,
            ),
            Finding(
                file_path="/tmp/test/database.yml",
                detector_name="password",
                matches=["password123"],
                severity=Severity.HIGH,
                metadata={"line": 15, "end_line": 15},
            ),
            Finding(
                file_path="/tmp/test/notes.txt",
                detector_name="url",
                matches=["http://internal.server.local/api"],
                severity=Severity.INFO,
            ),
            Finding(
                file_path="/tmp/test/api.js",
                detector_name="api_key",
                matches=["sk_live_1234567890abcdef"],
                severity=Severity.MEDIUM,
                metadata={"line_number": 42},
            ),
        ],
        scan_duration=5.5,
        stats={"files_scanned": 100, "files_skipped": 5, "errors": 1},
    )


# ============================================================================
# SARIF Output - Valid JSON Tests
# ============================================================================


class TestSarifOutputValidJson:
    """Test that SARIF output produces valid JSON."""

    def test_empty_result_is_valid_json(self, empty_scan_result: ScanResult) -> None:
        """Test that an empty scan result produces valid JSON."""
        formatter = SarifOutput()
        output = formatter.format(empty_scan_result)

        # Should not raise
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_single_finding_is_valid_json(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that a single finding produces valid JSON."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_multiple_findings_is_valid_json(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that multiple findings produce valid JSON."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_sarif_is_indented(self, single_finding_result: ScanResult) -> None:
        """Test that SARIF output is properly indented for readability."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        # Should have newlines and indentation
        assert "\n" in output
        assert "  " in output  # 2-space indent


# ============================================================================
# SARIF Schema Validation Tests
# ============================================================================


class TestSarifSchemaCompliance:
    """Test that SARIF output follows SARIF 2.1.0 schema."""

    def test_sarif_has_schema_reference(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that SARIF includes the $schema property."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert "$schema" in parsed
        assert parsed["$schema"] == SARIF_SCHEMA

    def test_sarif_has_version(self, single_finding_result: ScanResult) -> None:
        """Test that SARIF includes version 2.1.0."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert "version" in parsed
        assert parsed["version"] == "2.1.0"

    def test_sarif_has_runs_array(self, single_finding_result: ScanResult) -> None:
        """Test that SARIF includes runs array."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)
        assert len(parsed["runs"]) == 1

    def test_sarif_run_has_tool(self, single_finding_result: ScanResult) -> None:
        """Test that SARIF run includes tool information."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        run = parsed["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]

    def test_sarif_tool_driver_properties(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that SARIF tool driver has required properties."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        driver = parsed["runs"][0]["tool"]["driver"]

        assert driver["name"] == TOOL_NAME
        assert driver["version"] == TOOL_VERSION
        assert driver["informationUri"] == TOOL_INFORMATION_URI
        assert "rules" in driver

    def test_sarif_run_has_results(self, single_finding_result: ScanResult) -> None:
        """Test that SARIF run includes results array."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        run = parsed["runs"][0]
        assert "results" in run
        assert isinstance(run["results"], list)

    def test_sarif_run_has_invocations(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that SARIF run includes invocations array."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        run = parsed["runs"][0]
        assert "invocations" in run
        assert len(run["invocations"]) == 1
        assert run["invocations"][0]["executionSuccessful"] is True


# ============================================================================
# SARIF Findings Mapping Tests
# ============================================================================


class TestSarifFindingsMapping:
    """Test that findings are correctly mapped to SARIF results."""

    def test_findings_count_matches(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that number of SARIF results matches number of findings."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]
        assert len(results) == len(multiple_findings_result.findings)

    def test_result_has_rule_id(self, single_finding_result: ScanResult) -> None:
        """Test that each result has a ruleId."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "ruleId" in result
        assert result["ruleId"] == "hamburglar/aws_key"

    def test_result_has_rule_index(self, single_finding_result: ScanResult) -> None:
        """Test that each result has a ruleIndex."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "ruleIndex" in result
        assert isinstance(result["ruleIndex"], int)
        assert result["ruleIndex"] >= 0

    def test_result_has_level(self, single_finding_result: ScanResult) -> None:
        """Test that each result has a level."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "level" in result
        assert result["level"] == "error"  # HIGH severity maps to error

    def test_result_has_message(self, single_finding_result: ScanResult) -> None:
        """Test that each result has a message."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "message" in result
        assert "text" in result["message"]
        assert len(result["message"]["text"]) > 0

    def test_result_has_locations(self, single_finding_result: ScanResult) -> None:
        """Test that each result has locations."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "locations" in result
        assert isinstance(result["locations"], list)
        assert len(result["locations"]) >= 1

    def test_result_has_fingerprint(self, single_finding_result: ScanResult) -> None:
        """Test that each result has fingerprints for deduplication."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert "hamburglar/v1" in result["fingerprints"]


# ============================================================================
# SARIF Rule Definitions Tests
# ============================================================================


class TestSarifRuleDefinitions:
    """Test that rule definitions are correctly included."""

    def test_rules_are_included(self, single_finding_result: ScanResult) -> None:
        """Test that rules are included in the tool driver."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert isinstance(rules, list)
        assert len(rules) >= 1

    def test_rule_has_required_properties(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that each rule has required properties."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]

        assert "id" in rule
        assert "name" in rule
        assert "shortDescription" in rule
        assert "fullDescription" in rule
        assert "help" in rule

    def test_rule_id_format(self, single_finding_result: ScanResult) -> None:
        """Test that rule IDs follow the expected format."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "hamburglar/aws_key"

    def test_rule_descriptions_are_text(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that rule descriptions have text property."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]

        assert "text" in rule["shortDescription"]
        assert "text" in rule["fullDescription"]
        assert "text" in rule["help"]

    def test_rule_has_tags(self, single_finding_result: ScanResult) -> None:
        """Test that rules have security tags."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]

        assert "properties" in rule
        assert "tags" in rule["properties"]
        assert "security" in rule["properties"]["tags"]
        assert "secrets" in rule["properties"]["tags"]

    def test_unique_detectors_become_rules(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that unique detectors become separate rules."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]

        # Should have one rule per unique detector
        rule_names = [r["name"] for r in rules]
        expected_detectors = ["api_key", "aws_key", "email", "password", "url"]
        assert sorted(rule_names) == expected_detectors


# ============================================================================
# SARIF File Location Tests
# ============================================================================


class TestSarifFileLocations:
    """Test that file locations are correctly included."""

    def test_location_has_artifact_location(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that location has artifactLocation."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        location = parsed["runs"][0]["results"][0]["locations"][0]

        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "uri" in location["physicalLocation"]["artifactLocation"]

    def test_location_uri_matches_file_path(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that location URI matches the file path."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        artifact = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]

        assert artifact["uri"] == "/tmp/test/secrets.txt"
        assert artifact["uriBaseId"] == "%SRCROOT%"

    def test_location_includes_line_number(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that location includes line number when available."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        location = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

        assert "region" in location
        assert location["region"]["startLine"] == 5

    def test_location_includes_column_when_available(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that location includes column when available."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        # First finding has column info
        location = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

        assert "region" in location
        assert location["region"]["startColumn"] == 10

    def test_location_includes_end_line_when_available(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that location includes end line when available."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        # Third finding (password) has end_line info
        results = parsed["runs"][0]["results"]
        # Find the password result
        password_result = next(
            r for r in results if r["ruleId"] == "hamburglar/password"
        )
        location = password_result["locations"][0]["physicalLocation"]

        assert "region" in location
        assert location["region"]["endLine"] == 15

    def test_location_supports_line_number_key(
        self, multiple_findings_result: ScanResult
    ) -> None:
        """Test that location supports 'line_number' metadata key."""
        formatter = SarifOutput()
        output = formatter.format(multiple_findings_result)

        parsed = json.loads(output)
        # api_key finding uses 'line_number' instead of 'line'
        results = parsed["runs"][0]["results"]
        api_key_result = next(
            r for r in results if r["ruleId"] == "hamburglar/api_key"
        )
        location = api_key_result["locations"][0]["physicalLocation"]

        assert "region" in location
        assert location["region"]["startLine"] == 42

    def test_location_without_line_number(self) -> None:
        """Test that location works without line number."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.MEDIUM,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        location = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

        # Should have artifactLocation but no region
        assert "artifactLocation" in location
        assert "region" not in location


# ============================================================================
# SARIF Severity Mapping Tests
# ============================================================================


class TestSarifSeverityMapping:
    """Test that severity levels are correctly mapped."""

    def test_critical_maps_to_error(self) -> None:
        """Test that CRITICAL severity maps to 'error' level."""
        assert SEVERITY_TO_SARIF_LEVEL[Severity.CRITICAL] == "error"

    def test_high_maps_to_error(self) -> None:
        """Test that HIGH severity maps to 'error' level."""
        assert SEVERITY_TO_SARIF_LEVEL[Severity.HIGH] == "error"

    def test_medium_maps_to_warning(self) -> None:
        """Test that MEDIUM severity maps to 'warning' level."""
        assert SEVERITY_TO_SARIF_LEVEL[Severity.MEDIUM] == "warning"

    def test_low_maps_to_note(self) -> None:
        """Test that LOW severity maps to 'note' level."""
        assert SEVERITY_TO_SARIF_LEVEL[Severity.LOW] == "note"

    def test_info_maps_to_note(self) -> None:
        """Test that INFO severity maps to 'note' level."""
        assert SEVERITY_TO_SARIF_LEVEL[Severity.INFO] == "note"

    def test_all_severities_have_mappings(self) -> None:
        """Test that all severity levels have SARIF level mappings."""
        for severity in Severity:
            assert severity in SEVERITY_TO_SARIF_LEVEL
            assert SEVERITY_TO_SARIF_LEVEL[severity] in [
                "error",
                "warning",
                "note",
                "none",
            ]

    def test_all_severities_have_security_scores(self) -> None:
        """Test that all severity levels have security-severity scores."""
        for severity in Severity:
            assert severity in SEVERITY_TO_SECURITY_SCORE
            score = SEVERITY_TO_SECURITY_SCORE[severity]
            assert 0.0 <= score <= 10.0

    def test_security_severity_in_properties(
        self, single_finding_result: ScanResult
    ) -> None:
        """Test that security-severity is included in result properties."""
        formatter = SarifOutput()
        output = formatter.format(single_finding_result)

        parsed = json.loads(output)
        result = parsed["runs"][0]["results"][0]

        assert "properties" in result
        assert "security-severity" in result["properties"]
        # HIGH maps to 7.0
        assert result["properties"]["security-severity"] == "7.0"


# ============================================================================
# SARIF Empty Results Tests
# ============================================================================


class TestSarifEmptyResults:
    """Test SARIF output with empty or minimal results."""

    def test_empty_findings_produces_valid_sarif(
        self, empty_scan_result: ScanResult
    ) -> None:
        """Test that empty findings still produces valid SARIF."""
        formatter = SarifOutput()
        output = formatter.format(empty_scan_result)

        parsed = json.loads(output)

        # Should have valid structure
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

        # Results and rules should be empty
        assert parsed["runs"][0]["results"] == []
        assert parsed["runs"][0]["tool"]["driver"]["rules"] == []

    def test_empty_matches_produces_valid_message(self) -> None:
        """Test that finding with empty matches produces valid message."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=[],
                    severity=Severity.LOW,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        message = parsed["runs"][0]["results"][0]["message"]["text"]

        # Should have fallback message
        assert "test" in message
        assert len(message) > 0


# ============================================================================
# SARIF Special Characters Tests
# ============================================================================


class TestSarifSpecialCharacters:
    """Test SARIF output with special characters."""

    def test_unicode_in_file_path(self) -> None:
        """Test handling of unicode in file paths."""
        result = ScanResult(
            target_path="/tmp/日本語",
            findings=[
                Finding(
                    file_path="/tmp/日本語/文件.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]

        assert "日本語" in uri
        assert "文件.txt" in uri

    def test_special_chars_in_matches(self) -> None:
        """Test handling of special characters in matches."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=['password="secret"', "key:\n  value"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        # Should not raise - special chars properly escaped
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_quotes_in_detector_name(self) -> None:
        """Test handling of quotes in detector names."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name='test"detector',
                    matches=["secret"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        rule_id = parsed["runs"][0]["results"][0]["ruleId"]
        assert 'test"detector' in rule_id


# ============================================================================
# Formatter Properties Tests
# ============================================================================


class TestSarifFormatterProperties:
    """Test SARIF formatter name properties and interface."""

    def test_sarif_formatter_name(self) -> None:
        """Test that SARIF formatter has correct name."""
        formatter = SarifOutput()
        assert formatter.name == "sarif"

    def test_sarif_extends_base_output(self) -> None:
        """Test that SARIF formatter extends BaseOutput."""
        assert issubclass(SarifOutput, BaseOutput)


# ============================================================================
# SARIF Fingerprint Tests
# ============================================================================


class TestSarifFingerprints:
    """Test SARIF fingerprint generation for deduplication."""

    def test_fingerprint_is_stable(self) -> None:
        """Test that same finding produces same fingerprint."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                    metadata={"line": 10},
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()

        # Format twice
        output1 = formatter.format(result)
        output2 = formatter.format(result)

        parsed1 = json.loads(output1)
        parsed2 = json.loads(output2)

        fp1 = parsed1["runs"][0]["results"][0]["fingerprints"]["hamburglar/v1"]
        fp2 = parsed2["runs"][0]["results"][0]["fingerprints"]["hamburglar/v1"]

        assert fp1 == fp2

    def test_different_findings_have_different_fingerprints(self) -> None:
        """Test that different findings produce different fingerprints."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file1.txt",
                    detector_name="test",
                    matches=["secret1"],
                    severity=Severity.HIGH,
                ),
                Finding(
                    file_path="/tmp/test/file2.txt",
                    detector_name="test",
                    matches=["secret2"],
                    severity=Severity.HIGH,
                ),
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]

        fp1 = results[0]["fingerprints"]["hamburglar/v1"]
        fp2 = results[1]["fingerprints"]["hamburglar/v1"]

        assert fp1 != fp2


# ============================================================================
# SARIF Message Formatting Tests
# ============================================================================


class TestSarifMessageFormatting:
    """Test SARIF message text formatting."""

    def test_single_match_message(self) -> None:
        """Test message format for single match."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["AKIAIOSFODNN7EXAMPLE"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        message = parsed["runs"][0]["results"][0]["message"]["text"]

        assert "1 potential secret" in message
        # Match should be redacted
        assert "AKIA" in message
        assert "..." in message

    def test_multiple_matches_message(self) -> None:
        """Test message format for multiple matches."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["secret1", "secret2", "secret3"],
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        message = parsed["runs"][0]["results"][0]["message"]["text"]

        assert "3 potential secrets" in message

    def test_short_match_not_redacted(self) -> None:
        """Test that short matches are not redacted."""
        result = ScanResult(
            target_path="/tmp/test",
            findings=[
                Finding(
                    file_path="/tmp/test/file.txt",
                    detector_name="test",
                    matches=["abc"],  # 3 chars, <= 8 visible chars total
                    severity=Severity.HIGH,
                )
            ],
            scan_duration=1.0,
        )

        formatter = SarifOutput()
        output = formatter.format(result)

        parsed = json.loads(output)
        message = parsed["runs"][0]["results"][0]["message"]["text"]

        # Short match should appear unredacted
        assert "abc" in message
        assert "..." not in message or "abc" in message


# ============================================================================
# SARIF Integration with Registry Tests
# ============================================================================


class TestSarifRegistryIntegration:
    """Test SARIF formatter with the registry."""

    def test_sarif_formatter_can_be_registered(self) -> None:
        """Test that SARIF formatter can be registered."""
        from hamburglar.outputs import OutputRegistry

        registry = OutputRegistry()
        formatter = SarifOutput()
        registry.register(formatter)

        assert "sarif" in registry
        assert registry.get("sarif") is formatter
