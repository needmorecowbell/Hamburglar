"""Comprehensive tests for streaming output functionality.

This module tests the StreamingOutput class and related utilities for:
- NDJSON output format is correct
- Findings stream as discovered
- Stream can be interrupted
- Backpressure is handled correctly
"""

from __future__ import annotations

import asyncio
import io
import json
import sys
from pathlib import Path
from typing import AsyncIterator

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

from hamburglar.core.async_scanner import AsyncScanner  # noqa: E402
from hamburglar.core.models import Finding, ScanConfig, ScanResult, Severity  # noqa: E402
from hamburglar.detectors.regex_detector import RegexDetector  # noqa: E402
from hamburglar.outputs import BaseOutput  # noqa: E402
from hamburglar.outputs.streaming import (  # noqa: E402
    NDJSONStreamWriter,
    StreamingOutput,
    stream_to_ndjson,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample finding for testing."""
    return Finding(
        file_path="/tmp/test/secrets.txt",
        detector_name="aws_key",
        matches=["AKIAIOSFODNN7EXAMPLE"],
        severity=Severity.HIGH,
        metadata={"line": 5},
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Return a list of sample findings for testing."""
    return [
        Finding(
            file_path="/tmp/test/secrets.txt",
            detector_name="aws_key",
            matches=["AKIAIOSFODNN7EXAMPLE"],
            severity=Severity.CRITICAL,
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
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_findings: list[Finding]) -> ScanResult:
    """Return a sample scan result for testing."""
    return ScanResult(
        target_path="/tmp/test",
        findings=sample_findings,
        scan_duration=2.5,
        stats={"files_scanned": 10},
    )


async def async_findings_generator(
    findings: list[Finding],
    delay: float = 0,
) -> AsyncIterator[Finding]:
    """Helper to create an async iterator from a list of findings."""
    for finding in findings:
        if delay > 0:
            await asyncio.sleep(delay)
        yield finding


# ============================================================================
# StreamingOutput Basic Tests
# ============================================================================


class TestStreamingOutputBasic:
    """Test basic StreamingOutput functionality."""

    def test_name_property(self) -> None:
        """Test that the formatter has the correct name."""
        formatter = StreamingOutput()
        assert formatter.name == "ndjson"

    def test_extends_base_output(self) -> None:
        """Test that StreamingOutput extends BaseOutput."""
        assert issubclass(StreamingOutput, BaseOutput)

    def test_format_empty_result(self) -> None:
        """Test formatting an empty scan result."""
        formatter = StreamingOutput()
        result = ScanResult(
            target_path="/tmp/test",
            findings=[],
            scan_duration=1.0,
        )
        output = formatter.format(result)
        assert output == ""

    def test_format_single_finding(self, sample_finding: Finding) -> None:
        """Test formatting a single finding."""
        formatter = StreamingOutput()
        result = ScanResult(
            target_path="/tmp/test",
            findings=[sample_finding],
            scan_duration=1.0,
        )
        output = formatter.format(result)

        # Should be valid JSON
        parsed = json.loads(output)
        assert parsed["file_path"] == "/tmp/test/secrets.txt"
        assert parsed["detector_name"] == "aws_key"

    def test_format_multiple_findings(self, sample_findings: list[Finding]) -> None:
        """Test formatting multiple findings."""
        formatter = StreamingOutput()
        result = ScanResult(
            target_path="/tmp/test",
            findings=sample_findings,
            scan_duration=1.0,
        )
        output = formatter.format(result)

        # Should have 3 lines
        lines = output.split("\n")
        assert len(lines) == 3

        # Each line should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "file_path" in parsed
            assert "detector_name" in parsed


# ============================================================================
# NDJSON Format Tests
# ============================================================================


class TestNDJSONFormat:
    """Test that NDJSON format is correct."""

    def test_each_finding_is_single_line(self, sample_findings: list[Finding]) -> None:
        """Test that each finding is on a single line."""
        formatter = StreamingOutput()
        result = ScanResult(
            target_path="/tmp/test",
            findings=sample_findings,
            scan_duration=1.0,
        )
        output = formatter.format(result)

        lines = output.split("\n")
        for line in lines:
            assert "\n" not in line.strip()

    def test_no_trailing_comma(self, sample_findings: list[Finding]) -> None:
        """Test that there's no trailing comma (unlike regular JSON array)."""
        formatter = StreamingOutput()
        result = ScanResult(
            target_path="/tmp/test",
            findings=sample_findings,
            scan_duration=1.0,
        )
        output = formatter.format(result)

        lines = output.split("\n")
        for line in lines:
            assert not line.rstrip().endswith(",")

    def test_each_line_is_valid_json(self, sample_scan_result: ScanResult) -> None:
        """Test that each line can be parsed as valid JSON independently."""
        formatter = StreamingOutput()
        output = formatter.format(sample_scan_result)

        lines = output.split("\n")
        for line in lines:
            if line.strip():
                # Should not raise
                parsed = json.loads(line)
                assert isinstance(parsed, dict)

    def test_format_finding_returns_single_line(self, sample_finding: Finding) -> None:
        """Test that format_finding returns a single-line JSON string."""
        formatter = StreamingOutput()
        output = formatter.format_finding(sample_finding)

        assert "\n" not in output
        assert json.loads(output)  # Valid JSON

    def test_special_characters_escaped(self) -> None:
        """Test that special characters in matches are properly escaped."""
        finding = Finding(
            file_path="/tmp/test/file.txt",
            detector_name="test",
            matches=['quote: "value"', "newline:\nhere", "tab:\there"],
            severity=Severity.MEDIUM,
        )

        formatter = StreamingOutput()
        output = formatter.format_finding(finding)

        # Should be valid JSON with escaped characters
        parsed = json.loads(output)
        assert 'quote: "value"' in parsed["matches"]
        assert "newline:\nhere" in parsed["matches"]

    def test_unicode_characters_handled(self) -> None:
        """Test that unicode characters are handled correctly."""
        finding = Finding(
            file_path="/tmp/日本語/文件.txt",
            detector_name="пароль_детектор",
            matches=["密码: secretpassword", "🔑 api_key=abc123"],
            severity=Severity.HIGH,
        )

        formatter = StreamingOutput()
        output = formatter.format_finding(finding)

        parsed = json.loads(output)
        assert "日本語" in parsed["file_path"]
        assert "пароль_детектор" == parsed["detector_name"]


# ============================================================================
# Streaming Tests
# ============================================================================


class TestStreamFindings:
    """Test that findings stream as discovered."""

    @pytest.mark.asyncio
    async def test_stream_findings_yields_lines(
        self, sample_findings: list[Finding]
    ) -> None:
        """Test that stream_findings yields formatted lines."""
        formatter = StreamingOutput()
        iterator = async_findings_generator(sample_findings)

        lines: list[str] = []
        async for line in formatter.stream_findings(iterator):
            lines.append(line)

        assert len(lines) == 3

    @pytest.mark.asyncio
    async def test_stream_findings_real_time(self) -> None:
        """Test that findings are yielded as they become available."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name="test",
                matches=[f"match{i}"],
                severity=Severity.MEDIUM,
            )
            for i in range(5)
        ]

        formatter = StreamingOutput()
        received_times: list[float] = []
        start_time = asyncio.get_event_loop().time()

        async for _ in formatter.stream_findings(
            async_findings_generator(findings, delay=0.01)
        ):
            received_times.append(asyncio.get_event_loop().time() - start_time)

        # Findings should arrive at different times
        assert len(received_times) == 5
        # Each should arrive after the previous one
        for i in range(1, len(received_times)):
            assert received_times[i] > received_times[i - 1]

    @pytest.mark.asyncio
    async def test_stream_empty_iterator(self) -> None:
        """Test streaming from an empty iterator."""
        formatter = StreamingOutput()
        iterator = async_findings_generator([])

        lines: list[str] = []
        async for line in formatter.stream_findings(iterator):
            lines.append(line)

        assert len(lines) == 0


# ============================================================================
# Interrupt Tests
# ============================================================================


class TestStreamInterruption:
    """Test that stream can be interrupted."""

    @pytest.mark.asyncio
    async def test_stream_can_be_interrupted_early(self) -> None:
        """Test that the stream can be interrupted before completion."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name="test",
                matches=[f"match{i}"],
                severity=Severity.MEDIUM,
            )
            for i in range(100)
        ]

        formatter = StreamingOutput()
        received = 0

        async for _ in formatter.stream_findings(async_findings_generator(findings)):
            received += 1
            if received >= 10:
                break

        assert received == 10

    @pytest.mark.asyncio
    async def test_collect_findings_with_limit(self) -> None:
        """Test collecting findings with a maximum limit."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name="test",
                matches=[f"match{i}"],
                severity=Severity.MEDIUM,
            )
            for i in range(50)
        ]

        formatter = StreamingOutput()
        collected = await formatter.collect_findings(
            async_findings_generator(findings),
            max_findings=10,
        )

        assert len(collected) == 10

    @pytest.mark.asyncio
    async def test_collect_findings_no_limit(self) -> None:
        """Test collecting all findings without a limit."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name="test",
                matches=[f"match{i}"],
                severity=Severity.MEDIUM,
            )
            for i in range(25)
        ]

        formatter = StreamingOutput()
        collected = await formatter.collect_findings(
            async_findings_generator(findings),
            max_findings=None,
        )

        assert len(collected) == 25


# ============================================================================
# Write Stream Tests
# ============================================================================


class TestWriteStream:
    """Test write_stream functionality."""

    @pytest.mark.asyncio
    async def test_write_stream_to_buffer(
        self, sample_findings: list[Finding]
    ) -> None:
        """Test writing stream to a StringIO buffer."""
        formatter = StreamingOutput()
        buffer = io.StringIO()

        count = await formatter.write_stream(
            async_findings_generator(sample_findings),
            buffer,
            flush=True,
        )

        assert count == 3
        output = buffer.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 3

    @pytest.mark.asyncio
    async def test_write_stream_each_line_ends_with_newline(
        self, sample_findings: list[Finding]
    ) -> None:
        """Test that each written line ends with a newline."""
        formatter = StreamingOutput()
        buffer = io.StringIO()

        await formatter.write_stream(
            async_findings_generator(sample_findings),
            buffer,
        )

        output = buffer.getvalue()
        # Should end with a newline
        assert output.endswith("\n")
        # Each finding on its own line
        lines = output.split("\n")
        # Last element is empty due to trailing newline
        assert lines[-1] == ""
        assert len(lines) == 4  # 3 findings + empty string after trailing newline

    @pytest.mark.asyncio
    async def test_write_stream_returns_count(self) -> None:
        """Test that write_stream returns the correct count."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name="test",
                matches=[f"match{i}"],
                severity=Severity.MEDIUM,
            )
            for i in range(10)
        ]

        formatter = StreamingOutput()
        buffer = io.StringIO()

        count = await formatter.write_stream(
            async_findings_generator(findings),
            buffer,
        )

        assert count == 10


# ============================================================================
# NDJSONStreamWriter Tests
# ============================================================================


class TestNDJSONStreamWriter:
    """Test NDJSONStreamWriter for buffered output with backpressure."""

    @pytest.mark.asyncio
    async def test_writer_context_manager(self, sample_finding: Finding) -> None:
        """Test using the writer as an async context manager."""
        buffer = io.StringIO()

        async with NDJSONStreamWriter(buffer) as writer:
            await writer.write(sample_finding)

        output = buffer.getvalue()
        assert len(output) > 0
        # Should contain valid JSON
        parsed = json.loads(output.strip())
        assert parsed["detector_name"] == "aws_key"

    @pytest.mark.asyncio
    async def test_writer_buffers_findings(
        self, sample_findings: list[Finding]
    ) -> None:
        """Test that the writer buffers findings."""
        buffer = io.StringIO()

        async with NDJSONStreamWriter(buffer, buffer_size=10) as writer:
            for finding in sample_findings:
                await writer.write(finding)
            # Before flush, buffer might not be written
            assert writer.write_count == 3

        # After context exit, should be flushed
        output = buffer.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 3

    @pytest.mark.asyncio
    async def test_writer_flushes_at_buffer_size(self) -> None:
        """Test that the writer flushes when buffer size is reached."""
        buffer = io.StringIO()

        async with NDJSONStreamWriter(buffer, buffer_size=5) as writer:
            for i in range(7):
                await writer.write(
                    Finding(
                        file_path=f"/tmp/file{i}.txt",
                        detector_name="test",
                        matches=[f"match{i}"],
                        severity=Severity.MEDIUM,
                    )
                )

        output = buffer.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 7

    @pytest.mark.asyncio
    async def test_writer_write_count_property(self) -> None:
        """Test that write_count tracks number of findings written."""
        buffer = io.StringIO()

        async with NDJSONStreamWriter(buffer) as writer:
            for i in range(15):
                await writer.write(
                    Finding(
                        file_path=f"/tmp/file{i}.txt",
                        detector_name="test",
                        matches=[f"match{i}"],
                        severity=Severity.MEDIUM,
                    )
                )
            assert writer.write_count == 15

    @pytest.mark.asyncio
    async def test_writer_raises_when_closed(self, sample_finding: Finding) -> None:
        """Test that writing to a closed writer raises RuntimeError."""
        buffer = io.StringIO()

        writer = NDJSONStreamWriter(buffer)
        async with writer:
            await writer.write(sample_finding)

        # Writer is now closed
        with pytest.raises(RuntimeError, match="closed"):
            await writer.write(sample_finding)

    @pytest.mark.asyncio
    async def test_writer_manual_flush(self, sample_finding: Finding) -> None:
        """Test manually calling flush."""
        buffer = io.StringIO()

        async with NDJSONStreamWriter(buffer, buffer_size=100) as writer:
            await writer.write(sample_finding)
            # Before flush, buffer might be empty (depending on internal logic)
            await writer.flush()
            # After flush, should have output
            output = buffer.getvalue()
            assert len(output) > 0


# ============================================================================
# Convenience Function Tests
# ============================================================================


class TestStreamToNdjson:
    """Test the stream_to_ndjson convenience function."""

    @pytest.mark.asyncio
    async def test_collect_without_output(
        self, sample_findings: list[Finding]
    ) -> None:
        """Test collecting NDJSON strings without output file."""
        lines = await stream_to_ndjson(async_findings_generator(sample_findings))

        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "file_path" in parsed

    @pytest.mark.asyncio
    async def test_write_to_output(self, sample_findings: list[Finding]) -> None:
        """Test writing NDJSON to output file."""
        buffer = io.StringIO()

        result = await stream_to_ndjson(
            async_findings_generator(sample_findings),
            output=buffer,
        )

        # Should return empty list when writing to output
        assert result == []

        output = buffer.getvalue()
        lines = output.strip().split("\n")
        assert len(lines) == 3

    @pytest.mark.asyncio
    async def test_empty_iterator(self) -> None:
        """Test with empty iterator."""
        lines = await stream_to_ndjson(async_findings_generator([]))
        assert lines == []


# ============================================================================
# Integration Tests
# ============================================================================


class TestStreamingIntegration:
    """Integration tests with the actual async scanner."""

    @pytest.mark.asyncio
    async def test_stream_from_async_scanner(self, temp_directory: Path) -> None:
        """Test streaming output from AsyncScanner.scan_stream()."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        formatter = StreamingOutput()
        lines: list[str] = []

        async for line in formatter.stream_findings(scanner.scan_stream()):
            lines.append(line)

        # Should have received findings
        assert len(lines) > 0

        # Each should be valid JSON
        for line in lines:
            parsed = json.loads(line)
            assert "file_path" in parsed
            assert "detector_name" in parsed

    @pytest.mark.asyncio
    async def test_write_stream_from_scanner(self, temp_directory: Path) -> None:
        """Test write_stream with AsyncScanner."""
        config = ScanConfig(target_path=temp_directory)
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector])

        formatter = StreamingOutput()
        buffer = io.StringIO()

        count = await formatter.write_stream(scanner.scan_stream(), buffer)

        assert count > 0
        output = buffer.getvalue()
        assert len(output) > 0

    @pytest.mark.asyncio
    async def test_interrupt_scanner_stream(self, tmp_path: Path) -> None:
        """Test interrupting a scanner stream early."""
        # Create many files
        for i in range(20):
            (tmp_path / f"file{i}.txt").write_text(f"AKIAIOSFODNN7EXAMPLE content {i}")

        config = ScanConfig(target_path=tmp_path, blacklist=[])
        detector = RegexDetector()
        scanner = AsyncScanner(config, [detector], concurrency_limit=1)

        formatter = StreamingOutput()
        received = 0

        async for _ in formatter.stream_findings(scanner.scan_stream()):
            received += 1
            if received >= 5:
                break

        # Should have stopped early
        assert received == 5


# ============================================================================
# Edge Cases
# ============================================================================


class TestStreamingEdgeCases:
    """Test edge cases for streaming output."""

    def test_format_finding_empty_matches(self) -> None:
        """Test formatting a finding with empty matches list."""
        finding = Finding(
            file_path="/tmp/file.txt",
            detector_name="test",
            matches=[],
            severity=Severity.LOW,
        )

        formatter = StreamingOutput()
        output = formatter.format_finding(finding)

        parsed = json.loads(output)
        assert parsed["matches"] == []

    def test_format_finding_empty_metadata(self) -> None:
        """Test formatting a finding with empty metadata."""
        finding = Finding(
            file_path="/tmp/file.txt",
            detector_name="test",
            matches=["match"],
            severity=Severity.MEDIUM,
            metadata={},
        )

        formatter = StreamingOutput()
        output = formatter.format_finding(finding)

        parsed = json.loads(output)
        assert parsed["metadata"] == {}

    def test_format_finding_complex_metadata(self) -> None:
        """Test formatting a finding with complex metadata."""
        finding = Finding(
            file_path="/tmp/file.txt",
            detector_name="test",
            matches=["match"],
            severity=Severity.HIGH,
            metadata={
                "line": 42,
                "column": 10,
                "context": {"before": "...", "after": "..."},
                "tags": ["sensitive", "password"],
            },
        )

        formatter = StreamingOutput()
        output = formatter.format_finding(finding)

        parsed = json.loads(output)
        assert parsed["metadata"]["line"] == 42
        assert parsed["metadata"]["tags"] == ["sensitive", "password"]

    @pytest.mark.asyncio
    async def test_very_large_batch(self) -> None:
        """Test streaming a very large batch of findings."""
        findings = [
            Finding(
                file_path=f"/tmp/file{i}.txt",
                detector_name=f"detector_{i % 10}",
                matches=[f"match_{i}"],
                severity=list(Severity)[i % 5],
            )
            for i in range(1000)
        ]

        formatter = StreamingOutput()
        collected = await formatter.collect_findings(
            async_findings_generator(findings)
        )

        assert len(collected) == 1000

    def test_format_all_severity_levels(self) -> None:
        """Test that all severity levels are formatted correctly."""
        formatter = StreamingOutput()

        for severity in Severity:
            finding = Finding(
                file_path="/tmp/file.txt",
                detector_name="test",
                matches=["match"],
                severity=severity,
            )
            output = formatter.format_finding(finding)
            parsed = json.loads(output)
            assert parsed["severity"] == severity.value
