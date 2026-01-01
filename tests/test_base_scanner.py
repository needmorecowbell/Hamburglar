"""Tests for the BaseScanner abstract class."""

import pytest

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.core.progress import ScanProgress
from hamburglar.scanners import BaseScanner


class ConcreteScanner(BaseScanner):
    """Concrete implementation of BaseScanner for testing."""

    def __init__(self, *args, findings: list[Finding] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._findings = findings or []
        self._cancelled = False

    @property
    def scanner_type(self) -> str:
        return "test"

    async def scan(self) -> ScanResult:
        return ScanResult(
            target_path="/test/path",
            findings=self._findings,
            scan_duration=1.0,
            stats={"files_scanned": 1},
        )

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


class TestBaseScanner:
    """Tests for BaseScanner abstract class."""

    def test_scanner_type_property(self):
        """Test that scanner_type property returns correct value."""
        scanner = ConcreteScanner()
        assert scanner.scanner_type == "test"

    def test_init_with_no_args(self):
        """Test initialization with no arguments."""
        scanner = ConcreteScanner()
        assert scanner.detectors == []
        assert scanner.progress_callback is None

    def test_init_with_detectors(self):
        """Test initialization with detectors."""
        # Mock detector
        class MockDetector:
            pass

        detectors = [MockDetector(), MockDetector()]
        scanner = ConcreteScanner(detectors=detectors)
        assert len(scanner.detectors) == 2

    def test_init_with_progress_callback(self):
        """Test initialization with progress callback."""
        callback_called = []

        def callback(progress):
            callback_called.append(progress)

        scanner = ConcreteScanner(progress_callback=callback)
        assert scanner.progress_callback is callback

    async def test_scan_returns_scan_result(self):
        """Test that scan() returns a ScanResult."""
        scanner = ConcreteScanner()
        result = await scanner.scan()

        assert isinstance(result, ScanResult)
        assert result.target_path == "/test/path"
        assert result.scan_duration == 1.0

    async def test_scan_with_findings(self):
        """Test scan with findings."""
        findings = [
            Finding(
                file_path="/test/file.txt",
                detector_name="test_detector",
                matches=["secret123"],
                severity=Severity.HIGH,
            )
        ]
        scanner = ConcreteScanner(findings=findings)
        result = await scanner.scan()

        assert len(result.findings) == 1
        assert result.findings[0].matches == ["secret123"]

    async def test_scan_stream_yields_findings(self):
        """Test that scan_stream yields findings."""
        findings = [
            Finding(
                file_path="/test/file1.txt",
                detector_name="test_detector",
                matches=["secret1"],
                severity=Severity.HIGH,
            ),
            Finding(
                file_path="/test/file2.txt",
                detector_name="test_detector",
                matches=["secret2"],
                severity=Severity.MEDIUM,
            ),
        ]
        scanner = ConcreteScanner(findings=findings)

        collected = []
        async for finding in scanner.scan_stream():
            collected.append(finding)

        assert len(collected) == 2
        assert collected[0].matches == ["secret1"]
        assert collected[1].matches == ["secret2"]

    def test_cancel_default_implementation(self):
        """Test that cancel() works."""
        scanner = ConcreteScanner()
        assert not scanner.is_cancelled
        scanner.cancel()
        assert scanner.is_cancelled

    def test_is_cancelled_default(self):
        """Test that is_cancelled returns False by default for base implementation."""
        # Test the base class default - we need a minimal implementation
        class MinimalScanner(BaseScanner):
            @property
            def scanner_type(self) -> str:
                return "minimal"

            async def scan(self) -> ScanResult:
                return ScanResult(target_path="", findings=[])

        scanner = MinimalScanner()
        # Default base implementation should return False
        assert scanner.is_cancelled is False

    def test_report_progress_with_callback(self):
        """Test that _report_progress calls the callback."""
        progress_reports = []

        def callback(progress):
            progress_reports.append(progress)

        scanner = ConcreteScanner(progress_callback=callback)
        progress = ScanProgress(
            total_files=10,
            scanned_files=5,
            current_file="test.txt",
            bytes_processed=1000,
            findings_count=2,
            elapsed_time=1.5,
        )
        scanner._report_progress(progress)

        assert len(progress_reports) == 1
        assert progress_reports[0].total_files == 10
        assert progress_reports[0].scanned_files == 5

    def test_report_progress_without_callback(self):
        """Test that _report_progress works without callback."""
        scanner = ConcreteScanner()
        progress = ScanProgress(
            total_files=10,
            scanned_files=5,
            current_file="test.txt",
            bytes_processed=1000,
            findings_count=2,
            elapsed_time=1.5,
        )
        # Should not raise
        scanner._report_progress(progress)

    def test_report_progress_handles_callback_exception(self):
        """Test that _report_progress handles callback exceptions gracefully."""

        def failing_callback(progress):
            raise RuntimeError("Callback error")

        scanner = ConcreteScanner(progress_callback=failing_callback)
        progress = ScanProgress(
            total_files=10,
            scanned_files=5,
            current_file="test.txt",
            bytes_processed=1000,
            findings_count=2,
            elapsed_time=1.5,
        )
        # Should not raise despite callback error
        scanner._report_progress(progress)


class TestBaseScannerAbstract:
    """Tests to verify BaseScanner is properly abstract."""

    def test_cannot_instantiate_directly(self):
        """Test that BaseScanner cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BaseScanner()

        assert "abstract" in str(exc_info.value).lower()

    def test_must_implement_scanner_type(self):
        """Test that subclass must implement scanner_type."""

        class IncompleteScanner(BaseScanner):
            async def scan(self) -> ScanResult:
                return ScanResult(target_path="", findings=[])

        with pytest.raises(TypeError) as exc_info:
            IncompleteScanner()

        assert "scanner_type" in str(exc_info.value)

    def test_must_implement_scan(self):
        """Test that subclass must implement scan()."""

        class IncompleteScanner(BaseScanner):
            @property
            def scanner_type(self) -> str:
                return "incomplete"

        with pytest.raises(TypeError) as exc_info:
            IncompleteScanner()

        assert "scan" in str(exc_info.value)
