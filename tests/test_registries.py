"""Tests for detector and output registries.

This module tests the DetectorRegistry and OutputRegistry classes
for proper registration, retrieval, and management of components.
"""

from __future__ import annotations

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
from hamburglar.detectors import BaseDetector, DetectorRegistry, default_registry
from hamburglar.outputs import BaseOutput, OutputRegistry
from hamburglar.outputs import default_registry as output_default_registry


class MockDetector(BaseDetector):
    """Mock detector for testing."""

    def __init__(self, name: str = "mock") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        if "SECRET" in content:
            return [
                Finding(
                    file_path=file_path,
                    detector_name=self._name,
                    matches=["SECRET"],
                    severity=Severity.HIGH,
                    metadata={},
                )
            ]
        return []


class MockOutput(BaseOutput):
    """Mock output formatter for testing."""

    def __init__(self, name: str = "mock") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def format(self, result: ScanResult) -> str:
        return f"Mock output: {len(result.findings)} findings"


class TestDetectorRegistry:
    """Tests for DetectorRegistry class."""

    def test_register_detector(self) -> None:
        """Test registering a detector."""
        registry = DetectorRegistry()
        detector = MockDetector("test")
        registry.register(detector)
        assert "test" in registry
        assert len(registry) == 1

    def test_register_duplicate_raises(self) -> None:
        """Test that registering a duplicate name raises ValueError."""
        registry = DetectorRegistry()
        detector1 = MockDetector("test")
        detector2 = MockDetector("test")
        registry.register(detector1)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(detector2)

    def test_unregister_detector(self) -> None:
        """Test unregistering a detector."""
        registry = DetectorRegistry()
        detector = MockDetector("test")
        registry.register(detector)
        registry.unregister("test")
        assert "test" not in registry
        assert len(registry) == 0

    def test_unregister_nonexistent_raises(self) -> None:
        """Test that unregistering a nonexistent detector raises KeyError."""
        registry = DetectorRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.unregister("nonexistent")

    def test_get_detector(self) -> None:
        """Test retrieving a detector by name."""
        registry = DetectorRegistry()
        detector = MockDetector("test")
        registry.register(detector)
        retrieved = registry.get("test")
        assert retrieved is detector

    def test_get_nonexistent_raises(self) -> None:
        """Test that getting a nonexistent detector raises KeyError."""
        registry = DetectorRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.get("nonexistent")

    def test_get_all(self) -> None:
        """Test retrieving all detectors."""
        registry = DetectorRegistry()
        detector1 = MockDetector("test1")
        detector2 = MockDetector("test2")
        registry.register(detector1)
        registry.register(detector2)
        all_detectors = registry.get_all()
        assert len(all_detectors) == 2
        assert detector1 in all_detectors
        assert detector2 in all_detectors

    def test_list_names(self) -> None:
        """Test listing detector names."""
        registry = DetectorRegistry()
        detector1 = MockDetector("test1")
        detector2 = MockDetector("test2")
        registry.register(detector1)
        registry.register(detector2)
        names = registry.list_names()
        assert "test1" in names
        assert "test2" in names

    def test_len(self) -> None:
        """Test __len__ method."""
        registry = DetectorRegistry()
        assert len(registry) == 0
        registry.register(MockDetector("test"))
        assert len(registry) == 1

    def test_contains(self) -> None:
        """Test __contains__ method."""
        registry = DetectorRegistry()
        assert "test" not in registry
        registry.register(MockDetector("test"))
        assert "test" in registry

    def test_default_registry_exists(self) -> None:
        """Test that default_registry is available."""
        assert default_registry is not None
        assert isinstance(default_registry, DetectorRegistry)


class TestOutputRegistry:
    """Tests for OutputRegistry class."""

    def test_register_output(self) -> None:
        """Test registering an output formatter."""
        registry = OutputRegistry()
        output = MockOutput("test")
        registry.register(output)
        assert "test" in registry
        assert len(registry) == 1

    def test_register_duplicate_raises(self) -> None:
        """Test that registering a duplicate name raises ValueError."""
        registry = OutputRegistry()
        output1 = MockOutput("test")
        output2 = MockOutput("test")
        registry.register(output1)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(output2)

    def test_unregister_output(self) -> None:
        """Test unregistering an output formatter."""
        registry = OutputRegistry()
        output = MockOutput("test")
        registry.register(output)
        registry.unregister("test")
        assert "test" not in registry
        assert len(registry) == 0

    def test_unregister_nonexistent_raises(self) -> None:
        """Test that unregistering a nonexistent formatter raises KeyError."""
        registry = OutputRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.unregister("nonexistent")

    def test_get_output(self) -> None:
        """Test retrieving an output formatter by name."""
        registry = OutputRegistry()
        output = MockOutput("test")
        registry.register(output)
        retrieved = registry.get("test")
        assert retrieved is output

    def test_get_nonexistent_raises(self) -> None:
        """Test that getting a nonexistent formatter raises KeyError."""
        registry = OutputRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.get("nonexistent")

    def test_get_all(self) -> None:
        """Test retrieving all output formatters."""
        registry = OutputRegistry()
        output1 = MockOutput("test1")
        output2 = MockOutput("test2")
        registry.register(output1)
        registry.register(output2)
        all_outputs = registry.get_all()
        assert len(all_outputs) == 2
        assert output1 in all_outputs
        assert output2 in all_outputs

    def test_list_names(self) -> None:
        """Test listing output formatter names."""
        registry = OutputRegistry()
        output1 = MockOutput("test1")
        output2 = MockOutput("test2")
        registry.register(output1)
        registry.register(output2)
        names = registry.list_names()
        assert "test1" in names
        assert "test2" in names

    def test_len(self) -> None:
        """Test __len__ method."""
        registry = OutputRegistry()
        assert len(registry) == 0
        registry.register(MockOutput("test"))
        assert len(registry) == 1

    def test_contains(self) -> None:
        """Test __contains__ method."""
        registry = OutputRegistry()
        assert "test" not in registry
        registry.register(MockOutput("test"))
        assert "test" in registry

    def test_default_registry_exists(self) -> None:
        """Test that default_registry is available."""
        assert output_default_registry is not None
        assert isinstance(output_default_registry, OutputRegistry)


class TestMockDetectorBehavior:
    """Tests for MockDetector behavior to ensure it works as expected."""

    def test_mock_detector_finds_secret(self) -> None:
        """Test that mock detector finds SECRET in content."""
        detector = MockDetector("mock")
        findings = detector.detect("This contains SECRET data", "test.txt")
        assert len(findings) == 1
        assert findings[0].matches == ["SECRET"]

    def test_mock_detector_no_secret(self) -> None:
        """Test that mock detector returns empty for clean content."""
        detector = MockDetector("mock")
        findings = detector.detect("This is clean", "test.txt")
        assert len(findings) == 0


class TestMockOutputBehavior:
    """Tests for MockOutput behavior to ensure it works as expected."""

    def test_mock_output_formats_result(self) -> None:
        """Test that mock output formats a result."""
        output = MockOutput("mock")
        result = ScanResult(
            target_path="/test",
            findings=[
                Finding(
                    file_path="test.txt",
                    detector_name="mock",
                    matches=["SECRET"],
                    severity=Severity.HIGH,
                    metadata={},
                )
            ],
            scan_duration=0.1,
            stats={},
        )
        formatted = output.format(result)
        assert "1 findings" in formatted

    def test_mock_output_empty_result(self) -> None:
        """Test that mock output handles empty result."""
        output = MockOutput("mock")
        result = ScanResult(
            target_path="/test",
            findings=[],
            scan_duration=0.1,
            stats={},
        )
        formatted = output.format(result)
        assert "0 findings" in formatted
