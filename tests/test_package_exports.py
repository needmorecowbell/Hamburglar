"""Tests for package-level exports.

This module verifies that the main API classes are properly exported
from the hamburglar package for library usage.
"""


def test_scanner_exported():
    """Test that Scanner class is exported from the package."""
    from hamburglar import Scanner

    assert Scanner is not None
    assert hasattr(Scanner, "scan")


def test_scan_config_exported():
    """Test that ScanConfig class is exported from the package."""
    from hamburglar import ScanConfig

    assert ScanConfig is not None


def test_scan_result_exported():
    """Test that ScanResult class is exported from the package."""
    from hamburglar import ScanResult

    assert ScanResult is not None


def test_finding_exported():
    """Test that Finding class is exported from the package."""
    from hamburglar import Finding

    assert Finding is not None


def test_severity_exported():
    """Test that Severity enum is exported from the package."""
    from hamburglar import Severity

    assert Severity is not None
    assert hasattr(Severity, "CRITICAL")
    assert hasattr(Severity, "HIGH")
    assert hasattr(Severity, "MEDIUM")
    assert hasattr(Severity, "LOW")
    assert hasattr(Severity, "INFO")


def test_output_format_exported():
    """Test that OutputFormat enum is exported from the package."""
    from hamburglar import OutputFormat

    assert OutputFormat is not None
    assert hasattr(OutputFormat, "JSON")
    assert hasattr(OutputFormat, "TABLE")


def test_git_finding_exported():
    """Test that GitFinding class is exported from the package."""
    from hamburglar import GitFinding

    assert GitFinding is not None


def test_web_finding_exported():
    """Test that WebFinding class is exported from the package."""
    from hamburglar import WebFinding

    assert WebFinding is not None


def test_base_detector_exported():
    """Test that BaseDetector class is exported from the package."""
    from hamburglar import BaseDetector

    assert BaseDetector is not None


def test_detector_registry_exported():
    """Test that DetectorRegistry class is exported from the package."""
    from hamburglar import DetectorRegistry

    assert DetectorRegistry is not None


def test_default_registry_exported():
    """Test that default_registry instance is exported from the package."""
    from hamburglar import default_registry

    assert default_registry is not None


def test_hamburglar_error_exported():
    """Test that HamburglarError exception is exported from the package."""
    from hamburglar import HamburglarError

    assert HamburglarError is not None
    assert issubclass(HamburglarError, Exception)


def test_scan_error_exported():
    """Test that ScanError exception is exported from the package."""
    from hamburglar import ScanError

    assert ScanError is not None
    assert issubclass(ScanError, Exception)


def test_version_exported():
    """Test that __version__ is exported from the package."""
    from hamburglar import __version__

    assert __version__ is not None
    assert isinstance(__version__, str)


def test_all_exports_in_dunder_all():
    """Test that __all__ contains all the expected exports."""
    import hamburglar

    expected_exports = [
        "__version__",
        "Scanner",
        "Finding",
        "GitFinding",
        "OutputFormat",
        "ScanConfig",
        "ScanResult",
        "Severity",
        "WebFinding",
        "BaseDetector",
        "DetectorRegistry",
        "default_registry",
        "HamburglarError",
        "ScanError",
    ]

    for export in expected_exports:
        assert export in hamburglar.__all__, f"{export} not in __all__"


def test_import_all_at_once():
    """Test that all exports can be imported in a single statement."""
    from hamburglar import (
        BaseDetector,
        DetectorRegistry,
        Finding,
        GitFinding,
        HamburglarError,
        OutputFormat,
        ScanConfig,
        ScanError,
        ScanResult,
        Scanner,
        Severity,
        WebFinding,
        __version__,
        default_registry,
    )

    # All imports should succeed if we reach here
    # Note: We use 'is not None' checks because some objects like
    # default_registry may be falsy (empty registry has __len__ == 0)
    assert Scanner is not None
    assert ScanConfig is not None
    assert ScanResult is not None
    assert Finding is not None
    assert Severity is not None
    assert OutputFormat is not None
    assert GitFinding is not None
    assert WebFinding is not None
    assert BaseDetector is not None
    assert DetectorRegistry is not None
    assert default_registry is not None
    assert HamburglarError is not None
    assert ScanError is not None
    assert __version__ is not None
