"""Hamburglar - A static analysis tool for extracting sensitive information.

Hamburglar is designed to scan files and directories for patterns that may
indicate the presence of sensitive data such as API keys, credentials,
private keys, and other secrets. It supports multiple detection methods
including regex pattern matching and YARA rules.

Example usage::

    from hamburglar import Scanner, ScanConfig, Finding
    from pathlib import Path

    # Create a scan configuration
    config = ScanConfig(target_path=Path("/path/to/scan"))

    # Create and run the scanner
    scanner = Scanner(config)
    result = await scanner.scan()

    # Process findings
    for finding in result.findings:
        print(f"{finding.file_path}: {finding.detector_name} - {finding.severity}")
"""

__version__ = "2.0.0"

# Core scanner
from hamburglar.core.scanner import Scanner

# Data models
from hamburglar.core.models import (
    Finding,
    GitFinding,
    OutputFormat,
    ScanConfig,
    ScanResult,
    Severity,
    WebFinding,
)

# Detector base classes
from hamburglar.detectors import BaseDetector, DetectorRegistry, default_registry

# Exceptions
from hamburglar.core.exceptions import HamburglarError, ScanError

__all__ = [
    # Version
    "__version__",
    # Core scanner
    "Scanner",
    # Data models
    "Finding",
    "GitFinding",
    "OutputFormat",
    "ScanConfig",
    "ScanResult",
    "Severity",
    "WebFinding",
    # Detector classes
    "BaseDetector",
    "DetectorRegistry",
    "default_registry",
    # Exceptions
    "HamburglarError",
    "ScanError",
]
