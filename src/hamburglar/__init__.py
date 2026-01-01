"""Hamburglar - A static analysis tool for extracting sensitive information.

Hamburglar is designed to scan files and directories for patterns that may
indicate the presence of sensitive data such as API keys, credentials,
private keys, and other secrets. It supports multiple detection methods
including regex pattern matching and YARA rules.

Example usage::

    # High-level API (recommended)
    import asyncio
    from hamburglar import scan_directory, scan_git, scan_url

    # Scan a directory for secrets
    result = asyncio.run(scan_directory("/path/to/code"))
    for finding in result.findings:
        print(f"{finding.file_path}: {finding.detector_name}")

    # Scan a git repository
    result = asyncio.run(scan_git("https://github.com/user/repo"))

    # Scan a URL
    result = asyncio.run(scan_url("https://example.com"))

    # Low-level API (for more control)
    from hamburglar import Scanner, ScanConfig, Finding
    from pathlib import Path

    config = ScanConfig(target_path=Path("/path/to/scan"))
    scanner = Scanner(config)
    result = await scanner.scan()
"""

__version__ = "2.0.0"

# Core scanner
# High-level API functions
from hamburglar.api import (
    scan,
    scan_dir,
    scan_directory,
    scan_git,
    scan_repo,
    scan_url,
    scan_web,
)

# Exceptions
from hamburglar.core.exceptions import HamburglarError, ScanError

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
from hamburglar.core.scanner import Scanner

# Detector base classes
from hamburglar.detectors import BaseDetector, DetectorRegistry, default_registry

__all__ = [
    # Version
    "__version__",
    # High-level API functions
    "scan_directory",
    "scan_git",
    "scan_url",
    "scan",
    "scan_dir",
    "scan_repo",
    "scan_web",
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
