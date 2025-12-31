"""Core data models for Hamburglar.

This module defines the Pydantic models used throughout Hamburglar for
representing scan configuration, findings, and results.
"""

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    TABLE = "table"


class Finding(BaseModel):
    """Represents a single detection finding.

    A Finding is created when a detector matches content in a file,
    such as an API key, credential, or other sensitive data.
    """

    file_path: str = Field(..., description="Path to the file where the finding was detected")
    detector_name: str = Field(..., description="Name of the detector that found this match")
    matches: list[str] = Field(default_factory=list, description="List of matched strings")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity level of the finding")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about the finding")


class ScanResult(BaseModel):
    """Represents the complete result of a scan operation.

    Contains all findings from scanning a target path, along with
    statistics and timing information.
    """

    target_path: str = Field(..., description="The path that was scanned")
    findings: list[Finding] = Field(default_factory=list, description="List of all findings from the scan")
    scan_duration: float = Field(default=0.0, description="Duration of the scan in seconds")
    stats: dict[str, Any] = Field(
        default_factory=dict,
        description="Statistics about the scan (files scanned, errors, etc.)",
    )


class ScanConfig(BaseModel):
    """Configuration for a scan operation.

    Defines all parameters needed to execute a scan, including
    target path, filtering options, and output settings.
    """

    target_path: Path = Field(..., description="Path to scan (file or directory)")
    recursive: bool = Field(default=True, description="Whether to scan directories recursively")
    use_yara: bool = Field(default=False, description="Whether to use YARA rules for detection")
    yara_rules_path: Path | None = Field(default=None, description="Path to YARA rules directory")
    output_format: OutputFormat = Field(default=OutputFormat.TABLE, description="Output format for results")
    blacklist: list[str] = Field(
        default_factory=lambda: [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            ".env",
            "*.pyc",
            "*.pyo",
        ],
        description="Patterns to exclude from scanning",
    )
    whitelist: list[str] = Field(
        default_factory=list,
        description="If non-empty, only scan files matching these patterns",
    )
