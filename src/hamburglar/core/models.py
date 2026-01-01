"""Core data models for Hamburglar.

This module defines the Pydantic models used throughout Hamburglar for
representing scan configuration, findings, and results.
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


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
    SARIF = "sarif"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"


class Finding(BaseModel):
    """Represents a single detection finding.

    A Finding is created when a detector matches content in a file,
    such as an API key, credential, or other sensitive data.
    """

    file_path: str = Field(..., description="Path to the file where the finding was detected")
    detector_name: str = Field(..., description="Name of the detector that found this match")
    matches: list[str] = Field(default_factory=list, description="List of matched strings")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity level of the finding")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata about the finding"
    )


class ElementType(str, Enum):
    """Element types for web findings."""

    SCRIPT = "script"
    INLINE_SCRIPT = "inline_script"
    TEXT = "text"
    ATTRIBUTE = "attribute"


class GitFinding(Finding):
    """Represents a finding from a git repository scan.

    Extends Finding with git-specific context including commit information
    and the file path as it existed at the time of the commit.

    Attributes:
        commit_hash: Full SHA hash of the commit where the finding was detected.
        author: Author name of the commit.
        date: ISO format date string of when the commit was made.
        file_path_at_commit: Path to the file as it existed at the commit.
            This may differ from file_path if the file was renamed.
    """

    commit_hash: str = Field(..., description="Full SHA hash of the commit")
    author: str = Field(..., description="Author name of the commit")
    date: str = Field(..., description="ISO format date of the commit")
    file_path_at_commit: str = Field(
        ..., description="Path to the file as it existed at the commit"
    )


class WebFinding(Finding):
    """Represents a finding from a web URL scan.

    Extends Finding with web-specific context including the URL where
    the finding was detected and the type of HTML element containing it.

    Attributes:
        url: The full URL where the finding was detected.
        element_type: The type of element where the secret was found
            (script, inline_script, text, or attribute).
    """

    url: str = Field(..., description="URL where the finding was detected")
    element_type: ElementType = Field(..., description="Type of element containing the finding")


class SecretOccurrence(BaseModel):
    """Represents a single occurrence of a secret in a git commit.

    Tracks when and where a secret appeared or was removed in the
    repository history.

    Attributes:
        commit_hash: The commit hash where the secret was found.
        author: The author of the commit.
        date: The ISO format date of the commit.
        file_path: The file path at the time of the commit.
        line_type: Whether this was an addition ('+') or removal ('-').
        line_number: Optional line number in the diff.
    """

    commit_hash: str = Field(..., description="The commit hash where the secret was found")
    author: str = Field(..., description="The author of the commit")
    date: str = Field(..., description="The ISO format date of the commit")
    file_path: str = Field(..., description="The file path at the time of the commit")
    line_type: str = Field(..., description="Whether this was an addition ('+') or removal ('-')")
    line_number: int | None = Field(default=None, description="Optional line number in the diff")

    @field_validator("line_type")
    @classmethod
    def validate_line_type(cls, v: str) -> str:
        """Validate that line_type is either '+' or '-'."""
        if v not in ("+", "-"):
            raise ValueError("line_type must be '+' or '-'")
        return v


class SecretTimeline(BaseModel):
    """Tracks the lifecycle of a secret through git history.

    This model provides a complete timeline of when a secret was introduced,
    modified, and potentially removed from a repository. It enables security
    analysis of secret exposure duration and affected files.

    Attributes:
        secret_hash: A hash of the secret value (for grouping without storing the secret).
        secret_preview: A preview of the secret (first and last few chars).
        detector_name: The detector that found this secret.
        severity: The severity level of the finding.
        first_seen: The first occurrence where this secret was introduced.
        last_seen: The most recent occurrence of this secret.
        is_removed: Whether the secret has been removed from the current HEAD.
        occurrences: List of all occurrences of this secret in history.
        exposure_duration: Time between first introduction and removal (in seconds).
        affected_files: Set of file paths where this secret appeared.
    """

    secret_hash: str = Field(..., description="Hash of the secret value for grouping")
    secret_preview: str = Field(..., description="Preview of the secret (first and last few chars)")
    detector_name: str = Field(..., description="Name of the detector that found this secret")
    severity: Severity = Field(default=Severity.MEDIUM, description="Severity level of the finding")
    first_seen: SecretOccurrence | None = Field(
        default=None, description="First occurrence where this secret was introduced"
    )
    last_seen: SecretOccurrence | None = Field(
        default=None, description="Most recent occurrence of this secret"
    )
    is_removed: bool = Field(
        default=False, description="Whether the secret has been removed from current HEAD"
    )
    occurrences: list[SecretOccurrence] = Field(
        default_factory=list, description="All occurrences of this secret in history"
    )
    exposure_duration: float | None = Field(
        default=None, description="Time between introduction and removal in seconds"
    )
    affected_files: list[str] = Field(
        default_factory=list, description="File paths where this secret appeared"
    )

    def add_occurrence(self, occurrence: SecretOccurrence) -> None:
        """Add an occurrence and update first/last seen.

        Args:
            occurrence: The SecretOccurrence to add.
        """
        self.occurrences.append(occurrence)
        if occurrence.file_path not in self.affected_files:
            self.affected_files.append(occurrence.file_path)

        # Update first_seen (earliest addition)
        if occurrence.line_type == "+":
            if self.first_seen is None or occurrence.date < self.first_seen.date:
                self.first_seen = occurrence

        # Update last_seen (latest occurrence of any type)
        if self.last_seen is None or occurrence.date > self.last_seen.date:
            self.last_seen = occurrence

        # Check if removed (last occurrence is a removal)
        if self.last_seen.line_type == "-":
            self.is_removed = True
            if self.first_seen and self.last_seen:
                self._calculate_exposure_duration()

    def _calculate_exposure_duration(self) -> None:
        """Calculate the exposure duration between first seen and last seen."""
        if self.first_seen is None or self.last_seen is None:
            return

        try:
            first_dt = datetime.fromisoformat(self.first_seen.date.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(self.last_seen.date.replace("Z", "+00:00"))
            self.exposure_duration = (last_dt - first_dt).total_seconds()
        except (ValueError, TypeError):
            pass


class ScanResult(BaseModel):
    """Represents the complete result of a scan operation.

    Contains all findings from scanning a target path, along with
    statistics and timing information.
    """

    target_path: str = Field(..., description="The path that was scanned")
    findings: list[Finding] = Field(
        default_factory=list, description="List of all findings from the scan"
    )
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
    output_format: OutputFormat = Field(
        default=OutputFormat.TABLE, description="Output format for results"
    )
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
